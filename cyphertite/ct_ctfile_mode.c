/*
 * Copyright (c) 2011, 2012 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <libgen.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <regex.h>
#include <errno.h>

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <xmlsd.h>

#include <ctutil.h>
#include "ct_xml.h"

#include "ct.h"
#include "ct_crypto.h"

SLIST_HEAD(ctfile_list, ctfile_list_file);

struct ctfile_list			ctfile_list_files =
				     SLIST_HEAD_INITIALIZER(&ctfile_list_files);

void ct_cull_send_shas(struct ct_op *);
void ct_cull_setup(struct ct_op *);
void ct_cull_start_shas(struct ct_op *);
void ct_cull_start_complete(struct ct_op *op);
void ct_cull_send_complete(struct ct_op *op);
void ct_cull_complete(struct ct_op *op);
void ct_cull_collect_ctfiles(struct ct_op *op);
void ct_cull_fetch_all_ctfiles(struct ct_op *op);

struct xmlsd_v_elements ct_xml_cmds[] = {
	{ "ct_md_list", xe_ct_md_list },
	{ "ct_md_open_read", xe_ct_md_open_read },
	{ "ct_md_open_create", xe_ct_md_open_create },
	{ "ct_md_delete", xe_ct_md_delete },
	{ "ct_md_close", xe_ct_md_close },
	{ "ct_cull_setup", xe_ct_cull_setup },
	{ "ct_cull_shas", xe_ct_cull_shas },
	{ "ct_cull_complete", xe_ct_cull_complete },
	{ "ct_cull_setup_reply", xe_ct_cull_setup_reply },
	{ "ct_cull_shas_reply", xe_ct_cull_shas_reply },
	{ "ct_cull_complete_reply", xe_ct_cull_complete_reply },
	{ NULL, NULL }
};


/*
 * clean up after a ctfile archive/extract operation by freeing the remotename
 */
void
ctfile_op_cleanup(struct ct_op *op)
{
	struct ct_ctfileop_args	*cca = op->op_args;

	e_free(&cca->cca_remotename);
}

struct ctfile_archive_state {
	FILE		*cas_handle;
	struct fnode	*cas_fnode;
	off_t		 cas_size;
	off_t		 cas_offset;
	int		 cas_block_no;
	int		 cas_open_sent;
};

void
ctfile_archive(struct ct_op *op)
{
	char				 tpath[PATH_MAX];
	struct ct_ctfileop_args		*cca = op->op_args;
	struct ctfile_archive_state	*cas = op->op_priv;
	const char			*ctfile = cca->cca_localname;
	const char			*rname = cca->cca_remotename;
	struct ct_trans			*ct_trans;
	struct stat			 sb;
	ssize_t				 rsz, rlen;
	int				 error;

	if (ct_state->ct_file_state == CT_S_STARTING) {
		cas = e_calloc(1, sizeof(*cas));
		op->op_priv = cas;

		if (cca->cca_tdir) {
			snprintf(tpath, sizeof tpath, "%s/%s",
			    cca->cca_tdir, ctfile);
		} else {
			strlcpy(tpath, ctfile, sizeof(tpath));
		}
		CNDBG(CT_LOG_FILE, "opening ctfile for archive %s", ctfile);
		if ((cas->cas_handle = fopen(tpath, "rb")) == NULL)
			CFATAL("can't open %s for reading", ctfile);
		if (cca->cca_ctfile) {
			struct ctfile_parse_state	 xs_ctx;
			int				 ret;
			if (ctfile_parse_init_f(&xs_ctx, cas->cas_handle))
				CFATALX("%s is not a valid ctfile, can't "
				    "open", tpath);
			while ((ret = ctfile_parse(&xs_ctx)) != XS_RET_EOF) {
				if (ret == XS_RET_SHA)  {
					if (ctfile_parse_seek(&xs_ctx))
						CFATALX("seek failed");
				} else if (ret == XS_RET_FAIL) {
					CFATALX("%s is not a valid ctfile, EOF"
					    " not found", tpath);
				}

			}
			ctfile_parse_close(&xs_ctx);
			fseek(cas->cas_handle, 0L, SEEK_SET);
		}

		if (fstat(fileno(cas->cas_handle), &sb) == -1)
			CFATAL("can't stat backup file %s", ctfile);
		cas->cas_size = sb.st_size;
		cas->cas_fnode = e_calloc(1, sizeof(*cas->cas_fnode));

		if (rname == NULL) {
			rname = ctfile_cook_name(ctfile);
			cca->cca_remotename = (char *)rname;
		}
	} else if (ct_state->ct_file_state == CT_S_FINISHED) {
		/* We're done here */
		return;
	} else if (ct_state->ct_file_state == CT_S_WAITING_SERVER) {
		CNDBG(CT_LOG_FILE, "waiting on remote open");
		return;
	}

	CNDBG(CT_LOG_FILE, "entered for block %d", cas->cas_block_no);
	ct_set_file_state(CT_S_RUNNING);
loop:
	ct_trans = ct_trans_alloc();
	if (ct_trans == NULL) {
		/* system busy, return */
		CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	if (cas->cas_open_sent == 0) {
		cas->cas_open_sent = 1;
		ct_xml_file_open(ct_trans, rname, MD_O_WRITE, 0);
		/* xml thread will wake us up when it gets the open */
		ct_set_file_state(CT_S_WAITING_SERVER);
		return;
	}

	/* Are we done here? */
	if (cas->cas_size == cas->cas_offset) {
		ct_set_file_state(CT_S_FINISHED);

		ct_trans->tr_fl_node = NULL;
		ct_trans->tr_state = TR_S_XML_CLOSE;
		ct_trans->tr_eof = 1;
		ct_trans->tr_trans_id = ct_trans_id++;
		CNDBG(CT_LOG_FILE, "setting eof on trans %" PRIu64,
		    ct_trans->tr_trans_id);
		ct_trans->hdr.c_flags = C_HDR_F_METADATA;
		ct_trans->tr_ctfile_name = rname;
		ct_stats->st_bytes_tot += cas->cas_size;
		e_free(&cas);
		op->op_priv = NULL;
		ct_queue_transfer(ct_trans);
		return;
	}
	/* perform read */
	rsz = cas->cas_size - cas->cas_offset;

	CNDBG(CT_LOG_FILE, "rsz %ld max %d", (long) rsz, ct_max_block_size);
	if (rsz > ct_max_block_size) {
		rsz = ct_max_block_size;
	}

	ct_trans->tr_dataslot = 0;
	rlen = fread(ct_trans->tr_data[0], sizeof(char), rsz, cas->cas_handle);

	CNDBG(CT_LOG_FILE, "read %ld", (long) rlen);

	ct_stats->st_bytes_read += rlen;

	ct_trans->tr_fl_node = cas->cas_fnode;
	ct_trans->tr_chsize = ct_trans->tr_size[0] = rlen;
	ct_trans->tr_state = TR_S_READ;
	ct_trans->tr_type = TR_T_WRITE_CHUNK;
	ct_trans->tr_trans_id = ct_trans_id++;
	ct_trans->tr_eof = 0;
	ct_trans->hdr.c_flags = C_HDR_F_METADATA;
	ct_trans->hdr.c_flags |= cca->cca_encrypted ? C_HDR_F_ENCRYPTED : 0;
	ct_trans->hdr.c_ex_status = 2; /* we handle new metadata protocol */
	ct_trans->tr_ctfile_chunkno = cas->cas_block_no;
	ct_trans->tr_ctfile_name = rname;

	CNDBG(CT_LOG_FILE, " trans %"PRId64", read size %ld, into %p rlen %ld",
	    ct_trans->tr_trans_id, (long) rsz, ct_trans->tr_data[0],
	    (long) rlen);

	/*
	 * init iv to something that can be recreated, used if hdr->c_flags
	 * has C_HDR_F_METADATA set.
	 */
	bzero(ct_trans->tr_iv, sizeof(ct_trans->tr_iv));
	ct_trans->tr_iv[0] = (cas->cas_block_no >>  0) & 0xff;
	ct_trans->tr_iv[1] = (cas->cas_block_no >>  8) & 0xff;
	ct_trans->tr_iv[2] = (cas->cas_block_no >> 16) & 0xff;
	ct_trans->tr_iv[3] = (cas->cas_block_no >> 24) & 0xff;
	ct_trans->tr_iv[4] = (cas->cas_block_no >>  0) & 0xff;
	ct_trans->tr_iv[5] = (cas->cas_block_no >>  8) & 0xff;
	ct_trans->tr_iv[6] = (cas->cas_block_no >> 16) & 0xff;
	ct_trans->tr_iv[7] = (cas->cas_block_no >> 24) & 0xff;
	/* XXX - leaves the rest of the iv with 0 */

	cas->cas_block_no++;

	CNDBG(CT_LOG_FILE, "sizes rlen %ld offset %ld size %ld", (long) rlen,
	    (long)cas->cas_offset, (long)cas->cas_size);

	if (rsz != rlen || (rlen + cas->cas_offset) == cas->cas_size) {
		/* short read, file truncated or EOF */
		CNDBG(CT_LOG_FILE, "DONE");
		error = fstat(fileno(cas->cas_handle), &sb);
		if (error) {
			CWARNX("file stat error %s %d %s",
			    ctfile, errno, strerror(errno));
		} else if (sb.st_size != cas->cas_size) {
			CWARNX("file truncated during backup %s",
			    ctfile);
			/*
			 * may need to perform special nop processing
			 * to pad archive file to right number of chunks
			 */
		}
		/*
		 * we don't set eof here because the next go round
		 * will hit the state done case above
		 */
		cas->cas_offset = cas->cas_size;
		ct_trans->tr_eof = 1;
	} else {
		cas->cas_offset += rlen;
	}
	ct_queue_transfer(ct_trans);
	goto loop;
}

void
ct_xml_file_open(struct ct_trans *trans, const char *file, int mode,
    uint32_t chunkno)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	char				 b64[CT_MAX_MD_FILENAME];
	size_t				 sz;

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_OPEN;

	CNDBG(CT_LOG_XML, "setting up XML");

	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)file, strlen(file),
	    (uint8_t *)b64, sizeof(b64)))
		CFATALX("cant base64 encode %s", file);

	if (mode == MD_O_WRITE || mode == MD_O_APPEND) {
		xe = xmlsd_create(&xl, "ct_md_open_create");
		xmlsd_set_attr(xe, "version", CT_MD_OPEN_CREATE_VERSION);
	} else {	/* mode == MD_O_READ */
		xe = xmlsd_create(&xl, "ct_md_open_read");
		xmlsd_set_attr(xe, "version", CT_MD_OPEN_READ_VERSION);
	}

	xe = xmlsd_add_element(&xl, xe, "file");
	xmlsd_set_attr(xe, "name", b64);

	if (mode == MD_O_APPEND || chunkno) {
		xmlsd_set_attr_uint32(xe, "chunkno", chunkno);
	}

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;

	CNDBG(CT_LOG_XML, "open trans %"PRIu64, trans->tr_trans_id);
	ct_queue_transfer(trans);

}

int
ct_xml_file_open_polled(struct ct_assl_io_ctx *asslctx,
    const char *file, int mode, uint32_t chunkno)
{
#define ASSL_TIMEOUT 20
	extern uint64_t		 ct_packet_id;
	struct ct_header	 hdr;

	struct xmlsd_element_list xl;
	struct xmlsd_element	*xe;
	char			*body = NULL;
	char			 b64[CT_MAX_MD_FILENAME];
	size_t			 sz;
	int			 rv = 1;

	CNDBG(CT_LOG_XML, "setting up XML");

	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)file, strlen(file),
	    (uint8_t *)b64, sizeof(b64)))
		CFATALX("cant base64 encode %s", file);

	if (mode == MD_O_WRITE || mode == MD_O_APPEND) {
		xe = xmlsd_create(&xl, "ct_md_open_create");
		xmlsd_set_attr(xe, "version", CT_MD_OPEN_CREATE_VERSION);
	} else {	/* mode == MD_O_READ */
		xe = xmlsd_create(&xl, "ct_md_open_read");
		xmlsd_set_attr(xe, "version", CT_MD_OPEN_READ_VERSION);
	}

	xe = xmlsd_add_element(&xl, xe, "file");
	xmlsd_set_attr(xe, "name", b64);

	if (mode == MD_O_APPEND || chunkno) {
		xmlsd_set_attr_uint32(xe, "chunkno", chunkno);
	}

	body = xmlsd_generate(&xl, malloc, &sz, 1);
	xmlsd_unwind(&xl);

	hdr.c_version = C_HDR_VERSION;
	hdr.c_opcode = C_HDR_O_XML;
	hdr.c_flags = C_HDR_F_METADATA;
	/* use previous packet id so it'll fit with the state machine */
	hdr.c_tag = ct_packet_id - 1;
	hdr.c_size = sz;

	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(asslctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("could not write header");
		goto done;
	}
	if (ct_assl_io_write_poll(asslctx, body, sz,  ASSL_TIMEOUT) != sz) {
		CWARNX("could not write body");
		goto done;
	}
	free(body);

	/* get server reply */
	if (ct_assl_io_read_poll(asslctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("invalid header size");
		goto done;
	}
	ct_unwire_header(&hdr);

	if (hdr.c_status == C_HDR_S_OK && hdr.c_opcode == C_HDR_O_XML_REPLY)
		rv = 0;

	/* we know the open was ok or bad, just read the body and dump it */
	body = e_calloc(1, hdr.c_size);
	if (ct_assl_io_read_poll(asslctx, body, hdr.c_size, ASSL_TIMEOUT)
	    != hdr.c_size) {
		rv = 1;
	}
	e_free(&body);

done:
	if (body)
		e_free(&body);
	return (rv);
#undef ASSL_TIMEOUT
}

void
ct_xml_file_close(void)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	struct ct_trans			*trans;
	size_t				 sz;

	trans = ct_trans_alloc();
	if (trans == NULL) {
		/* system busy, return */
		CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_CLOSING;

	CNDBG(CT_LOG_XML, "setting up XML");

	xe = xmlsd_create(&xl, "ct_md_close");
	xmlsd_set_attr(xe, "version", CT_MD_CLOSE_VERSION);

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;

	ct_queue_transfer(trans);
}

struct ctfile_extract_state {
	struct fnode	*ces_fnode;
	int		 ces_block_no;
	int		 ces_open_sent;
	int		 ces_is_open;
};

void
ctfile_extract(struct ct_op *op)
{
	struct ct_ctfileop_args		*cca = op->op_args;
	struct ctfile_extract_state	*ces = op->op_priv;
	const char			*ctfile = cca->cca_localname;
	const char			*rname = cca->cca_remotename;
	struct ct_trans			*trans;
	struct ct_header		*hdr;

	if (ct_state->ct_file_state == CT_S_STARTING) {
		ces = e_calloc(1, sizeof(*ces));
		op->op_priv = ces;

		if (rname == NULL) {
			rname = ctfile_cook_name(ctfile);
			cca->cca_remotename = (char *)rname;
		}
		ct_file_extract_setup_dir(cca->cca_tdir);
	} else if (ct_state->ct_file_state == CT_S_FINISHED) {
		return;
	} else if (ct_state->ct_file_state == CT_S_WAITING_SERVER) {
		CNDBG(CT_LOG_FILE, "waiting on remote open");
		return;
	}

	ct_set_file_state(CT_S_RUNNING);

again:
	trans = ct_trans_alloc();
	if (trans == NULL) {
		/* system busy, return */
		CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}
	if (ces->ces_open_sent == 0) {
		ct_xml_file_open(trans, rname, MD_O_READ, 0);
		ces->ces_open_sent = 1;
		/* xml thread will wake us up when it gets the open */
		ct_set_file_state(CT_S_WAITING_SERVER);
		return;
	} else if (ces->ces_is_open == 0) {
		ces->ces_is_open = 1;
		extern struct dnode ct_rootdir;
		ces->ces_fnode = e_calloc(1, sizeof(*ces->ces_fnode));
		ces->ces_fnode->fl_type = C_TY_REG;
		ces->ces_fnode->fl_parent_dir = &ct_rootdir;
		ces->ces_fnode->fl_name = e_strdup(ctfile);
		ces->ces_fnode->fl_sname = e_strdup(ctfile);
		ces->ces_fnode->fl_mode = S_IRUSR | S_IWUSR;
		ces->ces_fnode->fl_uid = getuid();
		ces->ces_fnode->fl_gid = getgid();
		ces->ces_fnode->fl_atime = time(NULL);
		ces->ces_fnode->fl_mtime = time(NULL);

		trans = ct_trans_realloc_local(trans);
		trans->tr_fl_node = ces->ces_fnode;
		trans->tr_state = TR_S_EX_FILE_START;
		trans->tr_trans_id = ct_trans_id++;
		trans->hdr.c_flags |= C_HDR_F_METADATA;
		ct_queue_transfer(trans);
		goto again;
	}

	trans->tr_fl_node = ces->ces_fnode;
	trans->tr_state = TR_S_EX_SHA;
	trans->tr_type = TR_T_READ_CHUNK;
	trans->tr_trans_id = ct_trans_id++;
	trans->tr_eof = 0;
	trans->tr_ctfile_chunkno = ces->ces_block_no;
	trans->tr_ctfile_name = rname;

	hdr = &trans->hdr;
	hdr->c_ex_status = 2;
	hdr->c_flags |= C_HDR_F_METADATA;

	bzero(trans->tr_sha, sizeof(trans->tr_sha));
	trans->tr_sha[0] = (ces->ces_block_no >>  0) & 0xff;
	trans->tr_sha[1] = (ces->ces_block_no >>  8) & 0xff;
	trans->tr_sha[2] = (ces->ces_block_no >> 16) & 0xff;
	trans->tr_sha[3] = (ces->ces_block_no >> 24) & 0xff;
	bzero(trans->tr_iv, sizeof(trans->tr_iv));
	trans->tr_iv[0] = (ces->ces_block_no >>  0) & 0xff;
	trans->tr_iv[1] = (ces->ces_block_no >>  8) & 0xff;
	trans->tr_iv[2] = (ces->ces_block_no >> 16) & 0xff;
	trans->tr_iv[3] = (ces->ces_block_no >> 24) & 0xff;
	trans->tr_iv[4] = (ces->ces_block_no >>  0) & 0xff;
	trans->tr_iv[5] = (ces->ces_block_no >>  8) & 0xff;
	trans->tr_iv[6] = (ces->ces_block_no >> 16) & 0xff;
	trans->tr_iv[7] = (ces->ces_block_no >> 24) & 0xff;

	ces->ces_block_no++; /* next chunk on next pass */

	ct_queue_transfer(trans);
}

void
ct_complete_metadata(struct ct_trans *trans)
{
	int			slot, done = 0, release_fnode = 0;

	switch(trans->tr_state) {
	case TR_S_EX_FILE_START:
		/* XXX can we recover from this? */
		if (ct_file_extract_open(trans->tr_fl_node) != 0)
			CFATALX("unable to open file %s",
			    trans->tr_fl_node->fl_name);
		break;
	case TR_S_EX_READ:
	case TR_S_EX_DECRYPTED:
	case TR_S_EX_UNCOMPRESSED:
		if (trans->hdr.c_status == C_HDR_S_OK) {
			slot = trans->tr_dataslot;
			CNDBG(CT_LOG_FILE, "writing packet sz %d",
			    trans->tr_size[slot]);
			ct_file_extract_write(trans->tr_fl_node,
			    trans->tr_data[slot], trans->tr_size[slot]);
		} else {
			ct_state->ct_file_state = CT_S_FINISHED;
		}
		break;

	case TR_S_DONE:
		/* More operations to be done? */
		if (ct_op_complete())
			done = 1;

		/* Clean up reconnect name, shared between all trans */
		if (trans->tr_ctfile_name != NULL)
			e_free(&trans->tr_ctfile_name);

		if (!done)
			return;
		if (ct_verbose_ratios)
			ct_dump_stats(stdout);

		ct_shutdown();
		break;
	case TR_S_WMD_READY:
		if (trans->tr_eof != 0)
			release_fnode = 1;
	case TR_S_XML_OPEN:
	case TR_S_XML_CLOSING:
	case TR_S_XML_CLOSED:
	case TR_S_XML_OPENED:
	case TR_S_READ:
		break;
	case TR_S_EX_FILE_END:
		ct_file_extract_close(trans->tr_fl_node);
		ct_file_extract_cleanup_dir();
		release_fnode = 1;
		/* FALLTHROUGH */
	case TR_S_XML_CLOSE:
		CNDBG(CT_LOG_FILE, "eof reached, closing file");
		ct_xml_file_close();
		break;

	case TR_S_XML_CULL_REPLIED:
		ct_wakeup_file();
		break;
	default:
		CFATALX("unexpected tr state in %s %d", __func__,
		    trans->tr_state);
	}

	if (release_fnode != 0)
		ct_free_fnode(trans->tr_fl_node);
}

void
ctfile_list_start(struct ct_op *op)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	struct ct_trans			*trans;
	size_t				 sz;

	ct_set_file_state(CT_S_FINISHED);

	trans = ct_trans_alloc();

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_LIST;

	CNDBG(CT_LOG_XML, "setting up XML");

	xe = xmlsd_create(&xl, "ct_md_list");
	xmlsd_set_attr(xe, "version", CT_MD_LIST_VERSION);

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;

	ct_queue_transfer(trans);
}

void
ctfile_list_complete(int matchmode, char **flist, char **excludelist,
    struct ctfile_list_tree *results)
{
	struct ct_match		*match, *ex_match = NULL;
	struct ctfile_list_file	*file;

	if (SLIST_EMPTY(&ctfile_list_files))
		return;

	match = ct_match_compile(matchmode, flist);
	if (excludelist)
		ex_match = ct_match_compile(matchmode, excludelist);
	while ((file = SLIST_FIRST(&ctfile_list_files)) != NULL) {
		SLIST_REMOVE_HEAD(&ctfile_list_files, mlf_link);
		if (ct_match(match, file->mlf_name) == 0 && (ex_match == NULL ||
		    ct_match(ex_match, file->mlf_name) == 1)) {
			RB_INSERT(ctfile_list_tree, results, file);
		} else {
			e_free(&file);
		}
	}
	if (ex_match != NULL)
		ct_match_unwind(ex_match);
	ct_match_unwind(match);
}

int
ct_cmp_ctfile(struct ctfile_list_file *f1, struct ctfile_list_file *f2)
{
	return (strcmp(f1->mlf_name, f2->mlf_name));
}

RB_GENERATE(ctfile_list_tree, ctfile_list_file, mlf_next, ct_cmp_ctfile);

void
ctfile_delete(struct ct_op *op)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	const char			*rname = op->op_args;
	struct ct_trans			*trans;
	char				 b64[CT_MAX_MD_FILENAME * 2];
	size_t				 sz;

	rname = ctfile_cook_name(rname);

	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)rname, strlen(rname),
	    (uint8_t *)b64, sizeof(b64)))
		CFATALX("cant base64 encode %s", rname);

	xe = xmlsd_create(&xl, "ct_md_delete");
	xmlsd_set_attr(xe, "version", CT_MD_DELETE_VERSION);
	xe = xmlsd_add_element(&xl, xe, "file");
	xmlsd_set_attr(xe, "name", b64);

	e_free(&rname);

	trans = ct_trans_alloc();
	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_DELETE;

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;

	ct_queue_transfer(trans);
}

void
ct_handle_xml_reply(struct ct_trans *trans, struct ct_header *hdr,
    void *vbody)
{
	struct xmlsd_element_list xl;
	struct xmlsd_attribute *xa;
	struct xmlsd_element *xe;
	char *body = vbody;
	char *filename;
	char b64[CT_MAX_MD_FILENAME * 2];
	int r;

	CNDBG(CT_LOG_XML, "xml [%s]", (char *)vbody);

	/* Dispose of last parsed command. */
	TAILQ_INIT(&xl);

	r = xmlsd_parse_mem(body, hdr->c_size - 1, &xl);
	if (r)
		CFATALX("XML parse failed! (%d)", r);

	TAILQ_FOREACH(xe, &xl, entry) {
		CNDBG(CT_LOG_XML, "%d %s = %s (parent = %s)",
		    xe->depth, xe->name, xe->value ? xe->value : "NOVAL",
		    xe->parent ? xe->parent->name : "NOPARENT");
		TAILQ_FOREACH(xa, &xe->attr_list, entry)
			CNDBG(CT_LOG_XML, "\t%s = %s", xa->name, xa->value);
	}

	r = xmlsd_validate(&xl, ct_xml_cmds);
	if (r)
		CFATALX("XML validate of '%s' failed! (%d)", body, r);

	if (TAILQ_EMPTY(&xl))
		CFATALX("parse command: No XML");

	xe = TAILQ_FIRST(&xl);
	if (strncmp(xe->name, "ct_md_open", strlen("ct_md_open")) == 0) {
		int die = 1;

		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				filename = xmlsd_get_attr(xe, "name");
				if (filename && filename[0] != '\0') {
					CNDBG(CT_LOG_FILE, "%s opened\n",
					    filename);
					die = 0;
					ct_set_file_state(CT_S_RUNNING);
					ct_wakeup_file();
				}
			}
		}
		if (die)
			CFATALX("couldn't open remote file");
		trans->tr_state = TR_S_XML_OPENED;
	} else if (strcmp(xe->name, "ct_md_close") == 0) {
		trans->tr_state = TR_S_DONE;
	} else if (strcmp(xe->name, "ct_md_list") == 0) {
		struct ctfile_list_file	*file;
		const char		*errstr;
		char			*tmp;

		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				file = e_malloc(sizeof(*file));
				tmp = xmlsd_get_attr(xe, "name");
				if (tmp == NULL) {
					e_free(&file);
					continue;
				}

				if (ct_base64_encode(CT_B64_M_DECODE,
				    (uint8_t *)tmp, strlen(tmp),
				    (uint8_t *)file->mlf_name,
				    sizeof(file->mlf_name))) {
					    e_free(&file);
					    continue;
				}

				tmp = xmlsd_get_attr(xe, "size");
				file->mlf_size = strtonum(tmp, 0, LLONG_MAX,
				    &errstr);
				if (errstr != NULL)
					CFATAL("can't parse file size %s",
					    errstr);

				tmp = xmlsd_get_attr(xe, "mtime");
				file->mlf_mtime = strtonum(tmp, 0, LLONG_MAX,
				    &errstr);
				if (errstr != NULL)
					CFATAL("can't parse mtime: %s", errstr);
				SLIST_INSERT_HEAD(&ctfile_list_files, file,
				    mlf_link);
			}
		}
		trans->tr_state = TR_S_DONE;
	} else  if (strcmp(xe->name, "ct_md_delete") == 0) {
		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				filename = xmlsd_get_attr(xe, "name");
				if (filename == NULL || filename[0] == '\0')
					printf("specified archive does not "
					    "exist\n");
				else {
					if (ct_base64_encode(CT_B64_M_DECODE,
					    (uint8_t *)filename, strlen(filename),
					    (uint8_t *)b64, sizeof(b64))) {
						CFATALX("cant base64 encode %s",
						    filename);
					}
					printf("%s deleted\n", b64);
				}
			}
		}
		trans->tr_state = TR_S_DONE;
	} else  if (strcmp(xe->name, "ct_cull_setup_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_setup_reply");
		trans->tr_state = TR_S_DONE;
	} else  if (strcmp(xe->name, "ct_cull_shas_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_shas_reply");
		if (trans->tr_eof == 1)
			trans->tr_state = TR_S_DONE;
		else
			trans->tr_state = TR_S_XML_CULL_REPLIED;
	} else  if (strcmp(xe->name, "ct_cull_complete_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_complete_reply");
		trans->tr_state = TR_S_DONE;
	} else {
		CABORTX("unexpected XML returned [%s]", (char *)vbody);
	}

	ct_queue_transfer(trans);
	ct_body_free(NULL, vbody, hdr);
	ct_header_free(NULL, hdr);
	xmlsd_unwind(&xl);
}

#if 0
/*
 * Delete all metadata files that were found by the preceding list operation.
 */
void
ctfile_trigger_delete(struct ct_op *op)
{
	struct ctfile_list_tree	 results;
	struct ctfile_list_file	*file = NULL;

	RB_INIT(&results);
	ctfile_list_complete(op->op_matchmode, op->op_filelist,
	    op->op_excludelist, &results);
	while((file = RB_ROOT(&results)) != NULL) {
		CNDBG(CT_LOG_CRYPTO, "deleting remote crypto secrets file %s",
		    file->mlf_name);
		ct_add_operation_after(op, ctfile_delete, NULL, NULL,
		    e_strdup(file->mlf_name), NULL, NULL, NULL, 0, 0);
		RB_REMOVE(ctfile_list_tree, &results, file);
		e_free(&file);
	}
}
#endif

/*
 * Verify that the ctfile name is kosher.
 * - Encode the name (with a fake prefix) to make sure it fits.
 * - To help with interoperability, scan for a few special characters
 *   and punt if we find those.
 */
int
ctfile_verify_name(char *ctfile)
{
	const char	*set = CT_CTFILE_REJECTCHRS;
	char		 b[CT_CTFILE_MAXLEN], b64[CT_CTFILE_MAXLEN];
	size_t		 span, ctfilelen;
	int		 sz;

	if (ctfile == NULL)
		return 1;

	/* No processing for local mode. */
	if (ctfile_mode == CT_MDMODE_LOCAL)
		return 0;

	sz = snprintf(b, sizeof(b), "YYYYMMDD-HHMMSS-%s", ctfile);
	if (sz == -1 || sz >= sizeof(b))
		return 1;

	/* Make sure it fits. */
	sz = ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)b, strlen(b),
	    (uint8_t *)b64, sizeof(b64));
	if (sz != 0)
		return 1;

	ctfilelen = strlen(ctfile);
	span = strcspn(ctfile, set);
	return !(span == ctfilelen);
}

/*
 * Data structures to hold cull data
 *
 * Should this be stored in memory or build a temporary DB
 * to hold it due to the number of shas involved?
 */

RB_HEAD(ct_sha_lookup, sha_entry) ct_sha_rb_head =
     RB_INITIALIZER(&ct_sha_rb_head);
uint64_t shacnt;
uint64_t sha_payload_sz;

struct sha_entry {
	RB_ENTRY(sha_entry)      s_rb;
	uint8_t sha[SHA_DIGEST_LENGTH];
};

int ct_cmp_sha(struct sha_entry *, struct sha_entry *);

RB_PROTOTYPE(ct_sha_lookup, sha_entry, s_rb, ct_cmp_sha);
RB_GENERATE(ct_sha_lookup, sha_entry, s_rb, ct_cmp_sha);

int
ct_cmp_sha(struct sha_entry *d1, struct sha_entry *d2)
{
	return bcmp(d1->sha, d2->sha, sizeof (d1->sha));
}

void
ct_cull_sha_insert(const uint8_t *sha)
{
	//char			shat[SHA_DIGEST_STRING_LENGTH];
	struct sha_entry	*node, *oldnode;

	node = e_malloc(sizeof(*node));
	bcopy (sha, node->sha, sizeof(node->sha));

	//ct_sha1_encode((uint8_t *)sha, shat);
	//printf("adding sha %s\n", shat);

	oldnode = RB_INSERT(ct_sha_lookup, &ct_sha_rb_head, node);
	if (oldnode != NULL) {
		/* already present, throw away copy */
		e_free(&node);
	} else
		shacnt++;

}

void
ct_cull_kick(void)
{

	CNDBG(CT_LOG_TRANS, "add_op cull_setup");
	CNDBG(CT_LOG_SHA, "shacnt %" PRIu64 , shacnt);

	ct_add_operation(ctfile_list_start, ct_cull_fetch_all_ctfiles, NULL);
	ct_add_operation(ct_cull_collect_ctfiles, NULL,  NULL);
	ct_add_operation(ct_cull_setup, NULL, NULL);
	ct_add_operation(ct_cull_send_shas, NULL, NULL);
	ct_add_operation(ct_cull_send_complete, ct_cull_complete, NULL);
}

void
ct_cull_complete(struct ct_op *op)
{
	CNDBG(CT_LOG_SHA, "shacnt %" PRIu64 " shapayload %" PRIu64, shacnt,
	    sha_payload_sz);
}

uint64_t cull_uuid; /* set up with random number in ct_cull_setup() */
/* tune this */
int sha_per_packet = 1000;

void
ct_cull_setup(struct ct_op *op)
{
	struct xmlsd_element_list	xl;
	struct xmlsd_element		*xp, *xe;
	struct ct_trans			*trans;
	size_t				sz;

	arc4random_buf(&cull_uuid, sizeof(cull_uuid));

	CNDBG(CT_LOG_TRANS, "cull_setup");
	ct_set_file_state(CT_S_RUNNING);

	trans = ct_trans_alloc();

	if (trans == NULL) {
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_CULL_SEND;

	xp = xmlsd_create(&xl, "ct_cull_setup");
	xmlsd_set_attr(xp, "version", CT_CULL_SETUP_VERSION);
	xe = xmlsd_add_element(&xl, xp, "cull");
	xmlsd_set_attr(xe, "type", "precious");
	xmlsd_set_attr_uint64(xe, "uuid", cull_uuid);

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;

	ct_queue_transfer(trans);
}

int sent_complete;
void
ct_cull_send_complete(struct ct_op *op)
{
	struct xmlsd_element_list	xl;
	struct xmlsd_element		*xp, *xe;
	struct ct_trans			*trans;
	size_t				sz;

	if (sent_complete) {
		return;
	}
	sent_complete = 1;

	CNDBG(CT_LOG_TRANS, "send cull_complete");
	trans = ct_trans_alloc();

	if (trans == NULL) {
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_CULL_SEND;

	xp = xmlsd_create(&xl, "ct_cull_complete");
	xmlsd_set_attr(xp, "version", CT_CULL_COMPLETE_VERSION);
	xe = xmlsd_add_element(&xl, xp, "cull");
	xmlsd_set_attr(xe, "type", "process");
	xmlsd_set_attr_uint64(xe, "uuid", cull_uuid);

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;
	ct_set_file_state(CT_S_FINISHED);

	ct_queue_transfer(trans);
}


void
ct_cull_send_shas(struct ct_op *op)
{
	struct xmlsd_element_list	xl;
	struct xmlsd_element		*xe, *xp;
	struct ct_trans			*trans;
	struct sha_entry		*node;
	size_t				sz;
	int				sha_add;
	char				shat[SHA_DIGEST_STRING_LENGTH];

	CNDBG(CT_LOG_TRANS, "cull_send_shas");
	node = RB_ROOT(&ct_sha_rb_head);
	if (shacnt == 0 || node == NULL) {
		ct_set_file_state(CT_S_FINISHED);
		return;
	}
	ct_set_file_state(CT_S_RUNNING);

	trans = ct_trans_alloc();

	if (trans == NULL) {

		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_CULL_SEND;

	xp = xmlsd_create(&xl, "ct_cull_shas");
	xmlsd_set_attr(xp, "version", CT_CULL_SHA_VERSION);

	xe = xmlsd_add_element(&xl, xp, "uuid");
	xmlsd_set_attr_uint64(xe, "value", cull_uuid);

	sha_add = 0;

	while (node != NULL && sha_add < sha_per_packet) {
		xe = xmlsd_add_element(&xl, xp, "sha");
		ct_sha1_encode(node->sha, shat);
		//CNDBG(CT_LOG_SHA, "adding sha %s\n", shat);
		xmlsd_set_attr(xe, "sha", shat);
		shacnt--;
		sha_add++;
		RB_REMOVE(ct_sha_lookup, &ct_sha_rb_head, node);
		e_free(&node);

		node = RB_ROOT(&ct_sha_rb_head);
	}

	if ((trans->tr_data[2] = (uint8_t *)xmlsd_generate(&xl,
	    ct_body_alloc_xml, &sz, 1)) == NULL)
		CFATALX("%s: Could not allocate xml body", __func__);
	xmlsd_unwind(&xl);
	trans->tr_dataslot = 2;
	trans->tr_size[2] = sz;

	CNDBG(CT_LOG_SHA, "sending shas [%s]", (char *)trans->tr_data[2]);
	CNDBG(CT_LOG_SHA, "sending shas len %lu", (unsigned long) sz);
	sha_payload_sz += sz;
	ct_queue_transfer(trans);

	if (shacnt == 0 || node == NULL) {
		ct_set_file_state(CT_S_FINISHED);
		trans->tr_eof = 1;
		CNDBG(CT_LOG_SHA, "shacnt %" PRIu64, shacnt);
	}
}

/*
 * Code to get all metadata files on the server.
 * to be used for cull.
 */
struct ctfile_list_tree ct_cull_all_ctfiles =
    RB_INITIALIZER(&ct_cull_all_ctfiles);
char		*all_ctfiles_pattern[] = {
			"^[[:digit:]]{8}-[[:digit:]]{6}-.*",
			NULL,
		 };

void	ct_cull_extract_cleanup(struct ct_op *);
void
ct_cull_fetch_all_ctfiles(struct ct_op *op)
{
	struct ct_ctfileop_args	*cca;
	struct ctfile_list_tree	 results;
	struct ctfile_list_file	*file;
	char			*cachename;

	RB_INIT(&results);
	ctfile_list_complete(CT_MATCH_REGEX, all_ctfiles_pattern, NULL,
	    &results);
	while ((file = RB_ROOT(&results)) != NULL) {
		RB_REMOVE(ctfile_list_tree, &results, file);
		CNDBG(CT_LOG_CTFILE, "looking for file %s ", file->mlf_name);
		if (!ctfile_in_cache(file->mlf_name)) {
			cachename = ctfile_get_cachename(file->mlf_name);
			CNDBG(CT_LOG_CTFILE, "getting %s to %s", file->mlf_name,
			    cachename);
			cca = e_calloc(1, sizeof(*cca));
			cca->cca_localname = cachename;
			cca->cca_remotename = e_strdup(file->mlf_name);
			cca->cca_ctfile = 1;
			ct_add_operation_after(op, ctfile_extract,
			    ct_cull_extract_cleanup, cca);
		} else {
			CNDBG(CT_LOG_CTFILE, "already got %s", file->mlf_name);
		}
		RB_INSERT(ctfile_list_tree, &ct_cull_all_ctfiles, file);
	}
}

void
ct_cull_extract_cleanup(struct ct_op *op)
{
	struct ct_ctfileop_args *cca = op->op_args;

	e_free(&cca->cca_localname);
	e_free(&cca->cca_remotename);
	e_free(&cca);
}

void	ct_cull_delete_cleanup(struct ct_op *);
void
ct_cull_collect_ctfiles(struct ct_op *op)
{
	struct ctfile_list_file	*file, *prevfile, filesearch;
	char			*prev_filename;
	int			timelen;
	char			buf[TIMEDATA_LEN];
	time_t			now;
	int			keep_files = 0;

	if (ct_ctfile_keep_days == 0)
		CFATALX("cull: ctfile_cull_keep_days must be specified in "
		    "config");

	now = time(NULL);
	now -= (24 * 60 * 60 * ct_ctfile_keep_days);
	if (strftime(buf, TIMEDATA_LEN, "%Y%m%d-%H%M%S",
	    localtime(&now)) == 0)
		CFATALX("can't format time");

	timelen = strlen(buf);

	RB_FOREACH(file, ctfile_list_tree, &ct_cull_all_ctfiles) {
		if (strncmp (file->mlf_name, buf, timelen) < 0) {
			file->mlf_keep = 0;
		} else {
			file->mlf_keep = 1;
			keep_files++;
		}
	}

	if (keep_files == 0)
		CFATALX("All ctfiles are old and would be deleted, aborting.");

	RB_FOREACH(file, ctfile_list_tree, &ct_cull_all_ctfiles) {
		if (file->mlf_keep == 0)
			continue;

		prev_filename = ctfile_get_previous(file->mlf_name);
prev_ct_file:
		if (prev_filename != NULL) {
			CINFO("prev filename %s", prev_filename);
			strncpy(filesearch.mlf_name, prev_filename,
			    sizeof(filesearch.mlf_name));
			prevfile = RB_FIND(ctfile_list_tree,
			    &ct_cull_all_ctfiles, &filesearch);
			if (prevfile == NULL) {
				CWARNX("file not found in ctfilelist [%s]",
				    prev_filename);
			} else {
				if (prevfile->mlf_keep == 0)
					CINFO("Warning, old ctfile %s still "
					    "referenced by newer backups, "
					    "keeping", prev_filename);
				prevfile->mlf_keep++;
				e_free(&prev_filename);

				prev_filename = ctfile_get_previous(
				    prevfile->mlf_name);
				goto prev_ct_file;
			}
			e_free(&prev_filename);
		}
	}
	RB_FOREACH(file, ctfile_list_tree, &ct_cull_all_ctfiles) {
		if (file->mlf_keep == 0) {
			CNDBG(CT_LOG_CTFILE, "adding %s to delete list",
			    file->mlf_name);
			ct_add_operation(ctfile_delete, ct_cull_delete_cleanup,
			    e_strdup(file->mlf_name));
		} else {
			CNDBG(CT_LOG_CTFILE, "adding %s to keep list",
			    file->mlf_name);
			ct_cull_add_shafile(file->mlf_name);
		}
	}

	/* cleanup */
	while((file = RB_ROOT(&ct_cull_all_ctfiles)) != NULL) {
		RB_REMOVE(ctfile_list_tree, &ct_cull_all_ctfiles, file);
		e_free(&file);
		/* XXX - name  */
	}
	ct_op_complete();
}

void
ct_cull_delete_cleanup(struct ct_op *op)
{
	char	*ctfile = op->op_args;

	e_free(&ctfile);
}
