/* $cyphertite$ */
/*
 * Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
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
#include <stdlib.h>
#include <dirent.h>
#include <libgen.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <regex.h>
#include <vis.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <xmlsd.h>
#include <fts.h>

#include <ctutil.h>
#include "ct_xml.h"

#include "ct.h"
#include "ct_crypto.h"

__attribute__((__unused__)) static const char *cvstag = "$cyphertite$";

struct md_list_file {
	union {
		RB_ENTRY(md_list_file)		nxt;
		SLIST_ENTRY(md_list_file)	lnk;
	}					mlf_entries;
#define mlf_next	mlf_entries.nxt
#define mlf_link	mlf_entries.lnk
	char					mlf_name[CT_MAX_MD_FILENAME];
	off_t					mlf_size;
	time_t					mlf_mtime;
};

SLIST_HEAD(md_list, md_list_file);
RB_HEAD(md_list_tree, md_list_file);
RB_PROTOTYPE(md_list_tree, md_list_file, next, ct_cmp_md);

struct md_list			ct_md_listfiles =
				     SLIST_HEAD_INITIALIZER(&ct_md_listfiles);
int				md_backup_fd = -1;
int				md_block_no = 0;
int				md_is_open = 0;
int				md_open_inflight = 0;
size_t				md_size, md_offset;
time_t				md_mtime;

int			strcompare(const void *, const void *);
void			ct_md_list_complete(int, char **, char **,
			    struct md_list_tree *);

struct xmlsd_v_elements ct_xml_cmds[] = {
	{ "ct_md_list", xe_ct_md_list },
	{ "ct_md_open_read", xe_ct_md_open_read },
	{ "ct_md_open_create", xe_ct_md_open_create },
	{ "ct_md_delete", xe_ct_md_delete },
	{ "ct_md_close", xe_ct_md_close },
	{ NULL, NULL }
};

char *
ct_md_cook_filename(const char *path)
{
	char	*bname, *fname, *pdup;

	fname = e_calloc(1, CT_MAX_MD_FILENAME);

	pdup = e_strdup(path);
	bname = basename(pdup);
	if (bname == NULL)
		CFATAL("can't basename metadata path");
	if (bname[0] == '/')
		CFATALX("invalid metadata filename");

	if (strnvis(fname, bname, CT_MAX_MD_FILENAME, VIS_GLOB |
	    VIS_WHITE | VIS_SAFE) >= CT_MAX_MD_FILENAME)
		CFATALX("metadata filename too long");
	e_free(&pdup);
	return (fname);
}

struct fnode	md_node;
void
ct_md_archive(struct ct_op *op)
{
	const char		*mfile = op->op_local_fname;
	const char		*mdname = op->op_remote_fname;
	struct stat		sb;
	ssize_t			rsz, rlen;
	struct ct_trans		*ct_trans;
	int			error;

	CDBG("md_fileio entered for block %d", md_block_no);
	ct_set_file_state(CT_S_RUNNING);
loop:
	ct_trans = ct_trans_alloc();
	if (ct_trans == NULL) {
		/* system busy, return */
		CDBG("ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	if (md_is_open == 0) {
		if (md_open_inflight) {
			CDBG("waiting on md open");
			ct_trans_free(ct_trans);
			ct_set_file_state(CT_S_WAITING_TRANS);
			return;
		}

		CDBG("opening md file for archive %s", mfile);
		md_backup_fd = open(mfile, O_RDONLY);
		if (md_backup_fd == -1)
			CFATAL("can't open %s for reading", mfile);

		md_offset = 0;
		md_block_no = 0;

		error = fstat(md_backup_fd, &sb);
		if (error) {
			CFATAL("can't stat backup file %s", mfile);
		} else {
			md_size = sb.st_size;
			md_mtime = sb.st_mtime;
		}

		if (mdname == NULL) {
			mdname = ct_md_cook_filename(mfile);
			op->op_remote_fname = (char *)mdname;
		}
		ct_xml_file_open(ct_trans, mdname, MD_O_WRITE, 0);
		md_open_inflight = 1;
		return;
	}

	/* Are we done here? */
	if (md_size == md_offset) {
		ct_set_file_state(CT_S_FINISHED);
		ct_trans->tr_fl_node = NULL;
		ct_trans->tr_state = TR_S_XML_CLOSE;
		ct_trans->tr_eof = 1;
		ct_trans->tr_trans_id = ct_trans_id++;
		CDBG("setting eof on trans %" PRIu64, ct_trans->tr_trans_id);
		ct_trans->hdr.c_flags = C_HDR_F_METADATA;
		ct_trans->tr_md_name = mdname;
		ct_queue_transfer(ct_trans);
		return;
	}
	/* perform read */
	rsz = md_size - md_offset;

	CDBG("rsz %zd max %d", rsz, ct_max_block_size);
	if (rsz > ct_max_block_size) {
		rsz = ct_max_block_size;
	}

	ct_trans->tr_dataslot = 0;
	rlen = read(md_backup_fd, ct_trans->tr_data[0], rsz);

	CDBG("read %zd", rlen);

	ct_stats->st_bytes_read += rlen;

	ct_trans->tr_fl_node = &md_node;
	ct_trans->tr_chsize = ct_trans->tr_size[0] = rlen;
	ct_trans->tr_state = TR_S_READ;
	ct_trans->tr_type = TR_T_WRITE_CHUNK;
	ct_trans->tr_trans_id = ct_trans_id++;
	ct_trans->tr_eof = 0;
	ct_trans->hdr.c_flags = C_HDR_F_METADATA;
	ct_trans->hdr.c_ex_status = 2; /* we handle new metadata protocol */
	ct_trans->tr_md_chunkno = md_block_no;
	ct_trans->tr_md_name = mdname;

	CDBG(" trans %"PRId64", read size %zd, into %p rlen %zd",
	    ct_trans->tr_trans_id, rsz, ct_trans->tr_data[0], rlen);

	/*
	 * init iv to something that can be recreated, used if hdr->c_flags
	 * has C_HDR_F_METADATA set.
	 */
	bzero(ct_trans->tr_iv, sizeof(ct_trans->tr_iv));
	ct_trans->tr_iv[0] = (md_block_no >>  0) & 0xff;
	ct_trans->tr_iv[1] = (md_block_no >>  8) & 0xff;
	ct_trans->tr_iv[2] = (md_block_no >> 16) & 0xff;
	ct_trans->tr_iv[3] = (md_block_no >> 24) & 0xff;
	ct_trans->tr_iv[4] = (md_block_no >>  0) & 0xff;
	ct_trans->tr_iv[5] = (md_block_no >>  8) & 0xff;
	ct_trans->tr_iv[6] = (md_block_no >> 16) & 0xff;
	ct_trans->tr_iv[7] = (md_block_no >> 24) & 0xff;
	/* XXX - leaves the rest of the iv with 0 */

	md_block_no++;

	CDBG("sizes rlen %zd offset %zd size %zd", rlen, md_offset, md_size);

	if (rsz != rlen || (rlen + md_offset) == md_size) {
		/* short read, file truncated or EOF */
		CDBG("DONE");
		error = fstat(md_backup_fd, &sb);
		if (error) {
			CWARNX("file stat error %s %d %s",
			    mdname, errno, strerror(errno));
		} else if (sb.st_size != md_size) {
			CWARNX("file truncated during backup %s",
			    mdname);
			/*
			 * may need to perform special nop processing
			 * to pad archive file to right number of chunks
			 */
		}
		/*
		 * we don't set eof here because the next go round
		 * will hit the state done case above
		 */
		md_offset = md_size;
	} else {
		md_offset += rlen;
	}
	ct_queue_transfer(ct_trans);
	goto loop;
}

void
ct_xml_file_open(struct ct_trans *trans, const char *file, int mode,
    uint32_t chunkno)
{
	struct ct_header	*hdr = NULL;
	char			*body = NULL;
	char			*buf = NULL;
	int			sz;

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_OPEN;

	CDBG("setting up XML");

	if (mode == MD_O_WRITE) {
		sz = e_asprintf(&buf, ct_md_open_create_fmt, file);
	} else if (mode == MD_O_APPEND) {
		sz = e_asprintf(&buf, ct_md_open_create_chunkno_fmt,
		    file, chunkno);
	} else if (chunkno) {
		sz = e_asprintf(&buf, ct_md_open_read_chunkno_fmt,
		    file, chunkno);
	} else {
		sz = e_asprintf(&buf, ct_md_open_read_fmt, file);
	}
	sz += 1;	/* include null */

	hdr = &trans->hdr;
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	/*
	 * XXX - yes I think this should be seperate
	 * so that xml size is independant of chunk size
	 */
	body = (char *)ct_body_alloc(NULL, hdr);
	CDBG("got body %p", body);
	bcopy(buf, body, sz);
	e_free(&buf);

	CDBG("open trans %"PRIu64, trans->tr_trans_id);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	/* did we idle out? - something better?*/
	while (ct_reconnect_pending) {
		if (ct_reconnect_internal() != 0) {
			sleep(30);
		} else {
			ct_reconnect_pending = 0;
		}
	}
	ct_assl_write_op(ct_assl_ctx, hdr, body);
}

int
ct_xml_file_open_polled(struct ct_assl_io_ctx *ct_assl_ctx,
    const char *file, int mode, uint32_t chunkno)
{
#define ASSL_TIMEOUT 20
	extern uint64_t		 ct_packet_id;
	struct ct_header	 hdr;

	char			*body = NULL;
	int			 sz, rv = 1;

	CDBG("setting up XML");

	if (mode == MD_O_WRITE) {
		sz = e_asprintf(&body, ct_md_open_create_fmt, file);
	} else if (mode == MD_O_APPEND) {
		sz = e_asprintf(&body, ct_md_open_create_chunkno_fmt,
		    file, chunkno);
	} else if (chunkno) {
		sz = e_asprintf(&body, ct_md_open_read_chunkno_fmt,
		    file, chunkno);
	} else {
		sz = e_asprintf(&body, ct_md_open_read_fmt, file);
	}
	sz += 1;	/* include NUL */

	hdr.c_version = C_HDR_VERSION;
	hdr.c_opcode = C_HDR_O_XML;
	hdr.c_flags = C_HDR_F_METADATA;
	/* use previous packet id so it'll fit with the state machine */
	hdr.c_tag = ct_packet_id - 1;
	hdr.c_size = sz;

	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(ct_assl_ctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("could not write header");
		goto done;
	}
	if (ct_assl_io_write_poll(ct_assl_ctx, body, sz,  ASSL_TIMEOUT) != sz) {
		CWARNX("could not write body");
		goto done;
	}
	e_free(&body);

	/* get server reply */
	if (ct_assl_io_read_poll(ct_assl_ctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("invalid header size");
		goto done;
	}
	ct_unwire_header(&hdr);

	if (hdr.c_status == C_HDR_S_OK && hdr.c_opcode == C_HDR_O_XML_REPLY)
		rv = 0;

	/* we know the open was ok or bad, just read the body and dump it */
	body = e_calloc(1, hdr.c_size);
	if (ct_assl_io_read_poll(ct_assl_ctx, body, hdr.c_size, ASSL_TIMEOUT)
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
	struct ct_header	*hdr = NULL;
	struct ct_trans		*trans;
	char			*buf = NULL;
	char			*body = NULL;
	int			sz;

	trans = ct_trans_alloc();
	if (trans == NULL) {
		/* system busy, return */
		CDBG("ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_CLOSING;

	CDBG("setting up XML");

	// XXX: Some flavors of gcc don't like externed strings with no
	// arguments to printf style functions since the format specifiers
	// can't be checked at compile time.
	sz = e_asprintf(&buf, "%s", ct_md_close_fmt);
	sz += 1;	/* include null */

	hdr = &trans->hdr;
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	/*
	 * XXX - yes I think this should be seperate
	 * so that xml size is independant of chunk size
	 */
	body = (char *)ct_body_alloc(NULL, hdr);
	CDBG("got body %p", body);
	bcopy(buf, body, sz);
	e_free(&buf);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	/* did we idle out? - something better?*/
	while (ct_reconnect_pending) {
		if (ct_reconnect_internal() != 0) {
			sleep(30);
		} else {
			ct_reconnect_pending = 0;
		}
	}
	ct_assl_write_op(ct_assl_ctx, hdr, body);
}

void
ct_md_extract(struct ct_op *op)
{
	const char		*mfile = op->op_local_fname;
	const char		*mdname = op->op_remote_fname;
	struct ct_trans		*trans;
	struct ct_header	*hdr;

	ct_set_file_state(CT_S_RUNNING);

	trans = ct_trans_alloc();
	if (trans == NULL) {
		/* system busy, return */
		CDBG("ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}
	if (md_is_open == 0) {
		if (md_open_inflight) {
			CDBG("waiting on md open");
			ct_trans_free(trans);
			ct_set_file_state(CT_S_WAITING_TRANS);
			return;
		}

		/* XXX -chmod when done */
		if (md_backup_fd == -1) { /* may have been opened for us */
			if ((md_backup_fd = open(mfile,
			    O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1)
				CFATALX("unable to open file %s", mfile);
		}
		md_block_no = 0;

		if (mdname == NULL) {
			mdname = ct_md_cook_filename(mfile);
			op->op_remote_fname = (char *)mdname;
		}
		ct_xml_file_open(trans, mdname, MD_O_READ, 0);
		md_open_inflight = 1;
		return;
	}

	trans->tr_fl_node = &md_node;
	trans->tr_state = TR_S_EX_SHA;
	trans->tr_type = TR_T_READ_CHUNK;
	trans->tr_trans_id = ct_trans_id++;
	trans->tr_eof = 0;
	trans->tr_md_chunkno = md_block_no;
	trans->tr_md_name = mdname;

	hdr = &trans->hdr;
	hdr->c_ex_status = 2;
	hdr->c_flags |= C_HDR_F_METADATA;

	bzero(trans->tr_sha, sizeof(trans->tr_sha));
	trans->tr_sha[0] = (md_block_no >>  0) & 0xff;
	trans->tr_sha[1] = (md_block_no >>  8) & 0xff;
	trans->tr_sha[2] = (md_block_no >> 16) & 0xff;
	trans->tr_sha[3] = (md_block_no >> 24) & 0xff;
	bzero(trans->tr_iv, sizeof(trans->tr_iv));
	trans->tr_iv[0] = (md_block_no >>  0) & 0xff;
	trans->tr_iv[1] = (md_block_no >>  8) & 0xff;
	trans->tr_iv[2] = (md_block_no >> 16) & 0xff;
	trans->tr_iv[3] = (md_block_no >> 24) & 0xff;
	trans->tr_iv[4] = (md_block_no >>  0) & 0xff;
	trans->tr_iv[5] = (md_block_no >>  8) & 0xff;
	trans->tr_iv[6] = (md_block_no >> 16) & 0xff;
	trans->tr_iv[7] = (md_block_no >> 24) & 0xff;

	md_block_no++; /* next chunk on next pass */

	ct_queue_transfer(trans);
}

void
ct_complete_metadata(struct ct_trans *trans)
{
	ssize_t			wlen;
	int			slot, done = 0;

	switch(trans->tr_state) {
	case TR_S_EX_READ:
	case TR_S_EX_DECRYPTED:
	case TR_S_EX_UNCOMPRESSED:
		if (trans->hdr.c_status == C_HDR_S_OK) {
			slot = trans->tr_dataslot;
			CDBG("writing packet sz %d",
			    trans->tr_size[slot]);
			wlen = write(md_backup_fd, trans->tr_data[slot],
			    trans->tr_size[slot]);
			if (wlen != trans->tr_size[slot])
				CWARN("unable to write to md file");
		} else {
			ct_state->ct_file_state = CT_S_FINISHED;
		}
		break;

	case TR_S_DONE:
		/* More operations to be done? */
		if (ct_op_complete())
			done = 1;

		/* Clean up md reconnect name, shared between all trans */
		if (trans->tr_md_name != NULL)
			e_free(&trans->tr_md_name);

		if (!done)
			return;
		if (ct_verbose_ratios)
			ct_dump_stats(stdout);

		ct_file_extract_fixup();
		ct_shutdown();
		break;
	case TR_S_WMD_READY:
	case TR_S_XML_OPEN:
	case TR_S_XML_CLOSING:
	case TR_S_READ:
		break;
	case TR_S_XML_CLOSE:
		CDBG("eof reached, closing file");
		if (md_backup_fd != -1) {
			close(md_backup_fd);
			md_backup_fd = -1;
		}
		ct_xml_file_close();
		break;

	default:
		CFATALX("unexpected tr state in %s %d", __func__,
		    trans->tr_state);
	}
}

void
ct_md_list_start(struct ct_op *op)
{
	struct ct_header	*hdr;
	struct ct_trans		*trans;
	char			*body = NULL;
	char			*buf = NULL;
	int			 sz;

	ct_set_file_state(CT_S_FINISHED);

	trans = ct_trans_alloc();

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_LIST;

	CDBG("setting up XML");

	sz = e_asprintf(&buf, ct_md_list_fmt_v2, "");
	sz += 1;	/* include null */

	hdr = &trans->hdr;
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	/*
	 * XXX - yes I think this should be seperate
	 * so that xml size is independant of chunk size
	 */
	body = (char *)ct_body_alloc(NULL, hdr);
	CDBG("got body %p", body);
	bcopy(buf, body, sz);
	e_free(&buf);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	/* did we idle out? - something better?*/
	while (ct_reconnect_pending) {
		if (ct_reconnect_internal() != 0) {
			sleep(30);
		} else {
			ct_reconnect_pending = 0;
		}
	}
	ct_assl_write_op(ct_assl_ctx, hdr, body);
}

void
ct_md_list_complete(int matchmode, char **flist, char **excludelist,
    struct md_list_tree *results)
{
	struct ct_match		*match, *ex_match = NULL;
	struct md_list_file	*file;

	if (SLIST_EMPTY(&ct_md_listfiles))
		return;

	match = ct_match_compile(matchmode, flist);
	if (excludelist)
		ex_match = ct_match_compile(matchmode, excludelist);
	while ((file = SLIST_FIRST(&ct_md_listfiles)) != NULL) {
		SLIST_REMOVE_HEAD(&ct_md_listfiles, mlf_link);
		if (ct_match(match, file->mlf_name) == 0 && (ex_match == NULL ||
		    ct_match(ex_match, file->mlf_name) == 1)) {
			RB_INSERT(md_list_tree, results, file);
		} else {
			e_free(&file);
		}
	}
	if (ex_match != NULL)
		ct_match_unwind(ex_match);
	ct_match_unwind(match);
}

int
ct_cmp_md(struct md_list_file *f1, struct md_list_file *f2)
{
	return (strcmp(f1->mlf_name, f2->mlf_name));
}

RB_GENERATE(md_list_tree, md_list_file, mlf_next, ct_cmp_md);

/* Taken from OpenBSD ls */
static void
printtime(time_t ftime)
{
	int i;
	char *longstring;

	longstring = ctime(&ftime);
	for (i = 4; i < 11; ++i)
		(void)putchar(longstring[i]);

#define DAYSPERNYEAR	365
#define SECSPERDAY	(60*60*24)
#define	SIXMONTHS	((DAYSPERNYEAR / 2) * SECSPERDAY)
	if (ftime + SIXMONTHS > time(NULL))
		for (i = 11; i < 16; ++i)
			(void)putchar(longstring[i]);
	else {
		(void)putchar(' ');
		for (i = 20; i < 24; ++i)
			(void)putchar(longstring[i]);
	}
	(void)putchar(' ');
}


void
ct_md_list_print(struct ct_op *op)
{
	struct md_list_tree	 results;
	struct md_list_file	*file;
	long long		maxsz = 8;
	int			numlen;

	RB_INIT(&results);
	ct_md_list_complete(op->op_matchmode, op->op_filelist,
	    op->op_excludelist, &results);
	RB_FOREACH(file, md_list_tree, &results) {
		if (maxsz < (long long)file->mlf_size)
			maxsz  = (long long)file->mlf_size;
	}
	numlen = snprintf(NULL, 0, "%lld", maxsz);

	while ((file = RB_MIN(md_list_tree, &results)) != NULL) {
		RB_REMOVE(md_list_tree, &results, file);
		/* XXX only the extras if verbose? */
		printf("%*llu ", numlen, (unsigned long long)file->mlf_size);
		printtime(file->mlf_mtime);
		printf("\t");
		printf("%s\n", file->mlf_name);
		e_free(&file);
	}
}

void
ct_md_delete(struct ct_op *op)
{
	const char		*md = op->op_remote_fname;
	struct ct_header	*hdr;
	struct ct_trans		*trans;
	char			*buf, *body = NULL;
	int			 sz;

	CDBG("setting up XML");

	md = ct_md_cook_filename(md);

	sz = e_asprintf(&buf, ct_md_delete_fmt, md);
	sz += 1;	/* include null */

	e_free(&md);

	trans = ct_trans_alloc();
	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_DELETE;
	hdr = &trans->hdr;
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_size = sz;
	hdr->c_flags = C_HDR_F_METADATA;

	body = ct_body_alloc(NULL, hdr);
	bcopy(buf, body, sz);
	e_free(&buf);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	/* did we idle out? - something better?*/
	while (ct_reconnect_pending) {
		if (ct_reconnect_internal() != 0) {
			sleep(30);
		} else {
			ct_reconnect_pending = 0;
		}
	}
	ct_assl_write_op(ct_assl_ctx, hdr, body);
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
	int r;

	CDBG("xml [%s]", (char *)vbody);

	/* Dispose of last parsed command. */
	TAILQ_INIT(&xl);

	r = xmlsd_parse_mem(body, hdr->c_size - 1, &xl);
	if (r)
		CFATALX("XML parse failed! (%d)", r);

	TAILQ_FOREACH(xe, &xl, entry) {
		CDBG("%d %s = %s (parent = %s)",
		    xe->depth, xe->name, xe->value ? xe->value : "NOVAL",
		    xe->parent ? xe->parent->name : "NOPARENT");
		TAILQ_FOREACH(xa, &xe->attr_list, entry)
			CDBG("\t%s = %s", xa->name, xa->value);
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
					CDBG("%s opened\n", filename);
					die = 0;
					md_open_inflight = 0;
					md_is_open = 1;
					ct_wakeup_file();
				}
			}
		}
		if (die) {
			CWARNX("couldn't open md file");
			ct_shutdown();
		}
	} else if (strcmp(xe->name, "ct_md_close") == 0) {
		md_is_open = 0;
		trans->tr_state = TR_S_DONE;
	} else if (strcmp(xe->name, "ct_md_list") == 0) {
		struct md_list_file	*file;
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
				strlcpy(file->mlf_name, tmp,
				    sizeof(file->mlf_name));
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
				SLIST_INSERT_HEAD(&ct_md_listfiles, file,
				    mlf_link);
			}
		}
		trans->tr_state = TR_S_DONE;
	} else  if (strcmp(xe->name, "ct_md_delete") == 0) {
		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				filename = xmlsd_get_attr(xe, "name");
				if (filename)
					printf("%s deleted\n", filename);
			}
		}
		trans->tr_state = TR_S_DONE;
	}

	ct_queue_transfer(trans);
	ct_body_free(NULL, vbody, hdr);
	ct_header_free(NULL, hdr);
	xmlsd_unwind(&xl);
}

void
ct_mdmode_setup(const char *mdmode)
{
	CDBG("mdmode setup %s", mdmode ? mdmode : "");
	if (mdmode == NULL)
		return;

	if (strcmp(mdmode, "remote") == 0)
		ct_md_mode = CT_MDMODE_REMOTE;
	else if (strcmp(mdmode, "local") == 0)
		ct_md_mode = CT_MDMODE_LOCAL;
	else
		CFATALX("invalid metadata mode specified");
}

int
md_is_in_cache(const char *mdfile)
{
	struct dirent	*dp;
	DIR		*dirp;
	int		 found = 0;

	if ((dirp = opendir(ct_md_cachedir)) == NULL)
		CFATALX("can't open metadata cache dir");
	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, mdfile) == 0) {
			CDBG("found in cachedir");
			found = 1;
			break;
		}
	}
	closedir(dirp);

	return (found);
}

/*
 * return the filename in the cache directory that a mdfile would have
 * if it extisted.
 */
char *
ct_md_get_cachename(const char *mdfile)
{
	char	*cachename;

	/* ct_md_cachedir was made sure to terminate with / earlier */
	e_asprintf(&cachename, "%s%s", ct_md_cachedir, mdfile);
	return cachename;
}

/*
 * returns boolean 1/0 whether or not the mdname in question is the full tag
 * with date/time or not.
 */
int
ct_md_is_full_mdname(const char *mdname)
{
	char			*pattern = "^[[:digit:]]{8}-[[:digit:]]{6}-";
	char			error[1024];
	regex_t			re;
	int			match = 0, rv;
	if ((rv = regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB)) != 0) {
		regerror(rv, &re, error, sizeof(error) - 1);
		CFATALX("%s: regcomp failed: %s", __func__, error);
	}
	if (regexec(&re, mdname, 0, NULL, 0) == 0)
		match = 1;

	regfree(&re);
	return match;
}


#define			TIMEDATA_LEN	17	/* including NUL */
int
strcompare(const void *a, const void *b)
{
	/* sort purely based on date */
	return (strncmp(*(char **)b, *(char **)a, TIMEDATA_LEN - 1));
}

/*
 * filenames passed in remote mode are opaque tags for the md.
 * the are stored on the server and in remote mode in the form
 * YYYYMMDD-HHMMSS-<strnvis(mname)>
 */
void
ct_find_md_for_extract(struct ct_op *op)
{
	const char	*mdname = op->op_local_fname;
	struct ct_op	*list_fakeop;
	char	 	**bufp;
	int		 matchmode;

	/* cook the mdname so we only search for the actual tag */
	mdname = ct_md_cook_filename(mdname);

	list_fakeop = e_calloc(1, sizeof(*list_fakeop));
	bufp = e_calloc(2, sizeof(char **));
	if (ct_md_is_full_mdname(mdname)) {
		/* use md_list as stat() for now */
		*bufp = e_strdup(mdname);
		matchmode = CT_MATCH_GLOB;
	} else {
		e_asprintf(bufp, "^[[:digit:]]{8}-[[:digit:]]{6}-%s$", mdname);

		matchmode = CT_MATCH_REGEX;
		/*
		 * get the list of md matching this tag from the server.
		 * ct_md_list returns an empty list if it found
		 * nothing and NULL upon failure.
		 */
	}
	e_free(&mdname);

	CDBG("looking for %s", bufp[0]);

	list_fakeop->op_filelist = bufp;
	list_fakeop->op_matchmode = matchmode;

	op->op_priv = list_fakeop;
	ct_md_list_start(list_fakeop);
}

void
ct_free_mdname(struct ct_op *op)
{

	CDBG("%s: %s", __func__, op->op_local_fname);
	if (op->op_local_fname != NULL)
		e_free(&op->op_local_fname);
}

void
ct_free_remotename(struct ct_op *op)
{
	CDBG("%s: %s", __func__, op->op_local_fname);
	if (op->op_remote_fname != NULL)
		e_free(&op->op_remote_fname);
}

void
ct_free_mdname_and_remote(struct ct_op *op)
{
	ct_free_mdname(op);
	ct_free_remotename(op);
}

void ct_md_download_next(struct ct_op *op);
void
ct_md_download_next(struct ct_op *op)
{
	const char		*mfile = op->op_local_fname;
	const char		*mfilename = op->op_remote_fname;
	char			*md_prev;
	char			*cachename;

	md_is_open = 0;	/* prevent trying to close upon next download */
again:
	CDBG("mfile %s", mfile);

	md_prev = ct_metadata_check_prev(mfile);
	if (md_prev == NULL)
		goto out;

	if (md_prev[0] != '\0') {
		cachename = ct_md_get_cachename(md_prev);
		CDBG("prev file %s cachename %s", md_prev, cachename);
		if (!md_is_in_cache(cachename)) {
			e_free(&cachename);
			ct_add_operation_after(op, ct_md_extract,
			    ct_md_download_next, (char *)md_prev, md_prev,
				NULL, NULL, NULL, 0, 0); 
		} else {
			if (mfile == mfilename)
				e_free(&mfile);
			e_free(&cachename);
			mfile = mfilename = md_prev;
			goto again;
		}
	} else
		e_free(&md_prev);

out:
	if (mfile == mfilename) {
		e_free(&mfile);
	}

}

/*
 * now the operation has completed we can kick off the next operation knowing
 * that everything has been set up for it.
 */
void
ct_md_extract_nextop(struct ct_op *op)
{
	char	*mfile;

	md_is_open = 0;
	/*
	 * need to determine if this is a layered backup, if so, we need to
	 * queue download of that file
	 */
	if (op->op_action == CT_A_EXTRACT || op->op_action == CT_A_LIST)
		ct_md_download_next(op);

	/*
	 * Any recursive download after here will be placed after the
	 * current operation in the queue of ops. So we can now add the final 
	 * operation to the end of the queue without difficulty.
	 */
	switch (op->op_action) {
	case CT_A_EXTRACT:
		ct_add_operation(ct_extract, ct_free_mdname_and_remote,
		    op->op_local_fname, op->op_remote_fname, op->op_filelist,
		    op->op_excludelist, NULL, op->op_matchmode, 0);
		break;
	case CT_A_LIST:
		ct_add_operation(ct_list_op, ct_free_mdname_and_remote,
		    op->op_local_fname, op->op_remote_fname, op->op_filelist,
		    op->op_excludelist, NULL, op->op_matchmode, 0);
		break;
	case CT_A_ARCHIVE:
		if (op->op_remote_fname)
			e_free(&op->op_remote_fname);
		/*
		 * Since we were searching for previous, original mdname
		 * is stored in basis. Swap them.
		 */
		mfile = ct_find_md_for_archive(op->op_basis);
		CDBG("setting basisname %s", op->op_local_fname);
		/* XXX does this leak cachename? */
		ct_add_operation(ct_archive, NULL, mfile, NULL,
		    op->op_filelist, op->op_excludelist, op->op_local_fname,
		    op->op_matchmode, 0);
		ct_add_operation(ct_md_archive, ct_free_mdname_and_remote,
		    mfile, NULL, NULL, NULL, NULL, 0, 0);
		break;
	default:
		CFATALX("invalid action");
	}
}

void
ct_find_md_for_extract_complete(struct ct_op *op)
{
	struct ct_op		*list_fakeop = op->op_priv;
	struct md_list_tree	 result;
	struct md_list_file	*tmp;
	char	 		*best, *cachename = NULL;

	RB_INIT(&result);
	ct_md_list_complete(list_fakeop->op_matchmode, list_fakeop->op_filelist,
	    list_fakeop->op_excludelist, &result);
	e_free(list_fakeop->op_filelist);
	e_free(&list_fakeop->op_filelist);
	e_free(&list_fakeop);

	/* grab the newest one */
	if ((tmp = RB_MAX(md_list_tree, &result)) == NULL) {
		if (op->op_action == CT_A_ARCHIVE) {
			goto do_operation;
		} else  {
			CFATALX("unable to find metadata tagged %s",
			    op->op_local_fname);
		}
	}

	/* pick the newest one */
	best = e_strdup(tmp->mlf_name);
	CDBG("backup file is %s", best);

	while((tmp = RB_ROOT(&result)) != NULL) {
		RB_REMOVE(md_list_tree, &result, tmp);
		e_free(&tmp);
	}

	/*
	 * if the metadata file is not in the cache directory then we
	 * need to download it first. if we need to recursively download
	 * a differential chain then that code will handle scheduling
	 * those operations too. If we have it, we still need to check
	 * that all others in the chain exist, however.
	 */
	cachename = ct_md_get_cachename(best);
	if (!md_is_in_cache(best)) {
		/*
		 * since archive needs the original metadata name still
		 * and is searching for a prior archive for differentials
		 * we put local_fname (the original) in the basis slot here.
		 * nextop will fix it for us.
		 */
		ct_add_operation(ct_md_extract, ct_md_extract_nextop,
		    cachename, best, op->op_filelist, op->op_excludelist,
		    op->op_local_fname, op->op_matchmode, op->op_action);
	} else {
		e_free(&best);
do_operation:
		/*
		 * Don't need to grab this mdfile, but may need one later in
		 * the differential chain, recurse. When we know more we can
		 * prepare the final operation
		 */
		op->op_basis = op->op_local_fname;
		op->op_local_fname = cachename;
		ct_md_extract_nextop(op);
	}

}

char *
ct_find_md_for_archive(const char *mdname)
{
	char	 buf[TIMEDATA_LEN], *fullname, *cachename;
	time_t	 now;

	/* cook the mdname so we only search for the actual tag */
	mdname = ct_md_cook_filename(mdname);

	if (ct_md_is_full_mdname(mdname) != 0)
		CFATALX("metadata name with date tag already filled in");

	now = time(NULL);
	if (strftime(buf, TIMEDATA_LEN, "%Y%m%d-%H%M%S",
	    localtime(&now)) == 0)
		CFATALX("can't format time");
	e_asprintf(&fullname, "%s-%s", buf, mdname);
	CDBG("backup file is %s", fullname);

	/* check it isn't already in the cache */
	cachename = ct_md_get_cachename(fullname);
	if (md_is_in_cache(fullname))
		CFATALX("generated metadata name %s already in cache dir",
		    fullname);

	e_free(&mdname);
	e_free(&fullname);

	return (cachename);
}

/*
 * make fts_* return entities in mtime order, oldest first
 */
/* XXX: Need to clean this up with more portable code.  Using ifdefs for now
 * to make it compile.
 */
#ifdef __FreeBSD__
static int
datecompare(const FTSENT * const *a, const FTSENT * const *b)
{
	return (timespeccmp(&(*a)->fts_statp->st_mtimespec,
	    &(*b)->fts_statp->st_mtimespec, <));
}
#else
static int
datecompare(const FTSENT **a, const FTSENT **b)
{
	return (timespeccmp(&(*a)->fts_statp->st_mtim,
	    &(*b)->fts_statp->st_mtim, <));
}
#endif

/*
 * Trim down the metadata cachedir to be smaller than ``max_size''.
 *
 * We only look at files in the directory (and lower, since we use fts(3),
 * since cyphertite will only ever create files, not symlinkts or directories.
 * We delete files in date order, oldest first, until the size constraint has
 * been met.
 */
void
ct_mdcache_trim(const char *cachedir, long long max_size)
{
	char		*paths[2];
	FTS		*ftsp;
	FTSENT		*fe;
	long long	 dirsize = 0;

	paths[0] = (char *)cachedir;
	paths[1] = NULL;

	if ((ftsp = fts_open(paths, FTS_XDEV | FTS_PHYSICAL | FTS_NOCHDIR,
	   NULL)) == NULL)
		CFATAL("can't open metadata cache to scan");

	while ((fe = fts_read(ftsp)) != NULL) {
		switch(fe->fts_info) {
		case FTS_F:
			/*
			 * XXX no OFF_T_MAX in posix, on openbsd it is always a
			 * long long
			 */
			if (LLONG_MAX - dirsize < fe->fts_statp->st_size)
				CWARNX("dirsize overflowed");
			dirsize += fe->fts_statp->st_size;
			break;
		case FTS_ERR:
		case FTS_DNR:
		case FTS_NS:
			errno = fe->fts_errno;
			CFATAL("can't read directory entry");
		case FTS_DC:
			CWARNX("file system cycle found");
			/* FALLTHROUGH */
		default:
			/* valid but we don't care */
			continue;
		}
	}

	if (fts_close(ftsp))
		CFATAL("close directory failed");

	if (dirsize <= max_size)
		return;
	CDBG("cleaning up md cachedir, %llu > %llu",
	    (long long)dirsize, (long long)max_size);

	if ((ftsp = fts_open(paths, FTS_XDEV | FTS_PHYSICAL | FTS_NOCHDIR,
	    datecompare)) == NULL)
		CFATAL("can't open metadata cache to trim");

	while ((fe = fts_read(ftsp)) != NULL) {
		switch(fe->fts_info) {
		case FTS_F:
			CDBG("%s %llu", fe->fts_path,
			    (long long)fe->fts_statp->st_size);
			if (unlink(fe->fts_path) != 0) {
				CWARN("couldn't delete md file %s",
				    fe->fts_path);
				continue;
			}
			dirsize -= fe->fts_statp->st_size;
			break;
		case FTS_ERR:
		case FTS_DNR:
		case FTS_NS:
			errno = fe->fts_errno;
			CFATAL("can't read directory entry");
		case FTS_DC:
			CWARNX("file system cycle found");
			/* FALLTHROUGH */
		default:
			/* valid but we don't care */
			continue;
		}
		CDBG("size now %llu", (long long)dirsize);

		if (dirsize < max_size)
			break;
	}

	if (fts_close(ftsp))
		CFATAL("close directory failed");
}

/*
 * Functions for automatic crypto secrets storage on the server.
 */

void	ct_secrets_unlock(struct ct_op *);

/*
 * List available crypto secrets files so we can see if we are ahead or behind
 */
void
ct_check_crypto_secrets_nextop(struct ct_op *op)
{
	extern char		*ct_crypto_password;
	char			*current_secrets = op->op_local_fname;
	char			*t, *remote_name = NULL;
	char			 *dirp, dir[PATH_MAX], tmp[PATH_MAX];
	const char		*errstr;
	struct md_list_tree	 results;
	struct md_list_file	*file = NULL;
	struct stat		 sb;
	time_t			 mtime = 0, local_mtime = 0;

	RB_INIT(&results);
	ct_md_list_complete(op->op_matchmode, op->op_filelist,
	    op->op_excludelist, &results);
	/* We're interested in the newest. */
	if ((file = RB_MAX(md_list_tree, &results)) == NULL)
		goto check_local;

	CDBG("latest secrets file on server: %s", file->mlf_name);
	/* parse out mtime */
	if ((t = strchr(file->mlf_name, '-')) == NULL)
		CFATALX("invalid answer from server");
	*t = '\0';
	mtime = strtonum(file->mlf_name, LLONG_MIN, LLONG_MAX, &errstr);
	if (errstr)
		CFATALX("mtime %s from secrets file invalid: %s",
		    file->mlf_name, errstr);
	*t = '-'; /* put it back */
	remote_name = e_strdup(file->mlf_name);
	while((file = RB_ROOT(&results)) != NULL) {
		RB_REMOVE(md_list_tree, &results, file);
		e_free(&file);
	}

check_local:
	/* get mtime, if any for current secrets file */
	if (stat(current_secrets, &sb) != -1)
		local_mtime = sb.st_mtime;

	/* This includes the case where both are missing */
	if (mtime == local_mtime) {
		CDBG("dates match, nothing to do");
		if (remote_name)
			e_free(&remote_name);
		if (ct_create_or_unlock_secrets(current_secrets,
		    ct_crypto_password))
			CFATALX("can't unlock secrets file");
		ctdb_setup(ct_localdb, ct_encrypt_enabled);
	} else if (mtime < local_mtime) {
		/* XXX verify local file before upload? */
		CDBG("uploading local file");
		if (remote_name)
			e_free(&remote_name);
		e_asprintf(&remote_name, "%020lld-crypto.secrets",
		    (long long)local_mtime);
		ct_add_operation_after(op, ct_md_archive, ct_secrets_unlock,
		    current_secrets, remote_name, NULL, NULL, NULL, 0, 0);
	} else { /* mtime > local_mtime */
		CDBG("downloading remote file");
		strlcpy(dir, current_secrets, sizeof(dir));
		if ((dirp = dirname(dir)) == NULL)
			CFATALX("can't get dirname of secrets file");
		strlcpy(tmp, dirp, sizeof(tmp));
		strlcat(tmp, "/.ctcrypto.XXXXXXXX", sizeof(tmp));
		if ((md_backup_fd = mkstemp(tmp)) == -1)
			CFATAL("can't make temporary file");
		CDBG("temp file: %s", tmp);
		/* stash current name in basis in case we need to fallback */
		ct_add_operation_after(op, ct_md_extract, ct_secrets_unlock,
		    e_strdup(tmp), remote_name, NULL, NULL,  current_secrets,
		    0, 0);
	}
}

void
ct_secrets_unlock(struct ct_op *op)
{
	extern char		*ct_crypto_password;
	char			*crypto_secrets = op->op_local_fname;
	char			*old_secrets = op->op_basis;
	char			 tmp[PATH_MAX], *t;
	const char		*errstr;
	struct timeval		 times[2] = { };
	struct stat	 	 sb;

	CDBG("operation complete, unlocking secrets file");
again:
	if (stat(crypto_secrets, &sb) == -1) {
		if (old_secrets != NULL) {
			/* unlink tmp file */
			(void)unlink(crypto_secrets);
			e_free(&crypto_secrets);
			crypto_secrets = old_secrets;
			old_secrets = NULL;
			CWARNX("can't parse new secrets file, using old one");
			goto again;
		}
		/* XXX should we *ever* hit this case? */
		fprintf(stderr, "No crypto secrets file. Creating\n");
		if (ct_create_secrets(ct_crypto_password, ct_crypto_secrets,
		    NULL, NULL))
			CFATALX("can't create secrets");
	}
	if (ct_unlock_secrets(ct_crypto_password, crypto_secrets,
	    ct_crypto_key, sizeof (ct_crypto_key), ct_iv, sizeof ct_iv)) {
		if (old_secrets != NULL) {
			/* unlink tmp file */
			(void)unlink(crypto_secrets);
			e_free(&crypto_secrets);
			crypto_secrets = old_secrets;
			old_secrets = NULL;
			CWARNX("can't parse new secrets file, using old one");
			goto again;
		}
		CFATALX("can't unlock secrets");
	}
	if (old_secrets != NULL) {
		strlcpy(tmp, old_secrets, sizeof(tmp));
		strlcat(tmp, ".bak", sizeof(tmp));

		/* parse out mtime */
		if ((t = strchr(op->op_remote_fname, '-')) == NULL)
			CFATALX("invalid answer from server");
		*t = '\0';
		times[1].tv_sec = strtonum(op->op_remote_fname, LLONG_MIN,
		    LLONG_MAX, &errstr);
		if (errstr)
			CFATALX("mtime %s from secrets file invalid: %s",
			    op->op_remote_fname, errstr);
		times[0].tv_sec = times[1].tv_sec;

		/* remove an existing backup file */
		(void)unlink(tmp);
		/* save old file allow for failure in case it exists */
		if (stat(old_secrets, &sb) == 0) {
			if (link(old_secrets, tmp) != 0)
				CWARN("unable to backup secrets file");
		}
		/* rename to ``real'' filename */
		if (rename(crypto_secrets, old_secrets) != 0)
			CFATAL("can't rename secrets file to real name");
		/*
		 * Set mtime to the mtime we downloaded.
		 * XXX futimens() would be nice here since atime doesn't matter
		 */
		if (utimes(old_secrets, times) != 0)
			CWARN("couldn't set mtime on new secrets file");
		e_free(&crypto_secrets);
	}
	ct_encrypt_enabled = 1;
	ctdb_setup(ct_localdb, ct_encrypt_enabled);
}

/*
 * Delete all metadata files that were found by the preceding list operation.
 */
void
ct_md_trigger_delete(struct ct_op *op)
{
	struct md_list_tree	 results;
	struct md_list_file	*file = NULL;

	RB_INIT(&results);
	ct_md_list_complete(op->op_matchmode, op->op_filelist,
	    op->op_excludelist, &results);
	while((file = RB_ROOT(&results)) != NULL) {
		CDBG("deleting remote crypto secrets file %s", file->mlf_name);
		ct_add_operation_after(op, ct_md_delete, NULL, NULL,
		    e_strdup(file->mlf_name), NULL, NULL, NULL, 0, 0);
		RB_REMOVE(md_list_tree, &results, file);
		e_free(&file);
	}
}
