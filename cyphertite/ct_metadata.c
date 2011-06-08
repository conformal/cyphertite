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

#include <inttypes.h>
#include <stdlib.h>
#include <dirent.h>
#include <libgen.h>
#include <fnmatch.h>
#include <regex.h>
#include <vis.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <xmlsd.h>

#include <ctutil.h>
#include <ct_xml.h>

#include "ct.h"

void ct_md_fileio(void *);
void md_extract_chunk(void *);

const char			*md_filename;
char				**ct_md_listfiles;
int				md_backup_fd;
int				md_block_no = 0;
int				md_is_open = 0;
int				md_open_inflight = 0;
size_t				md_size, md_offset;
time_t				md_mtime;

int	strcompare(const void *, const void *);

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

	fname = e_malloc(CT_MAX_MD_FILENAME, E_MEM_CLEAR);
	if (fname == NULL)
		CFATALX("can't allocate space for filename");


	pdup = e_strdup(path);
	bname = basename(pdup);
	e_free(&pdup);
	if (bname == NULL)
		CFATAL("can't basename md path");
	if (bname[0] == '/')
		CFATALX("invalid md filename");

	if (strnvis(fname, bname, CT_MAX_MD_FILENAME, VIS_GLOB |
	    VIS_WHITE | VIS_SAFE) >= CT_MAX_MD_FILENAME)
		CFATALX("md filename too long");
	return (fname);
}

struct flist			*md_node;
int
ct_md_archive(const char *mfile, const char *mdname)
{
	struct stat		sb;
	int			error, rv;

	CDBG("opening md file for archive %s", mfile);

	md_backup_fd = open(mfile, O_RDONLY);

	md_offset = 0;
	if (md_backup_fd == -1) {
		CWARNX("unable to open file %s", mfile);
		return -1;
	}
	md_filename = mdname;
	md_node = e_malloc(sizeof(*md_node), E_MEM_CLEAR);
	CDBG("mdnode %p", md_node);

	error = fstat(md_backup_fd, &sb);
	if (error) {
		CWARNX("file stat error %s %d %s",
		    mfile, errno, strerror(errno));
		return -1;
	} else {
		md_size = sb.st_size;
		md_mtime = sb.st_mtime;
	}

	ct_event_init();

	ct_setup_assl();

	/* setup wakeup channels */
	ct_setup_wakeup_file(ct_state, ct_md_fileio);
	ct_setup_wakeup_sha(ct_state, ct_compute_sha);
	ct_setup_wakeup_compress(ct_state, ct_compute_compress);
	ct_setup_wakeup_csha(ct_state, ct_compute_csha);
	ct_setup_wakeup_encrypt(ct_state, ct_compute_encrypt);
	ct_setup_wakeup_complete(ct_state, ct_process_completions);


	/* poke file into action */
	ct_wakeup_file();

	/* start turning crank */
	rv = ct_event_dispatch();
	if (rv != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));
	md_filename = NULL;
	return (rv);
}

void
ct_md_fileio(void *unused)
{
	struct stat		sb;
	ssize_t			rsz, rlen;
	struct ct_trans		*ct_trans;
	int			error;

	CDBG("md_fileio entered for block %d", md_block_no);
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

		ct_xml_file_open(ct_trans, md_filename, MD_O_WRITE);
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

	ct_trans->tr_fl_node = md_node;
	ct_trans->tr_size[0] = rlen;
	ct_trans->tr_state = TR_S_READ;
	ct_trans->tr_type = TR_T_WRITE_CHUNK;
	ct_trans->tr_trans_id = ct_trans_id++;
	ct_trans->tr_eof = 0;
	ct_trans->hdr.c_flags = C_HDR_F_METADATA;

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
			    md_filename, errno, strerror(errno));
		} else if (sb.st_size != md_size) {
			CWARNX("file truncated during backup %s",
			    md_filename);
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
ct_xml_file_open(struct ct_trans *trans, const char *file, int mode)
{
	struct ct_header	*hdr = NULL;
	char			*body = NULL;
	char			*buf = NULL;
	int			sz;

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_OPEN;

	CDBG("setting up XML");

	if (mode)
		sz = asprintf(&buf, ct_md_open_create_fmt, file);
	else
		sz = asprintf(&buf, ct_md_open_read_fmt, file);
	if (sz == -1)
		CFATALX("cannot allocate memory");
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
	free(buf);

	CDBG("open trans %"PRIu64, trans->tr_trans_id);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	ct_assl_write_op(ct_assl_ctx, hdr, body);
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
	sz = asprintf(&buf, "%s", ct_md_close_fmt);
	if (sz == -1)
		CFATALX("cannot allocate memory");
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
	free(buf);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	ct_assl_write_op(ct_assl_ctx, hdr, body);
}

int
ct_md_extract(const char *mfile, const char *mdname)
{
	int rv;

	CDBG("yo");
	ct_event_init();

	ct_setup_assl();

	/* setup wakeup channels */
	/* XXX - bet these are not the right functions for md_extract */
	ct_setup_wakeup_file(ct_state, md_extract_chunk);
	ct_setup_wakeup_sha(ct_state, ct_compute_sha);
	ct_setup_wakeup_compress(ct_state, ct_compute_compress);
	ct_setup_wakeup_csha(ct_state, ct_compute_csha);
	ct_setup_wakeup_encrypt(ct_state, ct_compute_encrypt);
	ct_setup_wakeup_complete(ct_state, ct_process_completions);

	/* XXX -chmod when done */
	md_backup_fd = open(mfile, O_WRONLY|O_TRUNC|O_CREAT, 0600);
	if (md_backup_fd == -1) {
		CWARNX("unable to open file %s", mfile);
		return -1;
	}

	md_filename = mdname;

	/* poke file into action */
	ct_wakeup_file();

	/* start turning crank */
	rv = ct_event_dispatch();
	if (rv != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));
	md_filename = NULL;
	return 0;
}
int extract_id;

void
md_extract_chunk(void *unused)
{
	struct ct_trans		*trans;
	struct ct_header	*hdr;
	void			*data;

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

		ct_xml_file_open(trans, md_filename, MD_O_READ);
		md_open_inflight = 1;
		return;
	}

	trans->tr_fl_node = md_node;
	trans->tr_state = TR_S_EX_READ;
	trans->tr_type = TR_T_READ_CHUNK;
	trans->tr_trans_id = ct_trans_id++;
	trans->tr_eof = 0;

	hdr = &trans->hdr;

	hdr->c_opcode = C_HDR_O_READ;
	hdr->c_size = sizeof(trans->tr_sha);
	hdr->c_version = C_HDR_VERSION;
	hdr->c_flags |= C_HDR_F_METADATA;

	bzero(trans->tr_sha, sizeof(trans->tr_sha));
	trans->tr_sha[0] = (extract_id >>  0) & 0xff;
	trans->tr_sha[1] = (extract_id >>  8) & 0xff;
	trans->tr_sha[2] = (extract_id >> 16) & 0xff;
	trans->tr_sha[3] = (extract_id >> 24) & 0xff;
	bzero(trans->tr_iv, sizeof(trans->tr_iv));
	trans->tr_iv[0] = (extract_id >>  0) & 0xff;
	trans->tr_iv[1] = (extract_id >>  8) & 0xff;
	trans->tr_iv[2] = (extract_id >> 16) & 0xff;
	trans->tr_iv[3] = (extract_id >> 24) & 0xff;
	trans->tr_iv[4] = (extract_id >>  0) & 0xff;
	trans->tr_iv[5] = (extract_id >>  8) & 0xff;
	trans->tr_iv[6] = (extract_id >> 16) & 0xff;
	trans->tr_iv[7] = (extract_id >> 24) & 0xff;
	data = trans->tr_sha;
	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	extract_id ++; /* next chunk on next pass */

	ct_assl_write_op(ct_assl_ctx, hdr, data);
}

void
ct_complete_metadata(struct ct_trans *trans)
{
	ssize_t			wlen;
	int			slot;

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
		if (ct_verbose_ratios)
			ct_dump_stats(stdout);

		ct_file_extract_fixup();
		ct_shutdown();
		break;
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

char **
ct_md_list(char **pat, int match_mode)
{
	/* XXX - does mfile make sense for md list */
	struct ct_header	*hdr;
	struct ct_trans		*trans;
	char			*body = NULL;
	char			*buf = NULL;
	regex_t			*re = NULL;
	char			error[1024];
	char			**str, **matchedlist, *curstr;
	int			rv, sz, nfiles, i, match;

	ct_event_init();

	ct_setup_assl();
	ct_setup_wakeup_complete(ct_state, ct_process_completions);
	ct_set_file_state(CT_S_FINISHED);

	trans = ct_trans_alloc();

	trans->tr_trans_id = ct_trans_id++;
	trans->tr_state = TR_S_XML_LIST;
	
	CDBG("setting up XML");

	/* XXX - pat */
	sz = asprintf(&buf, ct_md_list_fmt, ""); 
	if (sz == -1)
		CFATALX("cannot allocate memory");
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
	free(buf);
	
	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	ct_assl_write_op(ct_assl_ctx, hdr, body);

	/* start turning crank */
	rv = ct_event_dispatch();
	if (rv != 0) {
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));
		return (NULL);
	}

	if (ct_md_listfiles == NULL)
		return (NULL);

	if (match_mode == CT_MATCH_REGEX && *pat) {
		re = e_malloc(sizeof(*re), E_MEM_CLEAR);
		if ((rv = regcomp(re, *pat,
		    REG_EXTENDED | REG_NOSUB)) != 0) {
			regerror(rv, re, error, sizeof(error) - 1);
			CFATALX("%s: regcomp failed: %s", __func__, error);
		}
	}


	str = ct_md_listfiles;
	nfiles = 0;
	while (*(str++) != NULL)
		nfiles++;

	matchedlist = e_malloc((nfiles + 1) * sizeof(*ct_md_listfiles),
	    E_MEM_CLEAR);

	str = ct_md_listfiles;
	i = 0;
	while ((curstr = *(str++)) != NULL) {
		match = 0;
		if (*pat == NULL) {
			match = 1;
		} else if (match_mode == CT_MATCH_REGEX) {
			if (regexec(re, curstr, 0, NULL, 0) == 0)
				match = 1;
		} else {
			if (fnmatch(*pat, curstr, 0) == 0)
				match = 1;
		}
		if (match) {
			matchedlist[i++] = curstr;
		} else {
			e_free(&curstr);
		}
	}
	matchedlist[i] = NULL;
	e_free(&ct_md_listfiles); /* sets md_listfiles to NULL, too */
	if (match_mode == CT_MATCH_REGEX && *pat) {
		regfree(re);
		e_free(&re);
	}
	
	return (matchedlist);
}

int
ct_md_list_print(char **pat, int match_mode)
{
	char	**results, **str, *curstr;

	results = ct_md_list(pat, match_mode);
	if (results == NULL)
		return (1);

	str = results;
	while ((curstr = *(str++)) != NULL) {
		printf("%s\n", curstr);
		e_free(&curstr);
	}
	e_free(&results);

	return (0);
}

int
ct_md_delete(const char *md)
{
	struct ct_header *hdr;
	struct ct_trans *trans;
	char *buf, *body = NULL;
	int rv, sz;

	CDBG("setting up XML");

	sz = asprintf(&buf, ct_md_delete_fmt, md);
	if (sz == -1)
		CFATALX("cannot allocate memory");
	sz += 1;	/* include null */

	ct_event_init();
	ct_setup_assl();
	ct_setup_wakeup_complete(ct_state, ct_process_completions);

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
	free(buf);

	TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
	ct_state->ct_queued_qlen++;

	ct_assl_write_op(ct_assl_ctx, hdr, body);

	/* start turning crank */
	rv = ct_event_dispatch();
	if (rv != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));

	return rv;
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
	if (r) {
		CDBG("parse FAILED! (%d)", r);
		goto done;
	}

	TAILQ_FOREACH(xe, &xl, entry) {
		CDBG("%d %s = %s (parent = %s)",
		    xe->depth, xe->name, xe->value ? xe->value : "NOVAL",
		    xe->parent ? xe->parent->name : "NOPARENT");
		TAILQ_FOREACH(xa, &xe->attr_list, entry)
			CDBG("\t%s = %s", xa->name, xa->value);
	}

	r = xmlsd_validate(&xl, ct_xml_cmds);
	if (r) {
		CDBG("validate of '%s' FAILED! (%d)", body, r);
		goto done;
	}

	if (TAILQ_EMPTY(&xl)) {
		CDBG("parse command: No XML");
		goto done;
	}

	xe = TAILQ_FIRST(&xl);
	if (strncmp(xe->name, "ct_md_open", strlen("ct_md_open")) == 0) {
		int die = 1;

		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				filename = xmlsd_get_attr(xe, "name");
				if (filename)
					CWARNX("%s opened\n", filename);
				die = 0;
				md_open_inflight = 0;
				md_is_open = 1;
				ct_wakeup_file();
			}
		}
		if (die) {
			CWARNX("couldn't open md file");
			ct_shutdown();
		}
	} else if (strcmp(xe->name, "ct_md_close") == 0) {
		trans->tr_state = TR_S_DONE;
	} else if (strcmp(xe->name, "ct_md_list") == 0) {
		int nfiles = 0;

		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0)
				nfiles++;
		}
		/* array is NULL terminated */
		ct_md_listfiles = e_malloc((nfiles + 1) *
		    sizeof(*ct_md_listfiles), E_MEM_CLEAR);
		nfiles = 0;
		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				filename = xmlsd_get_attr(xe, "name");
				if (filename) {
					ct_md_listfiles[nfiles] =
					    e_strdup(filename);
					nfiles++;
				}
			}
		}
		ct_md_listfiles[nfiles] = NULL;
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

done:
	ct_queue_transfer(trans);
	ct_header_free(NULL, hdr);
	xmlsd_unwind(&xl);
}

void
ct_mdmode_setup(char *mdmode)
{
	CWARNX("mdmode setup %s", mdmode ? mdmode : "");
	if (mdmode == NULL)
		return;

	if (strcmp(mdmode, "remote") == 0)
		ct_md_mode = CT_MDMODE_REMOTE;
	else if (strcmp(mdmode, "local") == 0)
		ct_md_mode = CT_MDMODE_LOCAL;
	else
		CFATALX("invalid md mode specified");
}

int
md_is_in_cache(const char *mdfile)
{
	struct dirent	*dp;
	DIR		*dirp;
	int		 found = 0;

	if ((dirp = opendir(ct_md_cachedir)) == NULL)
		CFATALX("can't open md cache dir");
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
char *
ct_find_md_for_extract(const char *mdname)
{
	char	**result, **tmp;
	char	 *buf, *best, *cachename; 
	int	 nresults = 0, ret;

	/* cook the mdname so we only search for the actual tag */
	mdname = ct_md_cook_filename(mdname);

	if (ct_md_is_full_mdname(mdname)) {
		/* use md_list as stat() for now */
		buf = (char *)mdname;
		if ((result = ct_md_list(&buf, CT_MATCH_GLOB)) == NULL)
			CFATALX("unable to list md files");
	} else {
		e_asprintf(&buf, "^[[:digit:]]{8}-[[:digit:]]{6}-%s$", mdname);

		/*
		 * get the list of md matching this tag from the server.
		 * ct_md_list returns an empty list if it found
		 * nothing and NULL upon failure.
		 */
		if ((result = ct_md_list(&buf, CT_MATCH_REGEX)) == NULL)
			CFATALX("unable to list md files");

		e_free(&buf);
	}

	tmp = result;
	while (*(tmp++) != NULL)
		nresults++;
	if (nresults == 0)
		CFATALX("unable to find metadata tagged %s", mdname);
		
	/* sort and calculate newest */
	qsort(result, nresults, sizeof(*result), strcompare);

	/* pick the newest one */
	best = e_strdup(result[0]);
	CDBG("backup file is %s", best);

	tmp = result;
	while (*tmp != NULL) {
		e_free(tmp);
		tmp++;
	}
	e_free(&result);

	cachename = ct_md_get_cachename(best);
	if (!md_is_in_cache(best)) {
		/* else grab it to the cache. XXX differentials? */
		if ((ret = ct_md_extract(cachename, best)) != 0)
			CFATALX("can't download md file");
	}

	e_free(&mdname);
	e_free(&best);

	/* return filename of file in cache. */
	return (cachename);
}

char *
ct_find_md_for_archive(const char *mdname)
{
	char	 buf[TIMEDATA_LEN], *fullname, *cachename; 
	time_t	 now;

	/* cook the mdname so we only search for the actual tag */
	mdname = ct_md_cook_filename(mdname);

	if (ct_md_is_full_mdname(mdname) != 0)
		CFATALX("mdname with data tag already filled in");

	now = time(NULL);
	if (strftime(buf, TIMEDATA_LEN, "%Y%m%d-%H%M%S",
	    localtime(&now)) == 0)
		CFATALX("can't format time");
	e_asprintf(&fullname, "%s-%s", buf, mdname);
	CDBG("backup file is %s", fullname);

	/* check it isn't already in the cache */
	cachename = ct_md_get_cachename(fullname);
	if (md_is_in_cache(fullname))
		CFATALX("generated mdname is already in cache dir");

	e_free(&mdname);
	e_free(&fullname);

	return (cachename);
}
