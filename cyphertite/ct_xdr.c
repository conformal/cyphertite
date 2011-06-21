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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <time.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"
#include "ct_xdr.h"

__attribute__((__unused__)) static const char *cvstag = "$cyphertite$";

int ct_populate_fnode(struct flist *, struct ct_md_header *, int *);
FILE *ct_extract_setup_queue(const char *);
FILE *ct_metadata_open_next(void);

XDR				xdr;
FILE				*ct_xdr_f;
time_t				ct_prev_backup_time;
int				md_dir = -1;
int64_t				ct_num_shas = -1;
struct flist			*fl_ex_node;
int				ct_doextract;


/* metadata */
bool_t
ct_xdr_dedup_sha(XDR *xdrs, uint8_t *sha)
{
	if (!xdr_opaque(xdrs, (caddr_t)sha, SHA_DIGEST_LENGTH))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_dedup_sha_crypto(XDR *xdrs, uint8_t *sha, uint8_t *csha, uint8_t *iv)
{
	if (!xdr_opaque(xdrs, (caddr_t)sha, SHA_DIGEST_LENGTH))
		return (FALSE);
	if (!xdr_opaque(xdrs, (caddr_t)csha, SHA_DIGEST_LENGTH))
		return (FALSE);
	if (!xdr_opaque(xdrs, (caddr_t)iv, E_IV_LEN))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_header(XDR *xdrs, struct ct_md_header *objp)
{
	if (!xdr_int(xdrs, &objp->cmh_beacon))
		return (FALSE);
	if (!xdr_u_int64_t(xdrs, &objp->cmh_nr_shas))
		return (FALSE);
	if (!xdr_u_int32_t(xdrs, &objp->cmh_uid))
		return (FALSE);
	if (!xdr_u_int32_t(xdrs, &objp->cmh_gid))
		return (FALSE);
	if (!xdr_u_int32_t(xdrs, &objp->cmh_mode))
		return (FALSE);
	if (!xdr_int32_t(xdrs, &objp->cmh_rdev))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->cmh_atime))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->cmh_mtime))
		return (FALSE);
	if (!xdr_u_char(xdrs, &objp->cmh_type))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->cmh_filename, PATH_MAX))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_trailer(XDR *xdrs, struct ct_md_trailer *objp)
{
	if (!ct_xdr_dedup_sha(xdrs, objp->cmt_sha))
		return (FALSE);
	if (!xdr_u_int64_t(xdrs, &objp->cmt_orig_size))
		return (FALSE);
	if (!xdr_u_int64_t(xdrs, &objp->cmt_comp_size))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_stdin(XDR *xdrs, struct ct_md_stdin *objp)
{
	if (!xdr_int(xdrs, &objp->cms_beacon))
		return (FALSE);
	/* XXX - crypt? */
	if (!ct_xdr_dedup_sha(xdrs, objp->cms_sha))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_gheader(XDR *xdrs, struct ct_md_gheader *objp)
{
	if (!xdr_int(xdrs, &objp->cmg_beacon))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->cmg_version))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->cmg_chunk_size))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->cmg_created))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->cmg_type))
		return (FALSE);
	if (!xdr_int(xdrs, &objp->cmg_flags))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->cmg_prevlvl_filename, PATH_MAX))
		return (FALSE);
	return (TRUE);
}

FILE *
ct_metadata_create(const char *filename, int intype)
{
	FILE			*f;
	struct ct_md_gheader	gh;

	/* open metadata file */
	f = fopen(filename, "wb");
	if (f == NULL)
		return (NULL);

	/* prepare header */
	bzero(&gh, sizeof gh);
	gh.cmg_beacon = CT_MD_BEACON;
	gh.cmg_version = CT_MD_VERSION;
	gh.cmg_chunk_size = ct_max_block_size;
	gh.cmg_created = time(NULL);
	gh.cmg_type = intype;
	gh.cmg_flags = 0;
	if (ct_encrypt_enabled)
		gh.cmg_flags |= CT_MD_CRYPTO;
	if (ct_multilevel_allfiles)
		gh.cmg_flags |= CT_MD_MLB_ALLFILES;
	gh.cmg_prevlvl_filename = ct_basisbackup ? ct_basisbackup : "";

	md_dir = XDR_ENCODE;
	/* write global header */
	xdrstdio_create(&xdr, f, XDR_ENCODE);
	if (ct_xdr_gheader(&xdr, &gh) == FALSE)
		CFATALX("e_xdr_gheader failed");

	return (f);
}

void
ct_metadata_close(FILE *file)
{
	struct ct_md_header	hdr;
	char			fake[1];

	/* write EOF header on close */
	if (md_dir == XDR_ENCODE) {
		bzero(&hdr, sizeof hdr);
		fake[0] = '\0';
		hdr.cmh_filename = fake;
		hdr.cmh_beacon = CT_HDR_EOF;
		if (ct_xdr_header(&xdr, &hdr) == FALSE)
			CWARNX("Failed to write archive footer");
	}

	xdr_destroy(&xdr);
	fclose(file);
}

int
ct_write_header(struct ct_trans *trans, char *filename)
{
	struct flist *fnode;
	struct ct_md_header	hdr;

	fnode = trans->tr_fl_node;

	CDBG("writing file header %s %s", trans->tr_fl_node->fl_sname,
	    filename);

	bzero(&hdr, sizeof hdr);

	if (fnode->fl_skip_file)
		hdr.cmh_nr_shas = -1LL;
	else if (C_ISREG(fnode->fl_type)) {
		hdr.cmh_nr_shas = fnode->fl_size / ct_max_block_size;
		if (fnode->fl_size % ct_max_block_size)
			hdr.cmh_nr_shas++;
	}

	hdr.cmh_beacon = CT_HDR_BEACON;
	hdr.cmh_uid = fnode->fl_uid;
	hdr.cmh_gid = fnode->fl_gid;
	hdr.cmh_mode = fnode->fl_mode;
	hdr.cmh_rdev = fnode->fl_rdev;
	hdr.cmh_atime = fnode->fl_atime;
	hdr.cmh_mtime = fnode->fl_mtime;
	hdr.cmh_filename = filename;
	hdr.cmh_type = fnode->fl_type;

	if (ct_xdr_header(&xdr, &hdr) == FALSE)
		return 1;

	return 0;
}

int
ct_write_trailer(struct ct_trans *trans)
{
	struct ct_md_trailer trl;
	struct flist *fnode;
	bool_t ret;

	fnode = trans->tr_fl_node;

	CDBG("multi %d", ct_multilevel_allfiles);

	CDBG("writing file trailer %s", fnode->fl_sname);
	bzero (&trl, sizeof trl);
	ct_sha1_final(trl.cmt_sha, &fnode->fl_shactx);
	trl.cmt_orig_size = fnode->fl_size;
	trl.cmt_comp_size = fnode->fl_comp_size;

	ret = ct_xdr_trailer(&xdr, &trl);

	if (ret == FALSE)
		CWARNX("failed to write trailer sha");

	return (ret == FALSE);
}

int
ct_write_sha(struct ct_trans *trans)
{
	bool_t ret;

	CDBG("XoX sha sz %d eof %d", trans->tr_size[(int)trans->tr_dataslot],
	    trans->tr_eof);
	ret = ct_xdr_dedup_sha(&xdr, trans->tr_sha);

	if (ret == FALSE)
		CWARNX("failed to write sha");

	return (ret == FALSE);
}

int
ct_write_sha_crypto(struct ct_trans *trans)
{
	bool_t ret;

	CDBG("XoX sha crypt");
	ret = ct_xdr_dedup_sha_crypto(&xdr, trans->tr_sha, trans->tr_csha,
	   trans->tr_iv);

	if (ret == FALSE)
		CWARNX("failed to write sha");

	return (ret == FALSE);
}

int
ct_list(const char *file, char **flist, int match_mode)
{
	FILE			*xdr_f;
	struct ct_md_gheader	gh;
	struct ct_md_header	hdr;
	struct ct_md_trailer	trl;
	struct flist		fnodestore;
	struct flist		*fnode = &fnodestore;
	int			state;
	int			doprint;

	off_t			pos0, pos1;
	int			sha_size = -1;
	int64_t			sha_cnt;
	int			ret;
	uint8_t			sha[SHA_DIGEST_LENGTH];
	uint8_t			csha[SHA_DIGEST_LENGTH];
	uint8_t			iv[E_IV_LEN];
	char			shat[SHA_DIGEST_STRING_LENGTH];
	char			*ct_next_filename;

	ct_match_compile(match_mode, flist);

	ct_verbose++;	/* by default print something. */

next_file:
	ct_next_filename = NULL;
	xdr_f = ct_metadata_open(file,  &gh);
	if (xdr_f == NULL)
		CFATALX("failed to open %s", file);
	bzero(&fnodestore, sizeof(fnodestore));
	file = NULL;

	ret = ct_read_header(&hdr);

	while (ret == 0 && hdr.cmh_beacon != CT_HDR_EOF) {
		doprint = (ct_all_files ||
		    !ct_match(match_mode, hdr.cmh_filename));
		ct_populate_fnode(fnode, &hdr, &state);

		if (doprint )
			ct_pr_fmt_file(fnode);

		if (C_ISREG(hdr.cmh_type)) {
			sha_cnt = hdr.cmh_nr_shas;
			if (sha_cnt == -1) {
				goto skipped;
			}
			if (doprint && ct_verbose > 2) {
				printf("\n");
				while (sha_cnt--) {
					if (ct_encrypt_enabled) {
						ret = ct_xdr_dedup_sha_crypto(
						    &xdr, sha, csha, iv);
					} else {
						ret = ct_xdr_dedup_sha(&xdr,
						    sha);
					}
					if (ret == FALSE)
						CFATALX("error deduping sha");
					ct_sha1_encode(sha, shat);
					printf(" sha %s\n", shat);
				}
			} else {
				if (sha_size < 0) {
					pos0 = ftello(xdr_f);
					if (ct_encrypt_enabled) {
						ret = ct_xdr_dedup_sha_crypto(
						    &xdr, sha, csha, iv);
					} else {
						ret = ct_xdr_dedup_sha(&xdr,
						    sha);
					}
					if (ret == FALSE)
						CFATALX("error deduping sha");
					pos1 = ftello(xdr_f);
					sha_size = pos1 - pos0;
					sha_cnt--;
				}
				fseek(xdr_f, sha_size * sha_cnt, SEEK_CUR);
			}
skipped:
			if (ct_read_trailer(&trl))
				CFATALX("trailer read failure");
			if (doprint && ct_verbose > 1)
				printf(" shas: %" PRIu64 " reduction: %" PRIu64 "%%\n",
				    hdr.cmh_nr_shas,
				    trl.cmt_orig_size == 0 ? 0 :
				    100 * (trl.cmt_orig_size-trl.cmt_comp_size)
				    /trl.cmt_orig_size);
			else if (doprint)
				printf("\n");
		} else if (doprint)
			printf("\n");

		/* give back memory associated with old fnode */
		if (fnode->fl_sname)
			e_free(&fnode->fl_sname);
		if (fnode->fl_hlname)
			e_free(&fnode->fl_hlname);

		ret = ct_read_header(&hdr);
	}

	ct_metadata_close(xdr_f);

	if (hdr.cmh_beacon != CT_HDR_EOF) {
		CWARNX("end of archive not hit");
	} else {
		if (ct_next_filename) {
			file = ct_next_filename;
			goto next_file;
		}
	}
	ct_unload_config();
	ct_match_unwind(match_mode);
	return (0);
}

FILE *
ct_metadata_open(const char *filename, struct ct_md_gheader *gh)
{
	FILE			*f;
	time_t			ltime;

	/* open metadata file */
	f = fopen(filename, "rb");
	if (f == NULL)
		return (NULL);

	md_dir = XDR_DECODE;
	xdrstdio_create(&xdr, f, XDR_DECODE);

	bzero(gh, sizeof *gh);

	if (ct_xdr_gheader(&xdr, gh) == FALSE)
		CFATALX("e_xdr_gheader failed");

	ltime = gh->cmg_created;
	if (ct_verbose > 1)
		printf("version: %d block size: %d created: %s",
		    gh->cmg_version, gh->cmg_chunk_size,
		    ctime(&ltime));

	if (gh->cmg_beacon != CT_MD_BEACON)
		CFATALX("Not a cyphertite file");
	if (gh->cmg_version != CT_MD_VERSION) {
		CFATALX("Invalid version %d, expected %d", gh->cmg_version,
		    CT_MD_VERSION);
	}
	ct_max_block_size = gh->cmg_chunk_size;
	ct_encrypt_enabled = (gh->cmg_flags & CT_MD_CRYPTO);
	ct_multilevel_allfiles = (gh->cmg_flags & CT_MD_MLB_ALLFILES);

	return (f);
}

int
ct_read_header(struct ct_md_header *hdr)
{
	bzero(hdr, sizeof *hdr);

	if (ct_xdr_header(&xdr, hdr) == FALSE)
		return 1;

	CDBG("header beacon 0x%08x 0x%08x shas %" PRIu64 " name %s", hdr->cmh_beacon,
	    CT_HDR_BEACON, hdr->cmh_nr_shas, hdr->cmh_filename);

	if (hdr->cmh_beacon != CT_HDR_BEACON && hdr->cmh_beacon != CT_HDR_EOF)
		return 1;

	return 0;
}

int
ct_read_trailer(struct ct_md_trailer *trl)
{
	bool_t ret;

	bzero (trl, sizeof *trl);

	ret = ct_xdr_trailer(&xdr, trl);

	if (ret == FALSE)
		CWARNX("failed to read trailer sha");

	return (ret == FALSE);
}

int ct_extract_second_pass;

struct ct_extract_stack   {
	TAILQ_ENTRY(ct_extract_stack)	next;
	char		*filename;
};
TAILQ_HEAD(, ct_extract_stack) ct_file_extract_head =
    TAILQ_HEAD_INITIALIZER(ct_file_extract_head);

void
ct_extract_setup(const char *file)
{
	FILE			*xdr_f;
	FILE			*last_xdr = NULL;
	struct ct_md_gheader	gh;
	struct ct_extract_stack	*nfile;

	xdr_f = ct_metadata_open(file,  &gh);
	if (xdr_f == NULL)
		CFATALX("ct_extract_setup unable to open metadata file '%s'\n",
		    file);

	ct_encrypt_enabled = (gh.cmg_flags & CT_MD_CRYPTO);
	ct_multilevel_allfiles = (gh.cmg_flags & CT_MD_MLB_ALLFILES);

	if (gh.cmg_prevlvl_filename && gh.cmg_prevlvl_filename[0] == '\0') {
		free(gh.cmg_prevlvl_filename);
		gh.cmg_prevlvl_filename = NULL;
	}
	if (gh.cmg_prevlvl_filename) {
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);
		TAILQ_INSERT_HEAD(&ct_file_extract_head, nfile, next);

		ct_metadata_close(xdr_f);
		last_xdr = ct_extract_setup_queue(gh.cmg_prevlvl_filename);
		free(gh.cmg_prevlvl_filename);

		if (ct_multilevel_allfiles) {
			ct_metadata_close(last_xdr);
			xdr_f = ct_metadata_open_next(); /* reopen first file */
		} else {
			xdr_f = last_xdr;
		}
	}

	ct_xdr_f = xdr_f;

	ct_set_file_state(CT_S_WAITING_TRANS);
}

FILE *
ct_extract_setup_queue(const char *file)
{
	FILE			*xdr_f;
	struct ct_md_gheader	gh;
	struct ct_extract_stack	*nfile;

	xdr_f = ct_metadata_open(file,  &gh);
	if (xdr_f == NULL)
		CFATALX("ct_extract_setup_queue unable to open metadata file "
		    "'%s'\n", file);

	ct_encrypt_enabled = (gh.cmg_flags & CT_MD_CRYPTO);
	if (gh.cmg_prevlvl_filename && gh.cmg_prevlvl_filename[0] == '\0') {
		free(gh.cmg_prevlvl_filename);
		gh.cmg_prevlvl_filename = NULL;
	}

	if (gh.cmg_prevlvl_filename) {
		printf("next [%s]\n", gh.cmg_prevlvl_filename);
		/* need to nest another level deep.*/
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);
		ct_metadata_close(xdr_f);
		if (ct_multilevel_allfiles)
			TAILQ_INSERT_TAIL(&ct_file_extract_head, nfile, next);
		else
			TAILQ_INSERT_HEAD(&ct_file_extract_head, nfile, next);
		xdr_f = ct_extract_setup_queue(gh.cmg_prevlvl_filename);
		free(gh.cmg_prevlvl_filename);
	} else {
		if (ct_multilevel_allfiles) {
			nfile = e_malloc(sizeof(*nfile));
			nfile->filename = e_strdup(file);
			TAILQ_INSERT_TAIL(&ct_file_extract_head, nfile, next);
		}
	}
	return xdr_f;
}

FILE *
ct_metadata_open_next()
{
	FILE			*xdr_f;
	struct ct_md_gheader	gh;
	struct ct_extract_stack *next;

	if (!TAILQ_EMPTY(&ct_file_extract_head)) {
		next = TAILQ_FIRST(&ct_file_extract_head);
		CINFO("should start restoring [%s]", next->filename);
		TAILQ_REMOVE(&ct_file_extract_head, next, next);

		xdr_f = ct_metadata_open(next->filename,  &gh);
		ct_encrypt_enabled = (gh.cmg_flags & CT_MD_CRYPTO);

		if (gh.cmg_prevlvl_filename)
			free(gh.cmg_prevlvl_filename);
	} else {
		CFATALX("open next with no next archive");
	}
	return xdr_f;
}

void
ct_extract(struct ct_op *op)
{
	const char		*mfile = op->op_arg1;
	char			**filelist = op->op_arg2;
	int			 match_mode = op->op_arg4;
	struct flist		*fnode;
	struct ct_md_header	hdr;
	struct ct_md_trailer	trl;
	int			ret;
	struct ct_trans		*trans;
	char			shat[SHA_DIGEST_STRING_LENGTH];

	CDBG("entry");
	if (ct_state->ct_file_state == CT_S_STARTING) {
		ct_match_compile(match_mode, filelist);
		ct_extract_setup(mfile);
	} else if (ct_state->ct_file_state == CT_S_FINISHED) {
		return;
	}
	ct_set_file_state(CT_S_RUNNING);
	while (1) {
		trans = ct_trans_alloc();
		if (trans == NULL) {
			/* system busy, return */
			CDBG("ran out of transactions, waiting");
			ct_set_file_state(CT_S_WAITING_TRANS);
			return;
		}

		CDBG("shacnt %" PRId64, ct_num_shas);
		if (ct_num_shas == -1) {
			/* read header */
			if (ct_read_header(&hdr))
				CFATALX("failure reading header");

			switch (hdr.cmh_beacon) {
			case CT_HDR_BEACON:
				/* all is good */
				break;
			case CT_HDR_EOF:
				CDBG("Hit end of md");
				ct_metadata_close(ct_xdr_f);
				if (!TAILQ_EMPTY(&ct_file_extract_head)) {
					ct_metadata_close(ct_xdr_f);

					ct_xdr_f = ct_metadata_open_next();

					/* poke file into action */
					ct_wakeup_file();
				} else {
					ct_match_unwind(match_mode);
					trans->tr_state = TR_S_DONE;
					trans->tr_trans_id = ct_trans_id++;
					ct_queue_transfer(trans);
					ct_set_file_state(CT_S_FINISHED);
				}
				return;
			default:
				CFATALX("invalid archive");
			}

			ct_doextract = (ct_all_files ||
			    !ct_match(match_mode, hdr.cmh_filename));

			if (C_ISREG(hdr.cmh_type)) {
				ct_num_shas = hdr.cmh_nr_shas;
				if (ct_num_shas == -1) {
					CINFO("mark file %s as restore from "
					    "previous backup",
					    hdr.cmh_filename);
					    ct_num_shas = 0;
				}
			}

			fnode = e_calloc(1, sizeof(*fnode));
			fl_ex_node = fnode;

			trans->tr_fl_node = fnode;

			ct_populate_fnode(fnode, &hdr, &trans->tr_state);

			if (ct_doextract == 0) {
				if (fnode->fl_sname)
					e_free(&fnode->fl_sname);
				if (fnode->fl_hlname)
					e_free(&fnode->fl_hlname);
				e_free(&fnode);
				ct_trans_free(trans);
				continue;
			}

			CDBG("file %s numshas %" PRId64, fnode->fl_sname,
			    ct_num_shas);

			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
		} else if (ct_num_shas == 0) {
			ct_num_shas--;
			trans->tr_fl_node = fl_ex_node;
			/* consume trailer */
			if (ct_read_trailer(&trl))
				CFATALX("trailer read failure");
			if (ct_doextract == 0) {
				ct_trans_free(trans);
				continue;
			}
			bcopy(trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_fl_node->fl_size = trl.cmt_orig_size;
			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
		} else {
			trans->tr_fl_node = fl_ex_node;
			/* in middle of file */
			ct_num_shas--;

			/*
			 * note that this extracts into tr_sha
			 * if it is encrypt or non-encrypt
			 */
			if (ct_encrypt_enabled) {
				/*
				 * yes csha and sha are reversed, we want
				 * to download csha, but putting it in sha
				 * simplifies the code
				 */
				ret = ct_xdr_dedup_sha_crypto(&xdr,
				    trans->tr_csha,
				    trans->tr_sha,
				    trans->tr_iv);
			} else {
				ret = ct_xdr_dedup_sha(&xdr,
				    trans->tr_sha);
			}
			if (ret == FALSE)
				CFATALX("error deduping sha");
			if (ct_doextract == 0) {
				ct_trans_free(trans);
				continue;
			}
			if (ct_verbose) {
				ct_sha1_encode(trans->tr_sha, shat);
				CDBG("extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_dataslot = 0;
			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
		}
	}
}

int
ct_populate_fnode(struct flist *fnode, struct ct_md_header *hdr, int *state)
{
	int ret;
	struct ct_md_header	hdr2;

	fnode->fl_sname = e_strdup(hdr->cmh_filename);

	if (C_ISLINK(hdr->cmh_type)) {
		/* hardlink/symlink */
		bzero(&hdr2, sizeof(hdr2));
		ret = ct_read_header(&hdr2);
		if (ret)
			return ret;
		fnode->fl_hlname = e_strdup(hdr2.cmh_filename);
		fnode->fl_hardlink = !C_ISLINK(hdr2.cmh_type);
		*state = TR_S_EX_SPECIAL;

	} else if (!C_ISREG(hdr->cmh_type)) {
		/* special file/dir */
		*state = TR_S_EX_SPECIAL;
	} else {
		/* regular file */
		*state = TR_S_EX_FILE_START;
	}
	/* ino not preserved? */
	fnode->fl_rdev = hdr->cmh_rdev;
	fnode->fl_uid = hdr->cmh_uid;
	fnode->fl_gid = hdr->cmh_gid;
	fnode->fl_mode = hdr->cmh_mode;
	fnode->fl_mtime = hdr->cmh_mtime;
	fnode->fl_atime = hdr->cmh_atime;
	fnode->fl_type = hdr->cmh_type;

	return 0;
}

void
ct_basis_setup(const char *basisbackup)
{
	struct ct_md_gheader	gh;
	FILE			*xdr_f;
	int			alldata;

	alldata = ct_multilevel_allfiles;
	xdr_f = ct_metadata_open(basisbackup,  &gh);
	if (xdr_f == NULL)
		CFATALX("unable to open/parse previous backup %s",
		    basisbackup);
	ct_multilevel_allfiles = alldata; /* dont whack this flag from client */
	
	ct_prev_backup_time = gh.cmg_created;
	CINFO("prev backup time %s %s", ctime(&ct_prev_backup_time),
	    basisbackup);
	ct_metadata_close(xdr_f);
}
