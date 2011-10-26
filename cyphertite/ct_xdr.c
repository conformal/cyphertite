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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include <libgen.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"
#include "ct_xdr.h"


int	ct_populate_fnode(struct fnode *, struct ct_md_header *,
	    struct ct_md_header *, int *);
void	ct_extract_setup(struct ct_xdr_state *, const char *);
void	ct_extract_setup_queue(struct ct_xdr_state *, const char *);
void	ct_extract_open_next(struct ct_xdr_state *);

XDR				xdr;
struct ct_xdr_state		ct_xdr_ctx;
time_t				ct_prev_backup_time;
int				md_dir = -1;
struct fnode			*fl_ex_node;
int				ct_doextract;
int				ct_xdr_version;

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
	if (ct_xdr_version >= CT_MD_V3) {
		if (!xdr_int64_t(xdrs, &objp->cmh_parent_dir))
			return (FALSE);
	} else {
		/* Old xdr versions are read-only */
		objp->cmh_parent_dir = -1;
	}
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
ct_xdr_gheader(XDR *xdrs, struct ct_md_gheader *objp, int write)
{
	char	 *basep, base[PATH_MAX], *prevlvl;
	int	 i;

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
	if (md_dir  == XDR_ENCODE && ct_md_mode == CT_MDMODE_REMOTE &&
	    objp->cmg_prevlvl_filename != NULL &&
	    objp->cmg_prevlvl_filename[0] != '\0') {
		strlcpy(base, objp->cmg_prevlvl_filename, sizeof(base));
		if ((basep = basename(base)) == NULL)
			CFATALX("can't basename %s",
			    objp->cmg_prevlvl_filename);
		prevlvl = basep;
	} else {
		prevlvl = objp->cmg_prevlvl_filename;
	}
	if (!xdr_string(xdrs, &prevlvl, PATH_MAX))
		return (FALSE);
	if (md_dir == XDR_DECODE && ct_md_mode == CT_MDMODE_REMOTE &&
	    prevlvl != NULL && prevlvl[0] != '\0') {
		strlcpy(base, prevlvl, sizeof(base));
		if ((basep = basename(base)) == NULL)
			CFATALX("can't basename %s", prevlvl);
		if (asprintf(&objp->cmg_prevlvl_filename, "%s%s",
		    ct_md_cachedir, basep) == -1)
			CFATALX("out of memory");
	} else {
		objp->cmg_prevlvl_filename = prevlvl;
	}
	if (objp->cmg_version >= CT_MD_V2) {
		if (!xdr_int(xdrs, &objp->cmg_cur_lvl))
			return (FALSE);
		if (!xdr_string(xdrs, &objp->cmg_cwd, PATH_MAX))
			return (FALSE);
		if (!xdr_int(xdrs, &objp->cmg_num_paths))
			return (FALSE);
		if (write == 0) {
			objp->cmg_paths = e_calloc(objp->cmg_num_paths,
			    sizeof(*objp->cmg_paths));
		}
		for (i = 0; i < objp->cmg_num_paths; i++) {
			if (!xdr_string(xdrs, &objp->cmg_paths[i], PATH_MAX))
				return (FALSE);
		}
	}
	return (TRUE);
}

FILE *
ct_metadata_create(const char *filename, int intype, const char *basis, int lvl,
    char *cwd, char **filelist)
{
	char			**fptr;
	FILE			*f;
	struct ct_md_gheader	gh;

	/* always save to the current version */
	ct_xdr_version = CT_MD_VERSION;

	if (lvl != 0 && basis == NULL)
		CFATALX("multilevel archive with no basis");

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
	gh.cmg_prevlvl_filename = basis ? (char *)basis : "";
	gh.cmg_cur_lvl = lvl;
	gh.cmg_cwd = cwd;

	fptr = filelist;
	while((*fptr++) != NULL)
		gh.cmg_num_paths++;
	gh.cmg_paths = filelist;


	md_dir = XDR_ENCODE;
	/* write global header */
	xdrstdio_create(&xdr, f, XDR_ENCODE);
	if (ct_xdr_gheader(&xdr, &gh, 1) == FALSE)
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

int64_t ct_dirnum = -1;
void ct_alloc_dirnum(struct dnode *, struct dnode *);

void
ct_alloc_dirnum(struct dnode *dnode, struct dnode *parentdir)
{
	struct fnode	*fnode_dir;

	if (dnode->d_num != -1)
		return;

	/* flag as allocate dirnum */
	dnode->d_num = -2;

	if (parentdir && parentdir->d_num == -1) {
		ct_alloc_dirnum(parentdir, parentdir->d_parent);
	}

	/*
	 * lazy directory header writing
	 */
	fnode_dir = ct_populate_fnode_from_flist(dnode->d_flnode);
	CDBG("alloc_dirnum dir %"PRId64" %s", dnode->d_num,
	    fnode_dir->fl_sname);
	ct_write_header(fnode_dir, fnode_dir->fl_sname, 1);
	ct_free_fnode(fnode_dir);
}

int
ct_write_header(struct fnode *fnode, char *filename, int base)
{
	struct ct_md_header	hdr;


	CDBG("writing file header %s %s", fnode->fl_sname,
	    filename);

	bzero(&hdr, sizeof hdr);

	if (C_ISDIR(fnode->fl_type)) {
		if (fnode->fl_curdir_dir->d_parent == NULL)
			fnode->fl_curdir_dir->d_parent = fnode->fl_parent_dir;

		if (fnode->fl_curdir_dir->d_num == -2) {
			fnode->fl_curdir_dir->d_num = ++ct_dirnum;
			CDBG("tagging dir %s as %" PRId64,
			    fnode->fl_curdir_dir->d_name,
			    fnode->fl_curdir_dir->d_num);

		} else if (fnode->fl_curdir_dir->d_num == -1) {
			if (fnode->fl_skip_file == 0) {
				/* timestamp newer, back up this node */

				/* alloc_dirnum will write the node */
				ct_alloc_dirnum(fnode->fl_curdir_dir,
				    fnode->fl_parent_dir);
			} else {
				CDBG("skipping dir %s", filename);
				/* do not write 'unused' dirs */
			}
			return 0;
		}
		CDBG("WRITING %s tag %" PRId64,
		    fnode->fl_curdir_dir->d_name,
		    fnode->fl_curdir_dir->d_num);
	} else if (fnode->fl_skip_file)
		hdr.cmh_nr_shas = -1LL;
	else if (C_ISREG(fnode->fl_type)) {
		hdr.cmh_nr_shas = fnode->fl_size / ct_max_block_size;
		if (fnode->fl_size % ct_max_block_size)
			hdr.cmh_nr_shas++;
	}

	if (fnode->fl_parent_dir) {
		if (fnode->fl_parent_dir->d_num == -1) {
			ct_alloc_dirnum(fnode->fl_parent_dir,
			    fnode->fl_parent_dir->d_parent);
		}
		hdr.cmh_parent_dir = fnode->fl_parent_dir->d_num;
	} else
		hdr.cmh_parent_dir = -1;
	hdr.cmh_beacon = CT_HDR_BEACON;
	hdr.cmh_uid = fnode->fl_uid;
	hdr.cmh_gid = fnode->fl_gid;
	hdr.cmh_mode = fnode->fl_mode;
	hdr.cmh_rdev = fnode->fl_rdev;
	hdr.cmh_atime = fnode->fl_atime;
	hdr.cmh_mtime = fnode->fl_mtime;
	if (base)
		hdr.cmh_filename = basename(filename);
	else
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
	struct fnode *fnode;
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

void
ct_list_op(struct ct_op *op)
{
	struct ct_trans		*trans;

	ct_list(op->op_local_fname, op->op_filelist, op->op_excludelist,
	    op->op_matchmode);
	trans = ct_trans_alloc();
	if (trans == NULL) {
		/* system busy, return (should never happen) */
		CDBG("ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}
	trans->tr_state = TR_S_DONE;
	trans->tr_trans_id = ct_trans_id++;
	ct_queue_transfer(trans);
	ct_set_file_state(CT_S_FINISHED);
}

int
ct_list(const char *file, char **flist, char **excludelist, int match_mode)
{
	struct ct_xdr_state	xs_ctx;
	struct fnode		fnodestore;
	uint64_t		reduction;
	struct fnode		*fnode = &fnodestore;
	struct ct_match		*match, *ex_match = NULL;
	char			*ct_next_filename, *ct_filename_free = NULL;
	char			*sign;
	int			state;
	int			doprint = 0;
	int			ret;
	int			i;
	char			shat[SHA_DIGEST_STRING_LENGTH];

	match = ct_match_compile(match_mode, flist);
	if (excludelist != NULL)
		ex_match = ct_match_compile(match_mode, excludelist);

	ct_verbose++;	/* by default print something. */

next_file:
	ct_next_filename = NULL;

	ret = ct_xdr_parse_init(&xs_ctx, file);
	if (ret)
		CFATALX("failed to open %s", file);

	if (ct_filename_free) {
		free(ct_filename_free);
		ct_filename_free = NULL;
	}

	if (xs_ctx.xs_gh.cmg_prevlvl_filename) {
		if (xs_ctx.xs_gh.cmg_prevlvl_filename[0] != '\0') {
			CDBG("previous backup file %s\n",
			    xs_ctx.xs_gh.cmg_prevlvl_filename);
			ct_next_filename = xs_ctx.xs_gh.cmg_prevlvl_filename;
			ct_filename_free = ct_next_filename;
		} else {
			free(xs_ctx.xs_gh.cmg_prevlvl_filename);
			xs_ctx.xs_gh.cmg_prevlvl_filename = NULL;
		}
	}
	if (xs_ctx.xs_gh.cmg_paths != NULL) {
		for (i = 0; i < xs_ctx.xs_gh.cmg_num_paths; i++)
			free(xs_ctx.xs_gh.cmg_paths[i]);

		e_free(&xs_ctx.xs_gh.cmg_paths);
	}
	bzero(&fnodestore, sizeof(fnodestore));

	do {
		ret = ct_xdr_parse(&xs_ctx);
		switch (ret) {
		case XS_RET_FILE:
			ct_populate_fnode(fnode, &xs_ctx.xs_hdr,
			    &xs_ctx.xs_lnkhdr, &state);
			doprint = !ct_match(match, fnode->fl_sname);
			if (doprint && ex_match != NULL &&
			    !ct_match(ex_match, fnode->fl_sname))
				doprint = 0;
			if (doprint) {
				ct_pr_fmt_file(fnode);
				if (!C_ISREG(xs_ctx.xs_hdr.cmh_type) ||
				    ct_verbose > 2)
					printf("\n");
			}
			if (fnode->fl_hlname)
				e_free(&fnode->fl_hlname);
			if (fnode->fl_sname)
				e_free(&fnode->fl_sname);
			break;
		case XS_RET_FILE_END:
			sign = " ";
			if (xs_ctx.xs_trl.cmt_comp_size == 0)
				reduction = 100;
			else {
				uint64_t orig, comp;
				orig = xs_ctx.xs_trl.cmt_orig_size;
				comp = xs_ctx.xs_trl.cmt_comp_size;

				if (comp <= orig) {
					reduction = 100 * (orig - comp) / orig;
				} else  {
					reduction = 100 * (comp - orig) / orig;
					if (reduction != 0)
						sign = "-";
				}
			
			}
			if (doprint && ct_verbose > 1)
				printf(" sz: %" PRIu64 " shas: %" PRIu64
				    " reduction: %s%" PRIu64 "%%\n",
				    xs_ctx.xs_trl.cmt_orig_size,
				    xs_ctx.xs_hdr.cmh_nr_shas,
				    sign, reduction);
			else if (doprint)
				printf("\n");
			break;
		case XS_RET_SHA:
			if (!(doprint && ct_verbose > 2)) {
				if (ct_xdr_parse_seek(&xs_ctx)) {
					CFATALX("seek failed");
				}
			} else {
				ct_sha1_encode(xs_ctx.xs_sha, shat);
				printf(" sha %s\n", shat);
			}
			break;
		case XS_RET_EOF:
			break;
		case XS_RET_FAIL:
			;
		}

	} while (ret != XS_RET_EOF && ret != XS_RET_FAIL);

	if (ret != XS_RET_EOF) {
		CWARNX("end of archive not hit");
	} else {
		if (ct_next_filename) {
			file = ct_next_filename;
			goto next_file;
		}
	}
	ct_unload_config();
	ct_match_unwind(match);
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

	if (ct_xdr_gheader(&xdr, gh, 0) == FALSE)
		CFATALX("e_xdr_gheader failed");

	ltime = gh->cmg_created;
	if (ct_verbose > 1)
		printf("version: %d level: %d block size: %d created: %s",
		    gh->cmg_version, gh->cmg_cur_lvl, gh->cmg_chunk_size,
		    ctime(&ltime));

	if (gh->cmg_beacon != CT_MD_BEACON)
		CFATALX("Not a cyphertite file");
	if (gh->cmg_version > CT_MD_VERSION) {
		CFATALX("Invalid version %d, expected %d", gh->cmg_version,
		    CT_MD_VERSION);
	}

	ct_max_block_size = gh->cmg_chunk_size;
	ct_encrypt_enabled = (gh->cmg_flags & CT_MD_CRYPTO);
	ct_multilevel_allfiles = (gh->cmg_flags & CT_MD_MLB_ALLFILES);
	ct_xdr_version = gh->cmg_version;

	return (f);
}

int
ct_read_header(struct ct_md_header *hdr)
{
	bzero(hdr, sizeof *hdr);

	if (ct_xdr_header(&xdr, hdr) == FALSE)
		return 1;

	CDBG("header beacon 0x%08x 0x%08x shas %" PRIu64 " name %s",
	    hdr->cmh_beacon, CT_HDR_BEACON, hdr->cmh_nr_shas,
	    hdr->cmh_filename);

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

struct ct_extract_stack   {
	TAILQ_ENTRY(ct_extract_stack)	next;
	char		*filename;
};
TAILQ_HEAD(, ct_extract_stack) ct_file_extract_head =
    TAILQ_HEAD_INITIALIZER(ct_file_extract_head);

void
ct_extract_setup(struct ct_xdr_state *ctx, const char *file)
{
	struct ct_extract_stack	*nfile;
	char			*prevlvl;

	if (ct_xdr_parse_init(ctx, file))
		CFATALX("extract failure: unable to open metadata file '%s'\n",
		    file);

	ct_encrypt_enabled = (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO);
	ct_multilevel_allfiles = (ctx->xs_gh.cmg_flags &
	    CT_MD_MLB_ALLFILES);

	if (ctx->xs_gh.cmg_prevlvl_filename) {
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);
		TAILQ_INSERT_HEAD(&ct_file_extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);

		ct_xdr_parse_close(ctx);
		ct_extract_setup_queue(ctx, prevlvl);

		e_free(&prevlvl);

		if (ct_multilevel_allfiles) {
			ct_xdr_parse_close(ctx);
			/* reopen first file */
			ct_extract_open_next(ctx);
		} 
	}

	ct_set_file_state(CT_S_WAITING_TRANS);
}

void
ct_extract_setup_queue(struct ct_xdr_state *ctx, const char *file)
{
	char			*prevlvl;
	struct ct_extract_stack	*nfile;

	if (ct_xdr_parse_init(ctx, file))
		CFATALX("extract failure: unable to open differential archive"
		    "'%s'\n", file);

	ct_encrypt_enabled = (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO);

	if (ctx->xs_gh.cmg_prevlvl_filename) {
		printf("next [%s]\n", ctx->xs_gh.cmg_prevlvl_filename);
		/* need to nest another level deep.*/
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);

		if (ct_multilevel_allfiles)
			TAILQ_INSERT_TAIL(&ct_file_extract_head, nfile, next);
		else
			TAILQ_INSERT_HEAD(&ct_file_extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);
		ct_xdr_parse_close(ctx);

		ct_extract_setup_queue(ctx, prevlvl);
		e_free(&prevlvl);

	} else {
		if (ct_multilevel_allfiles) {
			nfile = e_malloc(sizeof(*nfile));
			nfile->filename = e_strdup(file);
			TAILQ_INSERT_TAIL(&ct_file_extract_head, nfile, next);
		}
	}
}

void
ct_extract_open_next(struct ct_xdr_state *ctx)
{
	struct ct_extract_stack *next;

	if (!TAILQ_EMPTY(&ct_file_extract_head)) {
		next = TAILQ_FIRST(&ct_file_extract_head);
		CDBG("should start restoring [%s]", next->filename);
		TAILQ_REMOVE(&ct_file_extract_head, next, next);

		if (ct_xdr_parse_init(ctx, next->filename))
			CFATALX("failed to open %s", next->filename);
		ct_encrypt_enabled = (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO);

		if (next->filename)
			e_free(&next->filename);
		if (next)
			e_free(&next);

	} else {
		CFATALX("open next with no next archive");
	}
}

struct ct_extract_priv {
	struct ct_match	*inc_match;
	struct ct_match	*ex_match;
};

void
ct_extract(struct ct_op *op)
{
	const char		*mfile = op->op_local_fname;
	char			**filelist = op->op_filelist;
	int			 match_mode = op->op_matchmode;
	struct fnode		*fnode;
	struct ct_extract_priv	*ex_priv = op->op_priv;
	int			ret;
	struct ct_trans		*trans;
	char			shat[SHA_DIGEST_STRING_LENGTH];

	CDBG("entry");
	if (ct_state->ct_file_state == CT_S_STARTING) {
		if (ex_priv == NULL) {
			ex_priv = e_calloc(1, sizeof(*ex_priv));
			ex_priv->inc_match = ct_match_compile(match_mode,
			    filelist);
			if (op->op_excludelist != NULL)
				ex_priv->ex_match = ct_match_compile(match_mode,
				    op->op_excludelist);
			op->op_priv = ex_priv;
		}
		ct_extract_setup(&ct_xdr_ctx, mfile);
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
		/* Correct unless new file or EOF. Will fix in those cases  */
		trans->tr_fl_node = fl_ex_node;

		switch ((ret = ct_xdr_parse(&ct_xdr_ctx))) {
		case XS_RET_FILE:
			/* won't hit this until we start using allfiles */
			if (ct_xdr_ctx.xs_hdr.cmh_nr_shas == -1) {
				CINFO("mark file %s as restore from "
				    "previous backup",
				    ct_xdr_ctx.xs_hdr.cmh_filename);
				ct_doextract = 0;
				goto skip; /* skip ze file for now */
			}
			trans->tr_fl_node = fl_ex_node = fnode =
			    e_calloc(1, sizeof(*fnode));

			ct_populate_fnode(fnode, &ct_xdr_ctx.xs_hdr,
			    &ct_xdr_ctx.xs_lnkhdr, &trans->tr_state);

			ct_doextract = !ct_match(ex_priv->inc_match,
			    fnode->fl_sname);
			if (ct_doextract && ex_priv->ex_match != NULL &&
			    !ct_match(ex_priv->ex_match, fnode->fl_sname))
				ct_doextract = 0;
			if (ct_doextract == 0) {
				ct_free_fnode(fnode);
skip:
				fnode = NULL;
				ct_trans_free(trans);
				continue;
			}

			CDBG("file %s numshas %" PRId64, fnode->fl_sname,
			    ct_xdr_ctx.xs_hdr.cmh_nr_shas);

			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_SHA:
			if (ct_doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				if (ct_xdr_parse_seek(&ct_xdr_ctx))
					CFATALX("can't seek past shas");
				ct_trans_free(trans);
				continue;
			}
			if (ct_xdr_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO) {
				/*
				 * yes csha and sha are reversed, we want
				 * to download csha, but putting it in sha
				 * simplifies the code
				 */
				bcopy(ct_xdr_ctx.xs_sha, trans->tr_csha,
				    sizeof(trans->tr_csha));
				bcopy(ct_xdr_ctx.xs_csha, trans->tr_sha,
				    sizeof(trans->tr_sha));
				bcopy(ct_xdr_ctx.xs_iv, trans->tr_iv,
				    sizeof(trans->tr_iv));
			} else {
				bcopy(ct_xdr_ctx.xs_sha, trans->tr_sha,
				    sizeof(trans->tr_sha));
			}
			if (ct_verbose) {
				ct_sha1_encode(trans->tr_sha, shat);
				CDBG("extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_dataslot = 0;
			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_FILE_END:
			if (ct_doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				ct_trans_free(trans);
				continue;
			}
			bcopy(ct_xdr_ctx.xs_trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_fl_node->fl_size =
			    ct_xdr_ctx.xs_trl.cmt_orig_size;
			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_EOF:
			CDBG("Hit end of md");
			ct_xdr_parse_close(&ct_xdr_ctx);
			if (!TAILQ_EMPTY(&ct_file_extract_head)) {
				ct_trans_free(trans);
				/* reinits ct_xdr_ctx */
				ct_extract_open_next(&ct_xdr_ctx);

				/* poke file into action */
				ct_wakeup_file();
			} else {
				ct_match_unwind(ex_priv->inc_match);
				if (ex_priv->ex_match)
					ct_match_unwind(
					    ex_priv->ex_match);
				e_free(&ex_priv);
				op->op_priv = NULL;
				trans->tr_state = TR_S_DONE;
				trans->tr_trans_id = ct_trans_id++;
				ct_queue_transfer(trans);
				CDBG("extract finished");
				ct_set_file_state(CT_S_FINISHED);
			}
			return;
			break;
		case XS_RET_FAIL:
			CFATALX("failed to parse metadata file");
			break;
		}
	}
}


int
ct_populate_fnode(struct fnode *fnode, struct ct_md_header *hdr,
    struct ct_md_header *hdrlnk, int *state)
{
	static int64_t		ct_ex_dirnum = 0;
	struct flist		flistnode;
	struct dnode		*dnode;

	if (C_ISLINK(hdr->cmh_type)) {
		/* hardlink/symlink */
		fnode->fl_hlname = e_strdup(hdrlnk->cmh_filename);
		fnode->fl_hardlink = !C_ISLINK(hdrlnk->cmh_type);
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

	if (hdr->cmh_parent_dir != -1) {
		flistnode.fl_fname = hdr->cmh_filename;

		flistnode.fl_parent_dir = gen_finddir(hdr->cmh_parent_dir);
		CDBG("parent_dir %p %" PRId64, flistnode.fl_parent_dir,
		    hdr->cmh_parent_dir);

		fnode->fl_sname = gen_fname(&flistnode);
	} else
		fnode->fl_sname = e_strdup(hdr->cmh_filename);
	CDBG("name %s from %s %" PRId64, fnode->fl_sname, hdr->cmh_filename,
	    hdr->cmh_parent_dir);

	if (C_ISDIR(hdr->cmh_type)) {
		dnode = e_calloc(1,sizeof (*dnode));
		dnode->d_name = e_strdup(fnode->fl_sname);
		dnode->d_num = ct_ex_dirnum++;
		RB_INSERT(d_num_tree, &ct_dnum_head, dnode);
		CDBG("inserting %s as %" PRId64, dnode->d_name, dnode->d_num );
	}


	return 0;
}

int
ct_basis_setup(const char *basisbackup, char **filelist)
{
	struct ct_xdr_state	 xs_ctx;
	char			 cwd[PATH_MAX], **fptr;
	int			 alldata, nextlvl, i, rooted = 1, ret;

	alldata = ct_multilevel_allfiles;
	if (ct_xdr_parse_init(&xs_ctx, basisbackup))
		CFATALX("unable to open/parse previous backup %s",
		    basisbackup);
	ct_multilevel_allfiles = alldata; /* dont whack this flag from client */

	if (ct_max_differentials == 0 ||
	    xs_ctx.xs_gh.cmg_cur_lvl < ct_max_differentials) {
		ct_prev_backup_time = xs_ctx.xs_gh.cmg_created;
		CINFO("prev backup time %s %s", ctime(&ct_prev_backup_time),
		    basisbackup);
		nextlvl = ++xs_ctx.xs_gh.cmg_cur_lvl;
	} else {
		nextlvl = 0;
	}

	/*
	 * if we have the list of dirs in this previous backup, check that
	 * our cwd matches and the list of dirs we care about are a strict
	 * superset of the previous backup
	 */
	if (xs_ctx.xs_gh.cmg_version >= CT_MD_V2) {
		if (getcwd(cwd, sizeof(cwd)) == NULL)
			CFATAL("can't get current working directory");

		for (i = 0, fptr = filelist; *fptr != NULL &&
		    i < xs_ctx.xs_gh.cmg_num_paths; fptr++, i++) {
			if (strcmp(xs_ctx.xs_gh.cmg_paths[i], *fptr) != 0)
				break;
			if (xs_ctx.xs_gh.cmg_paths[i][0] != '/')
				rooted = 0;
		}
		if (i < xs_ctx.xs_gh.cmg_num_paths || *fptr != NULL) {
			if (ct_verbose == 0) {
				CFATALX("list of directories provided does not"
				    " match list of directories in basis");
			} else {
				CWARNX("list of directories provided does not"
				    " match list of directories in basis:");
				for (i = 0; i < xs_ctx.xs_gh.cmg_num_paths; i++)
					CWARNX("%s", xs_ctx.xs_gh.cmg_paths[i]);
				exit(1);
			}

		}

		if (rooted == 0 && strcmp(cwd, xs_ctx.xs_gh.cmg_cwd) != 0)
			CFATALX("current working directory %s differs from "
			    " basis %s", cwd, xs_ctx.xs_gh.cmg_cwd);
		/* done with the paths now, don't leak them */
		e_free(&xs_ctx.xs_gh.cmg_paths);
	}

	while ((ret = ct_xdr_parse(&xs_ctx)) != XS_RET_EOF) {
		if (ret == XS_RET_SHA)  {
			if (ct_xdr_parse_seek(&xs_ctx))
				CFATALX("seek failed");
		} else if (ret == XS_RET_FAIL) {
			CFATALX("basis corrupt: EOF not found");
		}

	}
	ct_xdr_parse_close(&xs_ctx);

	return (nextlvl);
}

char *
ct_metadata_check_prev(const char *mdname)
{
	FILE			*md_file;
	struct ct_md_gheader	 gh;
	char			 *ret = NULL;

	if ((md_file = ct_metadata_open(mdname, &gh)) != NULL) {
		if (gh.cmg_prevlvl_filename)
			ret = e_strdup(gh.cmg_prevlvl_filename);
		if (gh.cmg_paths != NULL)
			e_free(&gh.cmg_paths);

		ct_metadata_close(md_file);
	}

	return ret;
}

int
ct_xdr_parse_init(struct ct_xdr_state *ctx, const char *file)
{
	ctx->xs_f = ct_metadata_open(file,  &ctx->xs_gh);
	if (ctx->xs_f == NULL)
		return 2;

	if (ctx->xs_gh.cmg_prevlvl_filename &&
	    ctx->xs_gh.cmg_prevlvl_filename[0] == '\0') {
		free(ctx->xs_gh.cmg_prevlvl_filename);
		ctx->xs_gh.cmg_prevlvl_filename = NULL;
	}

	ctx->xs_sha_sz = 0;
	ctx->xs_state = XS_STATE_FILE;
	return 0;
}

int
ct_xdr_parse(struct ct_xdr_state *ctx)
{
	off_t			pos0, pos1;
	int			ret;
	int			rv = XS_STATE_FAIL;

	pos0 = pos1 = 0;

	switch (ctx->xs_state) {
	case XS_STATE_FILE:
		/* actually between files, next expected object is hdr */
		ret = ct_read_header(&ctx->xs_hdr);
		if (ret)
			goto fail;

		if (ctx->xs_hdr.cmh_beacon == CT_HDR_EOF) {
			ctx->xs_state = XS_STATE_EOF;
			rv = XS_RET_EOF;
			break;
		}

		if (C_ISLINK(ctx->xs_hdr.cmh_type)) {
			ret = ct_read_header(&ctx->xs_lnkhdr);
			if (ret)
				goto fail;
		}
		if (C_ISREG(ctx->xs_hdr.cmh_type)) {
			ctx->xs_sha_cnt = ctx->xs_hdr.cmh_nr_shas;
			ctx->xs_state = XS_STATE_SHA;
		} else
			ctx->xs_state = XS_STATE_FILE;
		rv = XS_RET_FILE;
		break;
	case XS_STATE_SHA:
		/*
		 * in the middle of a file, expecting shas or trailer based
		 * based on sha cnt.
		 */
		 if (ctx->xs_sha_cnt > 0) {
			ctx->xs_sha_cnt--;
			/* XXX gh check? */
			if (ctx->xs_sha_sz == 0)
				pos0 = ftello(ctx->xs_f);

			if (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO) {
				ret = ct_xdr_dedup_sha_crypto(
				    &xdr, ctx->xs_sha, ctx->xs_csha,
				    ctx->xs_iv);
			} else {
				ret = ct_xdr_dedup_sha(&xdr,
				    ctx->xs_sha);
			}
			if (ret == FALSE)
				goto fail;

			if (ctx->xs_sha_sz == 0) {
				pos1 = ftello(ctx->xs_f);
				ctx->xs_sha_sz = pos1 - pos0;
			}

			/*
			 * this stays in SHA state even if
			 * xs_sha_cnt == 0 so that it will read the trailer
			 */
			rv = XS_RET_SHA;
		 } else {
			ret = ct_read_trailer(&ctx->xs_trl);
			if (ret)
				goto fail;

			ctx->xs_state = XS_STATE_FILE;
			rv = XS_RET_FILE_END;
		 }

		break;
	case XS_STATE_EOF:
		/*
		 * fall thru to fail here, reading again after end of file
		 * is not allowed
		 */
	case XS_STATE_FAIL:
		goto fail;

	}

	return rv;
fail:
	ctx->xs_state = XS_STATE_FAIL;
	return XS_RET_FAIL;
}

/*
 * If in SHA state, it is valid to tell the reader to seek to the end
 * of the shas and read the file trailer
 */
int
ct_xdr_parse_seek(struct ct_xdr_state *ctx)
{
	off_t	pos0, pos1;

	if (ctx->xs_state != XS_STATE_SHA)
		return 1;
	if (ctx->xs_sha_cnt <= 0)
		return 0;

	if (ctx->xs_sha_sz == 0) {
		pos0 = ftello(ctx->xs_f);
		if (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO) {
			if (ct_xdr_dedup_sha_crypto(&xdr, ctx->xs_sha,
			    ctx->xs_csha, ctx->xs_iv) == FALSE) {
				CFATALX("file corrupt: can't get sha");
				ctx->xs_state = XS_STATE_FAIL;
				return 1;
			}
		} else if (ct_xdr_dedup_sha(&xdr, ctx->xs_sha) == FALSE) {
			ctx->xs_state = XS_STATE_FAIL;
			return 1;
		}

		pos1 = ftello(ctx->xs_f);
		ctx->xs_sha_sz = pos1 - pos0;
		ctx->xs_sha_cnt--;
	}
	if (fseek(ctx->xs_f, ctx->xs_sha_sz * ctx->xs_sha_cnt, SEEK_CUR) != 0) {
		ctx->xs_state = XS_STATE_FAIL;
		return 1;
	}
	ctx->xs_sha_cnt = 0;

	return 0;
}

void
ct_xdr_parse_close(struct ct_xdr_state *ctx)
{
	if (ctx->xs_gh.cmg_prevlvl_filename)
		free(ctx->xs_gh.cmg_prevlvl_filename);
	if (ctx->xs_gh.cmg_paths != NULL)
		e_free(&ctx->xs_gh.cmg_paths);
	ct_metadata_close(ctx->xs_f);
}

int
ct_cull_add_shafile(const char *file)
{
	struct ct_xdr_state	xs_ctx;
	char			*ct_next_filename, *ct_filename_free = NULL;
	int			ret;
	int			i;

	CDBG("processing [%s]", file);

	/*
	 * XXX - should we keep a list of added files,
	 * since we do files based on the list and 'referenced' files?
	 * rather than operating on files multiple times?
	 * might be useful for marking files at 'do not delete'
	 * (depended on by other MD archives.
	 */

next_file:
	ct_next_filename = NULL;

	ret = ct_xdr_parse_init(&xs_ctx, file);
	CDBG("opening [%s]", file);
	if (ret)
		CFATALX("failed to open %s", file);

	if (ct_filename_free) {
		free(ct_filename_free);
		ct_filename_free = NULL;
	}

	if (xs_ctx.xs_gh.cmg_prevlvl_filename) {
		if (xs_ctx.xs_gh.cmg_prevlvl_filename[0] != '\0') {
			CDBG("previous backup file %s\n",
			    xs_ctx.xs_gh.cmg_prevlvl_filename);
			ct_next_filename = xs_ctx.xs_gh.cmg_prevlvl_filename;
			ct_filename_free = ct_next_filename;
		} else {
			free(xs_ctx.xs_gh.cmg_prevlvl_filename);
			xs_ctx.xs_gh.cmg_prevlvl_filename = NULL;
		}
	}
	if (xs_ctx.xs_gh.cmg_paths != NULL) {
		for (i = 0; i < xs_ctx.xs_gh.cmg_num_paths; i++)
			free(xs_ctx.xs_gh.cmg_paths[i]);

		e_free(&xs_ctx.xs_gh.cmg_paths);
	}

	do {
		ret = ct_xdr_parse(&xs_ctx);
		switch (ret) {
		case XS_RET_FILE:
			/* nothing to do, ct_populate_fnode2 is optional now */
			break;
		case XS_RET_FILE_END:
			/* nothing to do */
			break;
		case XS_RET_SHA:
			ct_cull_sha_insert(xs_ctx.xs_sha);
			break;
		case XS_RET_EOF:
			break;
		case XS_RET_FAIL:
			;
		}

	} while (ret != XS_RET_EOF && ret != XS_RET_FAIL);

	if (ret != XS_RET_EOF) {
		CWARNX("end of archive not hit");
	} else {
		if (ct_next_filename) {
			file = ct_next_filename;
			goto next_file;
		}
	}
	return (0);
}
