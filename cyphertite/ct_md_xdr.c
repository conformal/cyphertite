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
 */ #include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"

int	ct_populate_fnode(struct fnode *, struct ct_md_header *,
	    struct ct_md_header *, int *);

int64_t		ct_ex_dirnum = 0;
/*
 * Helper functions
 */
int
ct_populate_fnode(struct fnode *fnode, struct ct_md_header *hdr,
    struct ct_md_header *hdrlnk, int *state)
{
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

	if (hdr->cmh_parent_dir == -2) {
		/* rooted directory */
		flistnode.fl_fname = hdr->cmh_filename;
		e_asprintf(&fnode->fl_sname , "%s%s",
		    ct_strip_slash ? "" : "/", flistnode.fl_fname);
	} else if (hdr->cmh_parent_dir != -1) {
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

/*
 * MD content listing code.
 */
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
		CDBG("previous backup file %s\n",
		    xs_ctx.xs_gh.cmg_prevlvl_filename);
		ct_next_filename = xs_ctx.xs_gh.cmg_prevlvl_filename;
		ct_filename_free = ct_next_filename;
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

	ct_xdr_parse_close(&xs_ctx);

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

/*
 * Code for extract.
 */
void
ct_extract_setup(struct ct_extract_head *extract_head,
    struct ct_xdr_state *ctx, const char *file)
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
		TAILQ_INSERT_HEAD(extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);

		ct_xdr_parse_close(ctx);
		ct_extract_setup_queue(extract_head, ctx, prevlvl);

		e_free(&prevlvl);

		if (ct_multilevel_allfiles) {
			ct_xdr_parse_close(ctx);
			/* reopen first file */
			ct_extract_open_next(extract_head, ctx);
		} 
	}

	ct_set_file_state(CT_S_WAITING_TRANS);
}

void
ct_extract_setup_queue(struct ct_extract_head *extract_head,
    struct ct_xdr_state *ctx, const char *file)
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
			TAILQ_INSERT_TAIL(extract_head, nfile, next);
		else
			TAILQ_INSERT_HEAD(extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);
		ct_xdr_parse_close(ctx);

		ct_extract_setup_queue(extract_head, ctx, prevlvl);
		e_free(&prevlvl);

	} else {
		if (ct_multilevel_allfiles) {
			nfile = e_malloc(sizeof(*nfile));
			nfile->filename = e_strdup(file);
			TAILQ_INSERT_TAIL(extract_head, nfile, next);
		}
	}
}

void
ct_extract_open_next(struct ct_extract_head *extract_head,
    struct ct_xdr_state *ctx)
{
	struct ct_extract_stack *next;

	if (!TAILQ_EMPTY(extract_head)) {
		next = TAILQ_FIRST(extract_head);
		CDBG("should start restoring [%s]", next->filename);
		TAILQ_REMOVE(extract_head, next, next);

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
	struct ct_extract_head	 extract_head;
	struct ct_xdr_state	 xdr_ctx;
	struct ct_match		*inc_match;
	struct ct_match		*ex_match;
	struct fnode		*fl_ex_node;
	int			 doextract;
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
			TAILQ_INIT(&ex_priv->extract_head);

			ex_priv->inc_match = ct_match_compile(match_mode,
			    filelist);
			if (op->op_excludelist != NULL)
				ex_priv->ex_match = ct_match_compile(match_mode,
				    op->op_excludelist);
			op->op_priv = ex_priv;
		}
		ct_extract_setup(&ex_priv->extract_head,
		    &ex_priv->xdr_ctx, mfile);
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
		trans->tr_fl_node = ex_priv->fl_ex_node;

		switch ((ret = ct_xdr_parse(&ex_priv->xdr_ctx))) {
		case XS_RET_FILE:
			/* won't hit this until we start using allfiles */
			if (ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas == -1) {
				CINFO("mark file %s as restore from "
				    "previous backup",
				    ex_priv->xdr_ctx.xs_hdr.cmh_filename);
				ex_priv->doextract = 0;
				goto skip; /* skip ze file for now */
			}
			trans->tr_fl_node = ex_priv->fl_ex_node = fnode =
			    e_calloc(1, sizeof(*fnode));

			ct_populate_fnode(fnode, &ex_priv->xdr_ctx.xs_hdr,
			    &ex_priv->xdr_ctx.xs_lnkhdr, &trans->tr_state);

			ex_priv->doextract = !ct_match(ex_priv->inc_match,
			    fnode->fl_sname);
			if (ex_priv->doextract && ex_priv->ex_match != NULL &&
			    !ct_match(ex_priv->ex_match, fnode->fl_sname))
				ex_priv->doextract = 0;
			if (ex_priv->doextract == 0) {
				ct_free_fnode(fnode);
skip:
				fnode = NULL;
				ct_trans_free(trans);
				continue;
			}

			CDBG("file %s numshas %" PRId64, fnode->fl_sname,
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas);

			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_SHA:
			if (ex_priv->doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				if (ct_xdr_parse_seek(&ex_priv->xdr_ctx))
					CFATALX("can't seek past shas");
				ct_trans_free(trans);
				continue;
			}
			if (ex_priv->xdr_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO) {
				/*
				 * yes csha and sha are reversed, we want
				 * to download csha, but putting it in sha
				 * simplifies the code
				 */
				bcopy(ex_priv->xdr_ctx.xs_sha, trans->tr_csha,
				    sizeof(trans->tr_csha));
				bcopy(ex_priv->xdr_ctx.xs_csha, trans->tr_sha,
				    sizeof(trans->tr_sha));
				bcopy(ex_priv->xdr_ctx.xs_iv, trans->tr_iv,
				    sizeof(trans->tr_iv));
			} else {
				bcopy(ex_priv->xdr_ctx.xs_sha, trans->tr_sha,
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
			if (ex_priv->doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				ct_trans_free(trans);
				continue;
			}
			bcopy(ex_priv->xdr_ctx.xs_trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_fl_node->fl_size =
			    ex_priv->xdr_ctx.xs_trl.cmt_orig_size;
			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_EOF:
			CDBG("Hit end of md");
			ct_xdr_parse_close(&ex_priv->xdr_ctx);
			if (!TAILQ_EMPTY(&ex_priv->extract_head)) {
				ct_trans_free(trans);
				/* reinits ex_priv->xdr_ctx */
				ct_extract_open_next(&ex_priv->extract_head,
				    &ex_priv->xdr_ctx);

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

/*
 * Extract an individual file that has been passed into the op by op_priv.
 */
void
ct_extract_file(struct ct_op *op)
{
	struct ct_file_extract_priv	*ex_priv = op->op_priv;
	const char			*localfile = op->op_local_fname;
	struct ct_trans			*trans;
	int				 ret;
	char				 shat[SHA_DIGEST_STRING_LENGTH];

	CDBG("entry");
	if (ct_state->ct_file_state == CT_S_STARTING) {
		CDBG("starting");
		/* open file and seek to beginning of file */
		if (ct_xdr_parse_init_at(&ex_priv->xdr_ctx,
		    ex_priv->md_filename, ex_priv->md_offset) != 0)
			CFATALX("can't open metadata file %s",
			    ex_priv->md_filename);
		ct_encrypt_enabled =
		    (ex_priv->xdr_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO);
		ct_multilevel_allfiles = (ex_priv->xdr_ctx.xs_gh.cmg_flags &
		    CT_MD_MLB_ALLFILES);
	} else if (ct_state->ct_file_state == CT_S_FINISHED) {
		return;
	}

	ct_set_file_state(CT_S_RUNNING);
	while (1) {
		if ((trans = ct_trans_alloc()) == NULL) {
			CDBG("ran out of transactions, waiting");
			ct_set_file_state(CT_S_WAITING_TRANS);
			return;
		}
		/* unless start of file this is right */
		trans->tr_fl_node = ex_priv->fl_ex_node;
		trans->tr_trans_id = ct_trans_id++;

		if (ex_priv->done) {
			CDBG("Hit end of md");
			ct_xdr_parse_close(&ex_priv->xdr_ctx);
			trans->tr_state = TR_S_DONE;
			ct_queue_transfer(trans);
			CDBG("extract finished");
			ct_set_file_state(CT_S_FINISHED);
			return;
		}

		switch ((ret = ct_xdr_parse(&ex_priv->xdr_ctx))) {
		case XS_RET_FILE:
			CDBG("opening file");
			if (ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas == -1) 
				CFATALX("can't extract file with -1 shas");
			trans->tr_fl_node = ex_priv->fl_ex_node =
			    e_calloc(1, sizeof(*trans->tr_fl_node));

			/* Make it local directory, it won't be set up right. */
			ex_priv->xdr_ctx.xs_hdr.cmh_parent_dir = -1;
			ct_populate_fnode(trans->tr_fl_node,
			    &ex_priv->xdr_ctx.xs_hdr,
			    &ex_priv->xdr_ctx.xs_lnkhdr,
			    &trans->tr_state);

			/* XXX Check filename matches what we expect */
			e_free(&trans->tr_fl_node->fl_sname);
			trans->tr_fl_node->fl_sname = e_strdup(localfile);
			/* Set name pointer to something else passed in */

			CDBG("file %s numshas %" PRId64,
			    trans->tr_fl_node->fl_sname,
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas);
			break;
		case XS_RET_SHA:
			CDBG("sha!");
			if (ex_priv->xdr_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO) {
				/*
				 * yes csha and sha are reversed, we want
				 * to download csha, but putting it in sha
				 * simplifies the code
				 */
				bcopy(ex_priv->xdr_ctx.xs_sha, trans->tr_csha,
				    sizeof(trans->tr_csha));
				bcopy(ex_priv->xdr_ctx.xs_csha, trans->tr_sha,
				    sizeof(trans->tr_sha));
				bcopy(ex_priv->xdr_ctx.xs_iv, trans->tr_iv,
				    sizeof(trans->tr_iv));
			} else {
				bcopy(ex_priv->xdr_ctx.xs_sha, trans->tr_sha,
				    sizeof(trans->tr_sha));
			}
			if (ct_verbose) {
				ct_sha1_encode(trans->tr_sha, shat);
				CDBG("extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_dataslot = 0;
			break;
		case XS_RET_FILE_END:
			CDBG("file end!");
			bcopy(ex_priv->xdr_ctx.xs_trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_fl_node->fl_size =
			    ex_priv->xdr_ctx.xs_trl.cmt_orig_size;
			/* Done now, don't parse further. */
			ex_priv->done = 1;
			ct_queue_transfer(trans);
			return;
			break;
		case XS_RET_FAIL:
			CFATALX("failed to parse metadata file");
			break;
		default:
			CFATALX("%s: invalid state %d", __func__, ret);
		}
		ct_queue_transfer(trans);
	}
}

/*
 * Cull code.
 */
int
ct_cull_add_shafile(const char *file)
{
	struct ct_xdr_state	xs_ctx;
	char			*ct_next_filename, *ct_filename_free = NULL;
	int			ret;

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
		CDBG("previous backup file %s\n",
		    xs_ctx.xs_gh.cmg_prevlvl_filename);
		ct_next_filename = xs_ctx.xs_gh.cmg_prevlvl_filename;
		ct_filename_free = ct_next_filename;
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

	ct_xdr_parse_close(&xs_ctx);

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
