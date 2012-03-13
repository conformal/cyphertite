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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h> /* XXX portability */
#include <unistd.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"

int	ct_populate_fnode(struct ctfile_parse_state *, struct fnode *,
	    int *, int);

const uint8_t	 zerosha[SHA_DIGEST_LENGTH];

/*
 * MD content listing code.
 */
void
ct_list_op(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_args	*cea = op->op_args;
	struct ct_trans		*trans;

	ct_list(cea->cea_local_ctfile, cea->cea_filelist, cea->cea_excllist,
	    cea->cea_matchmode);
	/*
	 * Technicaly should be a local transaction.
	 * However, since this is just so that list can fit into the normal
	 * state machine for async operations and there should be none
	 * others allocated it doesn't really matter.
	 */
	trans = ct_trans_alloc();
	if (trans == NULL) {
		/* system busy, return (should never happen) */
		CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
		ct_set_file_state(state, CT_S_WAITING_TRANS);
		return;
	}
	trans->tr_state = TR_S_DONE;
	trans->tr_trans_id = ct_trans_id++;
	ct_queue_transfer(trans);
	ct_set_file_state(state, CT_S_FINISHED);
}

int
ct_list(const char *file, char **flist, char **excludelist, int match_mode)
{
	struct ctfile_parse_state	 xs_ctx;
	struct fnode			 fnodestore;
	uint64_t			 reduction;
	struct fnode			*fnode = &fnodestore;
	struct ct_match			*match, *ex_match = NULL;
	char				*ct_next_filename;
	char				*sign;
	int				 state;
	int				 doprint = 0;
	int				 ret;
	char				 shat[SHA_DIGEST_STRING_LENGTH];

	match = ct_match_compile(match_mode, flist);
	if (excludelist != NULL)
		ex_match = ct_match_compile(match_mode, excludelist);

	ct_verbose++;	/* by default print something. */

	ct_next_filename = NULL;
next_file:
	ret = ctfile_parse_init(&xs_ctx, file);
	if (ret)
		CFATALX("failed to open %s", file);

	if (ct_next_filename)
		e_free(&ct_next_filename);

	if (xs_ctx.xs_gh.cmg_prevlvl_filename) {
		CNDBG(CT_LOG_CTFILE, "previous backup file %s\n",
		    xs_ctx.xs_gh.cmg_prevlvl_filename);
		ct_next_filename = e_strdup(xs_ctx.xs_gh.cmg_prevlvl_filename);
	}
	bzero(&fnodestore, sizeof(fnodestore));

	do {
		ret = ctfile_parse(&xs_ctx);
		switch (ret) {
		case XS_RET_FILE:
			ct_populate_fnode(&xs_ctx, fnode, &state,
			    xs_ctx.xs_gh.cmg_flags & CT_MD_MLB_ALLFILES);
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
				if (ctfile_parse_seek(&xs_ctx)) {
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

	ctfile_parse_close(&xs_ctx);

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
static void	ct_extract_setup_queue(struct ct_extract_head *,
	    struct ctfile_parse_state *, const char *, int);

void
ct_extract_setup(struct ct_extract_head *extract_head,
    struct ctfile_parse_state *ctx, const char *file, int *is_allfiles)
{
	struct ct_extract_stack	*nfile;
	char			*prevlvl;

	if (ctfile_parse_init(ctx, file))
		CFATALX("extract failure: unable to open metadata file '%s'\n",
		    file);

	*is_allfiles = (ctx->xs_gh.cmg_flags & CT_MD_MLB_ALLFILES);

	if (ctx->xs_gh.cmg_prevlvl_filename) {
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);
		TAILQ_INSERT_HEAD(extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);

		ctfile_parse_close(ctx);
		ct_extract_setup_queue(extract_head, ctx, prevlvl,
		    *is_allfiles);

		e_free(&prevlvl);

		if (*is_allfiles) {
			ctfile_parse_close(ctx);
			/* reopen first file */
			ct_extract_open_next(extract_head, ctx);
		}
	}
}

static void
ct_extract_setup_queue(struct ct_extract_head *extract_head,
    struct ctfile_parse_state *ctx, const char *file, int is_allfiles)
{
	char			*prevlvl;
	struct ct_extract_stack	*nfile;

	if (ctfile_parse_init(ctx, file))
		CFATALX("extract failure: unable to open differential archive"
		    "'%s'\n", file);

	if (ctx->xs_gh.cmg_prevlvl_filename) {
		/* need to nest another level deep.*/
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);

		if (is_allfiles)
			TAILQ_INSERT_TAIL(extract_head, nfile, next);
		else
			TAILQ_INSERT_HEAD(extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);
		ctfile_parse_close(ctx);

		ct_extract_setup_queue(extract_head, ctx, prevlvl, is_allfiles);
		e_free(&prevlvl);

	} else if (is_allfiles) {
		/*
		 * Allfiles we work backwards down the chain, without it
		 * we work at the end and go backwards. Since this is the last
		 * entry we only need it for allfiles mode.
		 */
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);
		TAILQ_INSERT_TAIL(extract_head, nfile, next);
	}
}

void
ct_extract_open_next(struct ct_extract_head *extract_head, struct ctfile_parse_state *ctx)
{
	struct ct_extract_stack *next;

	if (!TAILQ_EMPTY(extract_head)) {
		next = TAILQ_FIRST(extract_head);
		CNDBG(CT_LOG_CTFILE,
		    "should start restoring [%s]", next->filename);
		TAILQ_REMOVE(extract_head, next, next);

		if (ctfile_parse_init(ctx, next->filename))
			CFATALX("failed to open %s", next->filename);

		if (next->filename)
			e_free(&next->filename);
		if (next)
			e_free(&next);
	} else {
		CFATALX("open next with no next archive");
	}
}

void
ct_extract_cleanup_queue(struct ct_extract_head *extract_head)
{
	struct ct_extract_stack *next;

	while ((next = TAILQ_FIRST(extract_head)) != NULL) {
		TAILQ_REMOVE(extract_head, next, next);
		e_free(&next->filename);
		e_free(&next);
	}
}

struct ct_extract_priv {
	struct ct_extract_head		 extract_head;
	struct ctfile_parse_state	 xdr_ctx;
	struct ct_match			*inc_match;
	struct ct_match			*ex_match;
	struct ct_match			*rb_match;
	struct fnode			*fl_ex_node;
	int				 doextract;
	int				 fillrb;
	int				 haverb;
	int				 allfiles;
};

void
ct_extract(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_args	*cea = op->op_args;
	const char		*ctfile = cea->cea_local_ctfile;
	char			**filelist = cea->cea_filelist;
	int			 match_mode = cea->cea_matchmode;
	struct fnode		*fnode;
	struct ct_extract_priv	*ex_priv = op->op_priv;
	int			ret;
	struct ct_trans		*trans;
	char			shat[SHA_DIGEST_STRING_LENGTH];

	CNDBG(CT_LOG_TRANS, "entry");
	switch (ct_get_file_state(state)) {
	case CT_S_STARTING:
		if (ex_priv == NULL) {
			ex_priv = e_calloc(1, sizeof(*ex_priv));
			TAILQ_INIT(&ex_priv->extract_head);

			ex_priv->inc_match = ct_match_compile(match_mode,
			    filelist);
			if (cea->cea_excllist != NULL)
				ex_priv->ex_match = ct_match_compile(match_mode,
				    cea->cea_excllist);
			op->op_priv = ex_priv;
		}
		ct_extract_setup(&ex_priv->extract_head,
		    &ex_priv->xdr_ctx, ctfile, &ex_priv->allfiles);
		ct_file_extract_setup_dir(cea->cea_tdir);
		/* create rb tree head, prepare to start inserting */
		if (ex_priv->allfiles) {
			char *nothing = NULL;
			ex_priv->rb_match =
			    ct_match_compile(CT_MATCH_RB, &nothing);
			ex_priv->fillrb = 1;
		}
		break;
	case CT_S_FINISHED:
		return;
	default:
		break;
	}

	ct_set_file_state(state, CT_S_RUNNING);
	while (1) {
		trans = ct_trans_alloc();
		if (trans == NULL) {
			/* system busy, return */
			CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
			ct_set_file_state(state, CT_S_WAITING_TRANS);
			return;
		}
		/* Correct unless new file or EOF. Will fix in those cases  */
		trans->tr_fl_node = ex_priv->fl_ex_node;

		switch ((ret = ctfile_parse(&ex_priv->xdr_ctx))) {
		case XS_RET_FILE:
			if (ex_priv->fillrb == 0 &&
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas == -1) {
				if (ex_priv->allfiles == 0)
					CINFO("file %s has negative shas "
					    "and backup is not allfiles",
					    ex_priv->xdr_ctx.xs_hdr.cmh_filename);
				ex_priv->doextract = 0;
				goto skip; /* skip ze file for now */
			}

			trans = ct_trans_realloc_local(trans);
			trans->tr_fl_node = ex_priv->fl_ex_node = fnode =
			    e_calloc(1, sizeof(*fnode));

			ct_populate_fnode(&ex_priv->xdr_ctx, fnode,
			    &trans->tr_state, ex_priv->allfiles);

			ex_priv->doextract = !ct_match(ex_priv->inc_match,
			    fnode->fl_sname);
			if (ex_priv->doextract && ex_priv->ex_match != NULL &&
			    !ct_match(ex_priv->ex_match, fnode->fl_sname))
				ex_priv->doextract = 0;
			/*
			 * If we're on the first ctfile in an allfiles backup
			 * put the matches with -1 on the rb tree so we'll
			 * remember to extract it from older files.
			 */
			if (ex_priv->doextract == 1 && ex_priv->fillrb &&
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas == -1) {
				ct_match_insert_rb(ex_priv->rb_match,
					    fnode->fl_sname);
				ex_priv->doextract = 0;
				goto skipfree;
			}
			if (ex_priv->doextract == 0) {
skipfree:
				ct_free_fnode(fnode);
skip:
				fnode = NULL;
				ct_trans_free(trans);
				continue;
			}

			CNDBG(CT_LOG_CTFILE,
			    "file %s numshas %" PRId64, fnode->fl_sname,
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas);

			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_SHA:
			if (ex_priv->doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				if (ctfile_parse_seek(&ex_priv->xdr_ctx))
					CFATALX("can't seek past shas");
				ct_trans_free(trans);
				continue;
			}

			if (memcmp(zerosha, ex_priv->xdr_ctx.xs_sha,
				SHA_DIGEST_LENGTH) == 0) {
				CWARNX("\"%s\" truncated during backup",
				    trans->tr_fl_node->fl_sname);
				if (ctfile_parse_seek(&ex_priv->xdr_ctx))
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
				CNDBG(CT_LOG_SHA, "extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_dataslot = 0;
			trans->tr_trans_id = ct_trans_id++;
			ct_queue_transfer(trans);
			break;
		case XS_RET_FILE_END:
			trans = ct_trans_realloc_local(trans);
			trans->tr_fl_node = ex_priv->fl_ex_node; /* reload */

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
			CNDBG(CT_LOG_CTFILE, "Hit end of ctfile");
			ctfile_parse_close(&ex_priv->xdr_ctx);
			/* if rb tree and rb is empty, goto end state */
			if ((ex_priv->haverb &&
			    ct_match_rb_is_empty(ex_priv->inc_match)) ||
			    (ex_priv->fillrb &&
			    ct_match_rb_is_empty(ex_priv->rb_match))) {
				/*
				 * Cleanup extract queue, in case we had files
				 * left.
				 */
				ct_extract_cleanup_queue(
				    &ex_priv->extract_head);
				goto we_re_done_here;
			}


			if (!TAILQ_EMPTY(&ex_priv->extract_head)) {
				/*
				 * if allfiles and this was the first pass.
				 * free the current match lists
				 * switch to rb tree mode
				 */
				if (ex_priv->fillrb) {
					ct_match_unwind(ex_priv->inc_match);
					if (ex_priv->ex_match)
						ct_match_unwind(
						    ex_priv->ex_match);
					ex_priv->ex_match = NULL;
					ex_priv->inc_match = ex_priv->rb_match;
					ex_priv->rb_match = NULL;
					ex_priv->haverb = 1;
					ex_priv->fillrb = 0;
				}
				ct_trans_free(trans);
				/* reinits ex_priv->xdr_ctx */
				ct_extract_open_next(&ex_priv->extract_head,
				    &ex_priv->xdr_ctx);

				/* poke file into action */
				ct_wakeup_file();
			} else {
				/*
				 * If rb tree and it is still has entries,
				 * bitch about it
				 */
				/* XXX print out missing files */
				if ((ex_priv->haverb || ex_priv->fillrb) &&
				    !ct_match_rb_is_empty(ex_priv->inc_match))
					CWARNX("out of ctfiles but some "
					    "files are not found");

we_re_done_here:
				ct_match_unwind(ex_priv->inc_match);
				if (ex_priv->ex_match)
					ct_match_unwind(
					    ex_priv->ex_match);
				e_free(&ex_priv);
				op->op_priv = NULL;
				trans->tr_state = TR_S_DONE;
				trans->tr_trans_id = ct_trans_id++;
				/*
				 * Technically this should be a local
				 * transaction. However, since we are done
				 * it doesn't really matter either way.
				 */
				ct_queue_transfer(trans);
				CNDBG(CT_LOG_TRANS, "extract finished");
				ct_set_file_state(state, CT_S_FINISHED);
			}
			return;
			break;
		case XS_RET_FAIL:
			CFATALX("failed to parse metadata file");
			break;
		}
	}
}

struct ct_file_extract_priv {
	struct ctfile_parse_state	 xdr_ctx;
	struct fnode			*fl_ex_node;
	int				 done;
};
/*
 * Extract an individual file that has been passed into the op by op_priv.
 */
void
ct_extract_file(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_file_args	*cefa = op->op_args;
	struct ct_file_extract_priv	*ex_priv = op->op_priv;
	const char			*localfile = cefa->cefa_filename;
	struct ct_trans			*trans;
	uint64_t			 ltrans_id;
	int				 ret;
	char				 shat[SHA_DIGEST_STRING_LENGTH];

	CNDBG(CT_LOG_TRANS, "entry");
	switch (ct_get_file_state(state)) {
	case CT_S_STARTING:
		CNDBG(CT_LOG_TRANS, "starting");
		ex_priv = e_calloc(1, sizeof(*ex_priv));
		/* open file and seek to beginning of file */
		if (ctfile_parse_init_at(&ex_priv->xdr_ctx,
		    cefa->cefa_ctfile, cefa->cefa_ctfile_off) != 0)
			CFATALX("can't open metadata file %s",
			    cefa->cefa_ctfile);
		ct_file_extract_setup_dir(NULL);
		break;
	case CT_S_FINISHED:
		return;
	default:
		break;
	}

	ct_set_file_state(state, CT_S_RUNNING);
	while (1) {
		if ((trans = ct_trans_alloc()) == NULL) {
			CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
			ct_set_file_state(state, CT_S_WAITING_TRANS);
			return;
		}
		/* unless start of file this is right */
		trans->tr_fl_node = ex_priv->fl_ex_node;
		trans->tr_trans_id = ltrans_id = ct_trans_id++;

		if (ex_priv->done) {
			CNDBG(CT_LOG_CTFILE, "Hit end of ctfile");
			ctfile_parse_close(&ex_priv->xdr_ctx);
			e_free(&ex_priv);
			trans->tr_state = TR_S_DONE;
			ct_queue_transfer(trans);
			CNDBG(CT_LOG_TRANS, "extract finished");
			ct_set_file_state(state, CT_S_FINISHED);
			e_free(&ex_priv);
			return;
		}

		switch ((ret = ctfile_parse(&ex_priv->xdr_ctx))) {
		case XS_RET_FILE:
			CNDBG(CT_LOG_CTFILE, "opening file");
			if (ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas == -1)
				CFATALX("can't extract file with -1 shas");

			trans = ct_trans_realloc_local(trans);
			trans->tr_trans_id = ltrans_id;
			trans->tr_fl_node = ex_priv->fl_ex_node =
			    e_calloc(1, sizeof(*trans->tr_fl_node));

			/* Make it local directory, it won't be set up right. */
			ex_priv->xdr_ctx.xs_hdr.cmh_parent_dir = -1;
			/* Allfiles doesn't matter, only processing one file. */
			ct_populate_fnode(&ex_priv->xdr_ctx, trans->tr_fl_node,
			    &trans->tr_state, 0);

			/* XXX Check filename matches what we expect */
			e_free(&trans->tr_fl_node->fl_sname);
			trans->tr_fl_node->fl_sname = e_strdup(localfile);
			/* Set name pointer to something else passed in */

			CNDBG(CT_LOG_CTFILE, "file %s numshas %" PRId64,
			    trans->tr_fl_node->fl_sname,
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas);
			break;
		case XS_RET_SHA:
			CNDBG(CT_LOG_SHA, "sha!");
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
				CNDBG(CT_LOG_SHA, "extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_dataslot = 0;
			break;
		case XS_RET_FILE_END:
			trans = ct_trans_realloc_local(trans);
			trans->tr_fl_node = ex_priv->fl_ex_node; /* reload */
			trans->tr_trans_id = ltrans_id;

			CNDBG(CT_LOG_CTFILE, "file end!");
			bcopy(ex_priv->xdr_ctx.xs_trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_fl_node->fl_size =
			    ex_priv->xdr_ctx.xs_trl.cmt_orig_size;
			/* Done now, don't parse further. */
			ex_priv->done = 1;
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

void
ct_extract_file_cleanup(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_file_args	*cefa = op->op_args;

	e_free(&cefa->cefa_filename);
	e_free(&cefa->cefa_ctfile);
	e_free(&cefa);
}

/*
 * Cull code.
 */
int
ct_cull_add_shafile(const char *file)
{
	struct ctfile_parse_state	xs_ctx;
	char				*ct_next_filename;
	char				*ct_filename_free = NULL;
	char				*cachename;
	int				ret;

	CNDBG(CT_LOG_TRANS, "processing [%s]", file);

	/*
	 * XXX - should we keep a list of added files,
	 * since we do files based on the list and 'referenced' files?
	 * rather than operating on files multiple times?
	 * might be useful for marking files at 'do not delete'
	 * (depended on by other MD archives.
	 */

next_file:
	ct_next_filename = NULL;

	/* filename may be absolute, or in cache dir */
	if (file[0] == '/') {
		cachename = e_strdup(file);
	} else {
		e_asprintf(&cachename, "%s%s", ctfile_cachedir, file);
	}

	ret = ctfile_parse_init(&xs_ctx, cachename);
	e_free(&cachename);
	CNDBG(CT_LOG_CTFILE, "opening [%s]", file);

	if (ret)
		CFATALX("failed to open %s", file);

	if (ct_filename_free) {
		e_free(&ct_filename_free);
	}

	if (xs_ctx.xs_gh.cmg_prevlvl_filename) {
		CNDBG(CT_LOG_CTFILE, "previous backup file %s\n",
		    xs_ctx.xs_gh.cmg_prevlvl_filename);
		ct_next_filename = e_strdup(xs_ctx.xs_gh.cmg_prevlvl_filename);
		ct_filename_free = ct_next_filename;
	}

	do {
		ret = ctfile_parse(&xs_ctx);
		switch (ret) {
		case XS_RET_FILE:
			/* nothing to do, ct_populate_fnode2 is optional now */
			break;
		case XS_RET_FILE_END:
			/* nothing to do */
			break;
		case XS_RET_SHA:
			if (xs_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO)
				ct_cull_sha_insert(xs_ctx.xs_csha);
			else
				ct_cull_sha_insert(xs_ctx.xs_sha);
			break;
		case XS_RET_EOF:
			break;
		case XS_RET_FAIL:
			;
		}

	} while (ret != XS_RET_EOF && ret != XS_RET_FAIL);

	ctfile_parse_close(&xs_ctx);

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
