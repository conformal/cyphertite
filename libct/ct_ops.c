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

#include <ct_ctfile.h>
#include <ct_match.h>
#include <ct_lib.h>

const uint8_t	 zerosha[SHA_DIGEST_LENGTH];

/*
 * Code for extract.
 */
static void	ct_extract_setup_queue(struct ct_extract_head *,
	    struct ctfile_parse_state *, const char *, const char *, int);

void
ct_extract_setup(struct ct_extract_head *extract_head,
    struct ctfile_parse_state *ctx, const char *file,
    const char *ctfile_basedir, int *is_allfiles)
{
	struct ct_extract_stack	*nfile;
	char			*prevlvl;

	if (ctfile_parse_init(ctx, file, ctfile_basedir))
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
		    ctfile_basedir, *is_allfiles);

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
    struct ctfile_parse_state *ctx, const char *file,
    const char *ctfile_basedir, int is_allfiles)
{
	char			*prevlvl;
	struct ct_extract_stack	*nfile;

	if (ctfile_parse_init(ctx, file, ctfile_basedir))
		CFATALX("extract failure: unable to open incremental archive"
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

		ct_extract_setup_queue(extract_head, ctx, prevlvl,
		    ctfile_basedir, is_allfiles);
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

		/* Basedir not needed here because we are done with prevlvl */
		if (ctfile_parse_init(ctx, next->filename, NULL))
			CFATALX("failed to open %s", next->filename);

		if (next->filename)
			e_free(&next->filename);
		if (next)
			e_free(&next);
	} else {
		CABORTX("open next with no next archive");
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

int
ct_extract_complete_special(struct ct_global_state *state,
    struct ct_trans *trans)
{
	ct_file_extract_special(state->extract_state,
	    trans->tr_fl_node);
	state->ct_print_file_start(state->ct_print_state,
	    trans->tr_fl_node);
	state->ct_print_file_end(state->ct_print_state,
	    trans->tr_fl_node, state->ct_max_block_size);
	ct_free_fnode(trans->tr_fl_node);
	trans->tr_fl_node = NULL;

	return (0);
}

int
ct_extract_complete_file_start(struct ct_global_state *state,
    struct ct_trans *trans)
{
	ct_sha1_setup(&trans->tr_fl_node->fl_shactx);
	if (ct_file_extract_open(state->extract_state,
	    trans->tr_fl_node) == 0) {
		state->ct_print_file_start(state->ct_print_state,
		    trans->tr_fl_node);
	} else {
		CWARN("unable to open file for writing %s",
		    trans->tr_fl_node->fl_sname);
		trans->tr_fl_node->fl_skip_file = 1;
	}

	return (0);
}

int
ct_extract_complete_file_read(struct ct_global_state *state,
    struct ct_trans *trans)
{
	int	slot, ret;

	state->ct_stats->st_chunks_completed++;
	if (trans->tr_fl_node->fl_skip_file == 0) {
		slot = trans->tr_dataslot;
		ct_sha1_add(trans->tr_data[slot],
		    &trans->tr_fl_node->fl_shactx,
		    trans->tr_size[slot]);
		if ((ret = ct_file_extract_write(state->extract_state,
		    trans->tr_fl_node, trans->tr_data[slot],
		    trans->tr_size[slot])) != 0)
			CFATALX("failed to write file: %s", ct_strerror(ret));
		state->ct_stats->st_bytes_written +=
		    trans->tr_size[slot];
	}

	return (0);
}

int
ct_extract_complete_file_end(struct ct_global_state *state,
    struct ct_trans *trans)
{
	if (trans->tr_fl_node->fl_skip_file == 0) {
		ct_sha1_final(trans->tr_csha,
		    &trans->tr_fl_node->fl_shactx);
		if (bcmp(trans->tr_csha, trans->tr_sha,
		    sizeof(trans->tr_sha)) != 0)
			CWARNX("extract sha mismatch on %s",
			    trans->tr_fl_node->fl_sname);
		ct_file_extract_close(state->extract_state,
		    trans->tr_fl_node);
	}
	ct_free_fnode(trans->tr_fl_node);
	trans->tr_fl_node = NULL;
	state->ct_stats->st_files_completed++;

	return (0);
}

int
ct_extract_complete_done(struct ct_global_state *state,
    struct ct_trans *trans)
{
	if (state->extract_state) {
		ct_file_extract_cleanup(state->extract_state);	
		state->extract_state = NULL;
	}
	return (1);
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

			if ((ret = ct_match_compile(&ex_priv->inc_match,
			    match_mode, filelist)) != 0)
				CFATALX("failed to compile include pattern: %s",
				    ct_strerror(ret));
			if (cea->cea_excllist != NULL &&
			    (ret = ct_match_compile(&ex_priv->ex_match,
			    match_mode, cea->cea_excllist)) != 0)
				CFATALX("failed to compile exclude pattern: %s",
				    ct_strerror(ret));
			op->op_priv = ex_priv;
		}
		ct_extract_setup(&ex_priv->extract_head,
		    &ex_priv->xdr_ctx, ctfile, cea->cea_ctfile_basedir,
		    &ex_priv->allfiles);
		state->ct_print_ctfile_info(state->ct_print_state,
		    ex_priv->xdr_ctx.xs_filename, &ex_priv->xdr_ctx.xs_gh);
		
		state->extract_state = ct_file_extract_init(cea->cea_tdir,
		    cea->cea_attr,  cea->cea_follow_symlinks,
		    ex_priv->allfiles, cea->cea_log_state,
		    cea->cea_log_chown_failed);
		/* XXX we should handle this better */
		if (state->ct_max_block_size <
		    ex_priv->xdr_ctx.xs_gh.cmg_chunk_size)
			CABORTX("block size negotiated with server %d is "
			    "smaller than file max block size %d",
			    state->ct_max_block_size,
			    ex_priv->xdr_ctx.xs_gh.cmg_chunk_size);
		/* create rb tree head, prepare to start inserting */
		if (ex_priv->allfiles) {
			char *nothing = NULL;
			if ((ret = ct_match_compile(&ex_priv->rb_match,
			    CT_MATCH_RB, &nothing)) != 0)
				CFATALX("couldn't create match tree: %s",
				    ct_strerror(ret));
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
		trans = ct_trans_alloc(state);
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

			trans = ct_trans_realloc_local(state, trans);
			trans->tr_fl_node = ex_priv->fl_ex_node = fnode =
			    e_calloc(1, sizeof(*fnode));

			ct_populate_fnode(state->extract_state,
			    &ex_priv->xdr_ctx, fnode, &trans->tr_state,
			    ex_priv->allfiles, cea->cea_strip_slash);
			if (trans->tr_state == TR_S_EX_SPECIAL) {
				trans->tr_complete =
				    ct_extract_complete_special;
			} else {
				trans->tr_complete =
				    ct_extract_complete_file_start;
			}

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
				ct_trans_free(state, trans);
				continue;
			}

			CNDBG(CT_LOG_CTFILE,
			    "file %s numshas %" PRId64, fnode->fl_sname,
			    ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas);

			ct_queue_first(state, trans);
			break;
		case XS_RET_SHA:
			if (ex_priv->doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				if (ctfile_parse_seek(&ex_priv->xdr_ctx))
					CFATALX("can't seek past shas");
				ct_trans_free(state, trans);
				continue;
			}

			if (memcmp(zerosha, ex_priv->xdr_ctx.xs_sha,
				SHA_DIGEST_LENGTH) == 0) {
				CWARNX("\"%s\" truncated during backup",
				    trans->tr_fl_node->fl_sname);
				if (ctfile_parse_seek(&ex_priv->xdr_ctx))
					CFATALX("can't seek past shas");
				ct_trans_free(state, trans);
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
			if (clog_mask_is_set(CT_LOG_SHA)) {
				ct_sha1_encode(trans->tr_sha, shat);
				CNDBG(CT_LOG_SHA, "extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_complete = ct_extract_complete_file_read;
			trans->tr_dataslot = 0;
			ct_queue_first(state, trans);
			break;
		case XS_RET_FILE_END:
			trans = ct_trans_realloc_local(state, trans);
			trans->tr_fl_node = ex_priv->fl_ex_node; /* reload */

			if (ex_priv->doextract == 0 ||
			    trans->tr_fl_node->fl_skip_file != 0) {
				ct_trans_free(state, trans);
				continue;
			}
			bcopy(ex_priv->xdr_ctx.xs_trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_complete = ct_extract_complete_file_end;
			trans->tr_fl_node->fl_size =
			    ex_priv->xdr_ctx.xs_trl.cmt_orig_size;
			ct_queue_first(state, trans);
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
				ct_trans_free(state, trans);
				/* reinits ex_priv->xdr_ctx */
				ct_extract_open_next(&ex_priv->extract_head,
				    &ex_priv->xdr_ctx);
				state->ct_print_ctfile_info(
				    state->ct_print_state,
				    ex_priv->xdr_ctx.xs_filename,
				    &ex_priv->xdr_ctx.xs_gh);

				/* poke file into action */
				ct_wakeup_file(state->event_state);
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
				trans->tr_complete = ct_extract_complete_done;
				/*
				 * Technically this should be a local
				 * transaction. However, since we are done
				 * it doesn't really matter either way.
				 */
				ct_queue_first(state, trans);
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
	int				 ret;
	char				 shat[SHA_DIGEST_STRING_LENGTH];

	CNDBG(CT_LOG_TRANS, "entry");
	switch (ct_get_file_state(state)) {
	case CT_S_STARTING:
		CNDBG(CT_LOG_TRANS, "starting");
		ex_priv = e_calloc(1, sizeof(*ex_priv));
		/* open file and seek to beginning of file */
		if (ctfile_parse_init_at(&ex_priv->xdr_ctx,
		    cefa->cefa_ctfile, NULL, cefa->cefa_ctfile_off) != 0)
			CFATALX("can't open metadata file %s",
			    cefa->cefa_ctfile);
		 /* XXX we should handle this better */
		if (state->ct_max_block_size <
		    ex_priv->xdr_ctx.xs_gh.cmg_chunk_size)
			CABORTX("block size negotiated with server %d is "
			    "smaller than file max block size %d",
			    state->ct_max_block_size,
			    ex_priv->xdr_ctx.xs_gh.cmg_chunk_size);
		state->extract_state = ct_file_extract_init(NULL,
		    0, 0, 0, NULL, NULL);
		op->op_priv = ex_priv;
		break;
	case CT_S_FINISHED:
		return;
	default:
		break;
	}

	ct_set_file_state(state, CT_S_RUNNING);
	while (1) {
		if ((trans = ct_trans_alloc(state)) == NULL) {
			CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
			ct_set_file_state(state, CT_S_WAITING_TRANS);
			return;
		}

		if (ex_priv->done) {
			CNDBG(CT_LOG_CTFILE, "Hit end of ctfile");
			ctfile_parse_close(&ex_priv->xdr_ctx);
			e_free(&ex_priv);
			trans->tr_state = TR_S_DONE;
			trans->tr_complete = ct_extract_complete_done;
			ct_queue_first(state, trans);
			CNDBG(CT_LOG_TRANS, "extract finished");
			ct_set_file_state(state, CT_S_FINISHED);
			return;
		}

		/* unless start of file this is right */
		trans->tr_fl_node = ex_priv->fl_ex_node;

		switch ((ret = ctfile_parse(&ex_priv->xdr_ctx))) {
		case XS_RET_FILE:
			CNDBG(CT_LOG_CTFILE, "opening file");
			if (ex_priv->xdr_ctx.xs_hdr.cmh_nr_shas == -1)
				CABORTX("can't extract file with -1 shas");

			trans = ct_trans_realloc_local(state, trans);
			trans->tr_fl_node = ex_priv->fl_ex_node =
			    e_calloc(1, sizeof(*trans->tr_fl_node));

			/* Make it local directory, it won't be set up right. */
			ex_priv->xdr_ctx.xs_hdr.cmh_parent_dir = -1;
			/*
			 * Allfiles doesn't matter, only processing one file.
			 * We have a full path to extract to so always strip
			 * slash.
			 */
			ct_populate_fnode(state->extract_state,
			    &ex_priv->xdr_ctx, trans->tr_fl_node,
			    &trans->tr_state, 0, 1);
			if (trans->tr_state == TR_S_EX_SPECIAL) {
				trans->tr_complete =
				    ct_extract_complete_special;
			} else {
				trans->tr_complete =
				    ct_extract_complete_file_start;
			}

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
			if (clog_mask_is_set(CT_LOG_SHA)) {
				ct_sha1_encode(trans->tr_sha, shat);
				CNDBG(CT_LOG_SHA, "extracting sha %s", shat);
			}
			trans->tr_state = TR_S_EX_SHA;
			trans->tr_complete = ct_extract_complete_file_read;
			trans->tr_dataslot = 0;
			break;
		case XS_RET_FILE_END:
			trans = ct_trans_realloc_local(state, trans);
			trans->tr_fl_node = ex_priv->fl_ex_node; /* reload */

			CNDBG(CT_LOG_CTFILE, "file end!");
			bcopy(ex_priv->xdr_ctx.xs_trl.cmt_sha, trans->tr_sha,
			    sizeof(trans->tr_sha));
			trans->tr_state = TR_S_EX_FILE_END;
			trans->tr_complete = ct_extract_complete_file_end;
			trans->tr_fl_node->fl_size =
			    ex_priv->xdr_ctx.xs_trl.cmt_orig_size;
			/* Done now, don't parse further. */
			ex_priv->done = 1;
			break;
		case XS_RET_FAIL:
			CFATALX("failed to parse metadata file");
			break;
		default:
			CABORTX("%s: invalid state %d", __func__, ret);
		}
		ct_queue_first(state, trans);
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

