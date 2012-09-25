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
#include <errno.h>

#include <clog.h>
#include <exude.h>

#include <ct_ctfile.h>
#include <ct_match.h>
#include <cyphertite.h>
#include <ct_internal.h>
#include <ct_db.h>

const uint8_t	 zerosha[SHA_DIGEST_LENGTH];

/*
 * Code for extract.
 */
static int	ct_extract_setup_queue(struct ct_extract_head *,
	    struct ctfile_parse_state *, const char *, const char *, int);

int
ct_extract_setup(struct ct_extract_head *extract_head,
    struct ctfile_parse_state *ctx, const char *file,
    const char *ctfile_basedir, int *is_allfiles)
{
	struct ct_extract_stack	*nfile;
	char			*prevlvl;
	int			 ret;

	if ((ret = ctfile_parse_init(ctx, file, ctfile_basedir)) != 0)
		return (ret);

	*is_allfiles = (ctx->xs_gh.cmg_flags & CT_MD_MLB_ALLFILES);

	if (ctx->xs_gh.cmg_prevlvl_filename) {
		nfile = e_malloc(sizeof(*nfile));
		nfile->filename = e_strdup(file);
		TAILQ_INSERT_HEAD(extract_head, nfile, next);

		prevlvl = e_strdup(ctx->xs_gh.cmg_prevlvl_filename);

		ctfile_parse_close(ctx);
		if ((ret = ct_extract_setup_queue(extract_head, ctx, prevlvl,
		    ctfile_basedir, *is_allfiles)) != 0) {
			int s_errno = errno;

			/* unwind */
			e_free(&prevlvl);
			ct_extract_cleanup_queue(extract_head);

			errno = s_errno;
			return (ret);
		}

		e_free(&prevlvl);

		if (*is_allfiles) {
			ctfile_parse_close(ctx);
			/* reopen first file */
			ret = ct_extract_open_next(extract_head, ctx);
		}
	}

	return (ret);
}

static int
ct_extract_setup_queue(struct ct_extract_head *extract_head,
    struct ctfile_parse_state *ctx, const char *file,
    const char *ctfile_basedir, int is_allfiles)
{
	char			*prevlvl;
	struct ct_extract_stack	*nfile;
	int			 ret;

	if ((ret = ctfile_parse_init(ctx, file, ctfile_basedir)) != 0)
		return (ret);

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

	return (0);
}

int
ct_extract_open_next(struct ct_extract_head *extract_head, struct ctfile_parse_state *ctx)
{
	struct ct_extract_stack *next;
	int			 ret, s_errno;

	if (!TAILQ_EMPTY(extract_head)) {
		next = TAILQ_FIRST(extract_head);
		CNDBG(CT_LOG_CTFILE,
		    "should start restoring [%s]", next->filename);

		/* Basedir not needed here because we are done with prevlvl */
		if ((ret = ctfile_parse_init(ctx, next->filename, NULL)) != 0) {
			s_errno = errno;
			/* chain is broken, clean it up */
			ct_extract_cleanup_queue(extract_head);
			errno = s_errno;
			return (ret);
		}

		TAILQ_REMOVE(extract_head, next, next);
		if (next->filename)
			e_free(&next->filename);
		if (next)
			e_free(&next);
	} else {
		CABORTX("open next with no next archive");
	}

	return (0);
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

void
ct_extract_cleanup_fnode(struct ct_global_state *state, struct ct_trans *trans)
{
	ct_free_fnode(trans->tr_fl_node);
	trans->tr_fl_node = NULL;
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
	if (trans->tr_errno != 0) {
		char		*errstr;
		char		 shat[SHA_DIGEST_STRING_LENGTH];
		/* any other read failure is bad */
		ct_sha1_encode(trans->tr_sha, shat);
		e_asprintf(&errstr, "Data missing on server: "
		    "file %s, sha %s",
		    trans->tr_fl_node ?
		    trans->tr_fl_node->fl_sname  : "unknown",
		    shat);
		ct_fatal(state, errstr, trans->tr_errno);
		free(errstr);
		return (0);
	}

	if (trans->tr_fl_node->fl_skip_file == 0) {
		slot = trans->tr_dataslot;
		ct_sha1_add(trans->tr_data[slot],
		    &trans->tr_fl_node->fl_shactx,
		    trans->tr_size[slot]);
		if ((ret = ct_file_extract_write(state->extract_state,
		    trans->tr_fl_node, trans->tr_data[slot],
		    trans->tr_size[slot])) != 0) {
			/*
			 * XXX really this shouldn't be fatal, just make us skip
			 * the file in future and CWARNX.
			 */
			ct_fatal(state, "Failed to write file", ret);
			return (0);
		}
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
		state->ct_print_file_end(state->ct_print_state,
		    trans->tr_fl_node, state->ct_max_block_size);
	}
	state->ct_stats->st_files_completed++;

	return (0);
}

int
ct_extract_complete_done(struct ct_global_state *state,
    struct ct_trans *trans)
{
	return (1);
}

void
ct_extract_cleanup_done(struct ct_global_state *state,
    struct ct_trans *trans)
{
	ct_file_extract_cleanup(state->extract_state);	
	state->extract_state = NULL;
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

/*
 * So that we can provide correct statistics we have to go through all ctfiles
 * being extracted and sum the sizes to be extracted. This is kinda expensive,
 * but not really avoidable if we want to provide the statistics.
 *
 * Failure means we have called ct fatal.
 */
int
ct_extract_calculate_total(struct ct_global_state *state,
    struct ct_extract_args *cea, struct ct_match *inc_match,
    struct ct_match *ex_match)
{
	struct ct_extract_head		 extract_head;
	struct ctfile_parse_state	 xdr_ctx;
	struct ct_match			*rb_match = NULL;
	struct fnode			*fnode;
	int				 allfiles;
	int				 fillrb = 0, haverb = 0;
	int				 doextract = 0;
	int				 tr_state;
	int				 ret;
	int				 retval = 1;

	TAILQ_INIT(&extract_head);

	if ((ret = ct_extract_setup(&extract_head,
	    &xdr_ctx, cea->cea_local_ctfile, cea->cea_ctfile_basedir,
	    &allfiles)) != 0) {
		ct_fatal(state, "can't setup extract queue", ret);
		goto done;
	}
	if (allfiles) {
		char *nothing = NULL;
		if ((ret = ct_match_compile(&rb_match,
		    CT_MATCH_RB, &nothing)) != 0) {
			ct_fatal(state, "Couldn't create match tree",
			    ret);
			goto done;
		}
		fillrb = 1;
	}

	while (1) {
		switch ((ret = ctfile_parse(&xdr_ctx))) {
		case XS_RET_FILE:
			if (fillrb == 0 && xdr_ctx.xs_hdr.cmh_nr_shas == -1) {
				continue;
			}

			fnode = e_calloc(1, sizeof(*fnode));
			/* XXX need the fnode for the correct paths */
			ct_populate_fnode(state->extract_state,
			    &xdr_ctx, fnode, &tr_state, allfiles,
			    cea->cea_strip_slash);
			/* we don't care about individual shas */
			if (C_ISREG(fnode->fl_type)) {
				ctfile_parse_seek(&xdr_ctx);
			}

			doextract = !ct_match(inc_match,
			    fnode->fl_sname);
			if (doextract && ex_match != NULL &&
			  !ct_match(ex_match, fnode->fl_sname))
				doextract = 0;
			/*
			 * If we're on the first ctfile in an allfiles backup
			 * put the matches with -1 on the rb tree so we'll
			 * remember to extract it from older files.
			 */
			if (doextract == 1 && fillrb &&
			    xdr_ctx.xs_hdr.cmh_nr_shas == -1) {
				ct_match_insert_rb(rb_match, fnode->fl_sname);
				doextract = 0;
			}
			ct_free_fnode(fnode);
			break;
		case XS_RET_FILE_END:
			if (doextract == 0)
				continue;
			/* update statistics */
			state->ct_stats->st_bytes_tot +=
			    xdr_ctx.xs_trl.cmt_orig_size;
			break;
		case XS_RET_EOF:
			ctfile_parse_close(&xdr_ctx);
			/* if rb tree and rb is empty, goto end state */
			if ((haverb && ct_match_rb_is_empty(inc_match)) ||
			    (fillrb && ct_match_rb_is_empty(rb_match))) {
				retval = 0;
				goto done;
			}

			if (!TAILQ_EMPTY(&extract_head)) {
				/*
				 * if allfiles and this was the first pass.
				 * free the current match lists
				 * switch to rb tree mode
				 */
				if (fillrb) {
					ex_match = NULL;
					inc_match = rb_match;
					rb_match = NULL;
					haverb = 1;
					fillrb = 0;
				}
				/* reinits xdr_ctx */
				if ((ret = ct_extract_open_next(&extract_head,
				    &xdr_ctx)) != 0) {
					ct_fatal(state,
					    "Can't open next ctfile", ret);
					goto done;
				}
			}
			retval = 0;
			goto done;
			break;
		case XS_RET_FAIL:
			ct_fatal(state, "Failed to parse ctfile",
			    xdr_ctx.xs_errno);
			goto done;
			break;
		}
	}

done:
	/* empty unless we quit early */
	ct_extract_cleanup_queue(&extract_head);
	/* only have control of the rb tree we made */
	if (haverb)
		ct_match_unwind(inc_match);
	if (rb_match != NULL)
		ct_match_unwind(rb_match);
		
	return (retval);
}

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

	/* if we were woken up due to fatal, just clean up local state */
	if (state->ct_dying != 0)
		goto dying;

	CNDBG(CT_LOG_TRANS, "entry");
	switch (ct_get_file_state(state)) {
	case CT_S_STARTING:
		if (ex_priv == NULL) {
			ex_priv = e_calloc(1, sizeof(*ex_priv));
			TAILQ_INIT(&ex_priv->extract_head);

			if ((ret = ct_match_compile(&ex_priv->inc_match,
			    match_mode, filelist)) != 0) {
				ct_fatal(state,
				    "failed to compile include pattern", ret);
				goto dying;
			}
			if (cea->cea_excllist != NULL &&
			    (ret = ct_match_compile(&ex_priv->ex_match,
			    match_mode, cea->cea_excllist)) != 0) {
				ct_fatal(state,
				    "failed to compile exclude pattern", ret);
				goto dying;
			}
			op->op_priv = ex_priv;
		}
		
		if ((ret = ct_file_extract_init(&state->extract_state,
		    cea->cea_tdir, cea->cea_attr,  cea->cea_follow_symlinks,
		    ex_priv->allfiles, cea->cea_log_state,
		    cea->cea_log_chown_failed)) != 0) {
			ct_fatal(state, "Can not initialize extract state",
			    ret);
			goto dying;
		}

		if (ct_extract_calculate_total(state, cea, ex_priv->inc_match,
		    ex_priv->ex_match) != 0) {
			CWARNX("failed to calculate stats");
			goto dying;
		}

		if ((ret = ct_extract_setup(&ex_priv->extract_head,
		    &ex_priv->xdr_ctx, ctfile, cea->cea_ctfile_basedir,
		    &ex_priv->allfiles)) != 0) {
			ct_fatal(state, "can't setup extract queue", ret);
			goto dying;
		}
		state->ct_print_ctfile_info(state->ct_print_state,
		    ex_priv->xdr_ctx.xs_filename, &ex_priv->xdr_ctx.xs_gh);
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
			    CT_MATCH_RB, &nothing)) != 0) {
				ct_fatal(state, "Couldn't create match tree",
				    ret);
				goto dying;
			}
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
		trans->tr_statemachine = ct_state_extract;

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
				trans->tr_cleanup = ct_extract_cleanup_fnode;
			} else {
				trans->tr_complete =
				    ct_extract_complete_file_start;
				trans->tr_cleanup = NULL;
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
				if (ctfile_parse_seek(&ex_priv->xdr_ctx)) {
					ct_fatal(state, "Can't seek past shas",
					    ex_priv->xdr_ctx.xs_errno);
					goto dying;
				}
				ct_trans_free(state, trans);
				continue;
			}

			if (memcmp(zerosha, ex_priv->xdr_ctx.xs_sha,
				SHA_DIGEST_LENGTH) == 0) {
				CWARNX("\"%s\" truncated during backup",
				    trans->tr_fl_node->fl_sname);
				if (ctfile_parse_seek(&ex_priv->xdr_ctx)) {
					ct_fatal(state, "Can't seek past "
					    "truncation shas",
					    ex_priv->xdr_ctx.xs_errno);
					goto dying;
				}
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
			trans->tr_cleanup = NULL;
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
			trans->tr_cleanup = ct_extract_cleanup_fnode;
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
				if ((ret =
				    ct_extract_open_next(&ex_priv->extract_head,
				    &ex_priv->xdr_ctx)) != 0) {
					ct_fatal(state,
					    "Can't open next ctfile", ret);
					goto dying;
				}
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
				trans->tr_cleanup = ct_extract_cleanup_done;
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
			ct_fatal(state, "Failed to parse ctfile",
			    ex_priv->xdr_ctx.xs_errno);
			goto dying;
			break;
		}
	}

	return;

dying:
	/* only if we hadn't sent the final transaction yet */
	if (ex_priv != NULL) {
		ct_extract_cleanup_queue(&ex_priv->extract_head);
		if (ex_priv->inc_match)
			ct_match_unwind(ex_priv->inc_match);
		if (ex_priv->ex_match)
			ct_match_unwind(ex_priv->ex_match);
		if (ex_priv->rb_match)
			ct_match_unwind(ex_priv->rb_match);
		/* XXX what about ex_priv->xdr_ctx ? */
		e_free(&ex_priv);
		op->op_priv = NULL;
		/* if ex_priv is gone then the trans will clean this up */
		if (state->extract_state)
			ct_file_extract_cleanup(state->extract_state);	
	}
	return;
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

	if (state->ct_dying != 0)
		goto dying;

	CNDBG(CT_LOG_TRANS, "entry");
	switch (ct_get_file_state(state)) {
	case CT_S_STARTING:
		CNDBG(CT_LOG_TRANS, "starting");
		ex_priv = e_calloc(1, sizeof(*ex_priv));
		/* open file and seek to beginning of file */
		if ((ret = ctfile_parse_init_at(&ex_priv->xdr_ctx,
		    cefa->cefa_ctfile, NULL, cefa->cefa_ctfile_off)) != 0) {
			/* XXX add pathname */
			ct_fatal(state, "Can't open ctfile", ret);
			e_free(&ex_priv);
			goto dying;
		}
		 /* XXX we should handle this better */
		if (state->ct_max_block_size <
		    ex_priv->xdr_ctx.xs_gh.cmg_chunk_size)
			CABORTX("block size negotiated with server %d is "
			    "smaller than file max block size %d",
			    state->ct_max_block_size,
			    ex_priv->xdr_ctx.xs_gh.cmg_chunk_size);
		if ((ret = ct_file_extract_init(&state->extract_state,
		    NULL, 0, 0, 0, NULL, NULL)) != 0) {
			ct_fatal(state, "Can not initialise extract state",
			    ret);
			e_free(&ex_priv);
			goto dying;
		}
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
		trans->tr_statemachine = ct_state_extract;

		if (ex_priv->done) {
			CNDBG(CT_LOG_CTFILE, "Hit end of ctfile");
			ctfile_parse_close(&ex_priv->xdr_ctx);
			e_free(&ex_priv);
			op->op_priv = NULL;
			trans->tr_state = TR_S_DONE;
			trans->tr_complete = ct_extract_complete_done;
			trans->tr_cleanup = ct_extract_cleanup_done;
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
				trans->tr_cleanup = ct_extract_cleanup_fnode;
			} else {
				trans->tr_complete =
				    ct_extract_complete_file_start;
				trans->tr_cleanup = NULL;
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
			trans->tr_cleanup = NULL;
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
			trans->tr_cleanup = ct_extract_cleanup_fnode;
			trans->tr_fl_node->fl_size =
			    ex_priv->xdr_ctx.xs_trl.cmt_orig_size;
			/* Done now, don't parse further. */
			ex_priv->done = 1;
			break;
		case XS_RET_FAIL:
			ct_fatal(state, "Failed to parse ctfile",
			    ex_priv->xdr_ctx.xs_errno);
			goto dying;
			break;
		default:
			CABORTX("%s: invalid state %d", __func__, ret);
		}
		ct_queue_first(state, trans);
	}
	return;

dying:
	if (ex_priv) {
		ctfile_parse_close(&ex_priv->xdr_ctx);
		e_free(&ex_priv);
		/* will be cleaned up by trans if ex_priv already gone */
		if (state->extract_state)
			ct_file_extract_cleanup(state->extract_state);	
	}
	return;
}

int
ct_extract_file_cleanup(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_file_args	*cefa = op->op_args;

	e_free(&cefa->cefa_filename);
	e_free(&cefa->cefa_ctfile);
	e_free(&cefa);

	return (0);
}

/* handlers for ct_exists_file. */
void
ct_state_exists(struct ct_global_state *state, struct ct_trans *trans)
{
	/*
	 * State flow:
	 * exists packets -> either EXISTS or NEXISTS.
	 * when all exists done, S_DONE trans sent.
	 */
	switch (trans->tr_state) {
	case TR_S_COMPSHA_ED:
	case TR_S_UNCOMPSHA_ED:
		/* do exists, will return with either S_EXISTS or S_NEXISTS */
		ct_queue_write(state, trans);
		break;

	case TR_S_EXISTS:
	case TR_S_NEXISTS:
	case TR_S_DONE:
		/* done here, complete */
		ct_queue_complete(state, trans);
		break;
	default:
		CABORTX("state %d, not handled in %s()",
		    trans->tr_state, __func__);
	}
}

/* completion handler for exists */
int
ct_exists_complete(struct ct_global_state *state,
    struct ct_trans *trans)
{
	struct ct_op		*op = ct_get_current_operation(state);
	struct ct_exists_args	*ce = op->op_args;

	if (trans->tr_state == TR_S_EXISTS) {
		/* Insert to localdb to save some effort later */
		ctdb_insert_sha(state->ct_db_state, trans->tr_sha,
		    trans->tr_csha, trans->tr_iv);
	} else {
		/* Call callback so caller can decide what to do with it. */
		ce->ce_nexists_cb(ce->ce_nexists_state, ce, trans);
	}

	return (0);
}
int
ct_exists_complete_done(struct ct_global_state *state,
    struct ct_trans *trans)
{
	return (1);
}

struct ct_exists_priv {
	struct ct_extract_head		 extract_head;
	struct ctfile_parse_state	 xdr_ctx;
};
/*
 * Perform EXISTS checking on every sha in a ctfile chain.
 *
 * We don't do any filtering. It is assumed that the localdb has been
 * flushed/made good before this operation starts so that we can trust lookups.
 */
void
ct_exists_file(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_exists_args	*ce = op->op_args;
	struct ct_exists_priv	*ex_priv = op->op_priv;
	struct ct_trans		*trans;
	int			 ret, allfiles;

	/* if we were woken up due to fatal, just clean up local state */
	if (state->ct_dying != 0)
		goto dying;

	CNDBG(CT_LOG_TRANS, "entry");
	switch (ct_get_file_state(state)) {
	case CT_S_STARTING:
		if (ex_priv == NULL) {
			ex_priv = e_calloc(1, sizeof(*ex_priv));
			TAILQ_INIT(&ex_priv->extract_head);
			op->op_priv = ex_priv;
		}
		if ((ret = ct_extract_setup(&ex_priv->extract_head,
		    &ex_priv->xdr_ctx, ce->ce_ctfile, ce->ce_ctfile_basedir,
		    &allfiles)) != 0) {
			ct_fatal(state, "can't setup extract queue", ret);
			goto dying;
		}
		
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
		trans->tr_statemachine = ct_state_exists;

		switch ((ret = ctfile_parse(&ex_priv->xdr_ctx))) {
		case XS_RET_FILE:
		case XS_RET_FILE_END:
			ct_trans_free(state, trans);
			break;
		case XS_RET_SHA:
			if (memcmp(zerosha, ex_priv->xdr_ctx.xs_sha,
			    SHA_DIGEST_LENGTH) == 0) {
				if (ctfile_parse_seek(&ex_priv->xdr_ctx)) {
					ct_fatal(state, "Can't seek past "
					    "truncation shas",
					    ex_priv->xdr_ctx.xs_errno);
					goto dying;
				}
				ct_trans_free(state, trans);
				continue;
			}

			if (ex_priv->xdr_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO) {
				/*
				 * yes csha and sha are reversed, we want
				 * to download csha, but putting it in sha
				 * simplifies the code
				 */
				bcopy(ex_priv->xdr_ctx.xs_sha, trans->tr_sha,
				    sizeof(trans->tr_csha));
				bcopy(ex_priv->xdr_ctx.xs_csha, trans->tr_csha,
				    sizeof(trans->tr_sha));
				bcopy(ex_priv->xdr_ctx.xs_iv, trans->tr_iv,
				    sizeof(trans->tr_iv));
				trans->tr_state = TR_S_COMPSHA_ED;
			} else {
				trans->tr_state = TR_S_UNCOMPSHA_ED;
				bcopy(ex_priv->xdr_ctx.xs_sha, trans->tr_sha,
				    sizeof(trans->tr_sha));
			}
			if (clog_mask_is_set(CT_LOG_SHA)) {
				char	 shat[SHA_DIGEST_STRING_LENGTH];

				ct_sha1_encode(trans->tr_sha, shat);
				CNDBG(CT_LOG_SHA, "EXISTSing sha %s", shat);
			}
			if (ctdb_lookup_sha(state->ct_db_state, trans->tr_sha,
			    trans->tr_csha, trans->tr_iv)) {
				CNDBG(CT_LOG_SHA, "sha already in localdb");
				state->ct_stats->st_bytes_exists +=
				    trans->tr_chsize;
				ct_trans_free(state, trans);
				continue;
			}

			trans->tr_complete = ct_exists_complete;
			trans->tr_cleanup = NULL;
			trans->tr_dataslot = 0;
			ct_queue_first(state, trans);
			break;
		case XS_RET_EOF:
			CNDBG(CT_LOG_CTFILE, "Hit end of ctfile");
			ctfile_parse_close(&ex_priv->xdr_ctx);

			if (!TAILQ_EMPTY(&ex_priv->extract_head)) {
				/*
				 * if allfiles and this was the first pass.
				 * free the current match lists
				 * switch to rb tree mode
				 */
				ct_trans_free(state, trans);
				/* reinits ex_priv->xdr_ctx */
				if ((ret =
				    ct_extract_open_next(&ex_priv->extract_head,
				    &ex_priv->xdr_ctx)) != 0) {
					ct_fatal(state,
					    "Can't open next ctfile", ret);
					goto dying;
				}
			} else {
				e_free(&ex_priv);
				op->op_priv = NULL;
				trans->tr_state = TR_S_DONE;
				trans->tr_complete = ct_exists_complete_done;
				trans->tr_cleanup = NULL;
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
			ct_fatal(state, "Failed to parse ctfile",
			    ex_priv->xdr_ctx.xs_errno);
			goto dying;
			break;
		}
	}

	return;

dying:
	/* only if we hadn't sent the final transaction yet */
	if (ex_priv != NULL) {
		ct_extract_cleanup_queue(&ex_priv->extract_head);
		/* XXX what about ex_priv->xdr_ctx ? */
		e_free(&ex_priv);
		op->op_priv = NULL;
	}
	return;
}
