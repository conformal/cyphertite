/*
 * Copyright (c) 2011-2013 Conformal Systems LLC <info@conformal.com>
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
#include <string.h>
#include <errno.h>

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include <ct_ctfile.h>
#include "ct_archive.h"

static inline int
ct_archive_file_cmp(struct ct_archive_file *a, struct ct_archive_file *b)
{
	return (strcmp(a->af_name, b->af_name));
}
RB_GENERATE(ct_archive_files, ct_archive_file, af_entry, ct_archive_file_cmp);

int
ct_basis_setup(struct ct_archive_state *state, struct ct_archive_args *caa,
    const char *cwd)
{
	struct ctfile_parse_state	 xs_ctx;
	struct dnode			*pdnode;
	struct ct_archive_dnode		*adnode;
	struct ct_archive_file		*af = NULL;
	char				*name;
	char				**fptr;
	time_t				 prev_backup_time = 0;
	int				 nextlvl, i, rooted = 1, ret, s_errno;

	if ((ret = ctfile_parse_init(&xs_ctx, caa->caa_basis, NULL)))
		return (ret);

	/* all archives are encrypted now, so if an old wasn't force lvl0 */
	if ((xs_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO) == 0) {
		nextlvl = 0;
		goto done;
	}

	if (caa->caa_max_incrementals == 0 ||
	    xs_ctx.xs_gh.cmg_cur_lvl < caa->caa_max_incrementals) {
		prev_backup_time = xs_ctx.xs_gh.cmg_created;
		CINFO("prev backup time %s %s", ctime(&prev_backup_time),
		    caa->caa_basis);
		nextlvl = ++xs_ctx.xs_gh.cmg_cur_lvl;
	} else {
		nextlvl = 0;
	}

	/* no more checking needed if we're a level 0 */
	if (nextlvl == 0)
		goto done;

	/*
	 * if we have the list of dirs in this previous backup, check that
	 * our cwd matches and the list of dirs we care about are a strict
	 * superset of the previous backup
	 */
	if (xs_ctx.xs_gh.cmg_version >= CT_MD_V2) {
		for (i = 0, fptr = caa->caa_filelist; *fptr != NULL &&
		    i < xs_ctx.xs_gh.cmg_num_paths; fptr++, i++) {
			if (strcmp(xs_ctx.xs_gh.cmg_paths[i], *fptr) != 0)
				break;
			if (!ct_absolute_path(xs_ctx.xs_gh.cmg_paths[i])) 
				rooted = 0;
		}
		if (i < xs_ctx.xs_gh.cmg_num_paths || *fptr != NULL) {
				nextlvl = 0;
		}

		if (rooted == 0 && strcmp(cwd, xs_ctx.xs_gh.cmg_cwd) != 0) {
			nextlvl = 0;
		}
	}

	/* no more checking needed if we're a level 0 */
	if (nextlvl == 0)
		goto done;

	while ((ret = ctfile_parse(&xs_ctx)) != XS_RET_EOF) {
		if (ret == XS_RET_FILE /* && 3factor */) {
			if (!C_ISDIR(xs_ctx.xs_hdr.cmh_type) &&
			    !C_ISREG(xs_ctx.xs_hdr.cmh_type)) 
				continue;
			/* set up parent dnode */
			pdnode = ct_archive_get_rootdir(state);
			if (xs_ctx.xs_hdr.cmh_parent_dir == -2) {
				e_asprintf(&name, "%s%s",
				    caa->caa_strip_slash ? "" : "/",
				    xs_ctx.xs_hdr.cmh_filename);
			} else if (xs_ctx.xs_hdr.cmh_parent_dir != -1) {
				pdnode = ctfile_parse_finddir(&xs_ctx,
				    xs_ctx.xs_hdr.cmh_parent_dir);
				
				e_asprintf(&name, "%s%c%s",
				    pdnode->d_name, CT_PATHSEP,
				    xs_ctx.xs_hdr.cmh_filename);
			} else {
				name = e_strdup(xs_ctx.xs_hdr.cmh_filename);
			}

			if (C_ISDIR(xs_ctx.xs_hdr.cmh_type)) {
				CNDBG(CT_LOG_FILE, "dir: %s", name);
				adnode = e_calloc(1, sizeof(*adnode));
				RB_INIT(&adnode->ad_children);
				adnode->ad_dnode.d_name = name;
				adnode->ad_dnode.d_fd = -1;
				adnode->ad_dnode.d_parent = pdnode;
				/*
				 * rest of this data will be filled
				 * in by ct_sched_backup_file
				 */
				if (ct_archive_insert_dir(state,
				    &adnode->ad_dnode) != NULL) {
					/* should not occur, easy to handle */
					ct_free_dnode(&adnode->ad_dnode);
					continue;
				}
				ctfile_parse_insertdir(&xs_ctx,
				    &adnode->ad_dnode);
			} else if (C_ISREG(xs_ctx.xs_hdr.cmh_type)) {
				CNDBG(CT_LOG_FILE, "file: %s (%s)", name,
				    xs_ctx.xs_hdr.cmh_filename);
				if (pdnode == NULL)
					CABORTX("that's unpossible!");
				adnode = (struct ct_archive_dnode *)pdnode;
				CNDBG(CT_LOG_FILE, "parent: %s",
				    pdnode->d_name);

				/* make file reference for self */
				af = e_calloc(1, sizeof(*af));
				/* want shortname here */
				af->af_name =
				    e_strdup(xs_ctx.xs_hdr.cmh_filename);
				af->af_mtime = xs_ctx.xs_hdr.cmh_mtime;
				/* size filled in by file trailer */

				RB_INSERT(ct_archive_files,
				    &adnode->ad_children, af);
			}
			/* build dnode stuff */
		} else if (ret == XS_RET_FILE_END /* && 3factor */) {
			if (af == NULL)
				CABORTX("file trailer without header");
			af->af_size = xs_ctx.xs_trl.cmt_orig_size;
			af = NULL; /* this file is ended now */
		} else if (ret == XS_RET_SHA)  {
			if (ctfile_parse_seek(&xs_ctx)) {
				s_errno = errno;
				ret = xs_ctx.xs_errno;
				ctfile_parse_close(&xs_ctx);
				errno = s_errno;
				return (ret);
			}
		} else if (ret == XS_RET_FAIL) {
			s_errno = errno;
			ret = xs_ctx.xs_errno;
			ctfile_parse_close(&xs_ctx);
			errno = s_errno;
			return (ret);
		}

	}
done:
	ctfile_parse_close(&xs_ctx);

	if (nextlvl != 0)
		ct_archive_set_prev_backup_time(state, prev_backup_time);

	ct_archive_set_level(state, nextlvl);
	return (0);
}
