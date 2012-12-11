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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
#include <libgen.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <ctutil.h>

#include <ct_crypto.h>
#include <cyphertite.h>
#include <ct_match.h>
#include <ct_ext.h>

int
ct_do_remotelist(struct ct_global_state *state, char **search, char **exclude,
    int matchmode,
    int (*printfn) (struct ct_global_state *state, struct ct_op *op))
{
	struct ct_ctfile_list_args	ccla;
	int				ret;

	ccla.ccla_search = search;
	ccla.ccla_exclude = exclude;
	ccla.ccla_matchmode = matchmode;
	ct_add_operation(state, ctfile_list_start,
	    printfn, &ccla);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else	
			CWARNX("%s", ct_strerror(ret));
	}
	return (ret);
}

int
ct_do_remotearchive(struct ct_global_state *state, char *ctfile, char **flist,
    char *tdir, char **excludelist, char **includelist, int match_mode,
    int no_cross_mounts, int strip_slash, int follow_root_symlink,
    int follow_symlinks, struct ct_config *conf)
{
	int			 ret;

        struct ct_archive_args           caa;

	ct_normalize_filelist(flist);
	caa.caa_filelist = flist;
	caa.caa_excllist = excludelist;
	caa.caa_matchmode = match_mode;
	caa.caa_includelist = includelist;
	caa.caa_tdir = tdir;
	caa.caa_tag = ctfile;
	caa.caa_ctfile_basedir = conf->ct_ctfile_cachedir;
	/* we want to encrypt as long as we have keys */
	caa.caa_no_cross_mounts = no_cross_mounts;
	caa.caa_strip_slash = strip_slash;
	caa.caa_follow_root_symlink = follow_root_symlink;
	caa.caa_follow_symlinks = follow_symlinks;
	caa.caa_max_incrementals = conf->ct_max_incrementals;
	if (conf->ct_auto_incremental)
		/*
		 * Need to work out basis filename and
		 * download it if necessary
		 */
		ctfile_find_for_operation(state, ctfile,
		    ctfile_nextop_archive, &caa, 0, 1);
	else   {
		/* No basis, just start the op */
		ctfile_nextop_archive(state, NULL, &caa);
	}


	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else	
			CWARNX("%s", ct_strerror(ret));
	}
	return (ret);
}

int
ct_do_remoteextract(struct ct_global_state *state, char *ctfile, char *tdir,
    char **excludelist, char **includelist, int match_mode, int strip_slash,
    int follow_symlinks, int preserve_attr,  struct ct_config *conf)
{
	int			 ret;

        struct ct_extract_args           cea;

	cea.cea_local_ctfile = NULL; /* to be found */
	cea.cea_filelist = includelist;
	cea.cea_excllist = excludelist;
	cea.cea_matchmode = match_mode;
	cea.cea_ctfile_basedir = conf->ct_ctfile_cachedir;
	cea.cea_tdir = tdir;
	cea.cea_strip_slash = strip_slash;
	cea.cea_attr = preserve_attr;
	cea.cea_follow_symlinks = follow_symlinks;
	ctfile_find_for_operation(state, ctfile,
	    ctfile_nextop_extract, &cea, 1, 0);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else	
			CWARNX("%s", ct_strerror(ret));
	}
	return (ret);
}
