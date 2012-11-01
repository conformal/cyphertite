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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>

#include <ct_sapi.h>

extern char *__progname;

int
main(int argc, char **argv)
{
	struct ct_global_state	*state = NULL;
	char			*config_file = NULL;
	uint32_t		 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	uint64_t		 debug_mask = 0;
	int			 i, filecount, ret;
	char                   **exclude;
	char                   **flist;
	char                   **include;
	char                    *tdir;
	char                    *ctfile;
	int                      no_cross_mounts, strip_slash;
	int                      follow_root_symlink, follow_symlinks;

	/* setup arguments */
	exclude = NULL;
	include = NULL;
	tdir = NULL;
	no_cross_mounts = 1;
	strip_slash = 1;
	follow_root_symlink = 1;
	follow_symlinks = 0;

	ct_setup_preinit(CT_INIT_ASSL | CT_INIT_CLOG | CT_INIT_EXUDE, cflags,
	    debug_mask);

	if (argc < 3) {
		CFATALX("usage: %s <metatdata file tag> <files>", __progname);
	}
	ctfile = e_strdup(argv[1]);	/* metafile tag		*/
	filecount = argc - 2;
	flist = e_calloc(filecount + 1, sizeof (char *));
	for(i = 0; i < filecount; i++)
		flist[i] = e_strdup(argv[i+2]);

	ct_setup_config(config_file, &state);

	ret = ct_do_archive(state, ctfile, flist, tdir, exclude,
	    include, CT_MATCH_INVALID, no_cross_mounts, strip_slash,
	    follow_root_symlink, follow_symlinks);

	ct_cleanup_all(state, config_file);

	if (ctfile)
		e_free(&ctfile);

	if (flist) {
		for(i = 0; i < filecount; i++)
			if (flist[i])
				e_free(&flist[i]);
		e_free(&flist);
	}

	return (ret);
}
