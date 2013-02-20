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

#include <sys/stat.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <clog.h>

#include "ct_fts.h"

extern char *__progname;

int follow_symlinks = 0;
int follow_root_symlink = 0;
int no_cross_mounts = 0;

int
main(int argc, char **argv)
{
	CT_FTS			*ftsp;
	CT_FTSENT		*fe;
	int			 fts_options;
	char			**paths = argv + 1;

	clog_init(1);
	(void)clog_set_flags(CLOG_F_STDERR | CLOG_F_ENABLE);

	if (argc < 2) {
		CFATALX("usage: %s <list of paths >", __progname);
	}

	fts_options = CT_FTS_NOCHDIR;
	if (follow_symlinks)
		fts_options |= CT_FTS_LOGICAL;
	else
		fts_options |= CT_FTS_PHYSICAL;
	if (follow_root_symlink) {
		fts_options |= CT_FTS_COMFOLLOW;
	}
	if (no_cross_mounts)
		fts_options |= CT_FTS_XDEV;
	ftsp = ct_fts_open(paths, fts_options, NULL);
	if (ftsp == NULL) {
		CFATAL("ct_fts_open");
	}

	while ((fe = ct_fts_read(ftsp)) != NULL) {
		switch (fe->fts_info) {
		case CT_FTS_D:
			CINFO("pre-order dir %s", fe->fts_name);
			break;
		case CT_FTS_DEFAULT:
			CINFO("default %s", fe->fts_name);
			break;
		case CT_FTS_F:
			CINFO("regular file %s size %" PRId64, fe->fts_name,
			    fe->fts_statp->st_size);
			break;
		case CT_FTS_SL:
			/* XXX print out destination? */
			CINFO("symbolic link %s", fe->fts_name);
			break;
		case CT_FTS_SLNONE:
			CINFO("symbolic link with no target %s", fe->fts_name);
			break;
		case CT_FTS_DP:
			CINFO("post-order dir: %s", fe->fts_name);
			break;
		case CT_FTS_DC:
			CWARNX("file system cycle found");
			continue;
		case CT_FTS_DNR:
		case CT_FTS_NS:
			errno = fe->fts_errno;
			CWARN("unable to access %s", fe->fts_path);
			continue;
		default:
			CABORTX("bad fts_info (%d)", fe->fts_info);
		}
	}
	if (ct_fts_close(ftsp))
		CFATAL("ct_fts_close");

	return (0);
}
