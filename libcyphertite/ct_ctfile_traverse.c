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


#include <sys/types.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <dirent.h>
#include <libgen.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <regex.h>
#include <errno.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>

#include <ctutil.h>

#include <cyphertite.h>
#include <ct_types.h>
#include <ct_crypto.h>
#include "ct_fts.h"

/* Taken from OpenBSD ls */
static void
printtime(time_t ftime)
{
	int i;
	char *longstring;

	longstring = ctime(&ftime);
	for (i = 4; i < 11; ++i)
		(void)putchar(longstring[i]);

#define DAYSPERNYEAR	365
#define SECSPERDAY	(60*60*24)
#define	SIXMONTHS	((DAYSPERNYEAR / 2) * SECSPERDAY)
	if (ftime + SIXMONTHS > time(NULL))
		for (i = 11; i < 16; ++i)
			(void)putchar(longstring[i]);
	else {
		(void)putchar(' ');
		for (i = 20; i < 24; ++i)
			(void)putchar(longstring[i]);
	}
	(void)putchar(' ');
}


int
ctfile_list_print(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_ctfile_list_args	*ccla = op->op_args;
	struct ctfile_list_tree		 results;
	struct ctfile_list_file		*file;
	int64_t				 maxsz = 8;
	int				 numlen;
	int				 ret = 0;

	RB_INIT(&results);
	if ((ret = ctfile_list_complete(&state->ctfile_list_files,
	    ccla->ccla_matchmode, ccla->ccla_search, ccla->ccla_exclude,
	    &results)) != 0)
		return (ret);
	RB_FOREACH(file, ctfile_list_tree, &results) {
		if (maxsz < (int64_t)file->mlf_size)
			maxsz  = (int64_t)file->mlf_size;
	}
	numlen = snprintf(NULL, 0, "%" PRId64, maxsz);

	while ((file = RB_MIN(ctfile_list_tree, &results)) != NULL) {
		RB_REMOVE(ctfile_list_tree, &results, file);

		printf("%*llu ", numlen, (unsigned long long)file->mlf_size);
		printtime(file->mlf_mtime);
		printf("\t");
		printf("%s\n", file->mlf_name);
		e_free(&file);
	}

	return (ret);
}


/*
 * make fts_* return entities in mtime order, oldest first
 */
/* XXX: Need to clean this up with more portable code.  Using ifdefs for now
 * to make it compile.
 */
#ifdef __FreeBSD__
static int
datecompare(const CT_FTSENT **a, const CT_FTSENT **b)
{
	return (timespeccmp(&(*a)->fts_statp->st_mtimespec,
	    &(*b)->fts_statp->st_mtimespec, <));
}
#else
static int
datecompare(const CT_FTSENT **a, const CT_FTSENT **b)
{
	return (timespeccmp(&(*a)->fts_statp->st_mtim,
	    &(*b)->fts_statp->st_mtim, <));
}
#endif

/*
 * Trim down the metadata cachedir to be smaller than ``max_size''.
 *
 * We only look at files in the directory (and lower, since we use fts(3),
 * since cyphertite will only ever create files, not symlinkts or directories.
 * We delete files in date order, oldest first, until the size constraint has
 * been met.
 */
int
ctfile_trim_cache(const char *cachedir, long long max_size)
{
	char		*paths[2];
	CT_FTS		*ftsp;
	CT_FTSENT		*fe;
	long long	 dirsize = 0;

	paths[0] = (char *)cachedir;
	paths[1] = NULL;

	if ((ftsp = ct_fts_open(paths, CT_FTS_XDEV | CT_FTS_PHYSICAL | CT_FTS_NOCHDIR,
	   NULL)) == NULL) {
		CNDBG(CT_LOG_CTFILE, "can't open metadata cache to scan");
		return (CTE_ERRNO);
	}

	while ((fe = ct_fts_read(ftsp)) != NULL) {
		switch(fe->fts_info) {
		case CT_FTS_F:
			/*
			 * XXX no OFF_T_MAX in posix, on openbsd it is always a
			 * long long
			 */
			if (LLONG_MAX - dirsize < fe->fts_statp->st_size)
				CWARNX("dirsize overflowed");
			dirsize += fe->fts_statp->st_size;
			break;
		case CT_FTS_ERR:
		case CT_FTS_DNR:
		case CT_FTS_NS:
			CNDBG(CT_LOG_CTFILE, "can't read directory entry %s",
			    strerror(fe->fts_errno));
			(void)ct_fts_close(ftsp);
			errno = fe->fts_errno;
			return (CTE_ERRNO);
		case CT_FTS_DC:
			CNDBG(CT_LOG_CTFILE, "file system cycle found");
			/* FALLTHROUGH */
		default:
			/* valid but we don't care */
			continue;
		}
	}

	(void)ct_fts_close(ftsp);

	if (dirsize <= max_size)
		return (0);
	CNDBG(CT_LOG_CTFILE, "cleaning up cachedir, %llu > %llu",
	    (long long)dirsize, (long long)max_size);

	if ((ftsp = ct_fts_open(paths, CT_FTS_XDEV | CT_FTS_PHYSICAL | CT_FTS_NOCHDIR,
	    datecompare)) == NULL) {
		CNDBG(CT_LOG_CTFILE, "can't open metadata cache to trim");
		return (CTE_ERRNO);
	}

	while ((fe = ct_fts_read(ftsp)) != NULL) {
		switch(fe->fts_info) {
		case CT_FTS_F:
			CNDBG(CT_LOG_CTFILE, "%s %llu", fe->fts_path,
			    (long long)fe->fts_statp->st_size);
			if (unlink(fe->fts_path) != 0) {
				CWARN("couldn't delete ctfile %s",
				    fe->fts_path);
				continue;
			}
			dirsize -= fe->fts_statp->st_size;
			break;
		case CT_FTS_ERR:
		case CT_FTS_DNR:
		case CT_FTS_NS:
			CNDBG(CT_LOG_CTFILE, "can't read directory entry %s",
			    strerror(fe->fts_errno));
			(void)ct_fts_close(ftsp);
			errno = fe->fts_errno;
			return (CTE_ERRNO);
		case CT_FTS_DC:
			CNDBG(CT_LOG_CTFILE, "file system cycle found");
			/* FALLTHROUGH */
		default:
			/* valid but we don't care */
			continue;
		}
		CNDBG(CT_LOG_CTFILE, "size now %llu", (long long)dirsize);

		if (dirsize < max_size)
			break;
	}

	(void)ct_fts_close(ftsp);

	return (0);
}

int
ctfile_cache_remove(const char *file, const char *cachedir)
{

	char		*cachename;
	int		 s_errno = 0, ret = 0;

	cachename = ctfile_get_cachename(file, cachedir);

	if (unlink(cachename) == -1) {
		ret = CTE_ERRNO;
		s_errno = errno;
	}

	e_free(&cachename);

	errno = s_errno;
	return (ret);
}
