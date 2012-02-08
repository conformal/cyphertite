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

#include <sys/types.h>
#include <sys/stat.h>

#include <inttypes.h>
#include <unistd.h>
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
#include <xmlsd.h>

#include <ctutil.h>

#include "ct.h"

void	ctfile_find_for_extract_complete(struct ct_op *);
void	ctfile_extract_nextop(struct ct_op *);
void	ctfile_download_next(struct ct_op *);

void
ctfile_mode_setup(const char *mode)
{
	CNDBG(CT_LOG_CTFILE, "%s", mode ? mode : "");
	if (mode == NULL)
		return;

	if (strcmp(mode, "remote") == 0)
		ctfile_mode = CT_MDMODE_REMOTE;
	else if (strcmp(mode, "local") == 0)
		ctfile_mode = CT_MDMODE_LOCAL;
	else
		CFATALX("invalid ctfile mode specified");
}

char *
ctfile_cook_name(const char *path)
{
	char	*bname;

	bname = basename((char *)path);
	if (bname == NULL)
		CFATAL("can't basename metadata path");
	if (bname[0] == '/')
		CFATALX("invalid metadata filename");

	return (e_strdup(bname));
}

/*
 * Return boolean whether the ctfile in question is already in the cache.
 */
int
ctfile_in_cache(const char *ctfile)
{
	struct dirent	*dp;
	DIR		*dirp;
	int		 found = 0;

	if ((dirp = opendir(ctfile_cachedir)) == NULL)
		CFATALX("can't open metadata cache dir");
	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, ctfile) == 0) {
			CNDBG(CT_LOG_CTFILE, "found in cachedir");
			found = 1;
			break;
		}
	}
	closedir(dirp);

	return (found);
}

/*
 * return the filename in the cache directory that a ctfile would have
 * if it extisted.
 */
char *
ctfile_get_cachename(const char *ctfile)
{
	char	*cachename;

	/* cachedir was made sure to terminate with / earlier */
	e_asprintf(&cachename, "%s%s", ctfile_cachedir, ctfile);
	return cachename;
}

/*
 * returns boolean 1/0 whether or not the ctfile in question is the full tag
 * with date/time or not.
 */
int
ctfile_is_fullname(const char *ctfile)
{
	char			*pattern = "^[[:digit:]]{8}-[[:digit:]]{6}-";
	char			error[1024];
	regex_t			re;
	int			match = 0, rv;
	if ((rv = regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB)) != 0) {
		regerror(rv, &re, error, sizeof(error) - 1);
		CFATALX("%s: regcomp failed: %s", __func__, error);
	}
	if (regexec(&re, ctfile, 0, NULL, 0) == 0)
		match = 1;

	regfree(&re);
	return match;
}

/*
 * filenames passed in remote mode are opaque tags for the backup.
 * they are stored on the server and in remote mode in the form
 * YYYYMMDD-HHMMSS-<strnvis(mname)>
 */
void
ctfile_find_for_extract(struct ct_op *op)
{
	const char	*ctfile = op->op_local_fname;
	struct ct_op	*list_fakeop;
	char	 	**bufp;
	int		 matchmode;

	/* cook the ctfile so we only search for the actual tag */
	ctfile = ctfile_cook_name(ctfile);

	list_fakeop = e_calloc(1, sizeof(*list_fakeop));
	bufp = e_calloc(2, sizeof(char **));
	if (ctfile_is_fullname(ctfile)) {
		/* use list as stat() for now */
		*bufp = e_strdup(ctfile);
		matchmode = CT_MATCH_GLOB;
	} else {
		e_asprintf(bufp, "^[[:digit:]]{8}-[[:digit:]]{6}-%s$", ctfile);

		matchmode = CT_MATCH_REGEX;
		/*
		 * get the list of files matching this tag from the server.
		 * list returns an empty list if it found
		 * nothing and NULL upon failure.
		 */
	}
	e_free(&ctfile);

	CNDBG(CT_LOG_CTFILE, "looking for %s", bufp[0]);

	list_fakeop->op_filelist = bufp;
	list_fakeop->op_matchmode = matchmode;

	op->op_priv = list_fakeop;
	ctfile_list_start(list_fakeop);
}

void
ctfile_find_for_extract_complete(struct ct_op *op)
{
	struct ct_op		*list_fakeop = op->op_priv;
	struct ctfile_list_tree	 result;
	struct ctfile_list_file	*tmp;
	char	 		*best, *cachename = NULL;

	RB_INIT(&result);
	ctfile_list_complete(list_fakeop->op_matchmode,
	    list_fakeop->op_filelist, list_fakeop->op_excludelist, &result);
	e_free(list_fakeop->op_filelist);
	e_free(&list_fakeop->op_filelist);
	e_free(&list_fakeop);

	/* grab the newest one */
	if ((tmp = RB_MAX(ctfile_list_tree, &result)) == NULL) {
		if (op->op_action == CT_A_ARCHIVE) {
			goto do_operation;
		} else  {
			CFATALX("unable to find metadata tagged %s",
			    op->op_local_fname);
		}
	}

	/* pick the newest one */
	best = e_strdup(tmp->mlf_name);
	CNDBG(CT_LOG_CTFILE, "backup file is %s", best);

	while((tmp = RB_ROOT(&result)) != NULL) {
		RB_REMOVE(ctfile_list_tree, &result, tmp);
		e_free(&tmp);
	}

	/*
	 * if the metadata file is not in the cache directory then we
	 * need to download it first. if we need to recursively download
	 * a differential chain then that code will handle scheduling
	 * those operations too. If we have it, we still need to check
	 * that all others in the chain exist, however.
	 */
	cachename = ctfile_get_cachename(best);
	if (!ctfile_in_cache(best)) {
		/*
		 * since archive needs the original metadata name still
		 * and is searching for a prior archive for differentials
		 * we put local_fname (the original) in the basis slot here.
		 * nextop will fix it for us.
		 */
		ct_add_operation(ctfile_extract, ctfile_extract_nextop,
		    cachename, best, op->op_filelist, op->op_excludelist,
		    op->op_local_fname, op->op_matchmode, op->op_action);
	} else {
		e_free(&best);
do_operation:
		/*
		 * Don't need to grab this ctfile, but may need one later in
		 * the differential chain, recurse. When we know more we can
		 * prepare the final operation
		 */
		op->op_basis = op->op_local_fname;
		op->op_local_fname = cachename;
		ctfile_extract_nextop(op);
	}

}

/*
 * now the operation has completed we can kick off the next operation knowing
 * that everything has been set up for it.
 */
void
ctfile_extract_nextop(struct ct_op *op)
{
	char			*ctfile, *tctfile, *trfile;
	extern int		 ctfile_is_open; /* XXX */

	ctfile_is_open = 0;
	/*
	 * need to determine if this is a layered backup, if so, we need to
	 * queue download of that file
	 */
	if (op->op_action == CT_A_EXTRACT || op->op_action == CT_A_LIST ||
	    op->op_action == CT_A_JUSTDL) {
		/*
		 * we need to keep these files, but download_next normally
		 * needs to free them, make a temporary copy.
		 */
		tctfile = op->op_local_fname;
		trfile = op->op_remote_fname;
		if (tctfile)
			op->op_local_fname = e_strdup(tctfile);
		if (trfile)
			op->op_remote_fname = e_strdup(trfile);
		ctfile_download_next(op);
		op->op_local_fname = tctfile;
		op->op_remote_fname = trfile;
	}

	/*
	 * Any recursive download after here will be placed after the
	 * current operation in the queue of ops. So we can now add the final
	 * operation to the end of the queue without difficulty.
	 */
	switch (op->op_action) {
	case CT_A_EXTRACT:
		ct_add_operation(ct_extract, ct_free_localname_and_remote,
		    op->op_local_fname, op->op_remote_fname, op->op_filelist,
		    op->op_excludelist, NULL, op->op_matchmode, 0);
		break;
	case CT_A_LIST:
		ct_add_operation(ct_list_op, ct_free_localname_and_remote,
		    op->op_local_fname, op->op_remote_fname, op->op_filelist,
		    op->op_excludelist, NULL, op->op_matchmode, 0);
		break;
	case CT_A_ARCHIVE:
		if (op->op_remote_fname)
			e_free(&op->op_remote_fname);
		/*
		 * Since we were searching for previous, original ctfile
		 * is stored in basis. Swap them.
		 */
		ctfile = ctfile_find_for_archive(op->op_basis);
		CNDBG(CT_LOG_CTFILE, "setting basisname %s",
		    op->op_local_fname);
		/* XXX does this leak cachename? */
		ct_add_operation(ct_archive, NULL, ctfile, NULL,
		    op->op_filelist, op->op_excludelist, op->op_local_fname,
		    op->op_matchmode, 0);
		ct_add_operation(ctfile_archive, ct_free_localname_and_remote,
		    ctfile, NULL, NULL, NULL, NULL, 0, 0);
		break;
	case CT_A_JUSTDL:
		{
		extern char * ct_fb_filename; 
		ct_fb_filename = op->op_local_fname; /* XXX ick */
		ct_add_operation(ct_shutdown_op, NULL, NULL, NULL, NULL, NULL,
		    NULL, 0, 0);
		}
		break;
	default:
		CFATALX("invalid action");
	}
}

/*
 * Download all dependant ctfiles of the current ctfile.
 * (called repeatedly until all are fetched).
 */
void
ctfile_download_next(struct ct_op *op)
{
	const char		*ctfile = op->op_local_fname;
	const char		*rfile = op->op_remote_fname;
	char			*prevfile;
	char			*cachename;
	char			*cookedname;
	extern int		 ctfile_is_open; /* XXX */

	ctfile_is_open = 0;	/* prevent trying to close upon next download */
again:
	CNDBG(CT_LOG_CTFILE, "ctfile %s", ctfile);

	/* this will provide us the path that we need to use */
	prevfile = ctfile_get_previous(ctfile);
	if (prevfile == NULL)
		goto out;

	if (prevfile[0] != '\0') {
		cookedname = ctfile_cook_name(prevfile);
		cachename = ctfile_get_cachename(cookedname);
		CNDBG(CT_LOG_CTFILE, "prev file %s cachename %s", prevfile,
		    cachename);
		if (!ctfile_in_cache(cachename)) {
			e_free(&cachename);
			ct_add_operation_after(op, ctfile_extract,
			    ctfile_download_next, (char *)prevfile, cookedname,
				NULL, NULL, NULL, 0, 0);
		} else {
			if (ctfile)
				e_free(&ctfile);
			if (rfile)
				e_free(&rfile);
			e_free(&cookedname);
			e_free(&cachename);
			ctfile = prevfile;
			goto again;
		}
	} else
		e_free(&prevfile);

out:
	if (ctfile)
		e_free(&ctfile);
	if (rfile)
		e_free(&rfile);

}

char *
ctfile_find_for_archive(const char *ctfile)
{
	char	 buf[TIMEDATA_LEN], *fullname, *cachename;
	time_t	 now;

	/* cook the ctfile so we only search for the actual tag */
	ctfile = ctfile_cook_name(ctfile);

	if (ctfile_is_fullname(ctfile) != 0)
		CFATALX("metadata name with date tag already filled in");

	now = time(NULL);
	if (strftime(buf, TIMEDATA_LEN, "%Y%m%d-%H%M%S",
	    localtime(&now)) == 0)
		CFATALX("can't format time");
	e_asprintf(&fullname, "%s-%s", buf, ctfile);
	CNDBG(CT_LOG_CTFILE, "backup file is %s", fullname);

	/* check it isn't already in the cache */
	cachename = ctfile_get_cachename(fullname);
	if (ctfile_in_cache(fullname))
		CFATALX("generated metadata name %s already in cache dir",
		    fullname);

	e_free(&ctfile);
	e_free(&fullname);

	return (cachename);
}

void
ct_free_localname(struct ct_op *op)
{

	if (op->op_local_fname != NULL)
		e_free(&op->op_local_fname);
}

void
ct_free_remotename(struct ct_op *op)
{
	if (op->op_remote_fname != NULL)
		e_free(&op->op_remote_fname);
}

void
ct_free_localname_and_remote(struct ct_op *op)
{
	ct_free_localname(op);
	ct_free_remotename(op);
}

