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

void	ctfile_find_for_extract(struct ct_op *);
void	ctfile_find_for_extract_complete(struct ct_op *);
void	ctfile_extract_nextop(struct ct_op *);
void	ctfile_download_next(struct ct_op *);
void	ctfile_nextop_extract_cleanup(struct ct_op *);
void	ctfile_nextop_archive_cleanup(struct ct_op *);

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

struct ct_ctfile_find_args {
	char			*ccfa_tag;
	ctfile_find_callback	*ccfa_nextop;
	void			*ccfa_nextop_args;
	int			 ccfa_download_chain;
	int			 ccfa_empty_ok;
};

struct ct_ctfile_find_fileop_args {
	struct ct_ctfileop_args	 ccffa_base;
	ctfile_find_callback	*ccffa_nextop;
	void			*ccffa_nextop_args;
	int			 ccffa_download_chain;
};

void
ctfile_find_for_operation(char *tag, ctfile_find_callback *nextop,
    void *nextop_args, int download_chain, int empty_ok)
{
	struct ct_ctfile_find_args  *ccfa;
	ccfa = e_calloc(1, sizeof(*ccfa));
	ccfa->ccfa_tag = tag;
	ccfa->ccfa_nextop = nextop;
	ccfa->ccfa_nextop_args = nextop_args;
	ccfa->ccfa_download_chain = download_chain;
	ccfa->ccfa_empty_ok = empty_ok;

	ct_add_operation(ctfile_find_for_extract,
	    ctfile_find_for_extract_complete, ccfa);
}
/*
 * filenames passed in remote mode are opaque tags for the backup.
 * they are stored on the server and in remote mode in the form
 * YYYYMMDD-HHMMSS-<strnvis(mname)>
 */
void
ctfile_find_for_extract(struct ct_op *op)
{
	struct ct_ctfile_find_args	*ccfa = op->op_args;
	const char			*ctfile = ccfa->ccfa_tag;
	struct ct_op			*list_fakeop;
	struct ct_ctfile_list_args	*ccla;

	/* cook the ctfile so we only search for the actual tag */
	ctfile = ctfile_cook_name(ctfile);

	list_fakeop = e_calloc(1, sizeof(*list_fakeop));
	ccla = e_calloc(1, sizeof(*ccla));
	list_fakeop->op_args = ccla;
	ccla->ccla_search = e_calloc(2, sizeof(char **));
	if (ctfile_is_fullname(ctfile)) {
		/* use list as stat() for now */
		*ccla->ccla_search = e_strdup(ctfile);
		ccla->ccla_matchmode = CT_MATCH_GLOB;
	} else {
		e_asprintf(ccla->ccla_search,
		    "^[[:digit:]]{8}-[[:digit:]]{6}-%s$", ctfile);

		ccla->ccla_matchmode = CT_MATCH_REGEX;
		/*
		 * get the list of files matching this tag from the server.
		 * list returns an empty list if it found
		 * nothing and NULL upon failure.
		 */
	}
	e_free(&ctfile);

	CNDBG(CT_LOG_CTFILE, "looking for %s", ccla->ccla_search[0]);

	op->op_priv = list_fakeop;
	ctfile_list_start(list_fakeop);
}

/*
 * List has completed.
 *
 * Select the best filename for download, and download it if missing.
 */
void
ctfile_find_for_extract_complete(struct ct_op *op)
{
	struct ct_ctfile_find_args		*ccfa = op->op_args;
	struct ct_ctfile_find_fileop_args	*ccffa;
	struct ct_op				*list_fakeop = op->op_priv;
	struct ct_ctfile_list_args		*ccla = list_fakeop->op_args;
	struct ctfile_list_tree			 result;
	struct ctfile_list_file			*tmp;
	char	 				*best, *cachename = NULL;

	RB_INIT(&result);
	ctfile_list_complete(ccla->ccla_matchmode, ccla->ccla_search,
	    ccla->ccla_exclude, &result);
	e_free(ccla->ccla_search);
	e_free(&ccla->ccla_search);
	e_free(&ccla);
	e_free(&list_fakeop);

	/*
	 * Prepare arguments for next operation.
	 * either we'll download the next file, or skip straight to
	 * the callback for after the download, either way we need the nextop
	 */
	ccffa = e_calloc(1, sizeof(*ccffa));
	ccffa->ccffa_nextop = ccfa->ccfa_nextop;
	ccffa->ccffa_nextop_args = ccfa->ccfa_nextop_args;
	ccffa->ccffa_download_chain = ccfa->ccfa_download_chain;

	/* grab the newest one */
	if ((tmp = RB_MAX(ctfile_list_tree, &result)) == NULL) {
		if (ccfa->ccfa_empty_ok) 
			goto do_operation;
		else 
			CFATALX("unable to find metadata tagged %s",
			    ccfa->ccfa_tag);
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
		ccffa->ccffa_base.cca_localname = cachename;
		ccffa->ccffa_base.cca_remotename = best;
		ct_add_operation(ctfile_extract, ctfile_extract_nextop,
		    ccffa);
	} else {
		e_free(&best);
do_operation:
		/*
		 * No download needed, fake the next operation callback
		 * to see if we need anymore.
		 */
		ccffa->ccffa_base.cca_localname = cachename;
		op->op_args = ccffa;
		ctfile_extract_nextop(op);
	}
	e_free(&ccfa);
}

/*
 * now the operation has completed we can kick off the next operation knowing
 * that everything has been set up for it.
 */
void
ctfile_extract_nextop(struct ct_op *op)
{
	struct ct_ctfile_find_fileop_args	*ccffa = op->op_args;
	struct ct_ctfileop_args			*cca;
	extern int		 		 ctfile_is_open; /* XXX */

	ctfile_is_open = 0;

	/*
	 * If this is an operation that needs the full differential chain
	 * recursively fetch the next one in the chain till done.
	 */
	if (ccffa->ccffa_download_chain) {
		/*
		 * download_next takes ownership of the pointers it is given,
		 * duplicate our copy.
		 */
		cca = e_calloc(1, sizeof(*cca));
		if (ccffa->ccffa_base.cca_localname)
			cca->cca_localname =
			    e_strdup(ccffa->ccffa_base.cca_localname);
		if (ccffa->ccffa_base.cca_remotename)
			cca->cca_remotename =
			    e_strdup(ccffa->ccffa_base.cca_remotename);
		op->op_args = cca;
		ctfile_download_next(op);
	}

	/*
	 * We now have the name of the file we wish to perform the main
	 * operation on, the nextop callback will add this operation
	 * to the operation list. Ownership of the allocated pointer
	 * passes to the child.
	 */
	ccffa->ccffa_nextop(ccffa->ccffa_base.cca_localname,
	    ccffa->ccffa_nextop_args);
	if (ccffa->ccffa_base.cca_remotename)
		e_free(&ccffa->ccffa_base.cca_remotename);
	e_free(&ccffa);
}

/*
 * Download all dependant ctfiles of the current ctfile.
 * (called repeatedly until all are fetched).
 */
void
ctfile_download_next(struct ct_op *op)
{
	struct ct_ctfileop_args	*cca = op->op_args, *nextcca; 
	const char		*ctfile = cca->cca_localname;
	const char		*rfile = cca->cca_remotename;
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
			nextcca = e_calloc(1, sizeof(*nextcca));
			nextcca->cca_localname = prevfile;
			nextcca->cca_remotename = cookedname;
			ct_add_operation_after(op, ctfile_extract,
			    ctfile_download_next, nextcca);
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
	e_free(&cca);
}

void
ctfile_nextop_extract(char *ctfile, void *args)
{
	struct ct_extract_args	*cea = args;

	cea->cea_local_ctfile = ctfile;
	ct_add_operation(ct_extract, ctfile_nextop_extract_cleanup, cea);
}

void
ctfile_nextop_list(char *ctfile, void *args)
{
	struct ct_extract_args	*cea = args;

	cea->cea_local_ctfile = ctfile;
	ct_add_operation(ct_list_op, ctfile_nextop_extract_cleanup, cea);
}

void
ctfile_nextop_extract_cleanup(struct ct_op *op)
{
	struct ct_extract_args	*cea = op->op_args;

	if (cea->cea_local_ctfile)
		e_free(&cea->cea_local_ctfile);
}

void
ctfile_nextop_archive(char *basis, void *args)
{
	struct ct_archive_args	*caa = args;
	struct ct_ctfileop_args	*cca;
	char			*ctfile;
	char	 		 buf[TIMEDATA_LEN], *fullname, *cachename;
	time_t	 		 now;

	CNDBG(CT_LOG_CTFILE, "setting basisname %s", basis);
	caa->caa_basis = basis;

	/*
	 * We now have the basis found for us, cook and prepare the tag
	 * we wish to create then add the operation.
	 */
	ctfile = ctfile_cook_name(caa->caa_tag);

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

	caa->caa_local_ctfile = cachename;
	ct_add_operation(ct_archive, NULL, caa);
	/*
	 * set up an additional operation to upload the newly created
	 * ctfile after the archive is completed.
	 */
	cca = e_calloc(1, sizeof(*cca));
	cca->cca_localname = cachename;
	ct_add_operation(ctfile_archive, ctfile_nextop_archive_cleanup, cca);
}

void
ctfile_nextop_archive_cleanup(struct ct_op *op)
{
	struct ct_ctfileop_args	*cca = op->op_args;

	if (cca->cca_localname)
		e_free(&cca->cca_localname);
	if (cca->cca_remotename)
		e_free(&cca->cca_remotename);
	e_free(&cca);
}

void
ctfile_nextop_justdl(char *ctfile, void *args)
{
	char		**filename = args;

	*filename = ctfile;

	/* done, jump out of the loop */
	ct_add_operation(ct_shutdown_op, NULL, NULL);
}
