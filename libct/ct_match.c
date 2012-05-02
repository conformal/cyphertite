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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/tree.h>
#include <regex.h>
#include <fnmatch.h>
#include <clog.h>
#include <exude.h>

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include "ct_match.h"


struct ct_match_node {
	RB_ENTRY(ct_match_node)	cmn_entry;
	char			*cmn_string;
};

RB_HEAD(ct_match_tree, ct_match_node);

struct ct_match {
	union {
		regex_t			*regex;
		char			**glob;
		struct ct_match_tree	*rb_head;
	}				 cm_pattern;
#define cm_regex	cm_pattern.regex
#define cm_glob		cm_pattern.glob
#define cm_rb_head	cm_pattern.rb_head
	int				 cm_mode;
};


void		ct_regex_comp(regex_t *, char **);
int		ct_regex_match(regex_t *, char *);
void		ct_regex_unwind(regex_t *);
void		ct_glob_unwind(char **);
int		ct_glob_match(char **, char *);
void		ct_rb_comp(struct ct_match_tree *, char **);
int		ct_rb_match(struct ct_match_tree *, char *);
void		ct_rb_unwind(struct ct_match_tree *);
int		ct_match_rb_cmp(struct ct_match_node *, struct ct_match_node *);
int
ct_match_rb_cmp(struct ct_match_node *d1, struct ct_match_node *d2)
{
	return (strcmp(d1->cmn_string, d2->cmn_string));
}

RB_PROTOTYPE(ct_match_tree, ct_match_node, cmn_entry, ct_match_rb_cmp);
RB_GENERATE(ct_match_tree, ct_match_node, cmn_entry, ct_match_rb_cmp);

void
ct_regex_comp(regex_t *re, char **flist)
{
	int i, rv;
	char *s, *q = NULL, error[1024];

	for (i = 0; flist[i] != NULL; i++) {
		if (flist[i] == NULL)
			break;

		if (i == 0)
			e_asprintf(&s, "%s", flist[i]);
		else
			e_asprintf(&s, "%s|%s", q, flist[i]);

		if (q)
			e_free(&q);
		q = s;
	}

	if (q == NULL)
		return;

	if ((rv = regcomp(re, q, REG_EXTENDED | REG_NOSUB)) != 0) {
		regerror(rv, re, error, sizeof(error) - 1);
		CFATALX("extract_archive: regcomp failed: %s", error);
	}

	e_free(&q);
}

int
ct_regex_match(regex_t *re, char *file)
{
	if (re == NULL)
		return (0); /* no pattern means everything matches */

	if (regexec(re, file, 0, NULL, 0) == 0) {
		/* we got a match */
		return (0);
	}

	return (1); /* no match */
}

void
ct_regex_unwind(regex_t *re)
{
	if (re == NULL)
		return;

	regfree(re);
}

void
ct_glob_unwind(char **g)
{
	int			i;

	for (i = 0; g[i] != NULL; i++) {
		if (g[i] == NULL)
			break;
		e_free(&g[i]);
	}
}

int
ct_glob_match(char **g, char *file)
{
	int			i;

	if (g == NULL)
		return (0); /* no pattern means everything matches */

	for (i = 0; g[i] != NULL; i++) {
		if (g[i] == NULL)
			break;
		if (fnmatch(g[i], file, 0) == 0)
			return (0); /* match */
	}

	return (1); /* no match */
}

void
ct_match_insert_rb(struct ct_match *match, char *string)
{
	struct ct_match_node	*n;

	if (match->cm_mode != CT_MATCH_RB)
		CFATALX("match mode %d is not rb", match->cm_mode);
	n = e_calloc(1, sizeof(struct ct_match_node));
	n->cmn_string = e_strdup(string);
	if (RB_INSERT(ct_match_tree, match->cm_rb_head, n)) {
		/* pattern already exists free it */
		e_free(&n->cmn_string);
		e_free(&n);
	}
}
int
ct_match_rb_is_empty(struct ct_match *match)
{
	if (match->cm_mode != CT_MATCH_RB)
		CFATALX("match mode %d is not rb", match->cm_mode);
	return (RB_EMPTY(match->cm_rb_head));
}


void
ct_rb_comp(struct ct_match_tree *head, char **flist)
{
	int			i;
	struct ct_match_node	*n;

	for (i = 0; flist[i] != NULL; i++) {
		if (flist[i] == NULL)
			break;
		n = e_calloc(1, sizeof(struct ct_match_node));
		n->cmn_string = e_strdup(flist[i]);
		if (RB_INSERT(ct_match_tree, head, n)) {
			/* pattern already exists free it */
			e_free(&n->cmn_string);
			e_free(&n);
			continue;
		}
	}
}

int
ct_rb_match(struct ct_match_tree *head, char *file)
{
	struct ct_match_node	*n, nfind;

	if (RB_EMPTY(head))
		return (1); /* no pattern means nothing matches */

	nfind.cmn_string = file;
	n = RB_FIND(ct_match_tree, head, &nfind);
	if (n == NULL)
		return (1);
	RB_REMOVE(ct_match_tree, head, n);
	e_free(&n->cmn_string);
	e_free(&n);

	return (0);
}

void
ct_rb_unwind(struct ct_match_tree *head)
{
	struct ct_match_node	*n;

	while (!RB_EMPTY(head)) {
		n = RB_MIN(ct_match_tree, head);
		RB_REMOVE(ct_match_tree, head, n);
		e_free(&n->cmn_string);
		e_free(&n);
	}
}

struct ct_match *
ct_match_compile(int mode, char **flist)
{
	struct ct_match	*match;
	int		 i;

	match = e_calloc(1, sizeof(*match));
	match->cm_mode = mode;

	switch (mode) {
	case CT_MATCH_REGEX:
		match->cm_regex = e_calloc(1, sizeof(regex_t));
		ct_regex_comp(match->cm_regex, flist);
		break;
	case CT_MATCH_RB:
		match->cm_rb_head = e_calloc(1, sizeof(*match->cm_rb_head));
		ct_rb_comp(match->cm_rb_head, flist);
		break;
	case CT_MATCH_GLOB:
		for (i = 0; flist[i] != NULL; i++)
			if (flist[i] == NULL)
				break;
		if (i == 0)
			return (match);
		i++; /* extra NULL */
		match->cm_glob = e_calloc(i, sizeof(char *));

		for (i = 0; flist[i] != NULL; i++) {
			if (flist[i] == NULL)
				break;
			match->cm_glob[i] = e_strdup(flist[i]);
		}
		break;
	default:
		CFATALX("invalid match mode");
	}

	return (match);
}

void
ct_match_unwind(struct ct_match *match)
{
	switch (match->cm_mode) {
	case CT_MATCH_REGEX:
		if (match->cm_regex) {
			ct_regex_unwind(match->cm_regex);
			e_free(&match->cm_regex);
		}
		break;
	case CT_MATCH_RB:
		if (match->cm_rb_head) {
			ct_rb_unwind(match->cm_rb_head);
			e_free(&match->cm_rb_head);
		}
		break;
	case CT_MATCH_GLOB:
		if (match->cm_glob) {
			ct_glob_unwind(match->cm_glob);
			e_free(&match->cm_glob);
		}
		break;
	default:
		CFATALX("invalid match mode");
	}
	e_free(&match);
}

int
ct_match(struct ct_match *match, char *candidate)
{
	switch (match->cm_mode) {
	case CT_MATCH_REGEX:
		return (ct_regex_match(match->cm_regex, candidate));
		break;
	case CT_MATCH_RB:
		return (ct_rb_match(match->cm_rb_head, candidate));
		break;
	case CT_MATCH_GLOB:
		return (ct_glob_match(match->cm_glob, candidate));
		break;
	default:
		CFATALX("invalid match mode");
	}
	/* NOTREACHED */
}

char **
ct_matchlist_fromfile(const char *file)
{
	FILE		*f;
	char		**flist, *line;
	size_t		 len, lineno = 0;
	int		 n = 0;

	if ((f = fopen(file, "r")) == NULL)
		CFATAL("can't open match file %s", file);

	/* XXX:
	 * Wish there was a nicer way to count these lines.
	 * Handle comments ?
	 */
	while ((line = fparseln(f, &len, NULL, NULL, 0)) != NULL) {
		if (len != 0)	/* skip empty lines */
			n++;
		free(line);
	}

	if (n == 0)
		return (NULL);
	if (fseeko(f, 0, SEEK_SET) != 0)
		CFATAL("can't seek to start of match file %s", file);
	flist = e_calloc(n + 1, sizeof(*flist));

	/* do it again actually parsing this time */
	n = 0;
	while ((line = fparseln(f, &len, &lineno, NULL, 0)) != NULL) {
		if (len == 0) {
			free(line);
			continue;
		}
		flist[n++] = line;
	}

	(void)fclose(f);

	return flist;
}

void
ct_matchlist_free(char **flist)
{
	char **tmp = flist;

	while (*tmp != NULL)
		free(*(tmp++));
	e_free(&flist);
}

struct ct_match *
ct_match_fromfile(const char *file, int matchmode)
{
	struct ct_match	*match;
	char		**flist;

	if ((flist = ct_matchlist_fromfile(file)) == NULL)
		return (NULL);

	match = ct_match_compile(matchmode, flist);

	return (match);
}

#if 0
int
main(int argc, char *argv[])
{
	uint32_t		cflags;
	int			c, imode;
	char			*mode = NULL, *match = NULL;

	clog_init(1);
	cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC | CLOG_F_LINE |
	    CLOG_F_DTIME;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");
	CINFO("start");

	while ((c = getopt(argc, argv, "m:M:")) != -1) {
		switch (c) {
		case 'm':
			mode = optarg;
			break;
		case 'M':
			match = optarg;
			break;
		default:
			CFATALX("invalid option");
		}
	}
	argc -= optind;
	argv += optind;

	if (mode) {
		if (!strcmp(mode, "regex"))
			imode = CT_MATCH_REGEX;
		else if (!strcmp(mode, "rb"))
			imode = CT_MATCH_RB;
		else if (!strcmp(mode, "glob"))
			imode = CT_MATCH_GLOB;
		else
			CFATALX("invalid mode %s", mode);
	} else
		CFATALX("no mode");

	if (match == NULL)
		CFATALX("no match");

	CDBG("mode: %s", mode);

	ct_match_compile(imode, argv);

	if (ct_match(imode, match))
		printf("%s not matched\n", match);
	else
		printf("%s matched\n", match);

	ct_match_unwind(imode);

	e_check_memory();

	return (0);
}
#endif
