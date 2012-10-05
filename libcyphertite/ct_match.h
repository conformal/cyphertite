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
#ifndef CT_MATCH_H
#define CT_MATCH_H

/* API to match straings against previously provided lists of criteria */
#define CT_MATCH_INVALID	(0)
#define CT_MATCH_REGEX		(1)
#define CT_MATCH_RB		(2)
#define CT_MATCH_GLOB		(3)
#define CT_MATCH_EVERYTHING	(4)

struct ct_match;

int			 ct_match_compile(struct ct_match **, int, char **);
char			**ct_matchlist_fromfile(const char *, int *);
void			 ct_matchlist_free(char **);
int			 ct_match(struct ct_match *, char *);
void			 ct_match_unwind(struct ct_match *);
void			 ct_match_insert_rb(struct ct_match *, char *);
int			 ct_match_rb_is_empty(struct ct_match *);

#endif /* ! CT_MATCH_H */
