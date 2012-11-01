/*
 * Copyright (c) 2012 Conformal Systems LLC <info@conformal.com>
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

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include <ct_match.h>

/* Flags */
#define CT_INIT_ASSL	1
#define CT_INIT_CLOG	2
#define CT_INIT_EXUDE	4

int ct_do_list(struct ct_global_state *, char **, char **,
    int,     int (*) (struct ct_global_state *, struct ct_op *));

int ct_do_archive(struct ct_global_state *, char *, char **,
    char *, char **, char **, int, int, int, int, int);

int ct_do_extract(struct ct_global_state *, char *, char *,
    char **, char **, int, int, int, int);

int ct_do_delete(struct ct_global_state *, char *, int);

int ct_setup_preinit(int, int, int);

int ct_setup_config(char *, struct ct_global_state **);

int ct_cleanup_all(struct ct_global_state *, char *);

int ct_do_check_existance(struct ct_global_state *, char *);

int list_print(struct ct_global_state *, struct ct_op *);
