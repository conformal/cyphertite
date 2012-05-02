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
#ifndef CT_DB_H
#define CT_DB_H

/* localdb interface */
struct ctdb_state;

struct ctdb_state		*ctdb_setup(const char *, int);
void				 ctdb_shutdown(struct ctdb_state *);
int				 ctdb_insert_sha(struct ctdb_state *,
				     uint8_t *, uint8_t *, uint8_t *);
int				 ctdb_lookup_sha(struct ctdb_state *,
				     uint8_t *, uint8_t *, uint8_t *);
int				 ctdb_get_genid(struct ctdb_state *);
void				 ctdb_reopendb(struct ctdb_state *, int);

#endif /* ! CT_DB_H */
