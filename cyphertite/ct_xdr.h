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

#ifdef __linux__
#define xdr_u_int32_t	xdr_uint32_t
#define xdr_u_int64_t	xdr_uint64_t
#endif

bool_t          ct_xdr_dedup_sha(XDR *, uint8_t *);
bool_t		ct_xdr_dedup_sha_crypto(XDR *, uint8_t *, uint8_t *,
			uint8_t *);
bool_t          ct_xdr_header(XDR *, struct ct_md_header *);
bool_t          ct_xdr_trailer(XDR *, struct ct_md_trailer *);
bool_t          ct_xdr_stdin(XDR *, struct ct_md_stdin *);
bool_t          ct_xdr_gheader(XDR *, struct ct_md_gheader *, int);

FILE           *ct_metadata_open(const char *,
			struct ct_md_gheader *);
int             ct_read_trailer(struct ct_md_trailer *);
