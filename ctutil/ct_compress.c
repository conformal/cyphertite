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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include <clog.h>

#include "ctutil.h"


int
ct_init_compression(uint16_t comp_type)
{
	uint16_t		comp;

	/* this is a little clunky */
	if ((comp_type & C_HDR_F_COMPRESSED_MASK) == C_HDR_F_COMP_LZO) {
		comp = SHRINK_ALG_LZO;
	} else if ((comp_type & C_HDR_F_COMPRESSED_MASK) == C_HDR_F_COMP_LZW) {
		comp = SHRINK_ALG_LZW;
	} else if ((comp_type & C_HDR_F_COMPRESSED_MASK) == C_HDR_F_COMP_LZMA) {
		comp = SHRINK_ALG_LZMA;
	} else {
		comp = SHRINK_ALG_LZW;
		CWARNX("defaulting to LZW compression");
	}

	if (s_init(comp, SHRINK_L_MID))
		return (1);

	return (0);
}

int
ct_uncompress(uint8_t *src, uint8_t *dst, size_t len, size_t *uncomp_sz)
{
	int			rv;

	if ((rv = s_decompress(src, dst, len, uncomp_sz, NULL)) != SHRINK_OK)
		return (1);
	return (0);
}

int
ct_compress(uint8_t *src, uint8_t *dst, size_t len, size_t *comp_sz)
{
	int			rv;

	if ((rv = s_compress(src, dst, len, comp_sz, NULL) != SHRINK_OK))
		return (1);
	return (0);
}

