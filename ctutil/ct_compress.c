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

#include <shrink.h>
#include <clog.h>

#include "ctutil.h"

/*
 * XXX may be easier to avoid the indirection and just use shrink directly from
 * within cyphertite.
 */
struct ct_compress_ctx {
	struct shrink_ctx	*ccc_shrink;
	uint16_t		 ccc_type;
};

struct ct_compress_ctx *
ct_init_compression(uint16_t comp_type)
{
	struct ct_compress_ctx	*ccc;
	uint16_t		 comp;
	uint16_t		 type;

	if ((ccc = calloc(1, sizeof(*ccc))) == NULL)
		return (NULL);
	
	type = comp_type & C_HDR_F_COMPRESSED_MASK;
	/* this is a little clunky */
	if (type == C_HDR_F_COMP_LZO) {
		comp = SHRINK_ALG_LZO;
	} else if (type == C_HDR_F_COMP_LZW) {
		comp = SHRINK_ALG_LZW;
	} else if (type == C_HDR_F_COMP_LZMA) {
		comp = SHRINK_ALG_LZMA;
	} else {
		comp = SHRINK_ALG_LZW;
		type = C_HDR_F_COMP_LZW;
		CWARNX("defaulting to LZW compression");
	}
	ccc->ccc_type = type;

	if ((ccc->ccc_shrink = shrink_init(comp, SHRINK_L_MID)) == NULL) {
		free(ccc);
		return (NULL);
	}

	return (ccc);
}

int
ct_uncompress(struct ct_compress_ctx *ccc, uint8_t *src, uint8_t *dst,
    size_t len, size_t *uncomp_sz)
{
	int			rv;

	if ((rv = shrink_decompress(ccc->ccc_shrink, src, dst, len, uncomp_sz,
	    NULL)) != SHRINK_OK)
		return (1);
	return (0);
}

int
ct_compress(struct ct_compress_ctx *ccc, uint8_t *src, uint8_t *dst,
    size_t len, size_t *comp_sz)
{
	int			rv;

	if ((rv = shrink_compress(ccc->ccc_shrink, src, dst, len,
	    comp_sz, NULL) != SHRINK_OK))
		return (1);
	return (0);
}

uint16_t
ct_compress_type(struct ct_compress_ctx *ccc)
{
	return (ccc->ccc_type);
}

size_t
ct_compress_bounds(struct ct_compress_ctx *ccc, size_t blocksize)
{
	return (shrink_compress_bounds(ccc->ccc_shrink, blocksize));
}

void
ct_cleanup_compression(struct ct_compress_ctx *ccc)
{
	if (ccc == NULL)
		return;
	shrink_cleanup(ccc->ccc_shrink);
	free(ccc);
}
