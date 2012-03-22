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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include <string.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#include <clog.h>

#include "ctutil.h"


void
ct_sha1(uint8_t *src, uint8_t *dst, size_t len)
{
	SHA_CTX		ctx;

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, src, len);
	SHA1_Final(dst, &ctx);
}

void
ct_sha1_setup(SHA_CTX *ctx)
{
	SHA1_Init(ctx);
}

void
ct_sha1_add(uint8_t *src, SHA_CTX *ctx, size_t len)
{
	SHA1_Update(ctx, src, len);
}

void
ct_sha1_final(uint8_t *dst, SHA_CTX *ctx)
{
	SHA1_Final(dst, ctx);
}

void
ct_sha1_encode(uint8_t *sha, char *s)
{
	int			i;

	if (!s)
		CFATALX("invalid s pointer");

	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		snprintf(&s[i * 2], 3, "%02x", sha[i]);
}


void
ct_sha512(uint8_t *src, uint8_t *dst, size_t len)
{
	SHA512_CTX		ctx;

	SHA512_Init(&ctx);
	SHA512_Update(&ctx, src, len);
	SHA512_Final(dst, &ctx);
}

void
ct_sha512_setup(SHA512_CTX *ctx)
{
	SHA512_Init(ctx);
}

void
ct_sha512_add(uint8_t *src, SHA512_CTX *ctx, size_t len)
{
	SHA512_Update(ctx, src, len);
}

void
ct_sha512_final(uint8_t *dst, SHA512_CTX *ctx)
{
	SHA512_Final(dst, ctx);
}

void
ct_sha512_encode(uint8_t *sha, char *s)
{
	int			i;

	if (!s)
		CFATALX("invalid s pointer");

	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		snprintf(&s[i * 2], 3, "%02x", sha[i]);
}

int
ct_base64_encode(int mode, uint8_t *src, size_t src_len, uint8_t *dst,
    size_t dst_len)
{
	int			rv = -1;
	BIO			*b64 = NULL, *rwbio = NULL;
	BUF_MEM			*p;
	size_t			i;

	if (src == NULL || dst == NULL || src_len < 1 || dst_len < 1) {
		CWARNX("invalid parameters");
		return (-1);
	}
	if (!(mode != CT_B64_ENCODE || mode != CT_B64_DECODE) ||
	    !(mode != CT_B64_M_ENCODE || mode != CT_B64_M_DECODE)) {
		CWARNX("invalid mode");
		return (-1);
	}

	bzero(dst, dst_len);

	if (mode == CT_B64_ENCODE || mode == CT_B64_M_ENCODE) {
		rwbio = BIO_new(BIO_s_mem());
		if (rwbio == NULL) {
			CWARNX("no rwbio");
			return (-1);
		}
	} else {
		if (mode == CT_B64_M_DECODE) {
			for (i = 0; i < src_len; i++) {
				if (src[i] == '-')
					src[i] = '/';
			}
		}
		rwbio = BIO_new_mem_buf(src, src_len);
		if (rwbio == NULL) {
			CWARNX("no rwbio");
			return (-1);
		}
	}

	b64 = BIO_new(BIO_f_base64());
	if (b64 == NULL) {
		CWARNX("no b64");
		BIO_free(rwbio);
		goto done;
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	rwbio = BIO_push(b64, rwbio);

	if (mode == CT_B64_ENCODE || mode == CT_B64_M_ENCODE) {
		if (BIO_write(rwbio, src, src_len) <= 0) {
			CWARNX("BIO_write base64 encode");
			goto done;
		}
		if (!BIO_flush(rwbio)) {
			CWARNX("can't flush rwbio");
			goto done;
		}
		BIO_get_mem_ptr(b64, &p);
		if (p->length > dst_len) {
			CWARNX("invalid destination length");
			goto done;
		}
		bcopy(p->data, dst, p->length);

		if (mode == CT_B64_M_ENCODE) {
			for (i = 0; i < p->length; i++) {
				if (dst[i] == '/')
					dst[i] = '-';
			}
		}

	} else {
		if (BIO_read(rwbio, dst, dst_len) <= 0) {
			CWARNX("BIO_read base64 decode");
			goto done;
		}
	}


	rv = 0;
done:
	if (b64)
		BIO_free_all(b64);

	return (rv);
}

