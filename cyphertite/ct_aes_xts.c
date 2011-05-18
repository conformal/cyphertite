/* $cyphertite$ */
/*
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2008 Damien Miller <djm@openbsd.org>
 * Copyright (c) 2010 Joel Sing <jsing@openbsd.org>
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

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_CRYPT_SIZE_TYPE size_t
#else
#define SSL_CRYPT_SIZE_TYPE unsigned int
#endif

#define GF2_128_ALPHA   0x87

struct aes_xts_ctx
{
	AES_KEY		aes_key1;
	AES_KEY		aes_key2;
	u_char		unit_no[AES_BLOCK_SIZE]; /* Unit no in network order. */
	u_char		tweak[AES_BLOCK_SIZE];
	int		init_tweak;
	int		enc;
};

const EVP_CIPHER *EVP_aes_xts(void);

static int
aes_xts_init(EVP_CIPHER_CTX *cc, const u_char *key, const u_char *iv, int enc)
{
	struct aes_xts_ctx *ctx;
	int i;

	ctx = EVP_CIPHER_CTX_get_app_data(cc);
	if (ctx == NULL) {
		ctx = malloc(sizeof(*ctx));
		if (ctx == NULL)
			return (0);
		bzero(ctx, sizeof(*ctx));
		EVP_CIPHER_CTX_set_app_data(cc, ctx);
	}

	if (enc != -1)
		ctx->enc = enc;

	if (iv != NULL) {
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			ctx->unit_no[i] = iv[i];
		ctx->init_tweak = 1;
	}

	if (key != NULL) {

		if (EVP_CIPHER_CTX_key_length(cc) != 32 &&
		    EVP_CIPHER_CTX_key_length(cc) != 64)
			return (0);

		if (enc)
			AES_set_encrypt_key(key,
			    (EVP_CIPHER_CTX_key_length(cc) / 2) * 8,
			    &ctx->aes_key1);
		else
			AES_set_decrypt_key(key,
			    (EVP_CIPHER_CTX_key_length(cc) / 2) * 8,
			    &ctx->aes_key1);

		AES_set_encrypt_key(key + (EVP_CIPHER_CTX_key_length(cc) / 2),
		    (EVP_CIPHER_CTX_key_length(cc) / 2) * 8, &ctx->aes_key2);

	}

	return (1);
}

static int
aes_xts_cleanup(EVP_CIPHER_CTX *cc)
{
	struct aes_xts_ctx *ctx;

	ctx = EVP_CIPHER_CTX_get_app_data(cc);
	if (ctx != NULL) {
		bzero(ctx, sizeof(*ctx));
		free(ctx);
		EVP_CIPHER_CTX_set_app_data(cc, NULL);
	}

	return (1);
}

static int
aes_xts_crypt(EVP_CIPHER_CTX *cc, u_char *dst, const u_char *src,
     SSL_CRYPT_SIZE_TYPE len)
{
	struct aes_xts_ctx *ctx;
	uint8_t block[AES_BLOCK_SIZE];
	uint carry_in, carry_out;
	int i, j;

	if (len % AES_BLOCK_SIZE != 0)
		return (0);

	ctx = EVP_CIPHER_CTX_get_app_data(cc);
	if (ctx == NULL)
		return (0);

	if (ctx->init_tweak) {

		/* Tweak starts as E(key2, unit_no as 128-bit LE). */
		for (i = 0; i < AES_BLOCK_SIZE; i++)
			ctx->tweak[i] = ctx->unit_no[AES_BLOCK_SIZE - 1 - i];
		AES_encrypt(ctx->tweak, ctx->tweak, &ctx->aes_key2);
		ctx->init_tweak = 0;

	}

	for (i = 0; i < len; i += AES_BLOCK_SIZE) {

		for (j = 0; j < AES_BLOCK_SIZE; j++)
			block[j] = src[i + j] ^ ctx->tweak[j];

		if (ctx->enc)
			AES_encrypt(block, dst + i, &ctx->aes_key1);
		else
			AES_decrypt(block, dst + i, &ctx->aes_key1);

		for (j = 0; j < AES_BLOCK_SIZE; j++)
			dst[i + j] ^= ctx->tweak[j];

		/* Exponentiate tweak. */
		carry_in = 0;
		for (j = 0; j < AES_BLOCK_SIZE; j++) {
			carry_out = ctx->tweak[j] & 0x80;
			ctx->tweak[j] =
			    (ctx->tweak[j] << 1) | (carry_in ? 1 : 0);
			carry_in = carry_out;
		}
		if (carry_in)
			ctx->tweak[0] ^= GF2_128_ALPHA;

	}

	bzero(block, sizeof(block));

	return (1);
}

const EVP_CIPHER
*EVP_aes_xts(void)
{
	static EVP_CIPHER aes_xts;

	bzero(&aes_xts, sizeof(EVP_CIPHER));

	aes_xts.nid = NID_undef;
	aes_xts.block_size = AES_BLOCK_SIZE;
	aes_xts.iv_len = 0;
	aes_xts.key_len = 0;
	aes_xts.init = aes_xts_init;
	aes_xts.cleanup = aes_xts_cleanup;
	aes_xts.do_cipher = aes_xts_crypt;
	aes_xts.flags = EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_ALWAYS_CALL_INIT |
	    EVP_CIPH_CUSTOM_IV;

	return (&aes_xts);
}
