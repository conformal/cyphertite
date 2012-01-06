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

#include <openssl/evp.h>

#define CT_KEY_LEN	(256>>3)
#define CT_IV_LEN	(256>>3)

int			ct_crypto_crypt(const EVP_CIPHER *, uint8_t *, size_t,
			    uint8_t *, size_t, uint8_t *, size_t, uint8_t *,
			    size_t, int);
int			ct_encrypt(uint8_t *, size_t, uint8_t *, size_t,
			    uint8_t *, size_t, uint8_t *, size_t);
int			ct_decrypt(uint8_t *, size_t, uint8_t *, size_t,
			    uint8_t *, size_t, uint8_t *, size_t);
int			ct_create_iv(uint8_t *, size_t, uint8_t *, size_t,
			    uint8_t *, size_t);
int			ct_create_secrets(const char *, const char *, uint8_t *, uint8_t *);
int			ct_unlock_secrets(const char *, const char *, uint8_t *, size_t,
			    uint8_t *, size_t);
void			ct_crypt_create_iv(uint8_t *iv, size_t, uint8_t *,
			    size_t);
int			ct_crypto_blocksz(void);
int			ct_create_or_unlock_secrets(const char *, const char *);
