/*
 * Copyright (c) 2010-2012 Conformal Systems LLC <info@conformal.com>
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

#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <clog.h>

#include "ct_crypto.h"
#include "ct.h"


#ifdef __linux__
#ifndef PASS_MAX
#define PASS_MAX		(1024)
#endif
#endif

const EVP_CIPHER *EVP_aes_xts(void);

/* passphrase stuff */
#define C_SALT_LEN		(128)
#define C_ROUNDS		(256000)
#define C_PWDKEY_LEN		(256>>3)
#define C_F_ROUNDS		("rounds = ")
#define C_F_ROUNDS_LEN		(strlen(C_F_ROUNDS))
#define C_F_SALT		("salt = ")
#define C_F_SALT_LEN		(strlen(C_F_SALT))
#define C_F_AESKEY		("e_aeskey = ")
#define C_F_AESKEY_LEN		(strlen(C_F_AESKEY))
#define C_F_IVKEY		("e_ivkey = ")
#define C_F_IVKEY_LEN		(strlen(C_F_IVKEY))
#define C_F_MASKKEY		("e_maskkey = ")
#define C_F_MASKKEY_LEN		(strlen(C_F_MASKKEY))
#define C_F_HMACMASKKEY		("hmac_maskkey = ")
#define C_F_HMACMASKKEY_LEN	(strlen(C_F_HMACMASKKEY))
#define C_F_DIGEST		("digest = ")
#define C_F_DIGEST_LEN		(strlen(C_F_DIGEST))
#define C_F_VERSION		("version = ")
#define C_F_VERSION_LEN		(strlen(C_F_VERSION))

#define C_FILE_VERSION		(1)

int	ct_crypto_init(EVP_CIPHER_CTX *, const EVP_CIPHER *, uint8_t *, size_t,
	    uint8_t *, size_t, int);
int	ct_crypto_update(EVP_CIPHER_CTX *, uint8_t *, size_t, uint8_t *, size_t);
int	ct_crypto_final(EVP_CIPHER_CTX *, uint8_t *);
int	ct_crypto_blocksz(void);
int	ct_passphrase_encrypt(uint8_t *, size_t, uint8_t *, size_t, uint8_t *,
	    size_t);
int	ct_passphrase_decrypt(uint8_t *, size_t, uint8_t *, size_t, uint8_t *,
	    size_t);
void	ct_fprintfhex(FILE *, char *, uint8_t *, size_t);
int	ct_fscanfhex(char *, uint8_t *, size_t);

/* crypto stuff */
int
ct_crypto_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key,
    size_t keylen, uint8_t *iv, size_t ivlen, int enc)
{
	int			rv = -1;

	/* setup crypto engine */
	EVP_CIPHER_CTX_init(ctx);
	if (!EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, enc)) {
		CNDBG(CT_LOG_CRYPTO, "can't init crypto");
		goto bad;
	}

	/* set key length */
	if (!EVP_CIPHER_CTX_set_key_length(ctx, keylen)) {
		CNDBG(CT_LOG_CRYPTO, "can't set key length");
		goto bad;
	}

	/* set key */
	if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc)) {
		CNDBG(CT_LOG_CRYPTO, "can't init crypto");
		goto bad;
	}

	/* sanity */
	if (EVP_CIPHER_CTX_key_length(ctx) != keylen) {
		CNDBG(CT_LOG_CRYPTO, "invalid key length");
		goto bad;
	}
	if (EVP_CIPHER_CTX_iv_length(ctx) != 0 &&
	    ivlen != 0 &&
	    EVP_CIPHER_CTX_iv_length(ctx) != ivlen) {
		CNDBG(CT_LOG_CRYPTO, "invalid iv length");
		goto bad;
	}

	rv = 0;
bad:
	return (rv);
}

int
ct_crypto_update(EVP_CIPHER_CTX *ctx, uint8_t *src, size_t srclen,
    uint8_t *dst, size_t dstlen)
{
	int			len = dstlen;

	if (!EVP_CipherUpdate(ctx, dst, &len, src, srclen)) {
		CNDBG(CT_LOG_CRYPTO, "couldn't encrypt");
		return (-1);
	}

	return (len);
}

int
ct_crypto_final(EVP_CIPHER_CTX *ctx, uint8_t *dst)
{
	int			len = -1;

	if (!EVP_CipherFinal_ex(ctx, dst, &len)) {
		CNDBG(CT_LOG_CRYPTO, "can't finalize encryption");
		return (-1);
	}

	return (len);
}

int
ct_crypto_crypt(const EVP_CIPHER *type, uint8_t *key, size_t keylen,
    uint8_t *iv, size_t ivlen, uint8_t *src, size_t srclen, uint8_t *dst,
    size_t dstlen, int enc)
{
	EVP_CIPHER_CTX		ctx;
	int			len, final, rv = -1;

	/* sanity */
	if (key == NULL || src == NULL || dst == NULL) {
		CNDBG(CT_LOG_CRYPTO, "invalid pointers");
		goto done;
	}
	if (srclen <= 0) {
		CNDBG(CT_LOG_CRYPTO, "invalid srclen");
		goto done;
	}

	/* encryption requires bigger block */
	if (enc && dstlen < srclen + EVP_CIPHER_block_size(type)) {
		CNDBG(CT_LOG_CRYPTO, "invalid dstlen while encrypting");
		goto done;
	}

	if (enc == 0 && dstlen < srclen - EVP_CIPHER_block_size(type)) {
		CNDBG(CT_LOG_CRYPTO, "invalid dstlen while decrypting");
		goto done;
	}

	if (ct_crypto_init(&ctx, type, key, keylen, iv, ivlen, enc)) {
		CNDBG(CT_LOG_CRYPTO, "can't init crypto engine");
		goto unwind;
	}

	if ((len = ct_crypto_update(&ctx, src, srclen, dst, dstlen)) == -1) {
		CNDBG(CT_LOG_CRYPTO, "can't encrypt");
		goto unwind;
	}

	if ((final = ct_crypto_final(&ctx, dst + len)) == -1) {
		CNDBG(CT_LOG_CRYPTO, "can't finalize encryption");
		goto unwind;
	}

	rv = final + len;
unwind:
	EVP_CIPHER_CTX_cleanup(&ctx);
done:
	return (rv);
}

int
ct_create_iv(uint8_t *key, size_t keylen, uint8_t *src, size_t srclen,
    uint8_t *iv, size_t ivlen)
{
	HMAC_CTX		hctx;

	if (ivlen != SHA256_DIGEST_LENGTH) {
		CNDBG(CT_LOG_CRYPTO, "invalid iv length");
		return (1);
	}

	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx, key, keylen, EVP_sha256(), NULL);
	HMAC_Update(&hctx, src, srclen >= ivlen ? ivlen : srclen);
	HMAC_Final(&hctx, iv, NULL);
	HMAC_CTX_cleanup(&hctx);

	return (0);
}

int
ct_encrypt(uint8_t *key, size_t keylen, uint8_t *iv, size_t ivlen,
    uint8_t *src, size_t srclen, uint8_t *dst, size_t dstlen)
{
	return (ct_crypto_crypt(EVP_aes_xts(), key, keylen, iv, ivlen, src,
	    srclen, dst, dstlen, 1));
}

int
ct_decrypt(uint8_t *key, size_t keylen, uint8_t *iv, size_t ivlen,
    uint8_t *src, size_t srclen, uint8_t *dst, size_t dstlen)
{
	return (ct_crypto_crypt(EVP_aes_xts(), key, keylen, iv, ivlen, src,
	    srclen, dst, dstlen, 0));
}

int
ct_crypto_blocksz(void)
{
	return (EVP_CIPHER_block_size(EVP_aes_xts()));
}

/* passphrase functions */
int
ct_passphrase_encrypt(uint8_t *key, size_t keylen, uint8_t *src,
    size_t srclen, uint8_t *dst, size_t dstlen)
{
	return (ct_crypto_crypt(EVP_aes_256_ecb(), key, keylen, NULL, 0, src,
	    srclen, dst, dstlen, 1));
}

int
ct_passphrase_decrypt(uint8_t *key, size_t keylen, uint8_t *src,
    size_t srclen, uint8_t *dst, size_t dstlen)
{
	return (ct_crypto_crypt(EVP_aes_256_ecb(), key, keylen, NULL, 0, src,
	    srclen, dst, dstlen, 0));
}

void
ct_fprintfhex(FILE *f, char *prefix, uint8_t *p, size_t len)
{
	int			i;

	fprintf(f, "%s", prefix);
	for (i = 0; i < len; i++)
		fprintf(f, "%02x", p[i]);
	fprintf(f, "\n");
}

int
ct_fscanfhex(char *src, uint8_t *dst, size_t dstlen)
{
	unsigned int		h;

	if (dstlen % 2)
		return (-1);
	if (strlen(src) / 2 != dstlen)
		return (-1);

	for(; sscanf(src, "%02x", &h) == 1 ; src += 2, dst++)
		*dst = (uint8_t)h;

	return (0);
}

/*
 * 0. save rounds used
 * 1. take the passphrase, run it through a kdf to get a key
 * 2. generate a random mask key
 * 3. use the mask key to encrypt the iv and your data key
 * 4. encrypt your mask key using your passphrase key and store it
 * 5. hmac your mask key and store the hmac
 *
 * so on disk you have a) encrypted iv (enc with mask key) b) encrypted data
 * key (enc with mask key) c) encrypted mask key (enc with passphrase derived
 * key) and d) hmac of uncrypted mask key
 */
int
ct_create_secrets(const char *passphrase, const char *filename,
    uint8_t *myaeskey, uint8_t *myivkey)
{
	const char		*p;
	char			pwd[PASS_MAX];
	uint8_t			salt[C_SALT_LEN];
	uint8_t			key[C_PWDKEY_LEN], maskkey[C_PWDKEY_LEN];
	uint8_t			aeskey[CT_KEY_LEN], ivkey[CT_IV_LEN];
	uint8_t			e_aeskey[CT_KEY_LEN + 16];
	uint8_t			e_ivkey[CT_IV_LEN + 16];
	uint8_t			e_maskkey[C_PWDKEY_LEN + 16];
	uint8_t			hmac_maskkey[SHA256_DIGEST_LENGTH];
	uint8_t			digest[SHA512_DIGEST_LENGTH];
	uint32_t		rounds, f_version;
	uint32_t		rounds_save, f_version_save;
	int			tot;
	HMAC_CTX		hctx;
	SHA512_CTX		ctx;
	FILE			*f;
	int			rv = -1;
	int			fd;

	if (filename == NULL) {
		CNDBG(CT_LOG_CRYPTO, "no filename");
		return (-1);
	}

	if (passphrase)
		p = passphrase;
	else {
		if (ct_get_password(pwd, sizeof pwd, NULL, 1))
			CFATALX("invalid password");
		p = pwd;
	}

	fd = open(filename, O_CREAT | O_WRONLY, 0600);
	if (fd == -1) {
		CWARN("can't open secrets file");
		return (-1);
	}
	f = fdopen(fd, "w");
	if (f == NULL) {
		CWARN("fdopen");
		return (-1);
	}


	bzero(salt, sizeof salt);
	bzero(e_aeskey, sizeof e_aeskey);
	bzero(e_ivkey, sizeof e_ivkey);
	bzero(e_maskkey, sizeof e_maskkey);
	bzero(hmac_maskkey, sizeof hmac_maskkey);

	/* step 0 */
	f_version = C_FILE_VERSION;
	f_version_save = htonl(f_version);
	ct_fprintfhex(f, C_F_VERSION, (uint8_t *)&f_version_save,
	    sizeof f_version_save);

	rounds = C_ROUNDS;
	rounds_save = htonl(rounds);
	ct_fprintfhex(f, C_F_ROUNDS, (uint8_t *)&rounds_save,
	    sizeof rounds_save);

	/* step 1 */
	arc4random_buf(salt, sizeof salt);

	ct_fprintfhex(f, C_F_SALT, salt, sizeof salt);

	if (!PKCS5_PBKDF2_HMAC_SHA1(p, strlen(p), salt,
	    sizeof(salt), rounds, sizeof key, key)) {
		CNDBG(CT_LOG_CRYPTO, "can't create key");
		goto done;
	}

	/* step 2 */
	arc4random_buf(maskkey, sizeof maskkey);

	/* step 3 */
	if (myaeskey)
		bcopy(myaeskey, aeskey, sizeof aeskey);
	else
		arc4random_buf(aeskey, sizeof aeskey);
	if (myivkey)
		bcopy(myivkey, ivkey, sizeof ivkey);
	else
		arc4random_buf(ivkey, sizeof ivkey);

	if ((tot = ct_passphrase_encrypt(maskkey, sizeof maskkey, aeskey,
	    sizeof aeskey, e_aeskey, sizeof e_aeskey)) <= 0) {
		CNDBG(CT_LOG_CRYPTO, "ct_passphrase_encrypt aeskey");
		goto done;
	}
	ct_fprintfhex(f, C_F_AESKEY, e_aeskey, tot);

	if ((tot = ct_passphrase_encrypt(maskkey, sizeof maskkey, ivkey,
	    sizeof ivkey, e_ivkey, sizeof e_ivkey)) <= 0) {
		CNDBG(CT_LOG_CRYPTO, "passphrase_encrypt ivkey");
		goto done;
	}
	ct_fprintfhex(f, C_F_IVKEY, e_ivkey, tot);

	/* step 4 */
	if ((tot = ct_passphrase_encrypt(key, sizeof key, maskkey,
	    sizeof maskkey, e_maskkey, sizeof e_maskkey)) <= 0) {
		CNDBG(CT_LOG_CRYPTO, "passphrase_encrypt maskkey");
		goto done;
	}
	ct_fprintfhex(f, C_F_MASKKEY, e_maskkey, tot);

	/* step 5 */
	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx, maskkey, sizeof maskkey, EVP_sha256(), NULL);
	HMAC_Final(&hctx, hmac_maskkey, NULL);
	HMAC_CTX_cleanup(&hctx);
	ct_fprintfhex(f, C_F_HMACMASKKEY, hmac_maskkey, sizeof hmac_maskkey);

	/* hash it all */
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, &rounds_save, sizeof rounds_save);
	SHA512_Update(&ctx, &f_version_save, sizeof f_version_save);
	SHA512_Update(&ctx, salt, sizeof salt);
	SHA512_Update(&ctx, e_aeskey, sizeof e_aeskey);
	SHA512_Update(&ctx, e_ivkey, sizeof e_ivkey);
	SHA512_Update(&ctx, e_maskkey, sizeof e_maskkey);
	SHA512_Update(&ctx, hmac_maskkey, sizeof hmac_maskkey);
	SHA512_Final(digest, &ctx);
	ct_fprintfhex(f, C_F_DIGEST, digest, sizeof digest);

	rv = 0;
done:
	if (fchmod(fd, 0400) == -1)
		CWARN("unable to chmod secrets file");
	fclose(f);

	/* clean things up */
	bzero(pwd, sizeof pwd);
	bzero(salt, sizeof salt);
	bzero(key, sizeof key);
	bzero(maskkey, sizeof maskkey);
	bzero(aeskey, sizeof aeskey);
	bzero(ivkey, sizeof ivkey);
	bzero(e_aeskey, sizeof e_aeskey);
	bzero(e_ivkey, sizeof e_ivkey);
	bzero(e_maskkey, sizeof e_maskkey);
	bzero(hmac_maskkey, sizeof hmac_maskkey);

	return (rv);
}

/*
 * unlocking:
 * 0. get rounds
 * 1. take the passphrase key and decrypt the mask key
 * 2. calculate a hmac of the decrypted key
 * 3. compare the new hmac to the one stored on disk (if they don't match
 *    then abort, incorrect passphrase provided)
 * 4. decrypt iv with mask key
 * 5. decrypt data key with mask key
 */
int
ct_unlock_secrets(const char *passphrase, const char *filename,
    uint8_t *outaeskey, size_t outaeskeylen, uint8_t *outivkey,
    size_t outivkeylen)
{
	char			old_crypto_secrets[PATH_MAX];
	uint8_t			salt[C_SALT_LEN];
	uint8_t			e_aeskey[CT_KEY_LEN + 16];
	uint8_t			e_ivkey[CT_IV_LEN + 16];
	uint8_t			e_maskkey[C_PWDKEY_LEN + 16];
	uint8_t			hmac_maskkey[SHA256_DIGEST_LENGTH];
	uint8_t			d_hmac_maskkey[SHA256_DIGEST_LENGTH];
	uint8_t			key[C_PWDKEY_LEN], maskkey[C_PWDKEY_LEN];
	uint8_t			aeskey[CT_KEY_LEN], ivkey[CT_IV_LEN + 16];
	uint8_t			digest[SHA512_DIGEST_LENGTH];
	uint8_t			digest_v[SHA512_DIGEST_LENGTH];
	uint32_t		rounds = 0, f_version = 0;
	uint32_t		rounds_load = 0, f_version_load = 0;
	const char		*p;
	char			pwd[PASS_MAX];
	char			line[1024], *s;
	FILE			*f;
	HMAC_CTX		hctx;
	SHA512_CTX		ctx;
	int			tot, tot_aes, tot_iv, rv = -1, got_digest = 0;
	struct stat		sb;

	if (filename == NULL) {
		CNDBG(CT_LOG_CRYPTO, "no filename");
		return (-1);
	}

	if (passphrase)
		p = passphrase;
	else {
		if (ct_get_password(pwd, sizeof pwd, "Crypto password: ", 0))
			CFATALX("invalid password");
		p = pwd;
	}

	f = fopen(filename, "r");
	if (f == NULL) {
		CWARN("can't fopen secrets file");
		return (-1);
	}

	while (fgets(line, sizeof line, f)) {
		if ((s = strchr(line, '\n')) == NULL) {
			CWARNX("input line too long");
			goto done;
		}
		*s = '\0';

		if (!strncmp(line, C_F_ROUNDS, C_F_ROUNDS_LEN)) {
			s = line + C_F_ROUNDS_LEN;
			if (ct_fscanfhex(s, (uint8_t *)&rounds_load,
			    sizeof rounds_load)) {
				CNDBG(CT_LOG_CRYPTO, "invalid rounds");
				goto done;
			}
		} else if (!strncmp(line, C_F_SALT, C_F_SALT_LEN)) {
			s = line + C_F_SALT_LEN;
			if (ct_fscanfhex(s, salt, sizeof salt)) {
				CNDBG(CT_LOG_CRYPTO, "invalid salt");
				goto done;
			}
		} else if (!strncmp(line, C_F_AESKEY, C_F_AESKEY_LEN)) {
			s = line + C_F_AESKEY_LEN;
			if (ct_fscanfhex(s, e_aeskey, sizeof e_aeskey)) {
				CNDBG(CT_LOG_CRYPTO, "invalid e_aeskey");
				goto done;
			}
		} else if (!strncmp(line, C_F_IVKEY, C_F_IVKEY_LEN)) {
			s = line + C_F_IVKEY_LEN;
			if (ct_fscanfhex(s, e_ivkey, sizeof e_ivkey)) {
				CNDBG(CT_LOG_CRYPTO, "invalid e_ivkey");
				goto done;
			}
		} else if (!strncmp(line, C_F_MASKKEY, C_F_MASKKEY_LEN)) {
			s = line + C_F_MASKKEY_LEN;
			if (ct_fscanfhex(s, e_maskkey, sizeof e_maskkey)) {
				CNDBG(CT_LOG_CRYPTO, "invalid e_maskkey");
				goto done;
			}
		} else if (!strncmp(line, C_F_HMACMASKKEY,
		    C_F_HMACMASKKEY_LEN)) {
			s = line + C_F_HMACMASKKEY_LEN;
			if (ct_fscanfhex(s, hmac_maskkey, sizeof hmac_maskkey)) {
				CNDBG(CT_LOG_CRYPTO, "invalid hmac_maskkey");
				goto done;
			}
		} else if (!strncmp(line, C_F_DIGEST,
		    C_F_DIGEST_LEN)) {
			s = line + C_F_DIGEST_LEN;
			if (ct_fscanfhex(s, digest, sizeof digest)) {
				CNDBG(CT_LOG_CRYPTO, "invalid digest");
				goto done;
			}
			got_digest = 1;
		} else if (!strncmp(line, C_F_VERSION,
		    C_F_VERSION_LEN)) {
			s = line + C_F_VERSION_LEN;
			if (ct_fscanfhex(s, (uint8_t *)&f_version_load,
			    sizeof f_version_load)) {
				CNDBG(CT_LOG_CRYPTO, "invalid version");
				goto done;
			}
		} else {
			CWARNX("invalid entry in secrets file");
			goto done;
		}
	};

	/* step 0 */
	rounds = ntohl(rounds_load);
	if (rounds == 0) {
		CNDBG(CT_LOG_CRYPTO, "invalid rounds");
		goto done;
	}
	f_version = ntohl(f_version_load);

	/*
	 * version check of the file
	 *
	 * Initial version: does not have file digest
	 * Next version   : does have file digest but no file version
	 * V1             : current version
	 */

	/* we assume that version <= 0 ALSO handles the got_digest == 0 case */
	if (f_version <= 0) {
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, &rounds, sizeof rounds);
		SHA512_Update(&ctx, salt, sizeof salt);
		SHA512_Update(&ctx, e_aeskey, sizeof e_aeskey);
		SHA512_Update(&ctx, e_ivkey, sizeof e_ivkey);
		SHA512_Update(&ctx, e_maskkey, sizeof e_maskkey);
		SHA512_Update(&ctx, hmac_maskkey, sizeof hmac_maskkey);
		SHA512_Final(digest_v, &ctx);

		/*
		 * update digest if we don't have it;
		 * this needs to go away over time
		 */
		if (got_digest == 0) {
			bcopy(digest_v, digest, sizeof digest);
			CNDBG(CT_LOG_CRYPTO, "adding digest to secrets file");
			if (fstat(fileno(f), &sb) == -1)
				CFATAL("stat");
			if (fchmod(fileno(f), S_IRWXU) == -1)
				CFATAL("fchmod");
			/* the race can bite me, everything else is worse */
			if (freopen(filename, "r+", f) == NULL)
				CFATAL("freopen");
			if (fseek(f, 0, SEEK_END) == -1)
				CFATAL("fseek");
			ct_fprintfhex(f, C_F_DIGEST, digest, sizeof digest);
			if (fchmod(fileno(f), sb.st_mode) == -1)
				CFATAL("fchmod");
		}

		if (bcmp(digest, digest_v, sizeof digest)) {
			CWARNX("corrupt secrets file");
			goto done;
		}
	} else {
		/* the final else must always be the CURRENT path */
		SHA512_Init(&ctx);
		SHA512_Update(&ctx, &rounds_load, sizeof rounds_load);
		SHA512_Update(&ctx, &f_version_load, sizeof f_version_load);
		SHA512_Update(&ctx, salt, sizeof salt);
		SHA512_Update(&ctx, e_aeskey, sizeof e_aeskey);
		SHA512_Update(&ctx, e_ivkey, sizeof e_ivkey);
		SHA512_Update(&ctx, e_maskkey, sizeof e_maskkey);
		SHA512_Update(&ctx, hmac_maskkey, sizeof hmac_maskkey);
		SHA512_Final(digest_v, &ctx);
	}

	if (bcmp(digest, digest_v, sizeof digest)) {
		CWARNX("corrupt secrets file");
		goto done;
	}

	/* step 1 */
	if (!PKCS5_PBKDF2_HMAC_SHA1(p, strlen(p), salt,
	    sizeof(salt), rounds, sizeof key, key)) {
		CNDBG(CT_LOG_CRYPTO, "can't create key");
		goto done;
	}

	if ((tot = ct_passphrase_decrypt(key, sizeof key, e_maskkey,
	    sizeof e_maskkey, maskkey, sizeof maskkey)) <= 0) {
		CNDBG(CT_LOG_CRYPTO, "ct_passphrase_decrypt maskkey");
		goto done;
	}

	/* step 2 */
	HMAC_CTX_init(&hctx);
	HMAC_Init_ex(&hctx, maskkey, sizeof maskkey, EVP_sha256(), NULL);
	HMAC_Final(&hctx, d_hmac_maskkey, NULL);
	HMAC_CTX_cleanup(&hctx);

	/* step 3 */
	if (bcmp(d_hmac_maskkey, hmac_maskkey, sizeof hmac_maskkey)) {
		CWARNX("invalid password");
		goto done;
	}

	/* step 4 */
	if ((tot_iv = ct_passphrase_decrypt(maskkey, sizeof maskkey, e_ivkey,
	    sizeof e_ivkey, ivkey, CT_IV_LEN)) <= 0) {
		CNDBG(CT_LOG_CRYPTO, "ct_passphrase_decrypt ivkey");
		goto done;
	}

	/* step 5 */
	if ((tot_aes = ct_passphrase_decrypt(maskkey, sizeof maskkey, e_aeskey,
	    sizeof e_aeskey, aeskey, sizeof aeskey)) <= 0) {
		CNDBG(CT_LOG_CRYPTO, "ct_passphrase_decrypt aeskey");
		goto done;
	}

	/* validate output */
	if (tot_aes != outaeskeylen) {
		CNDBG(CT_LOG_CRYPTO, "invalid aes key length");
		goto done;
	}
	if (tot_iv != outivkeylen) {
		CNDBG(CT_LOG_CRYPTO, "invalid iv key length");
		goto done;
	}

	if (f_version <= 0) {
		/* rewrite file */
		snprintf(old_crypto_secrets, sizeof old_crypto_secrets, "%s~",
		    filename);

		if (rename(filename, old_crypto_secrets))
			CFATAL("%s", filename);
		ct_create_secrets(p, filename, aeskey, ivkey);
	}

	bcopy(aeskey, outaeskey, outaeskeylen);
	bcopy(ivkey, outivkey, outivkeylen);

	rv = 0;
done:
	fclose(f);

	bzero(e_aeskey, sizeof e_aeskey);
	bzero(e_ivkey, sizeof e_ivkey);
	bzero(e_maskkey, sizeof e_maskkey);
	bzero(hmac_maskkey, sizeof hmac_maskkey);
	bzero(d_hmac_maskkey, sizeof d_hmac_maskkey);
	bzero(key, sizeof key);
	bzero(maskkey, sizeof maskkey);
	bzero(ivkey, sizeof ivkey);
	bzero(pwd, sizeof pwd);

	return (rv);
}
