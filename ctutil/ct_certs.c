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

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <exude.h>
#include <clog.h>
#include <ctutil.h>

#define URL		"https://www.cyphertite.com/"
#define LOGIN		"login.php"
#define LOGIN_LOGOUT	"?do=logout"
#define ACCOUNT		"account.php"
#define ACCOUNT_CERT	"?do=xml-certs"
#define INDEX		"index.php"

struct memdesc {
	char		*memory;
	size_t		size;
};

static CURLcode
sslctx_cb(CURL *c, void *ssl_ctx, void *parm)
{
	unsigned long	 ssl_err;
	int rv;
	X509_STORE 	*cert_store;
	X509		*cert = NULL;
	BIO		*bio;
	/* ValiCert Class 1 CA */
	char		*root_ca_cert =
	"-----BEGIN CERTIFICATE-----\n"\
	"MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0\n"\
	"IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAz\n"\
	"BgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9y\n"\
	"aXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG\n"\
	"9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE5MDYy\n"\
	"NjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29y\n"\
	"azEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENs\n"\
	"YXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRw\n"\
	"Oi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNl\n"\
	"cnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5avIWZJV16vY\n"\
	"dA757tn2VUdZZUcOBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zfN1SLUzm1NZ9\n"\
	"WlmpZdRJEy0kTRxQb7XBhVQ7/nHk01xC+YDgkRoKWzk2Z/M/VXwbP7RfZHM047QS\n"\
	"v4dk+NoS/zcnwbNDu+97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADt/UG9v\n"\
	"UJSZSWI4OB9L+KXIPqeCgfYrx+jFzug6EILLGACOTb2oWH+heQC1u+mNr0HZDzTu\n"\
	"IYEZoDJJKPTEjlbVUjP9UNV+mWwD5MlM/Mtsq2azSiGM5bUMMj4QssxsodyamEwC\n"\
	"W/POuZ6lcg5Ktz885hZo+L7tdEy8W9ViH0Pd\n"\
	"-----END CERTIFICATE-----\n";

	bio = BIO_new_mem_buf(root_ca_cert, -1);
	PEM_read_bio_X509(bio, &cert, 0, NULL);
	if (cert == NULL) {
		return CURLE_PEER_FAILED_VERIFICATION;
	}

	cert_store = SSL_CTX_get_cert_store((SSL_CTX *) ssl_ctx);
	if ((rv = X509_STORE_add_cert(cert_store, cert)) == 0) {
		ssl_err = ERR_get_error();
		if (ERR_GET_REASON(ssl_err) !=
		    X509_R_CERT_ALREADY_IN_HASH_TABLE) {
			return CURLE_PEER_FAILED_VERIFICATION;
		}
	}

	return CURLE_OK ;
}

static size_t
write_mem_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t		realsize = size * nmemb;
	struct		memdesc *mem = (struct memdesc *)userp;

	mem->memory = e_realloc(mem->memory, mem->size + realsize + 1);
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return (realsize);
}

int
ct_get_cert_bundle(const char *user, const char *pass, char **xml,
    size_t *xml_sz)
{
	CURL		*c = NULL;
	int		rv = -1;
	char		*username = NULL, *password = NULL, *mode = NULL;
	char		*login_post_data = NULL;
	long		rc;
	char		*ru;
	struct memdesc	chunk;
	char		*x = NULL;
	size_t		xs = 0;
	long		flags;

	/* init mem structure */
	chunk.memory = NULL;
	chunk.size = 0;

	/*
	 * Per the curl documentation, this function is not thread safe as it
	 * calls initialization routines of other libraries; This most notably
	 * causes issues with OpenSSL, so we rely on it having been initalized
	 * before hand [assl].
	 */
	flags = CURL_GLOBAL_ALL & (~CURL_GLOBAL_SSL);
	curl_global_init(flags);

	c = curl_easy_init();
	if (c == NULL)
		goto done;
#if 0
	/* debug */
	if (curl_easy_setopt(c, CURLOPT_VERBOSE, 1L)) {
		rv = -2;
		goto done;
	}
#endif
	/* enable cookies in memory */
	if (curl_easy_setopt(c, CURLOPT_COOKIEFILE, "")) {
		rv = -4;
		goto done;
	}

	/* verify cert */
	curl_easy_setopt(c, CURLOPT_SSL_CTX_FUNCTION, sslctx_cb);
	if (curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L)) {
		rv = -5;
		goto done;
	}
	if (curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L)) {
		rv = -6;
		goto done;
	}

	/* write callback */
	if (curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_mem_cb)) {
		rv = -7;
		goto done;
	}
	if (curl_easy_setopt(c, CURLOPT_WRITEDATA, (void *)&chunk)) {
		rv = -8;
		goto done;
	}

	/* login */
	if ((username = curl_easy_escape(c, user, 0)) == NULL) {
		rv = -10;
		goto done;
	}
	if ((password = curl_easy_escape(c, pass, 0)) == NULL) {
		rv = -11;
		goto done;
	}
	if ((mode = curl_easy_escape(c, "login-process", 0)) == NULL) {
		rv = -12;
		goto done;
	}
	e_asprintf(&login_post_data, "username=%s&password=%s&do=%s", username,
	    password, mode);
	curl_easy_setopt(c, CURLOPT_POSTREDIR, CURL_REDIR_POST_ALL);
	curl_easy_setopt(c, CURLOPT_POSTFIELDS, login_post_data);
	if (curl_easy_setopt(c, CURLOPT_URL, URL LOGIN)) {
		rv = -13;
		goto done;
	}
	if (curl_easy_perform(c)) {
		rv = -14;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &rc)) {
		rv = -15;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_REDIRECT_URL, &ru)) {
		rv = -16;
		goto done;
	}
	if (chunk.memory) {
		e_free(&chunk.memory);
		chunk.size = 0;
	}
	CDBG("login -> rc = %ld -> %s\n", rc, ru);
	if (strcmp(ru, URL ACCOUNT)) {
		rv = CT_CERT_BUNDLE_LOGIN_FAILED;
		goto done;
	}

	/* get certs */
	curl_easy_setopt(c, CURLOPT_POSTFIELDS, NULL);
	curl_easy_setopt(c, CURLOPT_POST, 0L);
	if (curl_easy_setopt(c, CURLOPT_URL, URL ACCOUNT ACCOUNT_CERT)) {
		rv = -20;
		goto done;
	}
	if (curl_easy_perform(c)) {
		rv = -21;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &rc)) {
		rv = -22;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_REDIRECT_URL, &ru)) {
		rv = -23;
		goto done;
	}
	CDBG("get certs: rc = %ld sz = %ld-> %s\n", rc, (long) chunk.size, ru);
	if (!(rc == 200 && ru == NULL)) {
		rv = -24;
		goto done;
	}
	xs = chunk.size;
	x = e_malloc(xs + 1); /* + nul */
	x[xs] = '\0';
	bcopy(chunk.memory, x, xs);

	/* logout */
	if (curl_easy_setopt(c, CURLOPT_URL, URL LOGIN LOGIN_LOGOUT)) {
		rv = -30;
		goto done;
	}
	if (curl_easy_perform(c)) {
		rv = -31;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &rc)) {
		rv = -32;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_REDIRECT_URL, &ru)) {
		rv = -33;
		goto done;
	}
	if (chunk.memory) {
		e_free(&chunk.memory);
		chunk.size = 0;
	}
	CDBG("logout: rc = %ld -> %s\n", rc, ru);
	if (strcmp(ru, URL INDEX)) {
		rv = -34;
		goto done;
	}

	rv = 0;
done:
	if (chunk.memory)
		e_free(&chunk.memory);
	if (username)
		curl_free(username);
	if (password)
		curl_free(password);
	if (mode)
		curl_free(mode);
	if (login_post_data)
		e_free(&login_post_data);
	if (c)
		curl_easy_cleanup(c);

	curl_global_cleanup();

	if (rv && x)
		e_free(&x);
	else {
		/* success */
		*xml = x;
		*xml_sz = xs;
	}

	return (rv);
}
