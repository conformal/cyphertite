/*
 * Copyright (c) 2013 Conformal Systems LLC <info@conformal.com>
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

#define CT_UPDATE_URL		"https://www.cyphertite.com/update.php"

int
ct_get_update_xml(char **xml, size_t *xml_sz)
{
	CURL		*c = NULL;
	int			rv = -1;
	long		rc;
	char		*ru;
	char		*buffer;
	struct memdesc	chunk;
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
	flags = CURL_GLOBAL_ALL;
#ifndef CT_CURL_INIT_SSL
	flags &= ~CURL_GLOBAL_SSL;
#endif
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

	/* get the xml */
	if (curl_easy_setopt(c, CURLOPT_URL, CT_UPDATE_URL)) {
		rv = -9;
		goto done;
	}
	if (curl_easy_perform(c)) {
		rv = -10;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &rc)) {
		rv = -11;
		goto done;
	}
	if (curl_easy_getinfo(c, CURLINFO_REDIRECT_URL, &ru)) {
		rv = -12;
		goto done;
	}

	CDBG("get update xml: rc = %ld sz = %ld-> %s\n", rc, (long) chunk.size, ru);
	if (!(rc == 200 && ru == NULL)) {
		rv = -13;
		goto done;
	}

	/* success */
	buffer = e_malloc(chunk.size + 1); /* + nul */
	buffer[chunk.size] = '\0';
	bcopy(chunk.memory, buffer, chunk.size);

	*xml = buffer;
	*xml_sz = chunk.size;
	rv = 0;

done:
	if (chunk.memory)
		e_free(&chunk.memory);
	if (c)
		curl_easy_cleanup(c);

	curl_global_cleanup();

	return (rv);
}

