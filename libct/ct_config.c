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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <pwd.h>
#include <limits.h>
#include <readpassphrase.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <xmlsd.h>

#include <ct_lib.h>
#include <ct_ext.h>


int
ct_get_answer(char *prompt, char *a1, char *a2, char *default_val,
    char *answer, size_t answer_len, int secret)
{
	char			*p;

	if (answer == NULL)
		return (-1);

	for (;;) {
		p = readpassphrase(prompt, answer, answer_len,
		    secret ? RPP_ECHO_OFF : RPP_ECHO_ON);
		if (p == NULL)
			CFATAL("readpassphrase");

		if (default_val && !strcmp(answer, "")) {
			strlcpy(answer, default_val, answer_len);
		}

		if (a1 == NULL && a2 == NULL)
			return (0); /* just get the string */

		/* check for proper answer */
		if (a1 && !strcasecmp(answer, a1))
			return (1);
		if (a2 && !strcasecmp(answer, a2))
			return (2);
		printf("please answer %s or %s\n", a1, a2);
	}

	return (-1);
}

int
ct_prompt_password(char *prompt, char *answer, size_t answer_len,
    char *answer2, size_t answer2_len, int confirm)
{
	int			i;

	if (answer == NULL || answer2 == NULL)
		return (-1);

	for (i = 0 ; i < 2;) {
		switch (i) {
		case 0:
			if (ct_get_answer(prompt, NULL, NULL, NULL, answer,
			    answer_len, 1))
				CFATALX("password");

			if (strlen(answer) != 0 && strlen(answer) < 7) {
				printf("invalid password length\n");
				continue;
			}
			i++;
			break;
		case 1:
			if (!confirm) {
				i++;
				break;
			}

			if (ct_get_answer("confirm: ",
			    NULL, NULL, NULL, answer2, answer2_len, 1))
				CFATALX("password");

			if (strlen(answer2) != 0 && strlen(answer2) < 7) {
				printf("invalid password length\n");
				continue;
			}
			if (strcmp(answer, answer2)) {
				printf("passwords don't match\n");
				i = 0;
				continue;
			}

			i++;
			break;
		}
	}
	return (0);
}

void
ct_download_decode_and_save_certs(struct ct_config *config)
{
	int			 rv, fd;
	uint8_t			 pwd_digest[SHA512_DIGEST_LENGTH];
	char			 b64[2048];
	char			*xml, *xml_val;
	size_t			 xml_size;
	struct			 xmlsd_element_list xel;
	char			*ca_cert, *user_cert, *user_key;
	FILE			*f = NULL;
	struct stat		sb;

	ct_sha512((uint8_t *)config->ct_password, pwd_digest,
	    strlen(config->ct_password));
	if (ct_base64_encode(CT_B64_ENCODE, pwd_digest, sizeof pwd_digest,
	    (uint8_t *)b64, sizeof b64)) {
		CFATALX("can't base64 encode password");
	}

	if ((rv = ct_get_cert_bundle(config->ct_username, b64, &xml,
	    &xml_size))) {
		if (rv == CT_CERT_BUNDLE_LOGIN_FAILED)
			CFATALX("Invalid login credentials.  Please check "
			    "your username and password.");
		else
			CFATALX("unable to get cert bundle, rv %d", rv);
	}

	TAILQ_INIT(&xel);
	if ((rv = xmlsd_parse_mem(xml, xml_size, &xel))) {
		CFATALX("unable to parse cert bundle xml, rv %d", rv);
	}

	/* ca cert */
	if (stat(config->ct_ca_cert , &sb) != 0) {
		xml_val = xmlsd_get_value(&xel, "ca_cert", NULL);
		if (xml_val == NULL) {
			CFATALX("unable to get ca cert xml");
		}
		bzero(b64, sizeof b64);
		if (ct_base64_encode(CT_B64_M_DECODE, (uint8_t *)xml_val,
		    strlen(xml_val), (uint8_t *)b64, sizeof b64)) {
			CFATALX("failed to decode ca cert xml");
		}
		e_asprintf(&ca_cert, "%s", b64);
		if (ct_make_full_path(config->ct_ca_cert, 0700)) {
			CFATAL("failed to make path to %s", config->ct_ca_cert);
		}
		if ((fd = open(config->ct_ca_cert, O_RDWR | O_CREAT | O_TRUNC,
				    0644)) == -1) {
			CFATAL("unable to open file for writing %s",
			    config->ct_ca_cert);
		}
		if ((f = fdopen(fd, "r+")) == NULL) {
			CFATAL("unable to open file %s", config->ct_ca_cert);
		}
		fprintf(f, "%s", ca_cert);
		fclose(f);
		if (ca_cert != NULL) {
			e_free(&ca_cert);
		}
	}

	/* user cert */
	if (stat(config->ct_cert , &sb) != 0) {
		xml_val = xmlsd_get_value(&xel, "user_cert", NULL);
		if (xml_val == NULL) {
			CFATALX("unable to get user cert xml");
		}
		bzero(b64, sizeof b64);
		if (ct_base64_encode(CT_B64_M_DECODE, (uint8_t *)xml_val,
		    strlen(xml_val), (uint8_t *)b64, sizeof b64)) {
			CFATALX("failed to decode user cert xml");
		}
		e_asprintf(&user_cert, "%s", b64);
		if (ct_make_full_path(config->ct_cert, 0700)) {
			CFATAL("failed to make path to %s", config->ct_cert);
		}
		if ((fd = open(config->ct_cert, O_RDWR | O_CREAT | O_TRUNC,
				    0644)) == -1) {
			CFATAL("unable to open file for writing %s",
			    config->ct_cert);
		}
		if ((f = fdopen(fd, "r+")) == NULL) {
			CFATAL("unable to open file %s", config->ct_cert);
		}
		fprintf(f, "%s", user_cert);
		fclose(f);
		if (user_cert != NULL) {
			e_free(&user_cert);
		}
	}

	/* user key */
	if (stat(config->ct_key, &sb) != 0) {
		xml_val = xmlsd_get_value(&xel, "user_key", NULL);
		if (xml_val == NULL) {
			CFATALX("unable to get user key xml");
		}
		bzero(b64, sizeof b64);
		if (ct_base64_encode(CT_B64_M_DECODE, (uint8_t *)xml_val,
		    strlen(xml_val), (uint8_t *)b64, sizeof b64)) {
			CFATALX("failed to decode user key xml");
		}
		e_asprintf(&user_key, "%s", b64);
		if (ct_make_full_path(config->ct_key, 0700)) {
			CFATAL("failed to make path to %s", config->ct_key);
		}
		if ((fd = open(config->ct_key, O_RDWR | O_CREAT | O_TRUNC,
				    0600)) == -1) {
			CFATAL("unable to open file for writing %s",
			    config->ct_key);
		}
		if ((f = fdopen(fd, "r+")) == NULL) {
			CFATAL("unable to open file %s", config->ct_key);
		}
		fprintf(f, "%s", user_key);
		fclose(f);
		if (user_key != NULL) {
			e_free(&user_key);
		}
	}

	xmlsd_unwind(&xel);
}

struct ct_config *
ct_load_config(char **configfile)
{
	struct ct_config	 conf, *config;
	char			*ct_compression_type = NULL;
	char			*ct_polltype = NULL;
	char			*ctfile_mode_str = NULL;
	char			*config_path = NULL;
	char			 ct_fullcachedir[PATH_MAX];
	int			 config_try = 0;
	struct ct_settings	 settings[] = {
		{ "queue_depth", CT_S_INT, &conf.ct_max_trans, NULL, NULL,
		    NULL },
		{ "bandwidth", CT_S_INT, &conf.ct_io_bw_limit, NULL, NULL,
		    NULL },
		{ "host", CT_S_STR, NULL, &conf.ct_host, NULL, NULL },
		{ "hostport", CT_S_STR, NULL, &conf.ct_hostport, NULL, NULL },
		{ "cache_db", CT_S_DIR, NULL, &conf.ct_localdb, NULL, NULL },
		{ "username", CT_S_STR, NULL, &conf.ct_username, NULL, NULL },
		{ "password", CT_S_STR, NULL, &conf.ct_password, NULL,
		    NULL, NULL, 1 },
		{ "ca_cert", CT_S_DIR, NULL, &conf.ct_ca_cert, NULL, NULL },
		{ "cert", CT_S_DIR, NULL, &conf.ct_cert, NULL, NULL },
		{ "key", CT_S_DIR, NULL, &conf.ct_key, NULL, NULL },
		{ "crypto_secrets", CT_S_DIR, NULL, &conf.ct_crypto_secrets, NULL,
		    NULL },
		{ "crypto_passphrase", CT_S_STR, NULL, &conf.ct_crypto_passphrase,
		    NULL, NULL, NULL,  1 }, /* name may NOT be modified */
		{ "session_compression", CT_S_STR, NULL, &ct_compression_type,
		   NULL, NULL },
		{ "polltype", CT_S_STR, NULL, &ct_polltype, NULL, NULL },
		{ "upload_crypto_secrets" , CT_S_INT, &conf.ct_secrets_upload,
		    NULL, NULL, NULL },
		{ "ctfile_cull_keep_days" , CT_S_INT, &conf.ct_ctfile_keep_days,
		    NULL, NULL, NULL },
		{ "ctfile_mode", CT_S_STR, NULL, &ctfile_mode_str, NULL, NULL },
		{ "ctfile_cachedir", CT_S_DIR, NULL, &conf.ct_ctfile_cachedir, NULL,
		    NULL },
		{ "ctfile_cachedir_max_size", CT_S_SIZE, NULL, NULL, NULL,
		    &conf.ct_ctfile_max_cachesize, NULL },
		{ "ctfile_remote_auto_differential" , CT_S_INT,
		    &conf.ct_auto_differential, NULL, NULL, NULL },
		{ "ctfile_max_differentials" , CT_S_INT, &conf.ct_max_differentials,
		    NULL, NULL, NULL },
		{ "ctfile_differential_allfiles", CT_S_INT,
		    &conf.ct_multilevel_allfiles, NULL, NULL, NULL },
		/* backwards compat, old names */
		{ "md_mode", CT_S_STR, NULL, &ctfile_mode_str, NULL, NULL },
		{ "md_cachedir", CT_S_DIR, NULL, &conf.ct_ctfile_cachedir, NULL, NULL },
		{ "md_cachedir_max_size", CT_S_SIZE, NULL, NULL, NULL,
		    &conf.ct_ctfile_max_cachesize, NULL },
		{ "md_remote_auto_differential" , CT_S_INT,
		    &conf.ct_auto_differential, NULL, NULL, NULL },
		{ "md_max_differentials" , CT_S_INT, &conf.ct_max_differentials,
		    NULL, NULL, NULL },
		{ "ctfile_expire_day" , CT_S_INT, &conf.ct_ctfile_keep_days,
		    NULL, NULL, NULL },
		{ "crypto_password", CT_S_STR, NULL, &conf.ct_crypto_passphrase,
		    NULL, NULL, NULL, 1 },
#if defined(CT_EXT_SETTINGS)
		CT_EXT_SETTINGS
#endif	/* CT_EXT_SETTINGS */
		{ NULL, 0, NULL, NULL, NULL,  NULL }
	};

	/* setup default */
	ct_default_config(&conf);
	if (*configfile != NULL) {
		if (ct_config_parse(settings, *configfile))
			CFATALX("Unable to open specified config file %s",
			   *configfile);
	} else {

		for (;;) {
			if (config_path != NULL)
				e_free(&config_path);

			switch(config_try) {
			case 0:
				config_path = ct_user_config();
				break;
			case 1:
				config_path = ct_user_config_old();
				break;
			case 2:
				config_path = ct_system_config();
				break;
			default:
				return (NULL);
				break;
			}
			if (ct_config_parse(settings, config_path) == 0) {
				*configfile = config_path;
				break;
			}
			config_try++;
		}
	}

	if (conf.ct_cert == NULL)
		CFATALX("cert: %s", ct_strerror(CTE_MISSING_CONFIG_VALUE));
	if (conf.ct_ca_cert == NULL)
		CFATALX("ca_cert: %s", ct_strerror(CTE_MISSING_CONFIG_VALUE));
	if (conf.ct_key == NULL)
		CFATALX("key: %s", ct_strerror(CTE_MISSING_CONFIG_VALUE));

	if (ctfile_mode_str != NULL) {
		if (strcmp(ctfile_mode_str, "remote") == 0)
			conf.ct_ctfile_mode = CT_MDMODE_REMOTE;
		else if (strcmp(ctfile_mode_str, "local") == 0)
			conf.ct_ctfile_mode = CT_MDMODE_LOCAL;
		else
			CFATALX("ctfile_mode: %s",
			    ct_strerror(CTE_INVALID_CONFIG_VALUE));
	}

	/* Fix up cachedir: code requires it to end with a slash. */
	if (conf.ct_ctfile_cachedir != NULL &&
	    conf.ct_ctfile_cachedir[strlen(conf.ct_ctfile_cachedir) - 1]
	    != CT_PATHSEP) {
		int rv;

		if ((rv = snprintf(ct_fullcachedir, sizeof(ct_fullcachedir),
		    "%s%c", conf.ct_ctfile_cachedir, CT_PATHSEP)) == -1 ||
		    rv > PATH_MAX)
			CFATALX("ctfile_cachedir: %s",
			    ct_strerror(CTE_INVALID_CONFIG_VALUE));
		free(conf.ct_ctfile_cachedir);
		conf.ct_ctfile_cachedir = strdup(ct_fullcachedir);
		/* XXX Wtf is this? */
		if (ct_fullcachedir == NULL)
			CFATALX("can't allocate memory for cachedir");

	}

	if (conf.ct_ctfile_mode == CT_MDMODE_REMOTE &&
	    conf.ct_ctfile_cachedir == NULL)
		CFATALX("ctfile_cachedir: %s",
		    ct_strerror(CTE_MISSING_CONFIG_VALUE));

	/* And make sure it exists. */
	if (conf.ct_ctfile_cachedir != NULL &&
	    ct_make_full_path(conf.ct_ctfile_cachedir, 0700) != 0)
		CFATALX("%s: %s", conf.ct_ctfile_cachedir,
		    ct_strerror(CTE_ERRNO));

	/* Apply compression from config. */
	if (ct_compression_type == NULL) {
		conf.ct_compress = 0;
	} else if (strcmp("lzo", ct_compression_type) == 0) {
		conf.ct_compress = C_HDR_F_COMP_LZO;
	} else if (strcmp("lzma", ct_compression_type) == 0) {
		conf.ct_compress = C_HDR_F_COMP_LZMA;
	} else if (strcmp("lzw", ct_compression_type) == 0) {
		conf.ct_compress = C_HDR_F_COMP_LZW;
	} else {
		CFATAL("session_compression: %s",
		    ct_strerror(CTE_MISSING_CONFIG_VALUE));
	}

	/*
	 * XXX - The bw limiting code algorithm isn't quite accurate right now,
	 * so tweak it slightly until we fix that.
	 */
	if (conf.ct_io_bw_limit) {
		conf.ct_io_bw_limit = conf.ct_io_bw_limit * 10 / 7;
	}
	/* set polltype used by libevent */
	ct_polltype_setup(ct_polltype);

	config = e_calloc(1, sizeof(*config));

	memcpy(config, &conf, sizeof(*config));
	config->ct_config_file = e_strdup(*configfile);

	return (config);
}

void
ct_unload_config(char *configfile, struct ct_config *config)
{
	e_free(&configfile);
	e_free(&config->ct_config_file);
}

void
ct_default_config(struct ct_config *config)
{
	bzero(config, sizeof(*config));
	config->ct_host = strdup("auth.cyphertite.com");
	config->ct_hostport = strdup("48879");
	config->ct_ctfile_mode = CT_MDMODE_LOCAL;
	config->ct_ctfile_max_cachesize = LLONG_MAX;
	config->ct_max_trans = 100;
}

void
ct_write_config(struct ct_config *config, FILE *f, int save_password,
    int save_crypto_passphrase)
{
	fprintf(f, "username\t\t\t\t= %s\n", config->ct_username);
	if (save_password && config->ct_password)
		fprintf(f, "password\t\t\t\t= %s\n", config->ct_password);
	else
		fprintf(f, "#password\t\t\t\t=\n");
	if (save_crypto_passphrase && config->ct_crypto_passphrase)
		fprintf(f, "crypto_passphrase\t\t\t= %s\n", config->ct_crypto_passphrase);
	else
		fprintf(f, "#crypto_passphrase\t\t\t=\n");

	if (config->ct_localdb)
		fprintf(f, "cache_db\t\t\t\t= %s%cct_db\n", config->ct_localdb,
		    CT_PATHSEP);
	else
		fprintf(f, "#cache_db\t\t\t\t=\n");
	fprintf(f, "session_compression\t\t\t= lzo\n");
	fprintf(f, "crypto_secrets\t\t\t\t= %s\n", config->ct_crypto_secrets);
	fprintf(f, "ca_cert\t\t\t\t\t= %s\n", config->ct_ca_cert);
	fprintf(f, "cert\t\t\t\t\t= %s\n", config->ct_cert);
	fprintf(f, "key\t\t\t\t\t= %s\n", config->ct_key);

	fprintf(f, "ctfile_mode\t\t\t\t= %s\n",
	    config->ct_ctfile_mode == CT_MDMODE_REMOTE ? "remote" : "local");
	if (config->ct_ctfile_mode == CT_MDMODE_REMOTE) {
		fprintf(f, "ctfile_cachedir\t\t\t\t= %s\n",
		    config->ct_ctfile_cachedir);
		fprintf(f, "ctfile_remote_auto_differential\t\t= %d\n",
		    config->ct_auto_differential);
	} else {
		fprintf(f, "#ctfile_cachedir\t\t\t= %s\n",
		    config->ct_ctfile_cachedir);
		fprintf(f, "#ctfile_remote_auto_differential\t= %d\n",
		    config->ct_auto_differential);
	}
	fprintf(f, "upload_crypto_secrets\t\t\t= %d\n",
	    config->ct_secrets_upload);
}
