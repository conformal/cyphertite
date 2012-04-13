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

#include "ct.h"
#include <ct_ext.h>

int			ct_max_trans = 100;
int			ct_max_block_size = 256 * 1024;
int			ct_io_bw_limit = 0;
char			*ct_host;
char			*ct_hostport;
char			*ct_localdb;
char			*ct_username;
char			*ct_password;
char			*ct_ca_cert;
char			*ct_cert;
char			*ct_key;
char			*ct_crypto_secrets;
char			*ct_crypto_passphrase;
char			*ct_compression_type;
char			*ct_polltype;
char			*ctfile_mode_str;
char			*ctfile_cachedir;
int			ctfile_mode = CT_MDMODE_LOCAL;
int			ct_compress_enabled;
int			ct_multilevel_allfiles;
int			ct_auto_differential;
long long		ctfile_max_cachesize = LLONG_MAX; /* unbounded */
int			ct_max_differentials;
int			ct_secrets_upload = 0;
int			ct_ctfile_keep_days = 0;

struct ct_settings	settings[] = {
	{ "queue_depth", CT_S_INT, &ct_max_trans, NULL, NULL, NULL },
	{ "bandwidth", CT_S_INT, &ct_io_bw_limit, NULL, NULL, NULL },
	{ "host", CT_S_STR, NULL, &ct_host, NULL, NULL },
	{ "hostport", CT_S_STR, NULL, &ct_hostport, NULL, NULL },
	{ "cache_db", CT_S_DIR, NULL, &ct_localdb, NULL, NULL },
	{ "username", CT_S_STR, NULL, &ct_username, NULL, NULL },
	{ "password", CT_S_STR, NULL, &ct_password, NULL, NULL, NULL, 1 },
	{ "ca_cert", CT_S_DIR, NULL, &ct_ca_cert, NULL, NULL },
	{ "cert", CT_S_DIR, NULL, &ct_cert, NULL, NULL },
	{ "key", CT_S_DIR, NULL, &ct_key, NULL, NULL },
	{ "crypto_secrets", CT_S_DIR, NULL, &ct_crypto_secrets, NULL, NULL },
	{ "crypto_passphrase", CT_S_STR, NULL, &ct_crypto_passphrase, NULL,
	   NULL, NULL, 1}, /* name may NOT be modified */
	{ "session_compression", CT_S_STR, NULL, &ct_compression_type, NULL,
	    NULL },
	{ "polltype", CT_S_STR, NULL, &ct_polltype, NULL, NULL },
	{ "upload_crypto_secrets" , CT_S_INT, &ct_secrets_upload,
	    NULL, NULL, NULL },
	{ "ctfile_cull_keep_days" , CT_S_INT, &ct_ctfile_keep_days,
	    NULL, NULL, NULL },
	{ "ctfile_mode", CT_S_STR, NULL, &ctfile_mode_str, NULL, NULL },
	{ "ctfile_cachedir", CT_S_DIR, NULL, &ctfile_cachedir, NULL, NULL },
	{ "ctfile_cachedir_max_size", CT_S_SIZE, NULL, NULL, NULL,
	    &ctfile_max_cachesize, NULL },
	{ "ctfile_remote_auto_differential" , CT_S_INT, &ct_auto_differential,
	    NULL, NULL, NULL },
	{ "ctfile_max_differentials" , CT_S_INT, &ct_max_differentials,
	    NULL, NULL, NULL },
	{ "ctfile_differential_allfiles", CT_S_INT, &ct_multilevel_allfiles,
	    NULL, NULL, NULL },
	/* backwards compat, old names */
	{ "md_mode", CT_S_STR, NULL, &ctfile_mode_str, NULL, NULL },
	{ "md_cachedir", CT_S_DIR, NULL, &ctfile_cachedir, NULL, NULL },
	{ "md_cachedir_max_size", CT_S_SIZE, NULL, NULL, NULL,
	    &ctfile_max_cachesize, NULL },
	{ "md_remote_auto_differential" , CT_S_INT, &ct_auto_differential,
	    NULL, NULL, NULL },
	{ "md_max_differentials" , CT_S_INT, &ct_max_differentials,
	    NULL, NULL, NULL },
	{ "ctfile_expire_day" , CT_S_INT, &ct_ctfile_keep_days,
	    NULL, NULL, NULL },
	{ "crypto_password", CT_S_STR, NULL, &ct_crypto_passphrase, NULL, NULL },
#if defined(CT_EXT_SETTINGS)
	CT_EXT_SETTINGS
#endif	/* CT_EXT_SETTINGS */
	{ NULL, 0, NULL, NULL, NULL,  NULL }
};

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
ct_create_config(void)
{
	char			prompt[1024];
	char			answer[1024], answer2[1024];
	uint8_t			ad[SHA512_DIGEST_LENGTH];
	char			b64d[128];
	char			*conf_buf = NULL;
	char			*conf = NULL, *dir = NULL;
	char			*mode = NULL;
	int			rv, fd;
	int			have_file = 0, save_password = 0;
	int			save_crypto_passphrase = 0;
	FILE			*f = NULL;
	struct stat		sb;

	/*
	 * config should not have been loaded by this point, but enforce
	 * defaults just in case.
	 */
	ct_auto_differential = ct_secrets_upload = 0;
	ct_username = ct_password = ct_crypto_passphrase =
	    ctfile_cachedir = NULL;
	ct_ca_cert = ct_cert = ct_key = NULL;


	/* help user create config file */
	conf_buf = ct_user_config();
	snprintf(prompt, sizeof prompt, "Target conf file [%s]: ", conf_buf);
	ct_get_answer(prompt, NULL, NULL, conf_buf, answer, sizeof answer, 0);
	if (conf_buf != NULL)
		e_free(&conf_buf);
	conf = e_strdup(answer);

	/*
	 * Make path and create conf file early so permission failures are
	 * are caught before the user fills out all of the information.
	 */
	conf_buf = e_strdup(conf);
	if (ct_make_full_path(conf_buf, 0700))
		CFATAL("unable to create directory %s", conf_buf);
	e_free(&conf_buf);

	if ((fd = open(conf, O_RDWR | O_CREAT | O_TRUNC, 0600)) == -1)
		CFATAL("unable to open file for writing %s", conf);
	if ((f = fdopen(fd, "r+")) == NULL)
		CFATAL("unable to open file %s", conf);

	while (ct_username == NULL) {
		strlcpy(prompt, "login username: ", sizeof(prompt));
		if (ct_get_answer(prompt, NULL, NULL, NULL, answer,
		    sizeof answer, 0)) {
			printf("must supply username\n");
			continue;
		}
		if (strlen(answer) < 3) {
			printf("invalid username length\n");
			continue;
		}
		ct_username = e_strdup(answer);
		ct_normalize_username(ct_username);
	}


	conf_buf = e_strdup(conf);
	dir = dirname(conf_buf);
	e_asprintf(&ctfile_cachedir, "%s/ct_cachedir", dir);
	e_asprintf(&ct_crypto_secrets, "%s/ct_crypto", dir);
	e_asprintf(&ct_cert, "%s/ct_certs/ct_%s.crt", dir, ct_username);
	e_asprintf(&ct_ca_cert, "%s/ct_certs/ct_ca.crt", dir);
	e_asprintf(&ct_key, "%s/ct_certs/private/ct_%s.key", dir, ct_username);

	if (stat(ct_cert , &sb) != 0)
		CFATALX("certificate file %s not found, please ensure you "
		    "have extracted the certificate bundle to your "
		    "configuration directory", ct_cert);

	if (stat(ct_ca_cert , &sb) != 0)
		CFATALX("ca certificate file %s not found, please ensure you "
		    "have extracted the certificate bundle to your "
		    "configuration directory", ct_ca_cert);
	if (stat(ct_key, &sb) != 0)
		CFATALX("certificate key file %s not found, please ensure you "
		    "have extracted the certificate bundle to your "
		    "configuration directory", ct_key);

	while (ct_password == NULL) {
		if (ct_prompt_password("login password: ", answer,
		    sizeof answer, answer2, sizeof answer2, 0))
			CFATALX("password");

		if (strlen(answer))
			ct_password = e_strdup(answer);
		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	/* Verify username and password are correct before continuing. */
	assl_initialize();
	ct_event_init();
	ct_assl_ctx = ct_ssl_connect(0);
	if (ct_assl_negotiate_poll(ct_assl_ctx)) {
		CFATALX("unable to connect to server");
	}
	/*
	 * XXX: It would make more sense to leave the connection open here, but
	 * there are some corner cases that need to be handled if so.
	 */
	ct_ssl_cleanup();

	strlcpy(prompt, "Save login password to configuration file? [yes]: ",
	    sizeof(prompt));
	if (ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0) == 1)
		save_password = 1;

	if (ct_have_remote_secrets_file()) {
		strlcpy(prompt, "Your account already has a crypto secrets "
		    "file associated with it.  Download it to the local "
		    "machine? [yes]: ", sizeof(prompt));
		rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0);
		if (rv == 1) {
			ct_secrets_upload = 1;
			ct_download_secrets_file();
			have_file = 1;
			goto crypto_passphrase;
		}
		/* XXX delete remote secrets if not? */
	}

	/* No remote secrets file (or user didn't want to use it). */
	if (stat(ct_crypto_secrets, &sb) == 0) {
		strlcpy(prompt, "Found an existing crypto secrets file. Use "
		    "this one? [yes]: ", sizeof(prompt));
		if (ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0) == 1) {
			have_file = 1;
			goto crypto_passphrase;
		} else {
			CWARNX("deleting existing secrets file");
			unlink(ct_crypto_secrets);
		}
	}

	/* No remote or local secrets file (or user didn't want to use them). */
	strlcpy(prompt, "Automatically generate crypto passphrase? [yes]: ",
	    sizeof(prompt));
	rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0);
	if (rv == 1) {
		arc4random_buf(answer2, sizeof answer2);
		ct_sha512((uint8_t *)answer2, ad, sizeof answer2);
		if (ct_base64_encode(CT_B64_ENCODE, ad,
		    sizeof ad, (uint8_t *)b64d, sizeof b64d))
			CFATALX("can't base64 encode crypto passphrase");

		ct_crypto_passphrase = e_strdup(b64d);
		save_crypto_passphrase = 1;
	} else {
		if (ct_prompt_password("crypto passphrase: ", answer,
		    sizeof answer, answer2, sizeof answer2, 1))
			CFATALX("crypto passphrase");

		if (strlen(answer))
			ct_crypto_passphrase = e_strdup(answer);

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}
	secrets_generate(NULL, 0, NULL);

crypto_passphrase:
	while (have_file && ct_crypto_passphrase == NULL) {
		if (ct_prompt_password("crypto passphrase: ", answer,
		    sizeof answer, answer2, sizeof answer2, 0))
			CFATALX("crypto password");

		if (strlen(answer))
			ct_crypto_passphrase = e_strdup(answer);

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);

		/* Check passphrase works for the file */
		CWARNX("checking local secrets file is valid");
		if (ct_unlock_secrets(ct_crypto_passphrase,
		    ct_crypto_secrets, ct_crypto_key,
		    sizeof(ct_crypto_key),
		    ct_iv, sizeof (ct_iv))) {
			CWARNX("password incorrect, try again");
			bzero(ct_crypto_passphrase,
			    sizeof ct_crypto_passphrase);
			e_free(&ct_crypto_passphrase);
		}
	}

	/* Prompt to save crytpo passphrase in config if not set. */
	if (!save_crypto_passphrase) {
		strlcpy(prompt,
		    "Save crypto passphrase to configuration file? [yes]: ",
		    sizeof(prompt));
		rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0);
		if (rv == 1)
			save_crypto_passphrase = 1;
	}


	/* Prompt to store secrets file on server if not set. */
	if (!ct_secrets_upload) {
		strlcpy(prompt, "Store crypto secrets file on server? [yes]: ",
		    sizeof(prompt));
		if ((ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0)) == 1)
			ct_secrets_upload = 1;
	}

	strlcpy(prompt,
	    "Choose a ctfile operation mode (remote/local) [remote]: ",
	    sizeof(prompt));
	rv = ct_get_answer(prompt, "remote", "local", "remote", answer,
	    sizeof answer, 0);
	mode = e_strdup(answer);

	if (rv == 1) {
		strlcpy(prompt, "Use automatic remote differentials? [no]: ",
		    sizeof(prompt));
		rv = ct_get_answer(prompt, "yes", "no", "no", answer,
		    sizeof answer, 0);
		if (rv == 1)
			ct_auto_differential = 1;
	}

	fprintf(f, "username\t\t\t\t= %s\n", ct_username);
	if (save_password && ct_password)
		fprintf(f, "password\t\t\t\t= %s\n", ct_password);
	else
		fprintf(f, "#password\t\t\t\t=\n");
	if (save_crypto_passphrase && ct_crypto_passphrase)
		fprintf(f, "crypto_passphrase\t\t\t= %s\n", ct_crypto_passphrase);
	else
		fprintf(f, "#crypto_passphrase\t\t\t=\n");

	fprintf(f, "cache_db\t\t\t\t= %s/ct_db\n", dir);
	fprintf(f, "session_compression\t\t\t= lzo\n");
	fprintf(f, "crypto_secrets\t\t\t\t= %s\n", ct_crypto_secrets);
	fprintf(f, "ca_cert\t\t\t\t\t= %s\n", ct_ca_cert);
	fprintf(f, "cert\t\t\t\t\t= %s\n", ct_cert);
	fprintf(f, "key\t\t\t\t\t= %s\n", ct_key);

	fprintf(f, "ctfile_mode\t\t\t\t= %s\n", mode);
	if (strcmp(mode, "remote") == 0) {
		fprintf(f, "ctfile_cachedir\t\t\t\t= %s\n", ctfile_cachedir);
		fprintf(f, "ctfile_remote_auto_differential\t\t= %d\n",
		    ct_auto_differential);
	} else {
		fprintf(f, "#ctfile_cachedir\t\t\t= %s\n", ctfile_cachedir);
		fprintf(f, "#ctfile_remote_auto_differential\t= %d\n",
		    ct_auto_differential);
	}
	fprintf(f, "upload_crypto_secrets\t\t\t= %d\n", ct_secrets_upload);

	printf("Configuration file created.\n");

	if (conf_buf)
		e_free(&conf_buf);
	if (ct_username)
		e_free(&ct_username);
	if (ct_password) {
		bzero(ct_password, strlen(ct_password));
		e_free(&ct_password);
	}
	if (ct_crypto_passphrase) {
		bzero(ct_crypto_passphrase, strlen(ct_crypto_passphrase));
		e_free(&ct_crypto_passphrase);
	}
	if (ct_crypto_secrets)
		e_free(&ct_crypto_secrets);
	if (mode)
		e_free(&mode);
	if (ctfile_cachedir)
		e_free(&ctfile_cachedir);
	if (f)
		fclose(f);
}

int
ct_load_config(struct ct_settings *mysettings)
{
	char		*config_path = NULL;
	int		config_try = 0;
	static char	ct_fullcachedir[PATH_MAX];

	if (ct_configfile) {
		if (ct_config_parse(mysettings, ct_configfile))
			CFATALX("Unable to open specified config file %s",
			   ct_configfile);
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
				return (1);
				break;
			}
			if (ct_config_parse(mysettings, config_path) == 0) {
				ct_configfile = config_path;
				break;
			}
			config_try++;
		}
	}

	ctfile_mode_setup(ctfile_mode_str);
	/* Fix up cachedir: code requires it to end with a slash. */
	if (ctfile_cachedir != NULL &&
	    ctfile_cachedir[strlen(ctfile_cachedir) - 1] != '/') {
		int rv;

		if ((rv = snprintf(ct_fullcachedir, sizeof(ct_fullcachedir),
		    "%s/", ctfile_cachedir)) == -1 || rv > PATH_MAX)
			CFATALX("invalid metadata pathname");
		ctfile_cachedir = ct_fullcachedir;

	}
	/* And make sure it exists. */
	if (ctfile_cachedir != NULL &&
	    ct_make_full_path(ctfile_cachedir, 0700) != 0)
		CFATALX("can't create ctfile cache directory %s",
		    ctfile_cachedir);

	/* Apply compression from config. */
	if (ct_compression_type == NULL) {
		ct_compress_enabled = 0;
	} else if (strcmp("lzo", ct_compression_type) == 0) {
		ct_compress_enabled = C_HDR_F_COMP_LZO;
	} else if (strcmp("lzma", ct_compression_type) == 0) {
		ct_compress_enabled = C_HDR_F_COMP_LZMA;
	} else if (strcmp("lzw", ct_compression_type) == 0) {
		ct_compress_enabled = C_HDR_F_COMP_LZW;
	} else {
		CFATAL("compression type %s not recognized",
		    ct_compression_type);
	}
	if (ct_compress_enabled != 0) {
		ct_init_compression(ct_compress_enabled);
		ct_cur_compress_mode = ct_compress_enabled;
	}

	return (0);
}

void
ct_unload_config(void)
{
}
