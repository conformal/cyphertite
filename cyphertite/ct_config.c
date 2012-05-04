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

#include "ct.h"
#include <ct_ext.h>

void ct_write_config(struct ct_config *, FILE *, int, int);
void ct_default_config(struct ct_config *);

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


void
ct_create_config(void)
{
	struct ct_global_state	*state;
	struct ct_config	config;
	char			prompt[1024];
	char			answer[1024], answer2[1024];
	uint8_t			ad[SHA512_DIGEST_LENGTH];
	char			b64d[128];
	char			*conf_buf = NULL, *conf = NULL;
	char			*conf_tmp = NULL, *dir = NULL;
	int			rv, fd;
	int			save_password = 0, save_crypto_passphrase = 0;
	int			autogen_crypto_passphrase = 0;
	int			expert_mode = 0, secrets_generated = 0;
	FILE			*f = NULL;
	struct stat		sb;

	/*
	 * config should not have been loaded by this point, but enforce
	 * defaults just in case.
	 */
	ct_default_config(&config);

	/* help user create config file */
	strlcpy(prompt, "Use expert setup mode? [no]: ",
	    sizeof(prompt));
	if (ct_get_answer(prompt, "yes", "no", "no", answer,
	    sizeof answer, 0) == 1) {
		expert_mode = 1;
	}

	conf_buf = ct_user_config();
	if (expert_mode) {
		snprintf(prompt, sizeof prompt,
		    "Target config file [%s]: ", conf_buf);
		ct_get_answer(prompt, NULL, NULL, conf_buf, answer,
		    sizeof answer, 0);
		if (conf_buf)
			e_free(&conf_buf);
		conf = e_strdup(answer);
	} else {
		conf = conf_buf;
	}

	if (stat(conf, &sb) == 0) {
		strlcpy(prompt, "Target config file already exists.  "
		    "Overwrite? [no]: ", sizeof(prompt));
		rv = ct_get_answer(prompt, "yes", "no", "no", answer,
		    sizeof answer, 0);
		if (rv == 2) {
			exit(1);
		}
	}
	/*
	 * Make path and create conf file early so permission failures are
	 * are caught before the user fills out all of the information.
	 */
	dir = ct_dirname(conf);
	conf_buf = e_strdup(conf);
	if (ct_make_full_path(conf_buf, 0700))
		CFATAL("unable to create path %s", conf_buf);
	if (e_asprintf(&conf_tmp, "%s/%s", dir,
	    "cyphertite.conf.XXXXXXXXXX") == -1)
		CFATAL("unable to allocate conf template");
	e_free(&conf_buf);

	if ((fd = mkstemp(conf_tmp)) == -1)
		CFATAL("unable to open temp file for writing");
	if ((f = fdopen(fd, "r+")) == NULL)
		CFATAL("unable to open file %s", conf_tmp);

	while (config.ct_username == NULL) {
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
		config.ct_username = e_strdup(answer);
		ct_normalize_username(config.ct_username);
	}


	e_asprintf(&config.ct_localdb, "%s%cct_db", dir, CT_PATHSEP);
	e_asprintf(&config.ct_ctfile_cachedir, "%s%cct_cachedir", dir,
	    CT_PATHSEP);
	e_asprintf(&config.ct_crypto_secrets, "%s%cct_crypto", dir, CT_PATHSEP);
	e_asprintf(&config.ct_cert, "%s%cct_certs%cct_%s.crt", dir,
	    CT_PATHSEP, CT_PATHSEP, config.ct_username);
	e_asprintf(&config.ct_ca_cert, "%s%cct_certs%cct_ca.crt", dir,
	    CT_PATHSEP, CT_PATHSEP);
	e_asprintf(&config.ct_key, "%s%cct_certs%cprivate%cct_%s.key", dir,
	    CT_PATHSEP, CT_PATHSEP, CT_PATHSEP, config.ct_username);

	while (config.ct_password == NULL) {
		if (ct_prompt_password("login password: ", answer,
		    sizeof answer, answer2, sizeof answer2, 0))
			CFATALX("password");

		if (strlen(answer))
			config.ct_password = e_strdup(answer);
		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	/* download certs if needed */
	if ((stat(config.ct_cert, &sb) != 0) ||
	    (stat(config.ct_ca_cert , &sb) != 0) ||
	    (stat(config.ct_key, &sb) != 0)) {
		CWARNX("Downloading certificates...");
		ct_download_decode_and_save_certs(&config);
	}

	/* Verify username and password are correct before continuing. */
	state = ct_setup_state(&config);
	assl_initialize();
	state->event_state = ct_event_init(state, NULL);
	state->ct_assl_ctx = ct_ssl_connect(state, 0);
	if (ct_assl_negotiate_poll(state)) {
		CFATALX("unable to connect to server");
	}
	/*
	 * XXX: It would make more sense to leave the connection open here, but
	 * there are some corner cases that need to be handled if so.
	 */
	ct_ssl_cleanup(state->ct_assl_ctx, state->bw_limit);
	state->ct_assl_ctx = NULL;
	state->bw_limit = NULL;
	ct_event_cleanup(state->event_state);
	state->event_state = NULL;

	if (expert_mode) {
		strlcpy(prompt,
		    "Save login password to configuration file? [yes]: ",
		    sizeof(prompt));
		if (ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0) == 1)
			save_password = 1;
	} else {
		save_password = 1;
	}

	if (ct_have_remote_secrets_file(&config)) {
		if (expert_mode) {
			strlcpy(prompt,
			    "Your account already has a crypto secrets "
			    "file associated with it.  Download it to the "
			    "local machine? [yes]: ", sizeof(prompt));
			rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
			    sizeof answer, 0);
			if (rv == 1) {
				config.ct_secrets_upload = 1;
				ct_download_secrets_file(&config);
				goto crypto_passphrase;
			}
			/* XXX delete remote secrets if not? */
		} else {
			config.ct_secrets_upload = 1;
			ct_download_secrets_file(&config);
			goto crypto_passphrase;
		}
	}

	/* No remote secrets file (or user didn't want to use it). */
	if (stat(config.ct_crypto_secrets, &sb) == 0) {
		if (expert_mode) {
			strlcpy(prompt,
			    "Found an existing crypto secrets file. Use "
			    "this one? [yes]: ", sizeof(prompt));
			if (ct_get_answer(prompt, "yes", "no", "yes", answer,
			    sizeof answer, 0) == 1) {
				goto crypto_passphrase;
			} else {
				CWARNX("deleting existing secrets file");
				unlink(config.ct_crypto_secrets);
			}
		} else {
			goto crypto_passphrase;
		}
	}

	/* No remote or local secrets file (or user didn't want to use them). */
	if (expert_mode) {
		strlcpy(prompt,
		    "Automatically generate crypto passphrase? [yes]: ",
		    sizeof(prompt));
		rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0);
		if (rv == 1) {
			autogen_crypto_passphrase = 1;
		}
	} else {
		autogen_crypto_passphrase = 1;
	}

	if (autogen_crypto_passphrase) {
		arc4random_buf(answer2, sizeof answer2);
		ct_sha512((uint8_t *)answer2, ad, sizeof answer2);
		if (ct_base64_encode(CT_B64_ENCODE, ad,
		    sizeof ad, (uint8_t *)b64d, sizeof b64d))
			CFATALX("can't base64 encode crypto passphrase");

		config.ct_crypto_passphrase = e_strdup(b64d);
		save_crypto_passphrase = 1;
	} else {
		if (ct_prompt_password("crypto passphrase: ", answer,
		    sizeof answer, answer2, sizeof answer2, 1))
			CFATALX("crypto passphrase");

		if (strlen(answer))
			config.ct_crypto_passphrase = e_strdup(answer);

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}
	CWARNX("Generating crypto secrets file...");
	if (ct_create_secrets(config.ct_crypto_passphrase,
	    config.ct_crypto_secrets, NULL, NULL))
		CFATALX("can't create secrets");

	secrets_generated = 1;

crypto_passphrase:
	while (!secrets_generated && config.ct_crypto_passphrase == NULL) {
		unsigned char		iv[CT_IV_LEN];
		unsigned char		crypto_key[CT_KEY_LEN];

		if (ct_prompt_password("crypto passphrase: ", answer,
		    sizeof answer, answer2, sizeof answer2, 0))
			CFATALX("crypto password");

		if (strlen(answer))
			config.ct_crypto_passphrase = e_strdup(answer);

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);

		/* Check passphrase works for the file */
		CWARNX("checking local secrets file is valid");
		if (ct_unlock_secrets(config.ct_crypto_passphrase,
		    config.ct_crypto_secrets, crypto_key,
		    sizeof(crypto_key), iv, sizeof (iv))) {
			CWARNX("password incorrect, try again");
			bzero(config.ct_crypto_passphrase,
			    strlen(config.ct_crypto_passphrase));
			e_free(&config.ct_crypto_passphrase);
		}
	}

	/*
	 * Always save the crypto passphrase to the file when not in expert
	 * mode
	 */
	if (!expert_mode)
		save_crypto_passphrase = 1;

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
	if (!config.ct_secrets_upload) {
		if (expert_mode) {
			strlcpy(prompt,
			    "Store crypto secrets file on server? [yes]: ",
			    sizeof(prompt));
			if ((ct_get_answer(prompt, "yes", "no", "yes", answer,
			    sizeof answer, 0)) == 1)
				config.ct_secrets_upload = 1;
		} else {
			config.ct_secrets_upload = 1;
		}
	}

	/*
	 * Store secrets file to the server now if flag is set and it was
	 * generated.
	 */
	if (secrets_generated && config.ct_secrets_upload) {
		ct_upload_secrets_file(&config);
	}

	if (expert_mode) {
		strlcpy(prompt,
		    "Choose a ctfile operation mode (remote/local) [remote]: ",
		    sizeof(prompt));
		rv = ct_get_answer(prompt, "remote", "local", "remote", answer,
		    sizeof answer, 0);
		if (strcmp(answer, "remote") == 0) {
			config.ct_ctfile_mode = CT_MDMODE_REMOTE;
		} else {
			config.ct_ctfile_mode = CT_MDMODE_LOCAL;
		}

		if (rv == 1) {
			strlcpy(prompt,
			    "Use automatic remote differentials? [no]: ",
			    sizeof(prompt));
			rv = ct_get_answer(prompt, "yes", "no", "no", answer,
			    sizeof answer, 0);
			if (rv == 1)
				config.ct_auto_differential = 1;
		}
	} else {
		config.ct_ctfile_mode = CT_MDMODE_REMOTE;
	}

	ct_write_config(&config, f, save_password, save_crypto_passphrase);

	printf("Configuration file created.\n");
	if (save_crypto_passphrase && config.ct_crypto_passphrase) {
		printf("WARNING: It is highly recommended that you store your "
		    "'%s' file to an offline location, preferrably offsite, as "
		    " your crypto passphrase CANNOT be recovered.\n", conf);
		printf("Examples:\n");
		printf(" - Copy it to a USB memory drive\n");
		printf(" - Print a copy of it and store it in a fire proof "
		    "safe\n");
	}

	if (f)
		fclose(f);

	if (rename(conf_tmp, conf) == -1) {
		unlink(conf_tmp);
		CFATAL("unable to move config file into place");
	}

	if (dir)
		e_free(&dir);
	if (conf_tmp)
		e_free(&conf_tmp);
	if (conf)
		e_free(&conf);
	if (config.ct_username)
		e_free(&config.ct_username);
	if (config.ct_password) {
		bzero(config.ct_password, strlen(config.ct_password));
		e_free(&config.ct_password);
	}
	if (config.ct_crypto_passphrase) {
		bzero(config.ct_crypto_passphrase,
		    strlen(config.ct_crypto_passphrase));
		e_free(&config.ct_crypto_passphrase);
	}
	if (config.ct_crypto_secrets)
		e_free(&config.ct_crypto_secrets);
	if (config.ct_ctfile_cachedir)
		e_free(&config.ct_ctfile_cachedir);
	if (config.ct_localdb)
		e_free(&config.ct_localdb);
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

	if (ctfile_mode_str != NULL) {
		if (strcmp(ctfile_mode_str, "remote") == 0)
			conf.ct_ctfile_mode = CT_MDMODE_REMOTE;
		else if (strcmp(ctfile_mode_str, "local") == 0)
			conf.ct_ctfile_mode = CT_MDMODE_LOCAL;
		else
			CFATALX("invalid ctfile mode specified");
	}

	/* Fix up cachedir: code requires it to end with a slash. */
	if (conf.ct_ctfile_cachedir != NULL &&
	    conf.ct_ctfile_cachedir[strlen(conf.ct_ctfile_cachedir) - 1]
	    != CT_PATHSEP) {
		int rv;

		if ((rv = snprintf(ct_fullcachedir, sizeof(ct_fullcachedir),
		    "%s%c", conf.ct_ctfile_cachedir, CT_PATHSEP)) == -1 ||
		    rv > PATH_MAX)
			CFATALX("invalid metadata pathname");
		free(conf.ct_ctfile_cachedir);
		conf.ct_ctfile_cachedir = strdup(ct_fullcachedir);
		if (ct_fullcachedir == NULL)
			CFATALX("can't allocate memory for cachedir");

	}

	if (conf.ct_ctfile_mode == CT_MDMODE_REMOTE &&
	    conf.ct_ctfile_cachedir == NULL)
		CFATALX("remote mode needs a cache directory set");

	/* And make sure it exists. */
	if (conf.ct_ctfile_cachedir != NULL &&
	    ct_make_full_path(conf.ct_ctfile_cachedir, 0700) != 0)
		CFATALX("can't create ctfile cache directory %s",
		    conf.ct_ctfile_cachedir);

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
		CFATAL("compression type %s not recognized",
		    ct_compression_type);
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
		fprintf(f, "cache_db\t\t\t\t= %s/ct_db\n", config->ct_localdb);
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
