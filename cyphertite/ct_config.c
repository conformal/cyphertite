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

#include <clog.h>
#include <exude.h>

#include "ct.h"

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
char			*ct_crypto_password;
char			*ct_compression_type;
char			*ct_polltype;
char			*ct_mdmode_str;
char			*ct_md_cachedir;
char			*ct_includefile;
int			ct_md_mode = CT_MDMODE_LOCAL;
int			ct_compress_enabled;
int			ct_encrypt_enabled;
int			ct_multilevel_allfiles;
int			ct_auto_differential;
long long		ct_max_mdcache_size = LLONG_MAX; /* unbounded */
int			ct_max_differentials;
int			ct_secrets_upload = 0;
int			ct_ctfile_expire_day = 0;

struct ct_settings	settings[] = {
	{ "queue_depth", CT_S_INT, &ct_max_trans, NULL, NULL, NULL },
	{ "bandwidth", CT_S_INT, &ct_io_bw_limit, NULL, NULL, NULL },
	{ "host", CT_S_STR, NULL, &ct_host, NULL, NULL },
	{ "hostport", CT_S_STR, NULL, &ct_hostport, NULL, NULL },
	{ "cache_db", CT_S_DIR, NULL, &ct_localdb, NULL, NULL },
	{ "username", CT_S_STR, NULL, &ct_username, NULL, NULL },
	{ "password", CT_S_STR, NULL, &ct_password, NULL, NULL },
	{ "ca_cert", CT_S_DIR, NULL, &ct_ca_cert, NULL, NULL },
	{ "cert", CT_S_DIR, NULL, &ct_cert, NULL, NULL },
	{ "key", CT_S_DIR, NULL, &ct_key, NULL, NULL },
	{ "crypto_secrets", CT_S_DIR, NULL, &ct_crypto_secrets, NULL, NULL },
	{ "crypto_password", CT_S_STR, NULL, &ct_crypto_password, NULL, NULL }, /* name may NOT be modified */
	{ "session_compression", CT_S_STR, NULL, &ct_compression_type, NULL,
	    NULL },
	{ "polltype", CT_S_STR, NULL, &ct_polltype, NULL, NULL },
	{ "md_mode", CT_S_STR, NULL, &ct_mdmode_str, NULL, NULL },
	{ "md_cachedir", CT_S_DIR, NULL, &ct_md_cachedir, NULL, NULL },
	{ "ctfile_differential_allfiles", CT_S_INT, &ct_multilevel_allfiles,
	    NULL, NULL, NULL },
	{ "md_cachedir_max_size", CT_S_SIZE, NULL, NULL, NULL,
	    &ct_max_mdcache_size, NULL },
	{ "md_remote_auto_differential" , CT_S_INT, &ct_auto_differential,
	    NULL, NULL, NULL },
	{ "md_max_differentials" , CT_S_INT, &ct_max_differentials,
	    NULL, NULL, NULL },
	{ "upload_crypto_secrets" , CT_S_INT, &ct_secrets_upload,
	    NULL, NULL, NULL },
	{ "ctfile_expire_day" , CT_S_INT, &ct_ctfile_expire_day,
	    NULL, NULL, NULL },
	{ NULL, 0, NULL, NULL, NULL,  NULL }
};

char *
ct_system_config(void)
{
	char			*conf;

	e_asprintf(&conf, "%s", "/etc/cyphertite/cyphertite.conf");

	return (conf);
}

char *
ct_user_config(void)
{
	char			*conf;
	struct			passwd *pwd;

	pwd = getpwuid(getuid());
	if (pwd == NULL)
		CFATALX("invalid user %d", getuid());

	e_asprintf(&conf, "%s/.cyphertite/cyphertite.conf", pwd->pw_dir);
	return (conf);
}

char *
ct_user_config_old(void)
{
	char			*conf;
	struct			passwd *pwd;

	pwd = getpwuid(getuid());
	if (pwd == NULL)
		CFATALX("invalid user %d", getuid());

	e_asprintf(&conf, "%s/.cyphertite.conf", pwd->pw_dir);
	return (conf);
}

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
    char *answer2, size_t answer2_len)
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
	char			*user = NULL, *password = NULL;
	char			*crypto_password = NULL;
	char			*md_mode = NULL, *md_cachedir = NULL;
	int			md_remote_diff = 0;
	int			rv, fd;
	FILE			*f = NULL;

	/* help user create config file */
	snprintf(prompt, sizeof prompt,
	    "%s config file not found. Create one? [yes]: ", __progname);
	if (ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0) != 1)
		CFATALX("%s requires a config file", __progname);

	conf_buf = ct_user_config();
	snprintf(prompt, sizeof prompt,
	    "Target conf file [%s]: ", conf_buf);
	ct_get_answer(prompt, NULL, NULL, conf_buf, answer,
	    sizeof answer, 0);
	if (conf_buf != NULL)
		e_free(&conf_buf);
	conf = e_strdup(answer);
	if (conf == NULL)
		CFATALX("conf");

	/*
	 * Make path and create conf file early so permission failures are
	 * are caught before the user fills out all of the information.
	 */
	conf_buf = strdup(conf);
	if (conf_buf == NULL)
		CFATALX("strdup conf");
	if (ct_make_full_path(conf_buf, 0700))
		CFATAL("unable to create directory %s", conf_buf);
	if (conf_buf != NULL)
		free(conf_buf);

	if ((fd = open(conf, O_RDWR | O_CREAT, 0400)) == -1)
		CFATAL("unable to open file for writing %s", conf);
	if ((f = fdopen(fd, "r+")) == NULL)
		CFATAL("unable to open file %s", conf);

	while (user == NULL) {
		snprintf(prompt, sizeof prompt,
		    "%s login username: ", __progname);
		if (ct_get_answer(prompt,
		    NULL, NULL, NULL, answer, sizeof answer, 0)) {
			printf("must supply username\n");
			continue;
		}
		if (strlen(answer) < 3) {
			printf("invalid username length\n");
			continue;
		}
		user = strdup(answer);
		if (user == NULL)
			CFATALX("strdup");
		ct_normalize_username(user);
	}

	snprintf(prompt, sizeof prompt,
	    "Save %s login password to configuration file? [yes]: ",
	    __progname);
	rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0);

	if (rv == 1) {
		if (ct_prompt_password("login password: ", answer,
		    sizeof answer, answer2, sizeof answer2))
			CFATALX("password");

		if (strlen(answer)) {
			password = strdup(answer);
			if (password == NULL)
				CFATALX("strdup");
		}
		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	snprintf(prompt, sizeof prompt,
	    "Save %s crypto passphrase to configuration file? [yes]: ",
	    __progname);
	rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0);

	if (rv == 1) {
		snprintf(prompt, sizeof prompt,
		    "Automatically generate crypto passphrase? [yes]: ");
		rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0);

		if (rv == 1) {
			arc4random_buf(answer2, sizeof answer2);
			ct_sha512((uint8_t *)answer2, ad, sizeof answer2);
			if (ct_base64_encode(CT_B64_ENCODE, ad,
			    sizeof ad, (uint8_t *)b64d, sizeof b64d))
				CFATALX("can't base64 encode "
				    "crypto passphrase");

			crypto_password = strdup(b64d);
			if (crypto_password == NULL)
				CFATALX("strdup");
		}
		else {
			if (ct_prompt_password("crypto passphrase: ", answer,
			    sizeof answer, answer2, sizeof answer2))
				CFATALX("password");

			if (strlen(answer)) {
				crypto_password = strdup(answer);
				if (crypto_password == NULL)
					CFATALX("strdup");
			}
		}

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	conf_buf = strdup(conf);
	if (conf_buf == NULL)
		CFATALX("strdup");
	dir = dirname(conf_buf);
	if (asprintf(&md_cachedir, "%s/ct_cachedir", dir) == -1)
		CFATALX("default md_cachedir");

	snprintf(prompt, sizeof prompt,
	    "Choose a metadata operation mode (remote/local) [remote]: ");
	rv = ct_get_answer(prompt, "remote", "local", "remote", answer,
	    sizeof answer, 0);
	md_mode = strdup(answer);
	if (md_mode == NULL)
		CFATALX("md_mode");

	if (rv == 1) {
		snprintf(prompt, sizeof prompt,
		    "Target metadata cache directory [%s]: ", md_cachedir);
		ct_get_answer(prompt, NULL, NULL, md_cachedir, answer,
		    sizeof answer, 0);
		if (md_cachedir != NULL)
			free(md_cachedir);
		md_cachedir = strdup(answer);
		if (md_cachedir == NULL)
			CFATALX("md_cachedir");

		snprintf(prompt, sizeof prompt,
		    "Use automatic remote differentials? [no]: ");
		rv = ct_get_answer(prompt, "yes", "no", "no", answer,
		    sizeof answer, 0);
		if (rv == 1)
			md_remote_diff = 1;
	}

	fprintf(f, "username\t\t\t= %s\n", user);
	if (password)
		fprintf(f, "password\t\t\t= %s\n", password);
	else
		fprintf(f, "#password\t\t\t=\n");
	if (crypto_password)
		fprintf(f, "crypto_password\t\t\t= %s\n", crypto_password);
	else
		fprintf(f, "#crypto_password\t\t=\n");

	fprintf(f, "cache_db\t\t\t= %s/ct_db\n", dir);
	fprintf(f, "session_compression\t\t= lzo\n");
	fprintf(f, "crypto_secrets\t\t\t= %s/ct_crypto\n", dir);
	fprintf(f, "ca_cert\t\t\t\t= %s/ct_certs/ct_ca.crt\n", dir);
	fprintf(f, "cert\t\t\t\t= %s/ct_certs/ct_%s.crt\n", dir, user);
	fprintf(f, "key\t\t\t\t= %s/ct_certs/private/ct_%s.key\n", dir, user);

	fprintf(f, "md_mode\t\t\t\t= %s\n", md_mode);
	if (strcmp(md_mode, "remote") == 0) {
		fprintf(f, "md_cachedir\t\t\t= %s\n", md_cachedir);
		fprintf(f, "md_remote_auto_differential\t= %d\n", md_remote_diff);
	}
	else
	{
		fprintf(f, "#md_cachedir\t\t\t= %s\n", md_cachedir);
		fprintf(f, "#md_remote_auto_differential\t= %d\n",
		    md_remote_diff);
	}

	printf("Configuration file created.\n");

	if (conf_buf)
		free(conf_buf);
	if (user)
		free(user);
	if (password) {
		bzero(password, strlen(password));
		free(password);
	}
	if (crypto_password) {
		bzero(crypto_password, strlen(crypto_password));
		free(crypto_password);
	}
	if (md_mode)
		free(md_mode);
	if (md_cachedir)
		free(md_cachedir);
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

	ct_mdmode_setup(ct_mdmode_str);
	/* Fix up md cachedir: code requires it to end with a slash. */
	if (ct_md_cachedir != NULL &&
	    ct_md_cachedir[strlen(ct_md_cachedir) - 1] != '/') {
		int rv;

		if ((rv = snprintf(ct_fullcachedir, sizeof(ct_fullcachedir),
		    "%s/", ct_md_cachedir)) == -1 || rv > PATH_MAX)
			CFATALX("invalid metadata pathname");
		ct_md_cachedir = ct_fullcachedir;

	}
	/* And make sure it exists. */
	if (ct_md_cachedir != NULL &&
	    ct_make_full_path(ct_md_cachedir, 0700) != 0)
		CFATALX("can't create metadata md_cachedir");

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
