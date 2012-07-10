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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <shrink.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <ctutil.h>

#include <cyphertite.h>
#include "ct.h"
#include "ct_ctl.h"
#include <ct_ext.h>


void cull(struct ct_cli_cmd *, int , char **);
void cpasswd(struct ct_cli_cmd *, int , char **);
void secrets_download(struct ct_cli_cmd *, int, char **);
void secrets_upload(struct ct_cli_cmd *, int, char **);
void secrets_generate(struct ct_cli_cmd *, int, char **);
void config_generate(struct ct_cli_cmd *, int, char **);

char		 *ctctl_configfile;
struct ct_config *ctctl_config;

void
cpasswd(struct ct_cli_cmd *c, int argc, char **argv)
{
	char		old_crypto_secrets[PATH_MAX];
	char		old_configfile[PATH_MAX];
	char		prompt[1024], buf[1024], *p;
	char		answer[1024], answer2[1024];
	char		*crypto_passphrase = NULL;
	struct stat	sb;
	int		rv, write_crypto_passphrase = 0;
	int		crypto_passphrase_written = 0;
	uint8_t		ad[SHA512_DIGEST_LENGTH];
	unsigned char	iv[CT_IV_LEN];
	unsigned char	crypto_key[CT_KEY_LEN];
	char		b64d[128];
	FILE		*fr, *fw;

	snprintf(prompt, sizeof prompt, "This operation overwrites %s "
	    "and %s, continue? [yes]: ", ctctl_configfile,
	    ctctl_config->ct_crypto_secrets);
	if (ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0) != 1)
		CFATALX("operation aborted");

	if (ctctl_config->ct_crypto_secrets == NULL)
		CFATALX("Crypto not enabled");

	if (stat(ctctl_config->ct_crypto_secrets, &sb) == -1)
		CFATALX("secrets file does not exist");

	if (ct_unlock_secrets(ctctl_config->ct_crypto_passphrase,
	    ctctl_config->ct_crypto_secrets,
	    crypto_key, sizeof(crypto_key), iv, sizeof (iv)))
		CFATALX("can't unlock secrets");

	snprintf(prompt, sizeof prompt,
	    "Save crypto passphrase to configuration file? [yes]: ");
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

			crypto_passphrase = strdup(b64d);
			if (crypto_passphrase == NULL)
				CFATALX("strdup");
		}

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
		write_crypto_passphrase = 1;
	}

	/* see if we had one autogenerated */
	if (crypto_passphrase == NULL) {
		if (ct_prompt_password("crypto passphrase: ", answer,
		    sizeof answer, answer2, sizeof answer2, 1))
			CFATALX("password");

		if (strlen(answer)) {
			crypto_passphrase = strdup(answer);
			if (crypto_passphrase == NULL)
				CFATALX("strdup");
		}

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	/* rename files */
	snprintf(old_configfile, sizeof old_configfile, "%s~",
	    ctctl_configfile);
	if (rename(ctctl_configfile, old_configfile))
		CFATAL("Can't rename %s to %s", ctctl_configfile,
		    old_configfile);

	snprintf(old_crypto_secrets, sizeof old_crypto_secrets, "%s~",
	    ctctl_config->ct_crypto_secrets);
	if (rename(ctctl_config->ct_crypto_secrets, old_crypto_secrets))
		CFATAL("Can't rename %s to %s",
		    ctctl_config->ct_crypto_secrets, old_crypto_secrets);

	/* rewrite files */
	fr = fopen(old_configfile, "r");
	if (fr == NULL)
		CFATAL("%s", old_configfile);
	fw = fopen(ctctl_configfile, "w");
	if (fw == NULL)
		CFATAL("%s", ctctl_configfile);

	while (fgets(buf, sizeof(buf), fr) != NULL) {
		if ((p = strchr(buf, '\n')) == NULL)
			CFATALX("input line too long.\n");
		*p = '\0';

		/* see what to do with crypto_passphrase */
		if (!strncmp(buf, "crypto_passphrase",
		    strlen("crypto_passphrase")) ||
		    !strncmp(buf, "crypto_password",
		    strlen("crypto_password"))) {
			if (write_crypto_passphrase) {
				fprintf(fw, "crypto_passphrase\t\t= %s\n",
				    crypto_passphrase);
				crypto_passphrase_written = 1;
			}
		} else
			fprintf(fw, "%s\n", buf);
	}
	if (crypto_passphrase_written == 0 && write_crypto_passphrase)
		fprintf(fw, "crypto_passphrase\t\t= %s\n", crypto_passphrase);

	fclose(fr);
	fclose(fw);

	ct_create_secrets(crypto_passphrase, ctctl_config->ct_crypto_secrets,
	    crypto_key, iv);

	bzero(crypto_passphrase, strlen(crypto_passphrase));
	free(crypto_passphrase);
}

struct ct_cli_cmd	cmd_secrets[] = {
	{ "upload", NULL, 0, "", secrets_upload },
	{ "download", NULL, 0, "", secrets_download },
	{ "passwd", NULL, 0, "", cpasswd},
	{ "generate", NULL, 0, "", secrets_generate },
	{ NULL, NULL, 0, NULL, NULL, 0}
};

struct ct_cli_cmd	cmd_config[] = {
	{ "generate", NULL, 0, "", config_generate },
	{ NULL, NULL, 0, NULL, NULL, 0}
};

struct ct_cli_cmd	cmd_list[] = {
	{ "cull", NULL, 0, "", cull },
	{ "secrets", cmd_secrets, CLI_CMD_SUBCOMMAND, "<action> ...", NULL },
	{ "config", cmd_config, CLI_CMD_SUBCOMMAND, "<action> ...", NULL },
#ifdef CT_EXT_CTCTL_CMDS
	CT_EXT_CTCTL_CMDS
#endif
	{ NULL, NULL, 0, NULL, NULL }
};

void
ctctl_usage(void)
{
	fprintf(stderr, "%s [-D debugstring] [-F configfile] <action>\n",
	    __progname);
	exit(1);
}

int
ctctl_main(int argc, char *argv[])
{
	int			c;
	struct ct_cli_cmd	*cc = NULL;
	char			*configfile = NULL;
	char			*debugstring = NULL;
	uint64_t		debug_mask = 0;
	uint32_t		cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	int			ret;

	while ((c = getopt(argc, argv, "D:F:")) != -1) {
		switch (c) {
		case 'D':
			if (debugstring != NULL)
				CFATALX("only one -D argument is valid");
			debugstring = optarg;
			break;
		case 'F':
			configfile = optarg;
			break;
		default:
			CWARNX("must specify action");
			ctctl_usage();
			/* NOTREACHED */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (debugstring) {
		cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC |
		    CLOG_F_LINE | CLOG_F_DTIME;
		exude_enable(CT_LOG_EXUDE);
#if CT_ENABLE_THREADS
		exude_enable_threads();
#endif
		debug_mask |= ct_get_debugmask(debugstring);
	}

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");
	clog_set_mask(debug_mask);

	/* We can allocate these now that we've decided if we need exude */
	if (configfile)
		ctctl_configfile= e_strdup(configfile);

	/* load config XXX ick... unless we're generating one. */
	if (!(argc == 2 && strcmp(argv[0], "config") == 0 && strcmp(argv[1],
	    "generate") == 0) &&
	    (ret = ct_load_config(&ctctl_config, &ctctl_configfile)) != 0) {
		CFATALX("%s", ct_strerror(ret));
	}

	if ((cc = ct_cli_validate(cmd_list, &argc, &argv)) == NULL)
		ct_cli_usage(cmd_list, NULL);

	ct_cli_execute(cc, &argc, &argv);

	if (ctctl_config != NULL)
		ct_unload_config(ctctl_configfile, ctctl_config);
	else if (ctctl_configfile != NULL)
		e_free(&ctctl_configfile);

	exude_cleanup();

	return (0);
}

/* cull - sha deletion from server operation */
void
cull(struct ct_cli_cmd *c, int argc, char **argv)
{
	struct ct_global_state	*state;
	int			 need_secrets, ret;

	/* XXX */

	ct_prompt_for_login_password(ctctl_config);

	need_secrets = 1;

	if ((ret = ct_init(&state, ctctl_config, need_secrets,
	    ct_info_sig)) != 0)
		CFATALX("failed to initialize: %s", ct_strerror(ret));

	ct_cull_kick(state);
	ct_wakeup_file(state->event_state);

	ret = ct_event_dispatch(state->event_state);
	if (ret != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));

	ct_cleanup(state);
	e_check_memory();
}

/* Make sure we don't overwrite the file without permission */
ct_op_cb ct_check_secrets_upload;
void
ct_check_secrets_upload(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_ctfileop_args	*cca = op->op_args;
	char			 answer[1024];

	/* Check to see if we already have a secrets file on the server */
	if (ct_file_on_server(state, cca->cca_remotename)) {
		if (ct_get_answer("There is already a crypto secrets file on "
		    "the server, would you like to replace it? [no]: ",
		    "yes", "no", "no", answer, sizeof answer, 0) != 1)
			CFATALX("not uploading secrets file");
		op = ct_add_operation_after(state, op, ctfile_delete, NULL,
		    cca->cca_remotename);
	}

	ct_add_operation_after(state, op, ctfile_archive, NULL, cca);

}

void
secrets_upload(struct ct_cli_cmd *c, int argc, char **argv)
{
	struct ct_ctfileop_args	 cca;

	CWARNX("Uploading secrets file to server...");

	cca.cca_localname = ctctl_config->ct_crypto_secrets;
	cca.cca_remotename = "crypto.secrets";
	cca.cca_tdir = NULL;
	cca.cca_encrypted = 0;
	cca.cca_ctfile = 0;

	ct_do_operation(ctctl_config, ctfile_list_start,
	    ct_check_secrets_upload, &cca, 0);
}

void
secrets_download(struct ct_cli_cmd *c, int argc, char **argv)
{
	struct ct_ctfileop_args	 cca;
	char			*dirpath, *fname;

	CWARNX("Downloading secrets file from server...");

	if ((dirpath = ct_dirname(ctctl_config->ct_crypto_secrets)) == NULL)
		CFATALX("can't get dirname of %s",
		    ctctl_config->ct_crypto_secrets);
	if ((fname = ct_basename(ctctl_config->ct_crypto_secrets)) == NULL)
		CFATALX("can't get basename of %s",
		    ctctl_config->ct_crypto_secrets);

	cca.cca_localname = fname;
	cca.cca_remotename = "crypto.secrets";
	cca.cca_tdir = dirpath;
	cca.cca_encrypted = 0;
	cca.cca_ctfile = 0;

	ct_do_operation(ctctl_config, ctfile_extract, NULL, &cca, 0);

	e_free(&dirpath);
	e_free(&fname);
}

void
secrets_generate(struct ct_cli_cmd *c, int argc, char **argv)
{
	struct stat	sb;

	if (stat(ctctl_config->ct_crypto_secrets, &sb) != -1)
		CFATALX("A crypto secrets file already exists!\n"
		    "Please check if it is valid before deleting.");
	CWARNX("Generating crypto secrets file...");
	if (ct_create_secrets(ctctl_config->ct_crypto_passphrase,
	    ctctl_config->ct_crypto_secrets, NULL, NULL))
		CFATALX("can't create secrets");

	if (ctctl_config->ct_secrets_upload != 0)
		secrets_upload(NULL, 0, NULL);
}

void
config_generate(struct ct_cli_cmd *c, int argc, char **argv)
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
			exit(0);
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
	if ((rv = ct_setup_state(&state, &config)) != 0)
		CFATALX("unable to setup state: %s", ct_strerror(rv));
	assl_initialize();
	state->event_state = ct_event_init(state, NULL, NULL);
	if ((rv = ct_ssl_connect(state)) != 0)
		CFATALX("unable to connect to server: %s", ct_strerror(rv));
	if ((rv = ct_assl_negotiate_poll(state)) != 0) {
		CFATALX("unable to log in to server: %s", ct_strerror(rv));
	}
	/*
	 * XXX: It would make more sense to leave the connection open here, but
	 * there are some corner cases that need to be handled if so.
	 */
	ct_ssl_cleanup(state);
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
				ctctl_config = &config;
				secrets_download(NULL, 0, NULL);
				goto crypto_passphrase;
			}
			/* XXX delete remote secrets if not? */
		} else {
			config.ct_secrets_upload = 1;
			ctctl_config = &config;
			secrets_download(NULL, 0, NULL);
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
	ctctl_config = &config;
	secrets_generate(NULL, 0, NULL);
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
		ctctl_config = &config;
		secrets_upload(NULL, 0, NULL);
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
			    "Use automatic remote incrementals? [no]: ",
			    sizeof(prompt));
			rv = ct_get_answer(prompt, "yes", "no", "no", answer,
			    sizeof answer, 0);
			if (rv == 1)
				config.ct_auto_incremental = 1;
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
