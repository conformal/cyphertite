/* $cyphertite$ */
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

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>

#include <ctutil.h>

#include "ct.h"
#include "ct_crypto.h"

void			ct_load_config(struct ct_settings *);
void			usage(void);

extern char		*__progname;

/* command line flags */
int			ct_debug;
int			ct_action = 0;
char			*ct_tdir;
FILE			*ct_listfile;
int			ct_strip_slash = 1;
int			ct_verbose_ratios;
int			ct_no_cross_mounts;
char			*ct_mfile;
int			ct_metadata;
int			ct_verbose;
char			*ct_basisbackup;
char			*ct_configfile;
int			ct_attr;
int			ct_match_mode = CT_MATCH_GLOB;

/* runtime */
int			ct_got_secrets;
int			ct_crypto = CT_MD_NOCRYPTO;
unsigned char		ct_iv[CT_IV_LEN];
unsigned char		ct_crypto_key[CT_KEY_LEN];

/* config */
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
int			ct_allow_uncompressed_writes;
char			*ct_compression_type;
char			*ct_polltype;
char			*ct_mdmode_str;
char			*ct_md_cachedir;
int			ct_md_mode = CT_MDMODE_LOCAL;
int			ct_compress_enabled;
int			ct_encrypt_enabled;
int			ct_multilevel_allfiles;

struct ct_settings	settings[] = {
	{ "max_chunk_size", CT_S_INT, &ct_max_block_size, NULL, NULL, NULL },
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
	{ "crypto_password", CT_S_STR, NULL, &ct_crypto_password, NULL, NULL },
	{ "allow_uncompressed_writes", CT_S_INT, &ct_allow_uncompressed_writes,
	    NULL, NULL, NULL },
	{ "session_compression", CT_S_STR, NULL, &ct_compression_type, NULL,
	    NULL },
	{ "polltype", CT_S_STR, NULL, &ct_polltype, NULL, NULL },
	{ "md_mode", CT_S_STR, NULL, &ct_mdmode_str, NULL, NULL },
	{ "md_cachedir", CT_S_STR, NULL, &ct_md_cachedir, NULL, NULL },
	{ NULL, 0, NULL, NULL, NULL,  NULL }
};

void
usage(void)
{
	fprintf(stderr, "%s {-ctx} [-BCDFPRXabdpv] -f <archive> [filelist]\n",
	    __progname);
	exit(0);
}

int
main(int argc, char **argv)
{
	char		pwd[PASS_MAX];
	char		*ct_mdname = NULL;
	char		ct_fullcachedir[PATH_MAX];
	struct stat	sb;
	int		c;
	int		cflags;
	int		debug;
	int		foreground = 1;
	int		ret;

	ct_savecore();

	clog_init(1);
	cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	ct_debug = debug = 0;
	while ((c = getopt(argc, argv, "B:C:DF:I:PRXa:cdef:mprtvx")) != -1) {
		switch (c) {
		case 'B':
			ct_basisbackup = optarg;
			break;
		case 'C':
			ct_tdir = optarg;
			break;
		case 'D':
			foreground = 0;
			break;
		case 'F':
			ct_configfile = optarg;
			break;
		case 'I':
			CFATALX("-I not supported");
			if ((ct_listfile = fopen(optarg, "r")) == NULL)
				CFATAL("option I: %s", optarg);
			break;
		case 'P':
			ct_strip_slash = 0;
			break;
		case 'R':
			ct_verbose_ratios = 1;
			break;
		case 'X':
			ct_no_cross_mounts = 1;
			break;
		case 'a':
			ct_multilevel_allfiles = 1;
			break;
		case 'c':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_ARCHIVE;
			break;
		case 'd':
			ct_debug = debug = 1;
			cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC |
			    CLOG_F_LINE | CLOG_F_DTIME;
			break;
		case 'e':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_ERASE;
			break;
		case 'f': /* metadata file */
			ct_mfile = optarg;
			break;
		case 'm': /* metadata processing - XXX temporary? */
			ct_metadata = 1;
			break;
		case 'r':
			ct_match_mode = CT_MATCH_REGEX;
			break;
		case 'p':
			ct_attr = 1;
			break;
		case 't':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_LIST;
			break;
		case 'v':	/* verbose */
			ct_verbose++;
			break;
		case 'x':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_EXTRACT;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	ct_load_config(settings);

	if (ct_password == NULL) {
		if (ct_get_password(pwd, sizeof pwd, "Login password: ", 0))
			CFATALX("invalid password");
		ct_password = strdup(pwd);
		if (ct_password == NULL)
			CFATAL("ct_password");
		bzero(pwd, sizeof pwd);
	}

	if (ct_crypto_secrets) {
		if (stat(ct_crypto_secrets, &sb) == -1) {
			fprintf(stderr, "No crypto secrets file. Creating\n");
			if (ct_create_secrets(ct_crypto_password,
			    ct_crypto_secrets))
				CFATALX("can't create secrets");
		}
		/* we got crypto */
		ct_crypto = CT_MD_CRYPTO;
		if (ct_unlock_secrets(ct_crypto_password,
		    ct_crypto_secrets,
		    ct_crypto_key,
		    sizeof ct_crypto_key,
		    ct_iv,
		    sizeof ct_iv))
			CFATALX("can't unlock secrets");
		ct_got_secrets = 1; /* XXX do we need this? */
		ct_encrypt_enabled = 1;
	}

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

	if (ct_mfile == NULL && !(ct_metadata && ct_action == CT_A_LIST)) {
		CWARNX("archive file is required");
		usage();
		return (1);
	}

	if (!foreground)
		cflags |= CLOG_F_SYSLOG;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	if (!foreground)
		if (daemon(1, debug) == -1)
			errx(1, "failed to daemonize");

	/* set polltype used by libevent */
	ct_polltype_setup(ct_polltype);
	ct_mdmode_setup(ct_mdmode_str);

	if (ct_metadata || ct_md_mode == CT_MDMODE_REMOTE) {
		if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0) {
			if (ct_md_cachedir == NULL)
				CFATALX("remote mode needs a cachedir set");
			if (ct_md_cachedir[strlen(ct_md_cachedir) - 1] != '/') {
				int rv;

				if ((rv = snprintf(ct_fullcachedir,
				    sizeof(ct_fullcachedir),
				    "%s/", ct_md_cachedir)) == -1 || rv >
				    PATH_MAX)
					CFATALX("invalid md pathname");
				ct_md_cachedir = ct_fullcachedir;
			}
				
			if (ct_make_full_path(ct_md_cachedir, 0700) != 0)
				CFATALX("can't create MD cachedir");

			if (ct_action == CT_A_EXTRACT) {
				/* Do we need to do this for erase or list? */
				ct_mfile = ct_find_md_for_extract(ct_mfile);	
			} else if (ct_action == CT_A_ARCHIVE) {
				ct_mfile = ct_find_md_for_archive(ct_mfile);
			}
		}
		
		switch (ct_action) {
		case CT_A_ARCHIVE:
		case CT_A_EXTRACT:
		case CT_A_ERASE:
			ct_mdname = ct_md_cook_filename(ct_mfile);
			if (ct_mdname == NULL)
				CFATALX("invalid metadata name");
			break;
		case CT_A_LIST:
		default:
			break;
		}
	}

	if (ct_metadata) {
		if (ct_action == CT_A_ARCHIVE) {
			ret = ct_md_archive(ct_mfile, ct_mdname);
		} else if (ct_action == CT_A_EXTRACT) {
			ret = ct_md_extract(ct_mfile, ct_mdname);
		} else if (ct_action == CT_A_LIST) {
			ret = ct_md_list_print(argv, ct_match_mode);
		} else if (ct_action == CT_A_ERASE) {
			ret = ct_md_delete(ct_mdname);
		} else {
			CWARNX("must specify action");
			usage();
			ret = 1;
		}
		if (ct_mdname)
			e_free(&ct_mdname);
		return (ret);
	}

	if (ct_action == CT_A_ARCHIVE) {
		ret = ct_archive(ct_mfile, argv, ct_basisbackup);
		if (ret == 0 && ct_md_mode == CT_MDMODE_REMOTE) {
			ct_metadata = 1; /* XXX this horrible hack must die */
			ret = ct_md_archive(ct_mfile, ct_mdname);
			ct_metadata = 0;
		}
	} else if (ct_action == CT_A_EXTRACT) {
		ret = ct_extract(ct_mfile, argv);
	} else if (ct_action == CT_A_LIST) {
		ret = ct_list(ct_mfile, argv);
	} else {
		CWARNX("must specify action");
		usage();
		ret = 1;
	}
	if (ct_mdname)
		e_free(&ct_mdname);

	return (ret);
}

void
ct_load_config(struct ct_settings *settings)
{
	char		*config_path = NULL;
	int		config_try = 0;

	if (ct_configfile) {
		if (ct_config_parse(settings, ct_configfile))
			CFATALX("Unable to open specified config file %s",
			   ct_configfile);
		return;
	}

	for (;;) {
		if (config_path != NULL)
			e_free(&config_path);

		switch(config_try) {
		case 0:
			config_path = ct_user_config();
			break;
		case 1:
			config_path = ct_system_config();
			break;
		default:
			config_path = ct_create_config();
			break;
		}
		if (ct_config_parse(settings, config_path) == 0) {
			if (config_path != NULL)
				e_free(&config_path);
			break;
		}
		config_try++;
	}
}

void
ct_unload_config(void)
{
}
