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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <libgen.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <shrink.h>
#include <xmlsd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <ctutil.h>

#include "ct.h"
#include "ct_crypto.h"

__attribute__((__unused__)) static const char *cvstag = "$cyphertite$";
__attribute__((__unused__)) static const char *vertag = "version: " CT_VERSION;

int			ct_load_config(struct ct_settings *);
void			usage(void);

extern char		*__progname;

/* command line flags */
int			ct_debug;
int			ct_action = 0;
char			*ct_tdir;
int			ct_strip_slash = 1;
int			ct_verbose_ratios;
int			ct_no_cross_mounts;
int			ct_verbose;
char			*ct_configfile;
int			ct_attr;

/* runtime */
unsigned char		ct_iv[CT_IV_LEN];
unsigned char		ct_crypto_key[CT_KEY_LEN];
char			*secrets_file_pattern[] =
			    { "^[[:digit:]]+-crypto.secrets", NULL };


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
char			*ct_compression_type;
char			*ct_polltype;
char			*ct_mdmode_str;
char			*ct_md_cachedir;
char			*ct_includefile;
char			*ct_excludefile;
int			ct_md_mode = CT_MDMODE_LOCAL;
int			ct_compress_enabled;
int			ct_encrypt_enabled;
int			ct_multilevel_allfiles;
int			ct_auto_differential;
long long		ct_max_mdcache_size = LLONG_MAX; /* unbounded */
int			ct_max_differentials;
int			ct_secrets_upload = 1;

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
	{ "crypto_password", CT_S_STR, NULL, &ct_crypto_password, NULL, NULL },
	{ "session_compression", CT_S_STR, NULL, &ct_compression_type, NULL,
	    NULL },
	{ "polltype", CT_S_STR, NULL, &ct_polltype, NULL, NULL },
	{ "md_mode", CT_S_STR, NULL, &ct_mdmode_str, NULL, NULL },
	{ "md_cachedir", CT_S_DIR, NULL, &ct_md_cachedir, NULL, NULL },
	{ "md_cachedir_max_size", CT_S_SIZE, NULL, NULL, NULL,
	    &ct_max_mdcache_size, NULL },
	{ "md_remote_auto_differential" , CT_S_INT, &ct_auto_differential,
	    NULL, NULL, NULL },
	{ "md_max_differentials" , CT_S_INT, &ct_max_differentials,
	    NULL, NULL, NULL },
	{ "upload_crypto_secrets" , CT_S_INT, &ct_secrets_upload,
	    NULL, NULL, NULL },
	{ NULL, 0, NULL, NULL, NULL,  NULL }
};

void
usage(void)
{
	fprintf(stderr, "%s {-ctxV} [-0BCDFPRXabdpv] -f <archive> [filelist]\n",
	    __progname);
	exit(1);
}

void
show_version(void)
{
	int major, minor, patch;
	const char *fmt = " %s: %u.%u.%u\n";

	fprintf(stderr, "%s version %u.%u.%u\n", __progname, CT_VERSION_MAJOR,
	    CT_VERSION_MINOR, CT_VERSION_PATCH);

	fprintf(stderr, "Run-time versions:\n");
	assl_version(&major, &minor, &patch);
	fprintf(stderr, fmt, "assl", major, minor, patch);
#ifdef NEED_LIBCLENS
	clens_version(&major, &minor, &patch);
	fprintf(stderr, fmt, "clens", major, minor, patch);
#endif /* NEED_LIBCLENS */
	clog_version(&major, &minor, &patch);
	fprintf(stderr, fmt, "clog", major, minor, patch);
	exude_version(&major, &minor, &patch);
	fprintf(stderr, fmt, "exude", major, minor, patch);
	shrink_version(&major, &minor, &patch);
	fprintf(stderr, fmt, "shrink", major, minor, patch);
	xmlsd_version(&major, &minor, &patch);
	fprintf(stderr, fmt, "xmlsd", major, minor, patch);
}

int
ct_load_config(struct ct_settings *settings)
{
	char		*config_path = NULL;
	int		config_try = 0;

	if (ct_configfile) {
		if (ct_config_parse(settings, ct_configfile))
			CFATALX("Unable to open specified config file %s",
			   ct_configfile);
		return (0);
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
			return (1);
			break;
		}
		if (ct_config_parse(settings, config_path) == 0) {
			if (config_path != NULL)
				e_free(&config_path);
			break;
		}
		config_try++;
	}

	return (0);
}

void
ct_unload_config(void)
{
}

int
ct_main(int argc, char **argv)
{
	char		pwd[PASS_MAX];
	char		ct_fullcachedir[PATH_MAX];
	char		*ct_basisbackup = NULL;
	char		*ct_mfile = NULL;
	int		ct_metadata = 0;
	int		ct_match_mode = CT_MATCH_GLOB;
	int		c;
	int		cflags;
	int		debug;
	int		foreground = 1;
	int		ret = 0;
	int		level0 = 0;

	ct_savecore();

	clog_init(1);
	cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	ct_debug = debug = 0;
	while ((c = getopt(argc, argv,
	    "B:C:DE:F:I:PRVXa:cdef:mprtvx0")) != -1) {
		switch (c) {
		case 'B':
			ct_basisbackup = e_strdup(optarg);
			break;
		case 'C':
			ct_tdir = optarg;
			break;
		case 'D':
			foreground = 0;
			break;
		case 'E':
			ct_excludefile = e_strdup(optarg);
			break;
		case 'F':
			ct_configfile = optarg;
			break;
		case 'I':
			ct_includefile = e_strdup(optarg);
			break;
		case 'P':
			ct_strip_slash = 0;
			break;
		case 'R':
			ct_verbose_ratios = 1;
			break;
		case 'V':
			show_version();
			exit(0);
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
			exude_enable();
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
		case '0':
			level0 = 1;
			ct_auto_differential = 0; /* force differential off */
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	/* Generate config file if one doesn't exist and there are no params. */
	if (ct_load_config(settings)) {
		if ((argc + optind) == 1) {
			ct_create_config();
			return (0);
		} else
			CFATALX("config file not found.  Use the -F option to "
			    "specify its path or run %s with no parameters "
			    "to generate one.", __progname);
	}

	if (ct_mfile == NULL && !(ct_metadata && ct_action == CT_A_LIST)) {
		CWARNX("archive file is required");
		usage();
	}

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	/* Run with restricted umask as we create numerous sensitive files. */
	umask(S_IRWXG|S_IRWXO);

	/* XXX - scale bandwith limiting until the algorithm is improved */
	if (ct_io_bw_limit) {
		ct_io_bw_limit = ct_io_bw_limit * 10 / 7;
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

	if (!foreground)
		cflags |= CLOG_F_SYSLOG;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	if (!foreground)
		if (daemon(1, debug) == -1)
			errx(1, "failed to daemonize");

	if (level0)
		ct_auto_differential = 0; /* force differential off */

	/* set polltype used by libevent */
	ct_polltype_setup(ct_polltype);
	ct_mdmode_setup(ct_mdmode_str);

	if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0) {
		if (ct_basisbackup != NULL)
			CFATALX("differential basis in remote mode");
		if (ct_md_cachedir == NULL)
			CFATALX("remote mode needs a cachedir set");
		if (ct_md_cachedir[strlen(ct_md_cachedir) - 1] != '/') {
			int rv;

			if ((rv = snprintf(ct_fullcachedir,
			    sizeof(ct_fullcachedir),
			    "%s/", ct_md_cachedir)) == -1 || rv >
			    PATH_MAX)
				CFATALX("invalid metadata pathname");
			ct_md_cachedir = ct_fullcachedir;
		}

		if (ct_make_full_path(ct_md_cachedir, 0700) != 0)
			CFATALX("can't create metadata cachedir");
	}

	/* Don't bother starting a connection if just listing local files. */
	if (ct_action == CT_A_LIST && ct_md_mode == CT_MDMODE_LOCAL &&
	    ct_metadata == 0 ) {
		ret = ct_list(ct_mfile, argv, ct_match_mode);
		goto out;
	}

	if (ct_password == NULL) {
		if (ct_get_password(pwd, sizeof pwd, "Login password: ", 0))
			CFATALX("invalid password");
		ct_password = strdup(pwd);
		if (ct_password == NULL)
			CFATAL("ct_password");
		bzero(pwd, sizeof pwd);
	}

	if (ct_crypto_secrets) {
		if (ct_secrets_upload == 0 &&
		    ct_create_or_unlock_secrets(ct_crypto_secrets,
		    ct_crypto_password))
			CFATALX("can't unlock secrets");
	} else {
		ctdb_setup(ct_localdb, 0);
	}

	ct_event_init();
	ct_setup_assl();

	ct_setup_wakeup_file(ct_state, ct_nextop);
	ct_setup_wakeup_sha(ct_state, ct_compute_sha);
	ct_setup_wakeup_compress(ct_state, ct_compute_compress);
	ct_setup_wakeup_csha(ct_state, ct_compute_csha);
	ct_setup_wakeup_encrypt(ct_state, ct_compute_encrypt);
	ct_setup_wakeup_complete(ct_state, ct_process_completions);

	if (ct_secrets_upload > 0) {
		CDBG("doing list for crypto secrets");
		ct_add_operation(ct_md_list_start,
		    ct_check_crypto_secrets_nextop, ct_crypto_secrets,
		    NULL, secrets_file_pattern, NULL, CT_MATCH_REGEX, 0);
	} else {
		ct_add_operation(ct_md_list_start,
		    ct_md_trigger_delete, NULL, NULL, secrets_file_pattern,
		    NULL, CT_MATCH_REGEX, 0);
	}

	if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0) {
		switch (ct_action) {
		case CT_A_EXTRACT:
		case CT_A_LIST:
			ct_add_operation(ct_find_md_for_extract,
			    ct_find_md_for_extract_complete, ct_mfile, NULL,
			    argv, NULL, ct_match_mode, ct_action);
			break;
		case CT_A_ARCHIVE:
			if (ct_auto_differential)
				ct_add_operation(ct_find_md_for_extract,
				    ct_find_md_for_extract_complete, ct_mfile,
				    NULL, argv, NULL, ct_match_mode, ct_action);
			else   {
				ct_mfile = ct_find_md_for_archive(ct_mfile);
				ct_add_operation(ct_archive, NULL, ct_mfile,
				    NULL, argv, NULL, 0, 0);
				ct_add_operation(ct_md_archive, NULL, ct_mfile,
				    NULL, NULL, NULL, ct_match_mode, 0);
			}
			break;
		default:
			CWARNX("invalid action");
			usage();
			/* NOTREACHED */
			break;
		}
	} else if (ct_metadata != 0) {
		switch (ct_action) {
		case CT_A_ARCHIVE:
			ct_add_operation(ct_md_archive, NULL,
			    ct_mfile, NULL, NULL, NULL, 0, 0);
			break;
		case CT_A_EXTRACT:
			ct_add_operation(ct_md_extract, NULL, ct_mfile,
			    NULL, NULL, NULL, 0, 0);
			break;
		case CT_A_LIST:
			ct_add_operation(ct_md_list_start, ct_md_list_print,
			    NULL, NULL, argv, NULL, ct_match_mode, 0);
			break;
		case CT_A_ERASE:
			ct_add_operation(ct_md_delete, NULL, NULL,
			    ct_mfile, NULL, NULL, 0, 0);
			break;
		default:
			CWARNX("must specify action");
			usage();
			/* NOTREACHED */
			break;
		}
	} else {
		/* list handled above. */
		switch (ct_action) {
		case CT_A_ARCHIVE:
			ct_add_operation(ct_archive, NULL, ct_mfile, NULL, argv,
			    ct_basisbackup, ct_match_mode, 0);
			break;
		case CT_A_EXTRACT:
			ct_add_operation(ct_extract, NULL, ct_mfile, NULL,
			    argv, NULL, ct_match_mode, 0);
			break;
		case CT_A_ERASE:
		default:
			CWARNX("must specify action");
			usage();
			break;
		}
	}

	ct_wakeup_file();

	ret = ct_event_dispatch();
	if (ret != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));

	ct_trans_cleanup();
	ct_flnode_cleanup();
	ct_ssl_cleanup();
out:
	if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0)
		ct_mdcache_trim(ct_md_cachedir, ct_max_mdcache_size);

#ifdef notyet
	e_check_memory();
#endif

	return (ret);
}

int
ctctl_main(int argc, char *argv[])
{
	return (EINVAL);
}

int
main(int argc, char *argv[])
{
	char *executablepath, *executablename;

	clog_init(1);
	if (clog_set_flags(CLOG_F_ENABLE | CLOG_F_STDERR))
		errx(1, "illegal clog flags");

	executablepath = strdup(argv[0]);
	executablename = basename(executablepath);

	if (!strcmp(executablename, "ct") ||
	    !strcmp(executablename, "cyphertite"))
		return (ct_main(argc, argv));
	if (!strcmp(executablename, "ctctl") ||
	    !strcmp(executablename, "cyphertitectl"))
		return (ctctl_main(argc, argv));
	else
		CFATALX("invalid executable name");
}
