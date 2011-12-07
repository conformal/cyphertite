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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
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
#include "ct_ctl.h"
#include "ct_fb.h"

#ifdef BUILDSTR
__attribute__((__unused__)) static const char *vertag = "version: " CT_VERSION\
    " " BUILDSTR;
#else
__attribute__((__unused__)) static const char *vertag = "version: " CT_VERSION;
#endif

void			ct_usage(void);
void			ctctl_usage(void);

extern char		*__progname;

/* command line flags */
int			ct_debug = 0;
int			ct_action = 0;
char			*ct_tdir;
int			ct_strip_slash = 1;
int			ct_verbose_ratios;
int			ct_no_cross_mounts;
int			ct_verbose;
char			*ct_configfile;
int			ct_attr;

/* runtime */
int			cflags;
unsigned char		ct_iv[CT_IV_LEN];
unsigned char		ct_crypto_key[CT_KEY_LEN];
char			*secrets_file_pattern[] =
			    { "^[[:digit:]]+-crypto.secrets", NULL };

void
ct_usage(void)
{
	fprintf(stderr,
	    "usage: %s {-ctxV} [-0BCDEFIPRXadprv] -f <ctfile> [filelist]\n",
	    __progname);
	fprintf(stderr,
	    "       %s -m {-cetx} [-CFdr] -f <metadata-tag> [pattern]\n",
	    __progname);
	exit(1);
}

void
show_version(void)
{
	const char *fmt = " %s: %s\n";

	fprintf(stderr, "%s %s\n", __progname, vertag);

	fprintf(stderr, "Run-time versions:\n");
	fprintf(stderr, fmt, "assl", assl_verstring());
#ifdef NEED_LIBCLENS
	fprintf(stderr, fmt, "clens", clens_verstring());
#endif /* NEED_LIBCLENS */
	fprintf(stderr, fmt, "clog", clog_verstring());
	fprintf(stderr, fmt, "exude", exude_verstring());
	fprintf(stderr, fmt, "shrink", shrink_verstring());
	fprintf(stderr, fmt, "xmlsd", xmlsd_verstring());
}

void
ct_init(int foreground, int need_secrets, int only_metadata)
{
	/* Run with restricted umask as we create numerous sensitive files. */
	umask(S_IRWXG|S_IRWXO);

	/* XXX - scale bandwith limiting until the algorithm is improved */
	if (ct_io_bw_limit) {
		ct_io_bw_limit = ct_io_bw_limit * 10 / 7;
	}

	if (!foreground)
		cflags |= CLOG_F_SYSLOG;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	if (!foreground)
		if (daemon(1, ct_debug) == -1)
			errx(1, "failed to daemonize");

	/* set polltype used by libevent */
	ct_polltype_setup(ct_polltype);

	if (ct_md_mode == CT_MDMODE_REMOTE && only_metadata == 0) {
		if (ct_md_cachedir == NULL)
			CFATALX("remote mode needs a md_cachedir set");
	}

	if (need_secrets != 0) {
		if (ct_crypto_secrets) {
			if (ct_secrets_upload == 0 &&
			    ct_create_or_unlock_secrets(ct_crypto_secrets,
				ct_crypto_password))
				CFATALX("can't unlock secrets");
		}
	}

	ct_init_eventloop();
}

void
ct_init_eventloop(void)
{
	ctdb_setup(ct_localdb, ct_crypto_secrets != NULL);

	assl_initialize();
	ct_event_init();
	ct_setup_state();

	gettimeofday(&ct_stats->st_time_start, NULL);
	ct_assl_ctx = ct_ssl_connect(0);
	if (ct_assl_negotiate_poll(ct_assl_ctx))
		CFATALX("negotiate failed");

	CDBG("assl data: as bits %d, protocol [%s]", ct_assl_ctx->c->as_bits,
	    ct_assl_ctx->c->as_protocol);

	ct_setup_wakeup_file(ct_state, ct_nextop);
	ct_setup_wakeup_sha(ct_state, ct_compute_sha);
	ct_setup_wakeup_compress(ct_state, ct_compute_compress);
	ct_setup_wakeup_csha(ct_state, ct_compute_csha);
	ct_setup_wakeup_encrypt(ct_state, ct_compute_encrypt);
	ct_setup_wakeup_complete(ct_state, ct_process_completions);
}

void
ct_update_secrets(void)
{
	if (ct_secrets_upload > 0) {
		CDBG("doing list for crypto secrets");
		ct_add_operation(ct_md_list_start,
		    ct_check_crypto_secrets_nextop, ct_crypto_secrets,
		    NULL, secrets_file_pattern, NULL, NULL,
		    CT_MATCH_REGEX, 0);
	} else {
		ct_add_operation(ct_md_list_start,
		    ct_md_trigger_delete, NULL, NULL,
		    secrets_file_pattern, NULL, NULL,
		    CT_MATCH_REGEX, 0);
	}
}

void
ct_cleanup_eventloop(void)
{
	ct_trans_cleanup();
	ct_flnode_cleanup();
	ct_ssl_cleanup();
}

void
ct_cleanup(void)
{
	if (ct_configfile)
		e_free(&ct_configfile);
	ct_cleanup_eventloop();
}

int
ct_main(int argc, char **argv)
{
	char		pwd[PASS_MAX], tpath[PATH_MAX];
	char		*ct_basisbackup = NULL;
	char		*ct_mfile = NULL;
	char		*ct_excludefile = NULL;
	char		**excludelist = NULL;
	char		**includelist = NULL;
	uint64_t	debug_mask = 0;
	int		ct_metadata = 0;
	int		ct_match_mode = CT_MATCH_GLOB;
	int		c;
	int		foreground = 1;
	int		ret = 0;
	int		level0 = 0;
	int		freeincludes = 0;
	int		need_secrets;

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
			ct_configfile = e_strdup(optarg);
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
			ct_debug++;
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
			ct_usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (ct_debug) {
		cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC |
		    CLOG_F_LINE | CLOG_F_DTIME;
		exude_enable(CT_LOG_EXUDE);
		if (ct_debug > 1)
			debug_mask |= CT_LOG_EXUDE;
	}

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");
	clog_set_mask(debug_mask);

	if ((ct_action == CT_A_LIST || ct_action == CT_A_EXTRACT)) {
		if (ct_includefile != NULL) {
			if (argc != 0)
				CFATALX("-I is invalid when a pattern is "
				    "provided on the command line");
			includelist = ct_matchlist_fromfile(ct_includefile);
			freeincludes = 1;
		} else {
			includelist = argv;
		}
	}
	if (ct_excludefile != NULL)
		excludelist = ct_matchlist_fromfile(ct_excludefile);


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

	if (!(ct_metadata && ct_action == CT_A_LIST)) {
		if (ct_mfile == NULL) {
			CWARNX("ctfile is required");
			ct_usage();
		}

		if (ct_md_verify_mfile(ct_mfile))
			CFATALX("invalid ctfile: %s", ct_mfile);
	}

	if (level0)
		ct_auto_differential = 0; /* force differential off */

	if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0 &&
	    ct_basisbackup != NULL)
		CFATALX("differential basis in remote mode");

	/* Don't bother starting a connection if just listing local files. */
	if (ct_action == CT_A_LIST && ct_md_mode == CT_MDMODE_LOCAL &&
	    ct_metadata == 0 ) {
		ret = ct_list(ct_mfile, includelist, excludelist,
		    ct_match_mode);
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

	need_secrets = (ct_action == CT_A_EXTRACT ||
	    ct_action == CT_A_ARCHIVE || (ct_action == CT_A_LIST &&
	    ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0));

	ct_init(foreground, need_secrets, ct_metadata);
	if (need_secrets != 0)
		ct_update_secrets();

	if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0) {
		switch (ct_action) {
		case CT_A_EXTRACT:
		case CT_A_LIST:
			ct_add_operation(ct_find_md_for_extract,
			    ct_find_md_for_extract_complete, ct_mfile, NULL,
			    includelist, excludelist, NULL, ct_match_mode,
			    ct_action);
			break;
		case CT_A_ARCHIVE:
			if (ct_auto_differential)
				ct_add_operation(ct_find_md_for_extract,
				    ct_find_md_for_extract_complete, ct_mfile,
				    NULL, argv, excludelist, NULL,
				    ct_match_mode, ct_action);
			else   {
				ct_mfile = ct_find_md_for_archive(ct_mfile);
				ct_add_operation(ct_archive, NULL, ct_mfile,
				    NULL, argv, excludelist, NULL,
				    ct_match_mode, 0);
				ct_add_operation(ct_md_archive, NULL, ct_mfile,
				    NULL, NULL, NULL, NULL, ct_match_mode, 0);
			}
			break;
		default:
			CWARNX("invalid action");
			ct_usage();
			/* NOTREACHED */
			break;
		}
	} else if (ct_metadata != 0) {
		if (ct_action == CT_A_ARCHIVE || ct_action == CT_A_EXTRACT) {
			if (ct_tdir) {
				snprintf(tpath, sizeof tpath, "%s/%s",
				    ct_tdir, ct_mfile);
			} else {
				strlcpy(tpath, ct_mfile, sizeof(tpath));
			}
		}
		switch (ct_action) {
		case CT_A_ARCHIVE:
			ct_add_operation(ct_md_archive, ct_free_remotename,
			    tpath, NULL, NULL, NULL, NULL, 0, 0);
			break;
		case CT_A_EXTRACT:
			ct_add_operation(ct_md_extract, ct_free_remotename,
			    tpath, NULL, NULL, NULL, NULL, 0, 0);
			break;
		case CT_A_LIST:
			ct_add_operation(ct_md_list_start, ct_md_list_print,
			    NULL, NULL, includelist, excludelist, NULL,
			    ct_match_mode, 0);
			break;
		case CT_A_ERASE:
			ct_add_operation(ct_md_delete, NULL, NULL,
			    ct_mfile, NULL, NULL, NULL, 0, 0);
			break;
		default:
			CWARNX("must specify action");
			ct_usage();
			/* NOTREACHED */
			break;
		}
	} else {
		/* list handled above. */
		switch (ct_action) {
		case CT_A_ARCHIVE:
			ct_add_operation(ct_archive, NULL, ct_mfile, NULL, argv,
			    excludelist, ct_basisbackup, ct_match_mode, 0);
			break;
		case CT_A_EXTRACT:
			ct_add_operation(ct_extract, NULL, ct_mfile, NULL,
			    includelist, excludelist, NULL, ct_match_mode, 0);
			break;
		case CT_A_ERASE:
		default:
			CWARNX("must specify action");
			ct_usage();
			break;
		}
	}

	ct_wakeup_file();

	ret = ct_event_dispatch();
	if (ret != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));

	ct_cleanup();
out:
	if (includelist && freeincludes == 1)
		ct_matchlist_free(includelist);
	if (excludelist)
		ct_matchlist_free(excludelist);
	if (ct_md_mode == CT_MDMODE_REMOTE && ct_metadata == 0)
		ct_mdcache_trim(ct_md_cachedir, ct_max_mdcache_size);

#ifdef notyet
	e_check_memory();
#endif
	return (ret);
}

int
main(int argc, char *argv[])
{
	char		*executablepath, *executablename, *executablestem;

	setlocale(LC_ALL, "");

	ct_savecore();

	clog_init(1);
	cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	executablepath = strdup(argv[0]);
	executablename = basename(executablepath);
	executablestem = ct_remove_ext(executablename);

	if (!strcmp(executablestem, "ct") ||
	    !strcmp(executablestem, "cyphertite"))
		return (ct_main(argc, argv));
	if (!strcmp(executablestem, "ctctl") ||
	    !strcmp(executablestem, "cyphertitectl"))
		return (ctctl_main(argc, argv));
	if (!strcmp(executablestem, "ctfb") ||
	    !strcmp(executablestem, "cyphertitefb"))
		return (ctfb_main(argc, argv));
	else
		CFATALX("invalid executable name");


	/* NOTREACHED */
	return (0);
}
