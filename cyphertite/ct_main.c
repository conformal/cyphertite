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

#ifndef nitems
#define nitems(_a)      (sizeof((_a)) / sizeof((_a)[0]))
#endif /* !nitems */

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
int			ct_follow_symlinks = 0;
int			ct_root_symlink = 0;
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
	char		padding[1024];

	/* Padding for aligning wrapped usage lines. + 7 is for "usage: " */
	(void) ct_str_repeat(padding, 1024, " ", strlen(__progname) + 7);

	/* ct general usage */
	fprintf(stderr,
	    "usage: %s {-ctxV} [-0AHPRXadhprv] [-B basisctfile] [-C directory]\n",
	    __progname);
	fprintf(stderr,
	    "%s [-D debugstring] [-E excludefile] [-F conffile] [-I includefile]\n",
	    padding);
	fprintf(stderr,
	    "%s -f ctfile [filelist]\n", padding);

	/* ct -me usage */
	fprintf(stderr,
	    "       %s -m -e [-D debugstring] [-F conffile] -f ctfile\n",
	    __progname);

	/* ct -mt usage */
	fprintf(stderr,
	    "       %s -m -t [-r] [-D debugstring] [-F conffile] [pattern]\n",
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

	if (ctfile_mode == CT_MDMODE_REMOTE && only_metadata == 0) {
		if (ctfile_cachedir == NULL)
			CFATALX("remote mode needs a cache directory set");
	}

	if (need_secrets != 0) {
		if (ct_crypto_secrets) {
			if (ct_secrets_upload == 0 &&
			    ct_create_or_unlock_secrets(ct_crypto_secrets,
				ct_crypto_passphrase))
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

	CNDBG(CT_LOG_NET, "assl data: as bits %d, protocol [%s]",
	    ct_assl_ctx->c->as_bits, ct_assl_ctx->c->as_protocol);

	CT_LOCK_INIT(&ct_state->ct_sha_lock);
	CT_LOCK_INIT(&ct_state->ct_comp_lock);
	CT_LOCK_INIT(&ct_state->ct_crypt_lock);
	CT_LOCK_INIT(&ct_state->ct_csha_lock);
	CT_LOCK_INIT(&ct_state->ct_write_lock);
	CT_LOCK_INIT(&ct_state->ct_queued_lock);
	CT_LOCK_INIT(&ct_state->ct_complete_lock);

	ct_setup_wakeup_file(ct_state, ct_nextop);
	ct_setup_wakeup_sha(ct_state, ct_compute_sha);
	ct_setup_wakeup_compress(ct_state, ct_compute_compress);
	ct_setup_wakeup_csha(ct_state, ct_compute_csha);
	ct_setup_wakeup_encrypt(ct_state, ct_compute_encrypt);
	ct_setup_wakeup_write(ct_state, ct_process_write);
	ct_setup_wakeup_complete(ct_state, ct_process_completions);
}

void
ct_update_secrets(void)
{
#if 0
	if (ct_secrets_upload > 0) {
		CNDBG(CT_LOG_CRYPTO, "doing list for crypto secrets");
		ct_add_operation(ctfile_list_start,
		    ct_check_crypto_secrets_nextop, ct_crypto_secrets,
		    NULL, secrets_file_pattern, NULL, NULL,
		    CT_MATCH_REGEX, 0);
	} else {
		ct_add_operation(ctfile_list_start,
		    ctfile_trigger_delete, NULL, NULL,
		    secrets_file_pattern, NULL, NULL,
		    CT_MATCH_REGEX, 0);
	}
#endif
}

void
ct_cleanup_eventloop(void)
{
	ct_trans_cleanup();
	ct_flnode_cleanup();
	ct_ssl_cleanup();
	ctdb_shutdown();
	ct_cleanup_login_cache();
	// XXX: ct_lock_cleanup();
	CT_LOCK_RELEASE(&ct_state->ct_sha_lock);
	CT_LOCK_RELEASE(&ct_state->ct_comp_lock);
	CT_LOCK_RELEASE(&ct_state->ct_crypt_lock);
	CT_LOCK_RELEASE(&ct_state->ct_csha_lock);
	CT_LOCK_RELEASE(&ct_state->ct_write_lock);
	CT_LOCK_RELEASE(&ct_state->ct_queued_lock);
	CT_LOCK_RELEASE(&ct_state->ct_complete_lock);
}

void
ct_cleanup(void)
{
	if (ct_configfile)
		e_free(&ct_configfile);
	ct_cleanup_eventloop();
}

uint64_t
ct_get_debugmask(char *debugstring)
{
	char		*cur, *next;
	uint64_t	 debug_mask = 0;
	int		 i;
	struct debuglvl {
		const char	*name;
		uint64_t	 mask;
	} debuglevels[] = {
		{ "socket", CT_LOG_SOCKET },
		{ "config", CT_LOG_CONFIG },
		{ "exude", CT_LOG_EXUDE },
		{ "net", CT_LOG_NET },
		{ "trans", CT_LOG_TRANS },
		{ "sha", CT_LOG_SHA },
		{ "ctfile", CT_LOG_CTFILE },
		{ "db", CT_LOG_DB },
		{ "crypto", CT_LOG_CRYPTO },
		{ "file", CT_LOG_FILE },
		{ "xml", CT_LOG_XML },
		{ "vertree", CT_LOG_VERTREE },
		{ "all", ~(0ULL) },
	};

	CWARNX("%s", __func__);
	next = debugstring;
	while ((cur = next) != NULL) {
		if ((next = strchr(next + 1, ',')) != NULL) {
			*(next++) = '\0';
		}
		for (i = 0; i < nitems(debuglevels); i++) {
			if (strcasecmp(debuglevels[i].name,
			    cur) == 0)
				break;
		}
		if (i == nitems(debuglevels)) {
			CWARNX("unrecognized debug option:"
			    "\"%s\"", cur);
			 continue;
		}

		debug_mask |= debuglevels[i].mask;
	}

	return (debug_mask);
}

int
ct_main(int argc, char **argv)
{
	struct ct_extract_args		 cea;
	struct ct_archive_args		 caa;
	struct ct_ctfileop_args 	 cca;
	struct ct_ctfile_list_args	 ccla;
	char				 tpath[PATH_MAX];
	char				*ct_basisbackup = NULL;
	char				*ctfile = NULL;
	char				*ct_includefile = NULL;
	char				*ct_excludefile = NULL;
	char				*configfile = NULL;
	char				*basisfile = NULL;
	char				*debugstring = NULL;
	char				**excludelist = NULL;
	char				**includelist = NULL;
	uint64_t			 debug_mask = 0;
	int				 ct_metadata = 0;
	int				 ct_match_mode = CT_MATCH_GLOB;
	int				 c;
	int				 foreground = 1;
	int				 ret = 0;
	int				 level0 = 0;
	int				 freeincludes = 0;
	int				 need_secrets;
	int				 force_allfiles = -1;

	while ((c = getopt(argc, argv,
	    "AB:C:D:E:F:HI:PRVXacdef:hmprtvx0")) != -1) {
		switch (c) {
		case 'A':
			force_allfiles = 0;
			break;
		case 'B':
			basisfile = optarg;
			break;
		case 'C':
			ct_tdir = optarg;
			break;
		case 'D':
			if (debugstring != NULL)
				CFATALX("only one -D argument is valid");
			ct_debug++;
			debugstring = optarg;
			break;
		case 'E':
			ct_excludefile = optarg;
			break;
		case 'F':
			configfile = optarg;
			break;
		case 'H':
			ct_root_symlink = 1;
			break;
		case 'I':
			ct_includefile = optarg;
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
			force_allfiles = 1;
			break;
		case 'c':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_ARCHIVE;
			break;
		case 'e':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_ERASE;
			break;
		case 'f': /* metadata file */
			ctfile = optarg;
			break;
		case 'h':
			ct_follow_symlinks = 1;
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
		debug_mask |= ct_get_debugmask(debugstring);
	}

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");
	clog_set_mask(debug_mask);

	/* We can allocate these now that we've decided if we need exude */
	if (configfile)
		ct_configfile = e_strdup(configfile);
	if (basisfile)
		ct_basisbackup = e_strdup(basisfile);

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

	/* ct -A or ct -a force allfiles on and off and cancel each other */
	if (force_allfiles != -1)
		ct_multilevel_allfiles = force_allfiles;

	if (!(ct_metadata && ct_action == CT_A_LIST)) {
		if (ctfile == NULL) {
			CWARNX("ctfile is required");
			ct_usage();
		}

		if (ctfile_verify_name(ctfile))
			CFATALX("invalid ctfile: %s", ctfile);
	}

	if (level0)
		ct_auto_differential = 0; /* force differential off */

	if (ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0 &&
	    ct_basisbackup != NULL)
		CFATALX("differential basis in remote mode");

	/* Don't bother starting a connection if just listing local files. */
	if (ct_action == CT_A_LIST && ctfile_mode == CT_MDMODE_LOCAL &&
	    ct_metadata == 0 ) {
		ret = ct_list(ctfile, includelist, excludelist,
		    ct_match_mode);
		goto out;
	}

	ct_prompt_for_login_password();

	need_secrets = (ct_action == CT_A_EXTRACT ||
	    ct_action == CT_A_ARCHIVE || (ct_action == CT_A_LIST &&
	    ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0));

	ct_init(foreground, need_secrets, ct_metadata);
	if (need_secrets != 0)
		ct_update_secrets();

	if (ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0) {
		switch (ct_action) {
		case CT_A_EXTRACT:
		case CT_A_LIST:
			cea.cea_local_ctfile = NULL; /* to be found */
			cea.cea_filelist = includelist;
			cea.cea_excllist = excludelist;
			cea.cea_matchmode = ct_match_mode;
			cea.cea_tdir = ct_tdir;
			ctfile_find_for_operation(ctfile,
			    ((ct_action == CT_A_EXTRACT)  ?
			    ctfile_nextop_extract : ctfile_nextop_list),
			    &cea, 1, 0);
			break;
		case CT_A_ARCHIVE:
			caa.caa_filelist = argv;
			caa.caa_excllist = excludelist;
			caa.caa_matchmode = ct_match_mode;
			caa.caa_includefile = ct_includefile;
			caa.caa_tdir = ct_tdir;
			caa.caa_tag = ctfile;
			if (ct_auto_differential)
				/*
				 * Need to work out basis filename and
				 * download it if necessary
				 */
				ctfile_find_for_operation(ctfile,
				    ctfile_nextop_archive, &caa, 0, 1);
			else   {
				/* No basis, just start the op */
				ctfile_nextop_archive(NULL, &caa);
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
				    ct_tdir, ctfile);
			} else {
				strlcpy(tpath, ctfile, sizeof(tpath));
			}
			cca.cca_localname = tpath;
			cca.cca_remotename = NULL;
			ct_add_operation(((ct_action == CT_A_ARCHIVE) ?
			    ctfile_archive : ctfile_extract), ctfile_op_cleanup,
			    &cca);
		} else if (ct_action == CT_A_ERASE) {
			ct_add_operation(ctfile_delete, NULL, ctfile);
		} else if (ct_action == CT_A_LIST) {
			ccla.ccla_search = includelist;
			ccla.ccla_exclude = excludelist;
			ccla.ccla_matchmode = ct_match_mode;
			ct_add_operation(ctfile_list_start, ctfile_list_print,
			    &ccla);
		} else {
			CWARNX("must specify action");
			ct_usage();
			/* NOTREACHED */
		}
	} else {
		/* list is handled above */
		if (ct_action == CT_A_ARCHIVE) {
			caa.caa_local_ctfile = ctfile;
			caa.caa_filelist = argv;
			caa.caa_excllist = excludelist;
			caa.caa_matchmode = ct_match_mode;
			caa.caa_includefile = ct_includefile;
			caa.caa_tag = ctfile;
			ct_add_operation(ct_archive, NULL, &caa);
		} else if (ct_action == CT_A_EXTRACT) {
			cea.cea_local_ctfile = ctfile;
			cea.cea_filelist = includelist;
			cea.cea_excllist = excludelist;
			cea.cea_matchmode = ct_match_mode;
			ct_add_operation(ct_extract, NULL, &cea);
		} else {
			CWARNX("must specify action");
			ct_usage();
			/* NOTREACHED */
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
	if (ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0)
		ctfile_trim_cache(ctfile_cachedir, ctfile_max_cachesize);

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

	/* set string defaults, don't use e_ functions for now */
	ct_host = strdup("auth.cyphertite.com");
	ct_hostport = strdup("48879");
	if (ct_host == NULL || ct_hostport == NULL)
		CFATALX("no memory for defaults");

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
