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
#include <ct_ext.h>

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

struct ct_global_state *
ct_init(struct ct_config *conf, int need_secrets, int verbose)
{
	struct ct_global_state *state;
	struct stat		sb;

	/* Run with restricted umask as we create numerous sensitive files. */
	umask(S_IRWXG|S_IRWXO);

	/* XXX - scale bandwith limiting until the algorithm is improved */
	if (conf->ct_io_bw_limit) {
		conf->ct_io_bw_limit = conf->ct_io_bw_limit * 10 / 7;
	}
	assl_initialize();
	state = ct_setup_state(conf);
	state->ct_verbose = verbose;

	ct_event_init(state);

	if (need_secrets != 0 && conf->ct_crypto_secrets != NULL) {
		if (stat(conf->ct_crypto_secrets, &sb) == -1) {
			CFATALX("No crypto secrets file, please run"
			    "ctctl secrets generate or ctctl secrets download");
		}
		/* we got crypto */
		if (ct_unlock_secrets(conf->ct_crypto_passphrase,
		    conf->ct_crypto_secrets,
		    state->ct_crypto_key, sizeof(state->ct_crypto_key),
		    state->ct_iv, sizeof(state->ct_iv)))
			CFATALX("can't unlock secrets file");
	}

	ct_init_eventloop(state);

	return (state);
}

void
ct_init_eventloop(struct ct_global_state *state)
{

#if defined(CT_EXT_INIT)
	CT_EXT_INIT();
#endif

	state->ct_db_state = ctdb_setup(state->ct_config->ct_localdb,
	    state->ct_config->ct_crypto_secrets != NULL);

	gettimeofday(&state->ct_stats->st_time_start, NULL);
	state->ct_assl_ctx = ct_ssl_connect(state, 0);
	if (ct_assl_negotiate_poll(state))
		CFATALX("negotiate failed");

	CNDBG(CT_LOG_NET, "assl data: as bits %d, protocol [%s]",
	    state->ct_assl_ctx->c->as_bits,
	    state->ct_assl_ctx->c->as_protocol);

	ct_set_file_state(state, CT_S_STARTING);
	CT_LOCK_INIT(&state->ct_sha_lock);
	CT_LOCK_INIT(&state->ct_comp_lock);
	CT_LOCK_INIT(&state->ct_crypt_lock);
	CT_LOCK_INIT(&state->ct_csha_lock);
	CT_LOCK_INIT(&state->ct_write_lock);
	CT_LOCK_INIT(&state->ct_queued_lock);
	CT_LOCK_INIT(&state->ct_complete_lock);

	ct_setup_wakeup_file(state, ct_nextop);
	ct_setup_wakeup_sha(state, ct_compute_sha);
	ct_setup_wakeup_compress(state, ct_compute_compress);
	ct_setup_wakeup_csha(state, ct_compute_csha);
	ct_setup_wakeup_encrypt(state, ct_compute_encrypt);
	ct_setup_wakeup_write(state, ct_process_write);
	ct_setup_wakeup_complete(state, ct_process_completions);
}

void
ct_cleanup_eventloop(struct ct_global_state *state)
{
	ct_trans_cleanup(state);
	if (state->ct_assl_ctx) {
		ct_ssl_cleanup(state->ct_assl_ctx);
		state->ct_assl_ctx = NULL;
	}
	ctdb_shutdown(state->ct_db_state);
	state->ct_db_state = NULL;
	ct_cleanup_login_cache();
	// XXX: ct_lock_cleanup();
	CT_LOCK_RELEASE(&state->ct_sha_lock);
	CT_LOCK_RELEASE(&state->ct_comp_lock);
	CT_LOCK_RELEASE(&state->ct_crypt_lock);
	CT_LOCK_RELEASE(&state->ct_csha_lock);
	CT_LOCK_RELEASE(&state->ct_write_lock);
	CT_LOCK_RELEASE(&state->ct_queued_lock);
	CT_LOCK_RELEASE(&state->ct_complete_lock);
	ct_event_cleanup();
}

void
ct_cleanup(struct ct_global_state *state)
{
	ct_cleanup_eventloop(state);
}

uint64_t
ct_get_debugmask(char *debugstring)
{
	char		*cur, *next;
	uint64_t	 debug_mask = 0;
	int		 i, neg;

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
		neg = 0;
		if ((next = strchr(next + 1, ',')) != NULL) {
			*(next++) = '\0';
		}
		if (*cur == '-') {
			neg = 1;
			cur++;
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

		if (neg)
			debug_mask &= ~debuglevels[i].mask;
		else
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
	struct ct_global_state		*state = NULL;
	struct ct_config		*conf;
	char				*ct_tdir = NULL;
	char				*ct_basisbackup = NULL;
	char				*ctfile = NULL;
	char				*ct_includefile = NULL;
	char				*ct_excludefile = NULL;
	char				*configfile = NULL, *config_file = NULL;
	char				*basisfile = NULL;
	char				*debugstring = NULL;
	char				**excludelist = NULL;
	char				**includelist = NULL;
	uint64_t			 debug_mask = 0;
	uint32_t			 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	int				 ct_metadata = 0;
	int				 ct_match_mode = CT_MATCH_GLOB;
	int				 c;
	int				 ret = 0;
	int				 level0 = 0;
	int				 freeincludes = 0;
	int				 need_secrets;
	int				 force_allfiles = -1;
	int				 no_cross_mounts = 0;
	int				 strip_slash = 1;
	int				 follow_root_symlink = 0;
	int				 follow_symlinks = 0;
	int				 attr = 0;
	int				 verbose = 0;
	int				 verbose_ratios = 0;

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
			follow_root_symlink = 1;
			break;
		case 'I':
			ct_includefile = optarg;
			break;
		case 'P':
			strip_slash = 0;
			break;
		case 'R':
			verbose_ratios = 1;
			break;
		case 'V':
			show_version();
			exit(0);
			break;
		case 'X':
			no_cross_mounts = 1;
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
			follow_symlinks = 1;
			break;
		case 'm': /* metadata processing - XXX temporary? */
			ct_metadata = 1;
			break;
		case 'r':
			ct_match_mode = CT_MATCH_REGEX;
			break;
		case 'p':
			attr = 1;
			break;
		case 't':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_LIST;
			break;
		case 'v':	/* verbose */
			verbose++;
			break;
		case 'x':
			if (ct_action)
				CFATALX("cannot mix operations, -c -e -t -x");
			ct_action = CT_A_EXTRACT;
			break;
		case '0':
			level0 = 1;
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
		config_file = e_strdup(configfile);
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


	if ((conf = ct_load_config(&config_file)) == NULL) {
		CFATALX("config file not found.  Use the -F option to "
		    "specify its path or run \"cyphertitectl config generate\" "
		    "to generate one.");
	}

	/* ct -A or ct -a force allfiles on and off and cancel each other */
	if (force_allfiles != -1)
		conf->ct_multilevel_allfiles = force_allfiles;

	if (!(ct_metadata && ct_action == CT_A_LIST)) {
		if (ctfile == NULL) {
			CWARNX("ctfile is required");
			ct_usage();
		}

		if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE &&
		    ctfile_verify_name(ctfile))
			CFATALX("invalid ctfile: %s", ctfile);
	}

	if (level0)
		conf->ct_auto_differential = 0; /* force differential off */

	if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0 &&
	    ct_basisbackup != NULL)
		CFATALX("differential basis in remote mode");

	/* Don't bother starting a connection if just listing local files. */
	if (ct_action == CT_A_LIST &&
	    conf->ct_ctfile_mode == CT_MDMODE_LOCAL &&
	    ct_metadata == 0 ) {
		ret = ct_list(ctfile, includelist, excludelist,
		    ct_match_mode, NULL, strip_slash, verbose);
		goto out;
	}

	ct_prompt_for_login_password(conf);

	need_secrets = (ct_action == CT_A_EXTRACT ||
	    ct_action == CT_A_ARCHIVE || (ct_action == CT_A_LIST &&
	    conf->ct_ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0));

	state = ct_init(conf, need_secrets, verbose);
	if (conf->ct_crypto_passphrase != NULL &&
	    conf->ct_secrets_upload != 0) {
		ct_add_operation(state, ctfile_list_start,
		    ct_check_secrets_extract, conf->ct_crypto_secrets);
	}

	if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0) {
		switch (ct_action) {
		case CT_A_EXTRACT:
		case CT_A_LIST:
			cea.cea_local_ctfile = NULL; /* to be found */
			cea.cea_filelist = includelist;
			cea.cea_excllist = excludelist;
			cea.cea_matchmode = ct_match_mode;
			cea.cea_ctfile_basedir = conf->ct_ctfile_cachedir;
			cea.cea_tdir = ct_tdir;
			cea.cea_strip_slash = strip_slash;
			cea.cea_attr = attr;
			cea.cea_follow_symlinks = follow_symlinks;
			ctfile_find_for_operation(state, ctfile,
			    ((ct_action == CT_A_EXTRACT)  ?
			    ctfile_nextop_extract : ctfile_nextop_list),
			    &cea, 1, 0);
			break;
		case CT_A_ARCHIVE:
			ct_normalize_filelist(argv);
			caa.caa_filelist = argv;
			caa.caa_excllist = excludelist;
			caa.caa_matchmode = ct_match_mode;
			caa.caa_includefile = ct_includefile;
			caa.caa_tdir = ct_tdir;
			caa.caa_tag = ctfile;
			caa.caa_ctfile_basedir = conf->ct_ctfile_cachedir;
			/* we want to encrypt as long as we have keys */
			caa.caa_encrypted = (conf->ct_crypto_secrets != NULL);
			caa.caa_allfiles = conf->ct_multilevel_allfiles;
			caa.caa_no_cross_mounts = no_cross_mounts;
			caa.caa_strip_slash = strip_slash;
			caa.caa_follow_root_symlink = follow_root_symlink;
			cea.cea_follow_symlinks = follow_symlinks;
			caa.caa_max_differentials = conf->ct_max_differentials;
			if (conf->ct_auto_differential)
				/*
				 * Need to work out basis filename and
				 * download it if necessary
				 */
				ctfile_find_for_operation(state, ctfile,
				    ctfile_nextop_archive, &caa, 0, 1);
			else   {
				/* No basis, just start the op */
				ctfile_nextop_archive(state, NULL, &caa);
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
			cca.cca_localname = ctfile;
			cca.cca_remotename = NULL;
			cca.cca_tdir = ct_tdir;
			cca.cca_ctfile = 1;
			/* only matters for archive */
			cca.cca_encrypted = (conf->ct_crypto_secrets != NULL);
			ct_add_operation(state,
			    ((ct_action == CT_A_ARCHIVE) ?
			    ctfile_archive : ctfile_extract),
			    ctfile_op_cleanup, &cca);
		} else if (ct_action == CT_A_ERASE) {
			ct_add_operation(state, ctfile_delete, NULL, ctfile);
		} else if (ct_action == CT_A_LIST) {
			ccla.ccla_search = includelist;
			ccla.ccla_exclude = excludelist;
			ccla.ccla_matchmode = ct_match_mode;
			ct_add_operation(state, ctfile_list_start,
			    ctfile_list_print, &ccla);
		} else {
			CWARNX("must specify action");
			ct_usage();
			/* NOTREACHED */
		}
	} else {
		/* list is handled above */
		if (ct_action == CT_A_ARCHIVE) {
			caa.caa_local_ctfile = ctfile;
			ct_normalize_filelist(argv);
			caa.caa_filelist = argv;
			caa.caa_excllist = excludelist;
			caa.caa_matchmode = ct_match_mode;
			caa.caa_includefile = ct_includefile;
			caa.caa_no_cross_mounts = no_cross_mounts;
			caa.caa_strip_slash = strip_slash;
			caa.caa_follow_root_symlink = follow_root_symlink;
			caa.caa_follow_symlinks = follow_symlinks;
			caa.caa_max_differentials = 0; /* unlimited */
			caa.caa_tag = ctfile;
			ct_add_operation(state, ct_archive, NULL, &caa);
		} else if (ct_action == CT_A_EXTRACT) {
			cea.cea_local_ctfile = ctfile;
			cea.cea_filelist = includelist;
			cea.cea_excllist = excludelist;
			cea.cea_matchmode = ct_match_mode;
			cea.cea_ctfile_basedir = NULL;
			cea.cea_strip_slash = strip_slash;
			cea.cea_attr = attr;
			cea.cea_follow_symlinks = follow_symlinks;
			ct_add_operation(state, ct_extract, NULL, &cea);
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

	if (verbose_ratios)
		ct_dump_stats(state, stdout);
	ct_cleanup(state);
out:
	if (includelist && freeincludes == 1)
		ct_matchlist_free(includelist);
	if (excludelist)
		ct_matchlist_free(excludelist);
	if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0)
		ctfile_trim_cache(conf->ct_ctfile_cachedir,
		    conf->ct_ctfile_max_cachesize);

	ct_unload_config(config_file, conf);
#ifdef notyet
	e_check_memory();
#endif
	exude_cleanup();

	return (ret);
}

int
main(int argc, char *argv[])
{
	char		*executablepath, *executablename, *executablestem;

	setlocale(LC_ALL, "");

	ct_savecore();

	clog_init(1);
	if (clog_set_flags(CLOG_F_ENABLE | CLOG_F_STDERR))
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
