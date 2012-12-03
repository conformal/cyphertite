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

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
#include <libgen.h>
#include <pwd.h>
#include <grp.h>

#include <assl.h>
#include <clog.h>
#include <exude.h>
#include <shrink.h>
#include <xmlsd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#include <ctutil.h>

#include <ct_crypto.h>
#include <cyphertite.h>
#include "ct.h"
#include "ct_ctl.h"
#include "ct_fb.h"
#include <ct_ext.h>

#ifndef nitems
#define nitems(_a)      (sizeof((_a)) / sizeof((_a)[0]))
#endif /* !nitems */

#define CT_CHECK_MEMORY 0

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
int			ct_action = 0;
int			ct_verbose = 0;

void ct_display_queues(struct ct_global_state *);
void ct_dump_stats(struct ct_global_state *state, FILE *outfh);

ct_log_file_start_fn		ct_pr_fmt_file;
ct_log_file_end_fn		ct_pr_fmt_file_end;
ct_log_file_start_fn		ct_print_file_start;
ct_log_file_end_fn		ct_print_file_end;
ct_log_file_skip_fn		ct_print_file_skip;
ct_log_ctfile_info_fn		ct_print_ctfile_info;
ct_log_traverse_start_fn	ct_print_traverse_start;
ct_log_traverse_end_fn		ct_print_traverse_end;
ct_log_chown_failed_fn		ct_print_extract_chown_failed;
ctfile_delete_complete_fn	ct_print_delete;
char			*ct_getloginbyuid(uid_t);
void			ct_cleanup_login_cache(void);
int		 ct_list(const char *, char **, char **, int, const char *,
		     int, int);
ct_op_cb	 ct_list_op;
ctfile_find_callback	 ctfile_nextop_list;

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
	    "       %s -m -e [-D debugstring] [-F conffile] <ctfilelist>\n",
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
	struct utsname u;
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

	fprintf(stderr, "O/S identification: ");
	if (uname(&u) == -1)
		fprintf(stderr, "INVALID\n");
	else
		fprintf(stderr, "%s-%s-%s %s\n", u.sysname, u.machine, u.release, u.version);
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
	struct ct_ctfile_delete_args	 ccda;
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
	int				 force_allfiles = -1;
	int				 no_cross_mounts = 0;
	int				 strip_slash = 1;
	int				 follow_root_symlink = 0;
	int				 follow_symlinks = 0;
	int				 attr = 0;
	int				 verbose_ratios = 0;
	int				 ct_flags = 0;

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
		case 'v':
			ct_verbose++;
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
		config_file = e_strdup(configfile);
	if (basisfile)
		ct_basisbackup = e_strdup(basisfile);

	if (ct_includefile != NULL) {
		int nentries;

		if ((ct_action == CT_A_LIST || ct_action == CT_A_EXTRACT) &&
		    argc != 0)
			CFATALX("-I is invalid when a pattern is "
			    "provided on the command line");
		includelist = ct_matchlist_fromfile(ct_includefile,
		    &nentries);
		if (nentries == -1)
			CFATAL("can't get includelist from %s",
			    ct_includefile);

		freeincludes = 1;
	} else if ((ct_action == CT_A_LIST || ct_action == CT_A_EXTRACT)) {
		includelist = argv;
	}
	if (ct_excludefile != NULL) {
		int	nentries;
		excludelist = ct_matchlist_fromfile(ct_excludefile, &nentries);
		if (nentries == -1)
			CFATAL("can't get excludelsit from %s", ct_excludefile);
	}


	if ((ret = ct_load_config(&conf, &config_file)) != 0) {
		CFATALX("%s", ct_strerror(ret));
	}

	/* ct -A or ct -a force allfiles on and off and cancel each other */
	if (force_allfiles != -1)
		conf->ct_multilevel_allfiles = force_allfiles;

	if (!(ct_metadata && (ct_action == CT_A_LIST ||
	    ct_action == CT_A_ERASE))) {
		if (ctfile == NULL) {
			CWARNX("ctfile is required");
			ct_usage();
		}

		if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE &&
		    ctfile_verify_name(ctfile))
			CFATALX("invalid ctfile: %s", ctfile);
	}

	/*
	 * !metadata extract with no args extracts everything.
	 * and all lists show everything if not filtered
	 */
	if (((ct_metadata == 0 && ct_action == CT_A_EXTRACT) ||
	    ct_action == CT_A_LIST) && argc == 0)
		ct_match_mode = CT_MATCH_EVERYTHING;

	if (level0)
		conf->ct_auto_incremental = 0; /* force incremental off */

	if (conf->ct_ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0 &&
	    ct_basisbackup != NULL)
		CFATALX("incremental basis in remote mode");

	/* Don't bother starting a connection if just listing local files. */
	if (ct_action == CT_A_LIST &&
	    conf->ct_ctfile_mode == CT_MDMODE_LOCAL &&
	    ct_metadata == 0 ) {
		ret = ct_list(ctfile, includelist, excludelist,
		    ct_match_mode, NULL, strip_slash, ct_verbose);
		goto out;
	}

	ct_prompt_for_login_password(conf);

	if (ct_action == CT_A_EXTRACT ||
	    ct_action == CT_A_ARCHIVE || (ct_action == CT_A_LIST &&
	    conf->ct_ctfile_mode == CT_MDMODE_REMOTE && ct_metadata == 0) ||
	    ct_action == CT_A_ERASE)
		ct_flags |= CT_NEED_SECRETS;
	if (ct_action == CT_A_ARCHIVE)
		ct_flags |= CT_NEED_DB;


	if ((ret = ct_init(&state, conf, ct_flags, ct_info_sig)) != 0)
		CFATALX("failed to initialise cyphertite: %s",
		    ct_strerror(ret));

#if defined(CT_EXT_INIT)
	CT_EXT_INIT(state);
#endif

	if (conf->ct_crypto_passphrase != NULL &&
	    conf->ct_secrets_upload != 0) {
		ct_add_operation(state, ctfile_list_start,
		    ct_check_secrets_extract, conf->ct_crypto_secrets);
	}

	if (ct_action == CT_A_EXTRACT)
		ct_set_log_fns(state, &ct_verbose, ct_print_ctfile_info,
		    ct_print_file_start, ct_print_file_end, ct_print_file_skip,
		    ct_print_traverse_start, ct_print_traverse_end);
	else if (ct_action == CT_A_ARCHIVE)
		ct_set_log_fns(state, &ct_verbose, ct_print_ctfile_info,
		    ct_pr_fmt_file, ct_pr_fmt_file_end, ct_print_file_skip,
		    ct_print_traverse_start, ct_print_traverse_end);

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
			cea.cea_log_state = &ct_verbose;
			cea.cea_log_chown_failed =
			    ct_print_extract_chown_failed;
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
			caa.caa_includelist = includelist;
			caa.caa_tdir = ct_tdir;
			caa.caa_tag = ctfile;
			caa.caa_ctfile_basedir = conf->ct_ctfile_cachedir;
			/* we want to encrypt as long as we have keys */
			caa.caa_encrypted = (conf->ct_crypto_secrets != NULL);
			caa.caa_allfiles = conf->ct_multilevel_allfiles;
			caa.caa_no_cross_mounts = no_cross_mounts;
			caa.caa_strip_slash = strip_slash;
			caa.caa_follow_root_symlink = follow_root_symlink;
			caa.caa_follow_symlinks = follow_symlinks;
			caa.caa_max_incrementals = conf->ct_max_incrementals;
			if (conf->ct_auto_incremental)
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
			if (ctfile != NULL)
				CFATALX("-f is not permitted with -me operation");
			if (argc == 0)
				CFATALX("no files specified");
			ccda.ccda_pattern = argv;
			ccda.ccda_matchmode = ct_match_mode;
			ccda.ccda_callback = ct_print_delete;
			ct_add_operation(state, ctfile_list_start,
			    ctfile_process_delete, &ccda);
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
			caa.caa_includelist = includelist;
			caa.caa_tdir = ct_tdir;
			caa.caa_tag = ctfile;
			caa.caa_ctfile_basedir = NULL;
			/* we want to encrypt as long as we have keys */
			caa.caa_encrypted = (conf->ct_crypto_secrets != NULL);
			caa.caa_allfiles = conf->ct_multilevel_allfiles;
			caa.caa_no_cross_mounts = no_cross_mounts;
			caa.caa_strip_slash = strip_slash;
			caa.caa_follow_root_symlink = follow_root_symlink;
			caa.caa_follow_symlinks = follow_symlinks;
			caa.caa_max_incrementals = 0; /* unlimited */
			caa.caa_basis = ct_basisbackup;

			ct_add_operation(state, ct_archive, NULL, &caa);
		} else if (ct_action == CT_A_EXTRACT) {
			cea.cea_local_ctfile = ctfile;
			cea.cea_filelist = includelist;
			cea.cea_excllist = excludelist;
			cea.cea_matchmode = ct_match_mode;
			cea.cea_ctfile_basedir = NULL;
			cea.cea_tdir = ct_tdir;
			cea.cea_strip_slash = strip_slash;
			cea.cea_attr = attr;
			cea.cea_follow_symlinks = follow_symlinks;
			cea.cea_log_state = &ct_verbose;
			cea.cea_log_chown_failed =
			    ct_print_extract_chown_failed;
			ct_add_operation(state, ct_extract, NULL, &cea);
		} else {
			CWARNX("must specify action");
			ct_usage();
			/* NOTREACHED */
		}
	}

	ct_wakeup_file(state->event_state);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg,
			    ct_strerror(ret));
		else
			CWARNX("%s", ct_strerror(ret));
		return (ret);
	}

	if (verbose_ratios)
		ct_dump_stats(state, stdout);
	ct_cleanup_login_cache();
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
#if CT_CHECK_MEMORY
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

	assl_initialize();

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


void
ct_display_queues(struct ct_global_state *state)
{
	if (ct_verbose > 1) {
		CT_LOCK(&state->ct_sha_lock);
		CT_LOCK(&state->ct_comp_lock);
		CT_LOCK(&state->ct_crypt_lock);
		CT_LOCK(&state->ct_csha_lock);
		CT_LOCK(&state->ct_write_lock);
		CT_LOCK(&state->ct_queued_lock);
		CT_LOCK(&state->ct_complete_lock);
		fprintf(stderr, "Sha      queue len %d\n",
		    state->ct_sha_qlen);
		CT_UNLOCK(&state->ct_sha_lock);
		fprintf(stderr, "Comp     queue len %d\n",
		    state->ct_comp_qlen);
		CT_UNLOCK(&state->ct_comp_lock);
		fprintf(stderr, "Crypt    queue len %d\n",
		    state->ct_crypt_qlen);
		CT_UNLOCK(&state->ct_crypt_lock);
		fprintf(stderr, "Csha     queue len %d\n",
		    state->ct_csha_qlen);
		CT_UNLOCK(&state->ct_csha_lock);
		fprintf(stderr, "Write    queue len %d\n",
		    state->ct_write_qlen);
		CT_UNLOCK(&state->ct_write_lock);
		fprintf(stderr, "CRqueued queue len %d\n",
		    state->ct_queued_qlen);
		CT_UNLOCK(&state->ct_queued_lock);
		// XXX: Add locks for inflight queue throughout?
		fprintf(stderr, "Inflight queue len %d\n",
		    state->ct_inflight_rblen);
		fprintf(stderr, "Complete queue len %d\n",
		    state->ct_complete_rblen);
		CT_UNLOCK(&state->ct_complete_lock);
		fprintf(stderr, "Free     queue len %d\n",
		    state->ct_trans_free);
	}
	ct_dump_stats(state, stderr);
}

void ct_display_assl_stats(struct ct_global_state *, FILE *);
void print_time_scaled(FILE *, char *s, struct timeval *t);
void
print_time_scaled(FILE *outfh, char *s, struct timeval *t)
{
	int			f = 3;
	double			te;
	char			*scale = "us";

	te = ((double)t->tv_sec * 1000000) + t->tv_usec;
	if (te > 1000) {
		te /= 1000;
		scale = "ms";
	}
	if (te > 1000) {
		te /= 1000;
		scale = "s";
	}

	fprintf(outfh, "%s%12.*f%-2s\n", s, f, te, scale);
}

void
ct_print_scaled_stat(FILE *outfh, const char *label, int64_t val,
    int64_t sec, int newline)
{
	char rslt[FMT_SCALED_STRSIZE];

	bzero(rslt, sizeof(rslt));
	rslt[0] = '?';
	fmt_scaled(val, rslt);
	fprintf(outfh, "%s\t%s", label, rslt);
	if (val == 0 || sec == 0) {
		if (newline)
			fprintf(outfh, "\n");
		return;
	}

	bzero(rslt, sizeof(rslt));
	rslt[0] = '?';
	fmt_scaled(val / sec, rslt);
	fprintf(outfh, "\t(%s/sec)%s", rslt, newline ? "\n": "");
}


void
ct_dump_stats(struct ct_global_state *state, FILE *outfh)
{
	struct timeval time_end, scan_delta, time_delta;
	int64_t sec;
	int64_t val;
	char *sign;
	uint64_t sent, total;

	gettimeofday(&time_end, NULL);

	timersub(&time_end, &state->ct_stats->st_time_start, &time_delta);
	sec = (int64_t)time_delta.tv_sec;
	timersub(&state->ct_stats->st_time_scan_end,
	    &state->ct_stats->st_time_start, &scan_delta);

	if (ct_action == CT_A_ARCHIVE) {
		fprintf(outfh, "Files scanned\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_files_scanned);

		ct_print_scaled_stat(outfh, "Total data\t\t",
		    (int64_t)state->ct_stats->st_bytes_tot, sec, 1);
	}

	if (ct_action == CT_A_ARCHIVE &&
	    state->ct_stats->st_bytes_tot != state->ct_stats->st_bytes_read)
		ct_print_scaled_stat(outfh, "Data read\t\t",
		    (int64_t)state->ct_stats->st_bytes_read, sec, 1);

	if (ct_action == CT_A_EXTRACT)
		ct_print_scaled_stat(outfh, "Data written\t\t",
		    (int64_t)state->ct_stats->st_bytes_written, sec, 1);

	if (ct_action == CT_A_ARCHIVE) {
		ct_print_scaled_stat(outfh, "Data compressed\t\t",
		    (int64_t)state->ct_stats->st_bytes_compressed, sec, 0);
		fprintf(outfh, "\t(%" PRId64 "%%)\n",
		    (state->ct_stats->st_bytes_uncompressed == 0) ? (int64_t)0 :
		    (int64_t)(state->ct_stats->st_bytes_compressed * 100 /
		    state->ct_stats->st_bytes_uncompressed));

		ct_print_scaled_stat(outfh, "Data exists\t\t",
		    (int64_t)state->ct_stats->st_bytes_exists, sec, 0);
		if (state->ct_stats->st_bytes_tot != 0) {
			fprintf(outfh, "\t(%" PRId64 "%%)\n",
			    (state->ct_stats->st_bytes_exists == 0) ?
			    (int64_t)0 :
			    (int64_t)(state->ct_stats->st_bytes_exists * 100 /
			    state->ct_stats->st_bytes_tot));
		}

		ct_print_scaled_stat(outfh, "Data sent\t\t",
		    state->ct_stats->st_bytes_sent, sec, 1);

		sign = " ";
		if (state->ct_stats->st_bytes_tot != 0) {
			total = state->ct_stats->st_bytes_tot;
			sent = state->ct_stats->st_bytes_sent;

			if (sent <= total) {
				val = 100 * (total - sent) / total;
			} else {
				val = 100 * (sent - total) / sent;
				if (val != 0)
					sign = "-";
			}
		} else
			val = 0;
		fprintf(outfh, "Reduction ratio\t\t%s%10" PRId64 "%%\n",
		    sign, val);
	}
	print_time_scaled(outfh, "Total Time\t\t    ",  &time_delta);

	if (ct_verbose > 2) {
		fprintf(outfh, "Total chunks\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_chunks_tot);
		ct_print_scaled_stat(outfh, "Data cryptedt\t\t",
		    (int64_t)state->ct_stats->st_bytes_crypted, 0, 1);
		ct_print_scaled_stat(outfh, "Data sha\t\t",
		    (int64_t)state->ct_stats->st_bytes_sha, 0, 1);
		ct_print_scaled_stat(outfh, "Data crypt\t\t",
		    state->ct_stats->st_bytes_crypt, 0, 1);
		ct_print_scaled_stat(outfh, "Data csha\t\t",
		    state->ct_stats->st_bytes_csha, 0, 1);
		fprintf(outfh, "Chunks completed\t%12" PRIu64 "\n",
		    state->ct_stats->st_chunks_completed);
		fprintf(outfh, "Files completed\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_files_completed);

		if (ct_action == CT_A_ARCHIVE)
			print_time_scaled(outfh, "Scan Time\t\t    ",
			    &scan_delta);
		ct_display_assl_stats(state, outfh);
	}
}

void
ct_display_assl_stats(struct ct_global_state *state, FILE *outfh)
{
	if (state->ct_assl_ctx == NULL)
		return;

	ct_print_scaled_stat(outfh, "SSL data written\t",
	    (int64_t)state->ct_assl_ctx->io_write_bytes, 0, 1);
	fprintf(outfh, "SSL writes\t\t%12" PRIu64 "\n",
	    state->ct_assl_ctx->io_write_count);
	fprintf(outfh, "Avg write len\t\t%12" PRIu64 "\n",
	    state->ct_assl_ctx->io_write_count == 0 ?  (int64_t)0 :
	    state->ct_assl_ctx->io_write_bytes /
	    state->ct_assl_ctx->io_write_count);
	ct_print_scaled_stat(outfh, "SSL data read\t\t",
	    (int64_t)state->ct_assl_ctx->io_read_bytes, 0 , 1);
	fprintf(outfh, "SSL reads\t\t%12" PRIu64 "\n",
	    state->ct_assl_ctx->io_read_count);
	fprintf(outfh, "Avg read len\t\t%12" PRIu64 "\n",
	    state->ct_assl_ctx->io_read_count == 0 ?  (int64_t)0 :
	    state->ct_assl_ctx->io_read_bytes /
	    state->ct_assl_ctx->io_read_count);
}

void
ct_info_sig(evutil_socket_t fd, short event, void *vctx)
{
	struct ct_global_state	*state = vctx;
	ct_display_queues(state);
}


/* Printing functions */
void
ct_pr_fmt_file(void *state, struct fnode *fnode)
{
	int		*verbose = state;
	char		*loginname;
	struct group	*group;
	char		*link_ty, *pchr;
	char		 filemode[11], uid[11], gid[11], lctime[26];
	time_t		 ltime;

	if (*verbose == 0)
		return;

	if (*verbose > 1) {
		switch(fnode->fl_type & C_TY_MASK) {
		case C_TY_DIR:
			filemode[0] = 'd'; break;
		case C_TY_CHR:
			filemode[0] = 'c'; break;
		case C_TY_BLK:
			filemode[0] = 'b'; break;
		case C_TY_REG:
			filemode[0] = '-'; break;
		case C_TY_FIFO:
			filemode[0] = 'f'; break;
		case C_TY_LINK:
			filemode[0] = 'l'; break;
		case C_TY_SOCK:
			filemode[0] = 's'; break;
		default:
			filemode[0] = '?';
		}
		filemode[1] = (fnode->fl_mode & 0400) ? 'r' : '-';
		filemode[2] = (fnode->fl_mode & 0100) ? 'w' : '-';
		filemode[3] = (fnode->fl_mode & 0200) ? 'x' : '-';
		filemode[4] = (fnode->fl_mode & 0040) ? 'r' : '-';
		filemode[5] = (fnode->fl_mode & 0020) ? 'w' : '-';
		filemode[6] = (fnode->fl_mode & 0010) ? 'x' : '-';
		filemode[7] = (fnode->fl_mode & 0004) ? 'r' : '-';
		filemode[8] = (fnode->fl_mode & 0002) ? 'w' : '-';
		filemode[9] = (fnode->fl_mode & 0001) ? 'x' : '-';
		filemode[10] = '\0';

		loginname = ct_getloginbyuid(fnode->fl_uid);
		if (loginname && (strlen(loginname) < sizeof(uid)))
			snprintf(uid, sizeof(uid), "%10s", loginname);
		else
			snprintf(uid, sizeof(uid), "%-10d", fnode->fl_uid);
		group = getgrgid(fnode->fl_gid);
		if (group && (strlen(group->gr_name) < sizeof(gid)))
			snprintf(gid, sizeof(gid), "%10s", group->gr_name);
		else
			snprintf(gid, sizeof(gid), "%-10d", fnode->fl_gid);
		ltime = fnode->fl_mtime;
		ctime_r(&ltime, lctime);
		pchr = strchr(lctime, '\n');
		if (pchr != NULL)
			*pchr = '\0'; /* stupid newline on ctime */

		printf("%s %s %s %s ", filemode, uid, gid, lctime);
	}
	printf("%s", fnode->fl_sname);

	if (*verbose > 1) {
		/* XXX - translate to guid name */
		if (C_ISLINK(fnode->fl_type))  {
			if (fnode->fl_hardlink)  {
				link_ty = "==";
			} else {
				link_ty = "->";
			}
			printf(" %s %s", link_ty, fnode->fl_hlname);
		} else if (C_ISREG(fnode->fl_type)) {
		}
	}
	fflush(stdout);
}

void
ct_pr_fmt_file_end(void *state, struct fnode *fnode, int block_size)
{
	int	*verbose = state;

	if (*verbose)
		printf("\n");
}

void
ct_print_file_start(void *state, struct fnode *fnode)
{
	int	*verbose = state;

	if (*verbose) {
		printf("%s", fnode->fl_sname);
		fflush(stdout);
	}
}

void
ct_print_file_end(void *state, struct fnode *fnode, int block_size)
{
	int			*verbose = state;
	int			 compression, nrshas;

	if (*verbose > 1) {
		if (fnode->fl_size == 0)
			compression = 0;
		else
			compression = 100 * (fnode->fl_size -
			    fnode->fl_comp_size) / fnode->fl_size;
		if (*verbose > 2) {
			nrshas = fnode->fl_size / block_size;
			if (fnode->fl_size % block_size)
				nrshas++;

			printf(" shas %d", nrshas);
		}
		printf(" (%d%%)\n", compression);
	} else if (*verbose)
		printf("\n");

}

void
ct_print_file_skip(void *state, struct fnode *fnode)
{
	int	*verbose = state;

	if (*verbose)
		CINFO("skipping file based on mtime %s", fnode->fl_sname);
}

void
ct_print_ctfile_info(void *state, const char *filename,
    struct ctfile_gheader *gh)
{
	int	*verbose = state;
	time_t ltime;

	if (*verbose) {
		ltime = gh->cmg_created;
		printf("file: %s version: %d level: %d block size: %d "
		    "created: %s", filename, gh->cmg_version, gh->cmg_cur_lvl,
		    gh->cmg_chunk_size, ctime(&ltime));
	}
}

void
ct_print_traverse_start(void *state, char **filelist)
{
	int	*verbose = state;

	if (*verbose)
		CINFO("Generating filelist, this may take a few minutes...");
}

void
ct_print_traverse_end(void *state, char **filelist)
{
	int	*verbose = state;

	if (*verbose)
		CINFO("Done! Initiating backup...");
}

void
ct_print_extract_chown_failed(void *state, struct fnode *fnode,
    struct dnode *dnode)
{
	int		*verbose = state;
	const char	*name;
	const char	*dir = "";

	if (fnode != NULL) {
		name = fnode->fl_sname;
	} else {
		name = dnode->d_name;
		dir = "directory ";
	}

	if (errno == EPERM && geteuid() != 0) {
		if (*verbose)
			CWARN("can't chown %s\"%s\"", dir, name);
	} else {
		CFATAL("can't chown %s\"%s\"", dir, name);
	}
}

void
ct_print_delete(struct ctfile_delete_args *cda,
    struct ct_global_state *state, struct ct_trans *trans)
{
	if (trans->tr_ctfile_name == NULL) {
		printf("could not delete %s\n", cda->cda_name);
	} else if (ct_verbose) {
		printf("%s deleted\n", trans->tr_ctfile_name);
	}
}

struct ct_login_cache {
	RB_ENTRY(ct_login_cache)	 lc_next;
	uid_t				 lc_uid;
	char				*lc_name;
};


int ct_cmp_logincache(struct ct_login_cache *, struct ct_login_cache *);

RB_HEAD(ct_login_cache_tree, ct_login_cache) ct_login_cache =
     RB_INITIALIZER(&login_cache);

#define MAX_LC_CACHE_SIZE 100
int ct_login_cache_size;

RB_PROTOTYPE(ct_login_cache_tree, ct_login_cache, lc_next, ct_cmp_logincache);
RB_GENERATE(ct_login_cache_tree, ct_login_cache, lc_next, ct_cmp_logincache);

void
ct_cleanup_login_cache(void)
{
	struct ct_login_cache *tmp;

	while ((tmp = RB_ROOT(&ct_login_cache)) != NULL) {
		RB_REMOVE(ct_login_cache_tree, &ct_login_cache, tmp);
		/* may cache negative entries, uid not found, avoid NULL free */
		if (tmp->lc_name != NULL) {
			e_free(&tmp->lc_name);
		}
		e_free(&tmp);
	}
	ct_login_cache_size  = 0;
}

char *
ct_getloginbyuid(uid_t uid)
{
	struct passwd *passwd;
	struct ct_login_cache *entry, search;

	search.lc_uid = uid;

	entry = RB_FIND(ct_login_cache_tree, &ct_login_cache, &search);

	if (entry != NULL) {
		return entry->lc_name;
	}

	/* if the cache gets too big, dump all entries and refill. */
	if (ct_login_cache_size > MAX_LC_CACHE_SIZE) {
		ct_cleanup_login_cache();
	}

	/* yes, this even caches negative entries */
	ct_login_cache_size++;

	entry = e_calloc(1, sizeof(*entry));
	entry->lc_uid = uid;

	passwd = getpwuid(uid);
	if (passwd)
		entry->lc_name = e_strdup(passwd->pw_name);
	else
		entry->lc_name = NULL; /* entry not found cache NULL */

	RB_INSERT(ct_login_cache_tree, &ct_login_cache, entry);

	return entry->lc_name;
}

int
ct_cmp_logincache(struct ct_login_cache *f1, struct ct_login_cache *f2)
{
	return ((f1->lc_uid < f2->lc_uid) ? -1 :
	    (f1->lc_uid == f2->lc_uid ? 0 : 1));
}

/*
 * MD content listing code.
 */
int
ct_list_complete_done(struct ct_global_state *state, struct ct_trans *trans)
{
	/* nothing to clean up, this is a fake */
	return (1);
}

void
ct_list_op(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_args	*cea = op->op_args;

	ct_list(cea->cea_local_ctfile, cea->cea_filelist, cea->cea_excllist,
	    cea->cea_matchmode, cea->cea_ctfile_basedir, cea->cea_strip_slash,
	    ct_verbose);

	/* short circuit state machine */
	if (ct_op_complete(state))
		ct_shutdown(state);
}

int
ct_list(const char *file, char **flist, char **excludelist, int match_mode,
    const char *ctfile_basedir, int strip_slash, int verbose)
{
	struct ct_extract_state		*ces;
	struct ctfile_parse_state	 xs_ctx;
	struct fnode			 fnodestore;
	uint64_t			 reduction;
	struct fnode			*fnode = &fnodestore;
	struct ct_match			*match, *ex_match = NULL;
	char				*ct_next_filename;
	char				*sign;
	int				 state;
	int				 doprint = 0;
	int				 ret;
	int				 s_errno = 0, ct_errno = 0;
	char				 shat[SHA_DIGEST_STRING_LENGTH];
	char				 cshat[SHA_DIGEST_STRING_LENGTH];
	char				 iv[CT_IV_LEN*2+1];

	if ((ret = ct_file_extract_init(&ces, NULL, 1, 1, 0, NULL, NULL)) != 0)
		CFATALX("failed to initialise extract state: %s",
		    ct_strerror(ret));
	if ((ret = ct_match_compile(&match, match_mode, flist)) != 0)
		CFATALX("failed to compile match pattern: %s",
		    ct_strerror(ret));
	if (excludelist != NULL && (ret = ct_match_compile(&ex_match,
	    match_mode, excludelist)) != 0)
		CFATALX("failed to compile exclude pattern: %s",
		    ct_strerror(ret));

	verbose++;	/* by default print something. */

	ct_next_filename = NULL;
next_file:
	ret = ctfile_parse_init(&xs_ctx, file, ctfile_basedir);
	if (ret)
		CFATALX("failed to open %s: %s", file, ct_strerror(ret));
	ct_print_ctfile_info(&verbose, file, &xs_ctx.xs_gh);

	if (ct_next_filename)
		e_free(&ct_next_filename);

	if (xs_ctx.xs_gh.cmg_prevlvl_filename) {
		CNDBG(CT_LOG_CTFILE, "previous backup file %s\n",
		    xs_ctx.xs_gh.cmg_prevlvl_filename);
		ct_next_filename = e_strdup(xs_ctx.xs_gh.cmg_prevlvl_filename);
	}
	bzero(&fnodestore, sizeof(fnodestore));

	do {
		ret = ctfile_parse(&xs_ctx);
		switch (ret) {
		case XS_RET_FILE:
			ct_populate_fnode(ces, &xs_ctx, fnode, &state,
			    xs_ctx.xs_gh.cmg_flags & CT_MD_MLB_ALLFILES,
			    strip_slash);
			doprint = !ct_match(match, fnode->fl_sname);
			if (doprint && ex_match != NULL &&
			    !ct_match(ex_match, fnode->fl_sname))
				doprint = 0;
			if (doprint) {
				ct_pr_fmt_file(&verbose, fnode);
				if (!C_ISREG(xs_ctx.xs_hdr.cmh_type) ||
				    verbose > 2)
					printf("\n");
			}
			if (fnode->fl_hlname)
				e_free(&fnode->fl_hlname);
			if (fnode->fl_sname)
				e_free(&fnode->fl_sname);
			break;
		case XS_RET_FILE_END:
			sign = " ";
			if (xs_ctx.xs_trl.cmt_comp_size == 0)
				reduction = 100;
			else {
				uint64_t orig, comp;
				orig = xs_ctx.xs_trl.cmt_orig_size;
				comp = xs_ctx.xs_trl.cmt_comp_size;

				if (comp <= orig) {
					reduction = 100 * (orig - comp) / orig;
				} else  {
					reduction = 100 * (comp - orig) / orig;
					if (reduction != 0)
						sign = "-";
				}
			}
			if (doprint && verbose > 1)
				printf(" sz: %" PRIu64 " shas: %" PRIu64
				    " reduction: %s%" PRIu64 "%%\n",
				    xs_ctx.xs_trl.cmt_orig_size,
				    xs_ctx.xs_hdr.cmh_nr_shas,
				    sign, reduction);
			else if (doprint)
				printf("\n");
			break;
		case XS_RET_SHA:
			if (!(doprint && verbose > 2)) {
				if (ctfile_parse_seek(&xs_ctx)) {
					CFATALX("seek failed");
				}
			} else {
				int i;
				ct_sha1_encode(xs_ctx.xs_sha, shat);
				switch (xs_ctx.xs_gh.cmg_flags & CT_MD_CRYPTO) {
				case 0:
					printf(" sha %s\n", shat);
					break;
				case CT_MD_CRYPTO:
					ct_sha1_encode(xs_ctx.xs_csha, cshat);
					for (i = 0; i < CT_IV_LEN; i++)
						snprintf(&iv[i * 2], 3, "%02x",
						    xs_ctx.xs_iv[i]);

					printf(" sha %s csha %s iv %s\n",
					    shat, cshat, iv);
				}
			}
			break;
		case XS_RET_EOF:
			break;
		case XS_RET_FAIL:
			s_errno = errno;
			ct_errno = xs_ctx.xs_errno;
			;
		}

	} while (ret != XS_RET_EOF && ret != XS_RET_FAIL);

	ctfile_parse_close(&xs_ctx);

	if (ret != XS_RET_EOF) {
		errno = s_errno;
		CWARNX("corrupt ctfile: %s", ct_strerror(ct_errno));
	} else {
		if (ct_next_filename) {
			file = ct_next_filename;
			goto next_file;
		}
	}
	ct_match_unwind(match);
	ct_file_extract_cleanup(ces);
	return (0);
}

ct_op_complete_cb ctfile_nextop_list_cleanup;
int
ctfile_nextop_list(struct ct_global_state *state, char *ctfile, void *args)
{
	struct ct_extract_args	*cea = args;

	cea->cea_local_ctfile = ctfile;
	ct_add_operation(state, ct_list_op, ctfile_nextop_list_cleanup, cea);

	return (0);
}

int
ctfile_nextop_list_cleanup(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_extract_args	*cea = op->op_args;

	if (cea->cea_local_ctfile)
		e_free(&cea->cea_local_ctfile);
	return (0);
}

