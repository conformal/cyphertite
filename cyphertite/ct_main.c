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
#include <ct_lib.h>
#include "ct.h"
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
int			ct_action = 0;
void ct_display_queues(struct ct_global_state *);
void ct_dump_stats(struct ct_global_state *state, FILE *outfh);

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

	state = ct_init(conf, need_secrets, verbose, ct_info_sig);
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
			caa.caa_follow_symlinks = follow_symlinks;
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

	ct_wakeup_file(state->event_state);

	ret = ct_event_dispatch(state->event_state);
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
	if (state->ct_verbose > 1) {
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

	fprintf(outfh, "%s%12" PRId64, label, val);
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
		fprintf(outfh, "Files scanned\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_files_scanned);

		ct_print_scaled_stat(outfh, "Total bytes\t\t\t",
		    (int64_t)state->ct_stats->st_bytes_tot, sec, 1);
	}

	if (ct_action == CT_A_ARCHIVE &&
	    state->ct_stats->st_bytes_tot != state->ct_stats->st_bytes_read)
		ct_print_scaled_stat(outfh, "Bytes read\t\t\t",
		    (int64_t)state->ct_stats->st_bytes_read, sec, 1);

	if (ct_action == CT_A_EXTRACT)
		ct_print_scaled_stat(outfh, "Bytes written\t\t\t",
		    (int64_t)state->ct_stats->st_bytes_written, sec, 1);

	if (ct_action == CT_A_ARCHIVE) {
		ct_print_scaled_stat(outfh, "Bytes compressed\t\t",
		    (int64_t)state->ct_stats->st_bytes_compressed, sec, 0);
		fprintf(outfh, "\t(%" PRId64 "%%)\n",
		    (state->ct_stats->st_bytes_uncompressed == 0) ? (int64_t)0 :
		    (int64_t)(state->ct_stats->st_bytes_compressed * 100 /
		    state->ct_stats->st_bytes_uncompressed));

		fprintf(outfh,
		    "Bytes exists\t\t\t%12" PRIu64 "\t(%" PRId64 "%%)\n",
		    state->ct_stats->st_bytes_exists,
		    (state->ct_stats->st_bytes_exists == 0) ? (int64_t)0 :
		    (int64_t)(state->ct_stats->st_bytes_exists * 100 /
		    state->ct_stats->st_bytes_tot));

		fprintf(outfh, "Bytes sent\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_bytes_sent);

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
		fprintf(outfh, "Reduction ratio\t\t\t\t%s%" PRId64 "%%\n",
		    sign, val);
	}
	print_time_scaled(outfh, "Total Time\t\t\t    ",  &time_delta);

	if (state->ct_verbose > 2) {
		fprintf(outfh, "Total chunks\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_chunks_tot);
		fprintf(outfh, "Bytes crypted\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_bytes_crypted);

		fprintf(outfh, "Bytes sha\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_bytes_sha);
		fprintf(outfh, "Bytes crypt\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_bytes_crypt);
		fprintf(outfh, "Bytes csha\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_bytes_csha);
		fprintf(outfh, "Chunks completed\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_chunks_completed);
		fprintf(outfh, "Files completed\t\t\t%12" PRIu64 "\n",
		    state->ct_stats->st_files_completed);

		if (ct_action == CT_A_ARCHIVE)
			print_time_scaled(outfh, "Scan Time\t\t\t    ",
			    &scan_delta);
		ct_display_assl_stats(state, outfh);
	}
}

void
ct_display_assl_stats(struct ct_global_state *state, FILE *outfh)
{
	if (state->ct_assl_ctx == NULL)
		return;

	fprintf(outfh, "ssl bytes written %" PRIu64 "\n",
	    state->ct_assl_ctx->io_write_bytes);
	fprintf(outfh, "ssl writes        %" PRIu64 "\n",
	    state->ct_assl_ctx->io_write_count);
	fprintf(outfh, "avg write len     %" PRIu64 "\n",
	    state->ct_assl_ctx->io_write_count == 0 ?  (int64_t)0 :
	    state->ct_assl_ctx->io_write_bytes /
	    state->ct_assl_ctx->io_write_count);
	fprintf(outfh, "ssl bytes read    %" PRIu64 "\n",
	    state->ct_assl_ctx->io_read_bytes);
	fprintf(outfh, "ssl reads         %" PRIu64 "\n",
	    state->ct_assl_ctx->io_read_count);
	fprintf(outfh, "avg read len      %" PRIu64 "\n",
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
