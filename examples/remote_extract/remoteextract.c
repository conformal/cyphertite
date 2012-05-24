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

#include <ctutil.h>

#include <ct_crypto.h>
#include <ct_lib.h>
#include <ct_match.h>
#include <ct_ext.h>

static void printtime(time_t ftime);

void
ct_info_sig(evutil_socket_t fd, short event, void *vctx)
{
	CINFO("signalled");
}

void
remotelist_print(struct ct_global_state *state, struct ct_op *op)
{
	struct ctfile_list_file         *file;
	int64_t                          maxsz = 8;
	int                              numlen;

	numlen = snprintf(NULL, 0, "%" PRId64, maxsz);

	while ((file = SIMPLEQ_FIRST(&state->ctfile_list_files)) != NULL) {
		SIMPLEQ_REMOVE_HEAD(&state->ctfile_list_files, mlf_link);

		printf("%*llu ", numlen, (unsigned long long)file->mlf_size);
		printtime(file->mlf_mtime);
		printf("\t");
		printf("%s\n", file->mlf_name);
		e_free(&file);
	}
}

/******************************  BEGIN MOVE TO LIBCT ******************/
#define CT_INIT_ASSL	1
#define CT_INIT_CLOG	2
#define CT_INIT_EXUDE	4

int ct_setup(int flags, int cflags, int debug_mask);
int 
ct_do_remotearchive(struct ct_global_state *state, char *ctfile, char **flist,
    char *tdir, char **excludelist, char *includefile, int match_mode,
    int no_cross_mounts, int strip_slash, int follow_root_symlink,
    int follow_symlinks, struct ct_config *conf);

int
ct_setup(int flags, int cflags, int debug_mask)
{
	static int ct_initted = 0;

	if ((flags & CT_INIT_ASSL) && (ct_initted & CT_INIT_ASSL) == 0) {
		ct_initted |= CT_INIT_ASSL;
		assl_initialize();
	}

	if ((flags & CT_INIT_CLOG) && (ct_initted & CT_INIT_CLOG) == 0) {
		ct_initted |= CT_INIT_CLOG;
		if (clog_set_flags(cflags)) {
			CWARNX( "illegal clog flags");
			return 1;
		}
		clog_set_mask(debug_mask);
	}

	if ((flags & CT_INIT_EXUDE) && (ct_initted & CT_INIT_EXUDE) == 0) {
		ct_initted |= CT_INIT_EXUDE;
		exude_enable_threads();
	}
	return 0;
}

int 
	
ct_do_remotearchive(struct ct_global_state *state, char *ctfile, char **flist,
    char *tdir, char **excludelist, char *includefile, int match_mode,
    int no_cross_mounts, int strip_slash, int follow_root_symlink,
    int follow_symlinks, struct ct_config *conf)
{
	int			 ret;

        struct ct_archive_args           caa;

	ct_normalize_filelist(flist);
	caa.caa_filelist = flist;
	caa.caa_excllist = excludelist;
	caa.caa_matchmode = match_mode;
	caa.caa_includefile = includefile;
	caa.caa_tdir = tdir;
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


	ct_wakeup_file(state->event_state);

	ret = ct_event_dispatch(state->event_state);
	if (ret != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));

	return ret;
}

int 
ct_do_remoteextract(struct ct_global_state *state, char *ctfile, char *tdir,
    char **excludelist, char **includefile, int match_mode, int strip_slash,
    int follow_symlinks, int preserve_attr,  struct ct_config *conf);

int 
ct_do_remoteextract(struct ct_global_state *state, char *ctfile, char *tdir,
    char **excludelist, char **includelist, int match_mode, int strip_slash,
    int follow_symlinks, int preserve_attr,  struct ct_config *conf)
{
	int			 ret;

        struct ct_extract_args           cea;

	cea.cea_local_ctfile = NULL; /* to be found */
	cea.cea_filelist = includelist;
	cea.cea_excllist = excludelist;
	cea.cea_matchmode = match_mode;
	cea.cea_ctfile_basedir = conf->ct_ctfile_cachedir;
	cea.cea_tdir = tdir;
	cea.cea_strip_slash = strip_slash;
	cea.cea_attr = preserve_attr;
	cea.cea_follow_symlinks = follow_symlinks;
	ctfile_find_for_operation(state, ctfile,
	    ctfile_nextop_extract, &cea, 1, 0);

	ct_wakeup_file(state->event_state);

	ret = ct_event_dispatch(state->event_state);
	if (ret != 0)
		CWARNX("event_dispatch returned, %d %s", errno,
		    strerror(errno));

	return ret;
}
/****************************** END MOVE TO LIBCT ******************/


int
main(int argc, char **argv)
{
	struct ct_config	*conf;
	struct ct_global_state	*state = NULL;
	char			*config_file = NULL;
	uint32_t		 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	uint64_t		 debug_mask = 0;

	char **excludelist;
	char **includelist;
	char  *tdir;
	char  *ctfile;
	char  *includenode = NULL;
	int    attr;
	int    match_mode, strip_slash;
	int    follow_symlinks;

	/* setup arguments */
	excludelist = NULL;
	includelist = &includenode;
	tdir = NULL;
	match_mode = CT_MATCH_GLOB;
	attr = 0;
	strip_slash = 1;
	follow_symlinks = 0;

	ct_setup(CT_INIT_ASSL|CT_INIT_CLOG|CT_INIT_EXUDE, cflags, debug_mask);

	if ((conf = ct_load_config(&config_file)) == NULL) {
		CFATALX("config file not found.  Use the -F option to "
		    "specify its path or run \"cyphertitectl config generate\" "
		    "to generate one.");
	}

	ct_prompt_for_login_password(conf);

	state = ct_init(conf, 0, 0, ct_info_sig);
	state->ct_verbose = 2;

	argv++; /* eat program name */
	ctfile = argv[0]; /* first arg is tag */


	ct_do_remoteextract(state, ctfile, tdir, excludelist, includelist,
	    match_mode, strip_slash, follow_symlinks, attr, conf);

	ct_cleanup(state);

	ct_unload_config(config_file, conf);

	return 0;
}

/* Taken from OpenBSD ls */
static void
printtime(time_t ftime)
{
        int i;
        char *longstring;

        longstring = ctime(&ftime);
        for (i = 4; i < 11; ++i)
                (void)putchar(longstring[i]);

#define DAYSPERNYEAR    365
#define SECSPERDAY      (60*60*24)
#define SIXMONTHS       ((DAYSPERNYEAR / 2) * SECSPERDAY)
        if (ftime + SIXMONTHS > time(NULL))
                for (i = 11; i < 16; ++i)
                        (void)putchar(longstring[i]);
        else {
                (void)putchar(' ');
                for (i = 20; i < 24; ++i)
                        (void)putchar(longstring[i]);
        }
        (void)putchar(' ');
}

