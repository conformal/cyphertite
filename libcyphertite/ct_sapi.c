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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
#include <libgen.h>
#include <inttypes.h>

#include <assl.h>

#include <ctutil.h>
#include <ct_crypto.h>
#include <ct_ext.h>

#include <ct_sapi.h>

static void printtime(time_t ftime);

static ct_op_complete_cb               ct_nextop_exists_cleanup;

/* Helper and callback function, not publicly needed. */

static int
ct_nextop_exists(struct ct_global_state *state, char *ctfile, void *arg)
{
	struct ct_exists_args	*ce = arg;

	ce->ce_ctfile = ctfile;
	ct_add_operation(state, ct_exists_file, ct_nextop_exists_cleanup, ce);

	return (0);
}

static int
ct_nextop_exists_cleanup(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_exists_args	*ce = op->op_args;

	e_free(&ce->ce_ctfile);

	return (0);
}

static void
nexists_cb(void *arg, struct ct_exists_args *ce, struct ct_trans *trans)
{
	char			shat[SHA_DIGEST_STRING_LENGTH];

	ct_sha1_encode(trans->tr_sha, shat);
	CWARNX("sha %s not found in backup", shat);
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

/* end helpers */

int
list_print(struct ct_global_state *state, struct ct_op *op)
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

	return (0);
}

int
ct_setup_preinit(int flags, int cflags, int debug_mask)
{
	static int ct_initted = 0;
	int        ret = 0;

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

	return (ret);
}

int
ct_setup_config(char *configfile, struct ct_global_state **state)
{
	int ret;
	struct ct_config *configlocal = NULL;
	struct ct_global_state *statelocal = NULL;
	int ct_flags = 0;

	if ((ret = ct_load_config(&configlocal, &configfile)) != 0) {
		CFATALX("Can not load config file: %s", ct_strerror(ret));
	}

	ct_prompt_for_login_password(configlocal);

	ct_flags |= CT_NEED_SECRETS;
	ct_flags |= CT_NEED_DB;

	if ((ret = ct_init(&statelocal, configlocal, ct_flags, NULL)) != 0)
		CFATALX("can't initialize: %s", ct_strerror(ret));

	*state = statelocal;

	return (ret);
}

int
ct_cleanup_all(struct ct_global_state *state,
    char *configfile)
{
	int ret = 0;

	ct_unload_config(configfile, state->ct_config);
	ct_cleanup(state);

	return (ret);
}

int
ct_do_list(struct ct_global_state *state, char **search, char **exclude,
    int matchmode, int (*printfn) (struct ct_global_state *state,
    struct ct_op *op))
{
	struct ct_ctfile_list_args	ccla;
	int				ret;

	ccla.ccla_search = search;
	ccla.ccla_exclude = exclude;
	ccla.ccla_matchmode = matchmode;
	ct_add_operation(state, ctfile_list_start,
	    printfn, &ccla);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else
			CWARNX("%s", ct_strerror(ret));
	}

	return (ret);
}

int
ct_do_archive(struct ct_global_state *state, char *ctfile, char **flist,
    char *tdir, char **excludelist, char **includelist, int matchmode,
    int no_cross_mounts, int strip_slash, int follow_root_symlink,
    int follow_symlinks)
{
	int                    ret;
	struct ct_archive_args caa;

	ct_normalize_filelist(flist);
	caa.caa_filelist = flist;
	caa.caa_excllist = excludelist;
	caa.caa_matchmode = matchmode;
	caa.caa_includelist = includelist;
	caa.caa_tdir = tdir;
	caa.caa_tag = ctfile;
	caa.caa_ctfile_basedir = state->ct_config->ct_ctfile_cachedir;
	/* we want to encrypt as long as we have keys */
	caa.caa_no_cross_mounts = no_cross_mounts;
	caa.caa_strip_slash = strip_slash;
	caa.caa_follow_root_symlink = follow_root_symlink;
	caa.caa_follow_symlinks = follow_symlinks;
	caa.caa_max_incrementals = state->ct_config->ct_max_incrementals;

	if (state->ct_config->ct_auto_incremental)
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


	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else
			CWARNX("%s", ct_strerror(ret));
	}

	return (ret);
}

int
ct_do_extract(struct ct_global_state *state, char *ctfile, char *tdir,
    char **excludelist, char **includelist, int matchmode, int strip_slash,
    int follow_symlinks, int preserve_attr)
{
	int		       ret;
	struct ct_extract_args cea;

	cea.cea_local_ctfile = NULL; /* to be found */
	cea.cea_filelist = includelist;
	cea.cea_excllist = excludelist;
	cea.cea_matchmode = matchmode;
	cea.cea_ctfile_basedir = state->ct_config->ct_ctfile_cachedir;
	cea.cea_tdir = tdir;
	cea.cea_strip_slash = strip_slash;
	cea.cea_attr = preserve_attr;
	cea.cea_follow_symlinks = follow_symlinks;

	ctfile_find_for_operation(state, ctfile,
	    ctfile_nextop_extract, &cea, 1, 0);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else
			CWARNX("%s", ct_strerror(ret));
	}

	return (ret);
}

int
ct_do_delete(struct ct_global_state *state, char *ctfile,
    int matchmode)
{
	int ret = 0;
	struct ct_ctfile_delete_args	 cda;
	char *delete_array[2] = { ctfile, NULL };

	cda.ccda_pattern = delete_array;
	cda.ccda_matchmode = matchmode;
	cda.ccda_callback = NULL;

	ct_add_operation(state, ctfile_list_start,
	    ctfile_process_delete, &cda);

	if ((ret = ct_run_eventloop(state)) != 0) {

		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg, ct_strerror(ret));
		else
			CWARNX("%s", ct_strerror(ret));
	}

	return (ret);
}

int
ct_do_check_existance(struct ct_global_state *state, char *ctfile)
{
	int                      ret = 0;
	struct ct_exists_args	 ce;

	ce.ce_ctfile_basedir = state->ct_config->ct_ctfile_cachedir;
	ce.ce_nexists_cb = nexists_cb;
	ce.ce_nexists_state = state;

	ctfile_find_for_operation(state, ctfile, ct_nextop_exists, &ce, 1, 0);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg,
			    ct_strerror(ret));
		else
			CWARNX("%s", ct_strerror(ret));
	} else {
		CWARNX("all shas in backup %s exists on server", ctfile);
	}

	return (ret);
}
