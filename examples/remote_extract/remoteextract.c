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

extern char *__progname;

void
ct_info_sig(evutil_socket_t fd, short event, void *vctx)
{
	CINFO("signalled");
}

#define CT_INIT_ASSL	1
#define CT_INIT_CLOG	2
#define CT_INIT_EXUDE	4

int ct_setup(int flags, int cflags, int debug_mask);

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
main(int argc, char **argv)
{
	struct ct_config	*conf;
	struct ct_global_state	*state = NULL;
	char			*config_file = NULL;
	uint32_t		 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	uint64_t		 debug_mask = 0;
	int			 rslt;

	char **excludelist;
	char **includelist;
	char  *tdir;
	char  *ctfile;
	char  *includenode = NULL;
	int    attr;
	int    match_mode, strip_slash;
	int    follow_symlinks;
	int    ret;

	/* setup arguments */
	excludelist = NULL;
	includelist = &includenode;
	tdir = NULL;
	match_mode = CT_MATCH_GLOB;
	attr = 0;
	strip_slash = 1;
	follow_symlinks = 0;

	ct_setup(CT_INIT_ASSL|CT_INIT_CLOG|CT_INIT_EXUDE, cflags, debug_mask);

	if (argc < 2) {
		CFATALX("usage: %s <metadata file tag>", __progname);
	}
	ctfile = e_strdup(argv[1]); /* metadata file tag */

	if ((conf = ct_load_config(&config_file)) == NULL) {
		CFATALX("config file not found. Run \"cyphertitectl config "
		    "generate\" to generate one.");
	}

	ct_prompt_for_login_password(conf);

	if ((ret = ct_init(&state, conf, 0, ct_info_sig)) != 0)
		CFATALX("can't initialize: %s", ct_strerror(ret));

	rslt = ct_do_remoteextract(state, ctfile, tdir, excludelist, includelist,
	    match_mode, strip_slash, follow_symlinks, attr, conf);

	ct_cleanup(state);

	ct_unload_config(config_file, conf);

	if (ctfile)
		e_free(&ctfile);

	return rslt;
}
