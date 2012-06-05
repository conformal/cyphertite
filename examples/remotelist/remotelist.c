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

/****************************** END MOVE TO LIBCT ******************/

int
main(int argc, char **argv)
{
	struct ct_config	*conf;
	struct ct_global_state	*state = NULL;
	char			*config_file = NULL;
	uint32_t		 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	uint64_t		 debug_mask = 0;

	ct_setup(CT_INIT_ASSL|CT_INIT_CLOG|CT_INIT_EXUDE, cflags, debug_mask);

	if ((conf = ct_load_config(&config_file)) == NULL) {
		CFATALX("config file not found.  Use the -F option to "
		    "specify its path or run \"cyphertitectl config generate\" "
		    "to generate one.");
	}

	ct_prompt_for_login_password(conf);

	state = ct_init(conf, 0, 0, ct_info_sig);

	char **search;
	char **exclude;
	int matchmode;

	search = NULL;
	exclude = NULL;
	matchmode = CT_MATCH_GLOB;

	ct_do_remotelist(state, search, exclude, matchmode, remotelist_print);

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

