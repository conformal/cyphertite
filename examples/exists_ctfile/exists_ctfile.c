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

#include <sys/types.h>
#include <sys/stat.h>

#include <ctutil.h>

#include <ct_crypto.h>
#include <cyphertite.h>
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

ct_op_complete_cb ct_nextop_exists_cleanup;

int
ct_nextop_exists(struct ct_global_state *state, char *ctfile, void *arg)
{
	struct ct_exists_args	*ce = arg;

	ce->ce_ctfile = ctfile;

	ct_add_operation(state, ct_exists_file, ct_nextop_exists_cleanup, ce);

	return (0);
}

int
ct_nextop_exists_cleanup(struct ct_global_state *state, struct ct_op *op)
{
	struct ct_exists_args	*ce = op->op_args;

	e_free(&ce->ce_ctfile);

	return (0);
}

void
nexists_cb(void *arg, struct ct_exists_args *ce, struct ct_trans *trans)
{
	char				 shat[SHA_DIGEST_STRING_LENGTH];

	ct_sha1_encode(trans->tr_sha, shat);

	CWARNX("sha %s not found in backup", shat);
}

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
	struct ct_exists_args	 ce;
	char			*config_file = NULL;
	uint32_t		 cflags = CLOG_F_ENABLE | CLOG_F_STDERR;
	uint64_t		 debug_mask = 0;
	int			 ret;

	ct_setup(CT_INIT_ASSL|CT_INIT_CLOG|CT_INIT_EXUDE, cflags, debug_mask);

	if (argc < 2) {
		CFATALX("usage: %s <metadata file tag>", __progname);
	}

	if ((ret = ct_load_config(&conf, &config_file)) != 0) {
		CFATALX("Can not load config file: %s", ct_strerror(ret));
	}
	ct_prompt_for_login_password(conf);

	if ((ret = ct_init(&state, conf, CT_NEED_DB | CT_NEED_SECRETS,
	    ct_info_sig)) != 0)
		CFATALX("can't initialize: %s", ct_strerror(ret));

	ce.ce_ctfile_basedir = conf->ct_ctfile_cachedir;
	ce.ce_nexists_cb = nexists_cb;
	ce.ce_nexists_state = state;
	ctfile_find_for_operation(state, argv[1], ct_nextop_exists,
	    &ce, 1, 0);

	if ((ret = ct_run_eventloop(state)) != 0) {
		if (state->ct_errmsg[0] != '\0')
			CWARNX("%s: %s", state->ct_errmsg,
			    ct_strerror(ret));
		else	
			CWARNX("%s", ct_strerror(ret));
	} else {
		CWARNX("all shas in backup %s exists on server", argv[1]);
	}


	ct_cleanup(state);

	ct_unload_config(config_file, conf);

	return (ret);
}
