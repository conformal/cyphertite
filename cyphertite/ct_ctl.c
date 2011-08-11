/* $cyphertite$ */
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

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

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

void
cpasswd(struct ct_cli_cmd *c, int argc, char **argv)
{
	struct stat		sb;

	if (ct_crypto_secrets == NULL)
		CFATALX("Crypto not enabled");

	if (stat(ct_crypto_secrets, &sb) == -1)
		CFATALX("secrets file does not exist");

	if (ct_unlock_secrets(ct_crypto_password, ct_crypto_secrets,
	    ct_crypto_key, sizeof(ct_crypto_key), ct_iv, sizeof (ct_iv)))
		CFATALX("can't unlock secrets");

	/* ct_create_secrets("mooo", "/tmp/moo", ct_crypto_key, ct_iv); */
}

struct ct_cli_cmd	cmd_cpasswd[] = {
	{ "change", NULL, 0, "", cpasswd, 0 },
	{ NULL, NULL, 0, NULL, NULL, 0}
};

struct ct_cli_cmd	cmd_list[] = {
	{ "cpasswd", NULL, 1, "<change>", cpasswd },
	{ NULL, NULL, 0, NULL, NULL }
};

void
ctctl_usage(void)
{
	fprintf(stderr, "%s [-d][-F configfile] action...\n",
	    __progname);
	exit(1);
}

int
ctctl_main(int argc, char *argv[])
{
	int			c;
	struct ct_cli_cmd	*cc = NULL;

	while ((c = getopt(argc, argv, "dF:")) != -1) {
		switch (c) {
		case 'd':
			ct_debug = 1;
			cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC |
			    CLOG_F_LINE | CLOG_F_DTIME;
			exude_enable();
			break;
		case 'F':
			ct_configfile = optarg;
			break;
		default:
			CWARNX("must specify action");
			ctctl_usage();
			/* NOTREACHED */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	/* load config */
	if (ct_load_config(settings))
		CFATALX("config file not found.  Use the -F option to "
		    "specify its path.");

	if ((cc = ct_cli_validate(cmd_list, &argc, &argv)) == NULL)
		ct_cli_usage(cmd_list, NULL);

	CDBG("calling %s", cc->cc_cmd);

	ct_cli_execute(cc, &argc, &argv);

	return (0);
}
