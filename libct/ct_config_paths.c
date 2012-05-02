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

#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <inttypes.h>

#include <exude.h>
#include <clog.h>

char *
ct_system_config(void)
{
	char			*conf;

	e_asprintf(&conf, "%s", "/etc/cyphertite/cyphertite.conf");

	return (conf);
}

char *
ct_user_config(void)
{
	char			*conf;
	struct			passwd *pwd;

	pwd = getpwuid(getuid());
	if (pwd == NULL)
		CFATALX("invalid user %d", getuid());

	e_asprintf(&conf, "%s/.cyphertite/cyphertite.conf", pwd->pw_dir);
	return (conf);
}

char *
ct_user_config_old(void)
{
	char			*conf;
	struct			passwd *pwd;

	pwd = getpwuid(getuid());
	if (pwd == NULL)
		CFATALX("invalid user %d", getuid());

	e_asprintf(&conf, "%s/.cyphertite.conf", pwd->pw_dir);
	return (conf);
}

