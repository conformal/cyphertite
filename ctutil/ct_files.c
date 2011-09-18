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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include <pwd.h>
#include <string.h>
#include <stdio.h>

#include <clog.h>

#include "ctutil.h"

void
ct_expand_tilde(struct ct_settings *cs, char **s, char *val)
{
	char			*uid_s;
	struct			passwd *pwd;
	int			i;
	uid_t			uid;

	if (cs == NULL || s == NULL)
		CFATALX("invalid parameter");

	if (val[0] == '~' && strlen(val) > 1) {
		if ((uid = getuid()) == 0) {
			/* see if we are using sudo and get caller uid */
			uid_s = getenv("SUDO_UID");
			if (uid_s)
				uid = atoi(uid_s);
		}
		pwd = getpwuid(uid);
		if (pwd == NULL)
			CFATALX("invalid user %d", uid);

		i = 1;
		while (val[i] == '/' && val[i] != '\0')
			i++;

		if (asprintf(s, "%s/%s", pwd->pw_dir, &val[i]) == -1)
			CFATALX("no memory for %s", cs->cs_name);
	} else
		*s = strdup(val);
}

/*
 * make all directories in the full path provided in ``path'' if they don't
 * exist.
 * returns 0 on success.
 */
int
ct_make_full_path(char *path, mode_t mode)
{
	char		*nxt = path;
	struct stat	 st;

	/* deal with full paths */
	if (*nxt == '/')
		nxt++;
	for (;;) {
		if ((nxt = strchr(nxt, '/')) == NULL)
			break;
		*nxt = '\0';

		if (lstat(path, &st) == 0) {
			*(nxt++) = '/';
			continue;
		}

		if (mkdir(path, mode) == -1)
			return (1);
		*(nxt++) = '/';
		/* XXX stupid umask? */
	}

	return (0);
}


