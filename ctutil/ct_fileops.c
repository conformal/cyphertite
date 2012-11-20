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
#include <fcntl.h>
#include <limits.h>

#include <clog.h>
#include <exude.h>
#include <ctutil.h>

void
ct_expand_tilde(char **path, const char *s)
{
        struct passwd           *pwd;
        const char              *sc = s;
        char                    *uid_s;
        char                     user[sysconf(_SC_LOGIN_NAME_MAX)];
        uid_t                    uid;
        int                      i;

        if (path == NULL || s == NULL)
                CFATALX("invalid parameters");

        if (s[0] != '~') {
                goto no_expansion;
        }

        ++s;
        for (i = 0; s[i] != CT_PATHSEP && s[i] != '\0'; ++i)
                user[i] = s[i];
        user[i] = '\0';
        s = &s[i];

        if (strlen(user) == 0) {
                uid = getuid();
                if (uid == 0) {
                        /* see if we are using sudo and get caller uid */
                        uid_s = getenv("SUDO_UID");
                        if (uid_s)
                                uid = atoi(uid_s);
                }
                if ((pwd = getpwuid(uid)) == NULL) {
                        goto no_expansion;
                }
        } else {
                if ((pwd = getpwnam(user)) == NULL) {
                        goto no_expansion;
                }
        }

        if (asprintf(path, "%s%s", pwd->pw_dir, s))
		CFATALX("no memory");
        return;

no_expansion:
        *path = strdup(sc);
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
	if (*nxt == CT_PATHSEP)
		nxt++;
	for (;;) {
		if ((nxt = strchr(nxt, CT_PATHSEP)) == NULL)
			break;
		*nxt = '\0';

		if (lstat(path, &st) == 0) {
			*(nxt++) = CT_PATHSEP;
			continue;
		}

		if (mkdir(path, mode) == -1)
			return (1);
		*(nxt++) = CT_PATHSEP;
		/* XXX stupid umask? */
	}

	return (0);
}

char *
ct_remove_ext(char *path)
{
	char *ret = NULL, *dot = NULL, *sep = NULL;

	if (path == NULL)
		CFATALX("invalid parameter to ct_remove_ext");

	if ((ret = strdup(path)) == NULL)
		CFATALX("strdup path in ct_remove_ext");

	dot = strrchr(ret, '.');
	sep = strrchr(ret, CT_PATHSEP);

	/* no extension */
	if (dot == NULL)
		return (ret);

	/* extension with no path separators */
	if (sep == NULL) {
		*dot = '\0';
		return (ret);
	}

	/* extension after last separator */
	if (dot > sep) {
		*dot = '\0';
		return (ret);
	}

	return (ret);
}

int
ct_set_pipe_nonblock(int fd)
{
	int			val, rv = 1;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0)
		goto done;

	if (val & O_NONBLOCK)
		return (0);

	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		goto done;

	rv = 0;
done:
	return (rv);
}
