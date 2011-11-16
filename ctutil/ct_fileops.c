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

#include <clog.h>

void
ct_expand_tilde(char **dst, char *key, char *val)
{
	char			*uid_s;
	struct			passwd *pwd;
	int			i;
	uid_t			uid;

	if (dst == NULL || key == NULL || val == NULL)
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

		if (asprintf(dst, "%s/%s", pwd->pw_dir, &val[i]) == -1)
			CFATALX("no memory for %s", key);
	} else
		*dst = strdup(val);
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

char *
ct_remove_ext(char *path)
{
	char *ret = NULL, *dot = NULL, *sep = NULL;

	if (path == NULL)
		CFATALX("invalid parameter to ct_remove_ext");

	if ((ret = strdup(path)) == NULL)
		CFATALX("strdup path in ct_remove_ext");

	dot = strrchr(ret, '.');
	sep = strrchr(ret, '/');

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
