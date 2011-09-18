/*
 * Copyright (c) 2004-2006 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
/* Based on "Id: undeadly.c,v 1.49 2008/06/19 12:49:31 dhartmei Exp" */

#include "ctutil.h"

#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>

#include <sys/stat.h>

#include <time.h>


extern char *__progname;

int
ct_savecore(void)
{
	char ocore[FILENAME_MAX+1];

	snprintf(ocore, sizeof(ocore), "%s.core", __progname);
	if (access(ocore, R_OK) == 0) {
		struct stat sb;

		if (stat(ocore, &sb)) {
			warn("stat");
			return -1;
		} else {
			int fd;
			struct tm *tm = gmtime(&sb.st_mtime);
			char ncore[FILENAME_MAX+1];

			snprintf(ncore, sizeof(ncore),
			    "%s.%4.4d%2.2d%2.2d%2.2d%2.2d%2.2d.core",
			    __progname, tm->tm_year + 1900, tm->tm_mon + 1,
			    tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);

			/* prevent core file from being overwritten */
			fd = open(ncore, O_CREAT | O_RDWR | O_EXCL, 0600);
			if (fd == -1) {
				warn("open");
				return -1;
			}

			/* empty dest file exists, and it belongs to us now */
			close(fd);

			if (rename(ocore, ncore)) {
				warn("rename(%s,%s)", ocore, ncore);
				return -1;
			} else {
				warnx("rename(%s,%s) ok", ocore, ncore);
				return 0;
			}
		}
	} else {
		if (errno != ENOENT) {
			warn("access");
			return -1; /* something went wrong */
		} else
			return 0; /* no core file, yay! */
	}
}

