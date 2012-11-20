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

#include <glob.h>
#include <ct_version_tree.h>

/* State function for current location in the version tree. */
struct ct_fb_state {
	struct ct_version_tree	*cfs_tree;
	struct ct_vertree_entry	*cfs_cwd;
	char			 cfs_curpath[PATH_MAX];
};

int		ctfb_main(int, char *[]);
void		ct_fb_print_entry(char *, struct ct_vertree_ver *, int);
int		ctfb_lstat(const char *, struct stat *);

typedef void    (ctfb_cmd)(int, const char **);
__dead void	ctfb_usage(void);
int		glob_ctfile(const char *, int, int (*)(const char *, int),
		    glob_t *, int);
void		 complete_display(char **, u_int);
char		*complete_ambiguous(const char *, char **, size_t);
int		 ctfb_get_version(struct ct_fb_state *, const char *,
		     int, struct ct_vertree_entry **, struct ct_vertree_ver **);
