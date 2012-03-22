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

/*
 * XXX ownership, times and mode can change in each differential,
 * perhaps needa a split
 */
struct ct_fb_ctfile {
	char		cff_path[PATH_MAX];	/* ctfile name */
};

TAILQ_HEAD(ct_fb_vers, ct_fb_key);
RB_HEAD(ct_fb_entries, ct_fb_entry);

struct ct_fb_entry {
	TAILQ_ENTRY(ct_fb_entry)	 cfb_link;
	RB_ENTRY(ct_fb_entry)		 cfb_entry;
	struct ct_fb_vers		 cfb_versions;
	struct ct_fb_entries		 cfb_children;
	char				*cfb_name;	/* filename */
	struct ct_fb_entry		*cfb_parent;	/* parent dir. */
};

/*
 * Version key.
 * subclasses of this have additional information.
 */
struct ct_fb_key {
	TAILQ_ENTRY(ct_fb_key)	 cfb_link;
	u_char			 cfb_type;	/* same types as in ctfile */
	uint32_t		 cfb_uid;	/* user id */
	uint32_t		 cfb_gid;	/* group id */
	uint32_t		 cfb_mode;	/* file mode */
	int64_t			 cfb_atime;	/* last access time */
	int64_t			 cfb_mtime;	/* last modification time */
};

struct ct_fb_file {
	struct ct_fb_key	 cfb_base;
	uint64_t		 cfb_nr_shas;	/* total shas */
	struct ct_fb_ctfile	*cfb_file;	/* file containing shas */
	off_t			 cfb_sha_offs;	/* offset into file */
	uint64_t		 cfb_file_size;
};

struct ct_fb_dir {
	struct ct_fb_key	cfb_base;
};

struct ct_fb_spec {
	struct ct_fb_key	cfb_base;
	int32_t			cfb_rdev;	/* major and minor */
};

struct ct_fb_link {
	struct ct_fb_key	 cfb_base;
	/* XXX hardlink has pointer to linkee? */
	char			*cfb_linkname;	/* where to link to */
	int			 cfb_hardlink;	/* boolean */
};

/* State function for current location in the version tree. */
struct ct_fb_state {
	struct ct_fb_entry	 cfs_tree;
	struct ct_fb_entry	*cfs_cwd;
	char			 cfs_curpath[PATH_MAX];
};

int		ctfb_main(int, char *[]);
void		ct_fb_print_entry(char *, struct ct_fb_key *, int);
int		ctfb_lstat(const char *, struct stat *);

typedef void    (ctfb_cmd)(int, const char **);
__dead void	ctfb_usage(void);
void		ct_build_tree(const char *, struct ct_fb_entry *);
int		glob_ctfile(const char *, int, int (*)(const char *, int),
		    glob_t *, int);
void		 complete_display(char **, u_int);
char		*complete_ambiguous(const char *, char **, size_t);
int		 ctfb_get_version(struct ct_fb_state *, const char *,
		     int, struct ct_fb_entry **, struct ct_fb_key **);
