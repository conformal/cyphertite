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
#ifndef CT_VERSION_TREE_H
#define CT_VERSION_TREE_H
TAILQ_HEAD(ct_vertree_ctfile_cache, ct_vertree_ctfile);
struct ct_vertree_ctfile {
	TAILQ_ENTRY(ct_vertree_ctfile)	 cvc_link;
	char				 cvc_path[PATH_MAX]; /* ctfile name */
};

/*
 * Version key.
 * subclasses of this have additional information.
 */
TAILQ_HEAD(ct_vertree_vers, ct_vertree_ver);
struct ct_vertree_ver {
	TAILQ_ENTRY(ct_vertree_ver)	 cvv_link;
	u_char				 cvv_type; /* same types as in ctfile */
	uint32_t			 cvv_uid; /* user id */
	uint32_t			 cvv_gid; /* group id */
	uint32_t			 cvv_mode; /* file mode */
	int64_t				 cvv_atime; /* last access time */
	int64_t				 cvv_mtime; /* last modification time */
};

struct ct_vertree_file {
	struct ct_vertree_ver		 cvf_base;
	uint64_t			 cvf_nr_shas;
	struct ct_vertree_ctfile	*cvf_file; /* ctfile with data */
	off_t				 cvf_sha_offs; /* offset into file */
	uint64_t			 cvf_file_size;
};

struct ct_vertree_dir {
	struct ct_vertree_ver	cvd_base;
};

struct ct_vertree_spec {
	struct ct_vertree_ver	cvs_base;
	int32_t			cvs_rdev;	/* major and minor */
};

struct ct_vertree_link {
	struct ct_vertree_ver	 cvl_base;
	char			*cvl_linkname;	/* where to link to */
	int			 cvl_hardlink;	/* boolean */
};

RB_HEAD(ct_vertree_entries, ct_vertree_entry);
struct ct_vertree_entry {
	RB_ENTRY(ct_vertree_entry)	 cve_entry;
	struct ct_vertree_vers		 cve_versions;
	struct ct_vertree_entries	 cve_children;
	char				*cve_name;	/* filename */
	struct ct_vertree_entry		*cve_parent;	/* parent dir. */
};
RB_PROTOTYPE(ct_vertree_entries, ct_vertree_entry, cve_entry,
    ct_cmp_entry);

struct ct_version_tree {
	struct ct_vertree_entry		cvt_head;
	struct ct_vertree_ctfile_cache	cvt_ctfiles;
};

int	ct_version_tree_build(const char *, const char *,
	    struct ct_version_tree **);
void	ct_version_tree_free(struct ct_version_tree *);

#endif /* ! CT_VERSION_TREE_H */
