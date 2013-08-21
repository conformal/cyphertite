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
#include <string.h>
#include <inttypes.h>
#include <limits.h>

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include <ct_ctfile.h>
#include <ct_version_tree.h>


/* Subclass of dnode for faster lookup. */
TAILQ_HEAD(ct_vertree_dnode_cache, ct_vertree_dnode);
struct ct_vertree_dnode {
	struct dnode			 cvd_dnode;
	TAILQ_ENTRY(ct_vertree_dnode)	 cvd_link;
	struct ct_vertree_entry		*cvd_dir;
};

static inline int
ct_cmp_entry(struct ct_vertree_entry *a, struct ct_vertree_entry *b)
{
	return strcmp(a->cve_name, b->cve_name);
}

RB_GENERATE(ct_vertree_entries, ct_vertree_entry, cve_entry,
    ct_cmp_entry);

/*
 * Main guts of  ctd_build_version_tree. Factored out to avoid deep nesting.
 * Insert or update an entry in the tree with the information received from
 * the ctfile.
 */
static struct ct_vertree_entry *
ct_vertree_add(struct ct_vertree_dnode_cache *dnode_cache,
    struct ct_vertree_entry *head, struct ctfile_parse_state *parse_state,
    struct ct_vertree_ctfile *ctfile, off_t fileoffset, int allfiles)
{
	struct ctfile_header		*hdr = &parse_state->xs_hdr;
	struct ctfile_header		*hdrlnk= &parse_state->xs_lnkhdr;
	struct dnode 			*dnode;
	struct ct_vertree_dnode		*fb_dnode;
	struct ct_vertree_entry		*parent = NULL, sentry, *entry;
	struct ct_vertree_ver		*lastver, *ver;
	struct ct_vertree_file		*file;
	struct ct_vertree_spec		*spec;
	struct ct_vertree_link		*linkver;
	size_t				 sz;

	entry = NULL;

	/* First find parent directory if any */
	if (hdr->cmh_parent_dir != -1 && hdr->cmh_parent_dir != -2) {
		if ((dnode = ctfile_parse_finddir(parse_state,
		    hdr->cmh_parent_dir)) == NULL) {
			CNDBG(CT_LOG_VERTREE, "can't find dir %" PRId64,
			    hdr->cmh_parent_dir);
			return NULL;
		}
		fb_dnode = (struct ct_vertree_dnode *)dnode;
		parent = fb_dnode->cvd_dir;
	} else {
		parent = head;
	}

	/*
	 * Have parent node, search children to see if we already exist.
	 * Else make a new one and insert.
	 */
	sentry.cve_name = e_strdup(hdr->cmh_filename);
	if ((entry = RB_FIND(ct_vertree_entries, &parent->cve_children,
	    &sentry)) == NULL) {
		/* new name, insert node */
		entry = e_calloc(1, sizeof(*entry));

		TAILQ_INIT(&entry->cve_versions);
		RB_INIT(&entry->cve_children);
		entry->cve_parent = parent;
		entry->cve_name = sentry.cve_name;
		if (RB_INSERT(ct_vertree_entries, &parent->cve_children,
		    entry) != NULL) {
			CNDBG(CT_LOG_VERTREE, "entry %s already exists",
			    sentry.cve_name);
			e_free(&sentry.cve_name);
			goto err;
		}
	} else {
		e_free(&sentry.cve_name);
	}

	/*
	 * then check version tags -> head/tail if mtime and type match, we're
	 * good else prepare version entry.
	 */
	if (allfiles) {
		lastver = TAILQ_FIRST(&entry->cve_versions);
	} else {
		lastver = TAILQ_LAST(&entry->cve_versions, ct_vertree_vers);
	}
	/* Don't check atime, it doesn't matter */
	if (lastver != NULL && lastver->cvv_type == hdr->cmh_type &&
	    lastver->cvv_mtime == hdr->cmh_mtime &&
	    lastver->cvv_uid == hdr->cmh_uid &&
	    lastver->cvv_gid == hdr->cmh_gid &&
	    lastver->cvv_mode == hdr->cmh_mode) {
		ver = lastver;
	} else { /* something changed. make a new one */
		if (C_ISDIR(hdr->cmh_type)) {
			sz = sizeof(struct ct_vertree_dir);
		} else if (C_ISBLK(hdr->cmh_type) ||
		    C_ISCHR(hdr->cmh_type)) {
			sz = sizeof(struct ct_vertree_spec);
		} else  if (C_ISLINK(hdr->cmh_type)) {
			sz = sizeof(struct ct_vertree_link);
		} else if (C_ISREG(hdr->cmh_type)) {
			sz = sizeof(struct ct_vertree_file);
		} else {
			CNDBG(CT_LOG_VERTREE, "invalid type %d", hdr->cmh_type);
			goto err;
		}
		ver = e_calloc(1, sz);
		ver->cvv_type = hdr->cmh_type;
		ver->cvv_mtime = hdr->cmh_mtime;
		ver->cvv_atime = hdr->cmh_atime;
		ver->cvv_uid = hdr->cmh_uid;
		ver->cvv_gid = hdr->cmh_gid;
		ver->cvv_mode = hdr->cmh_mode;
		/* dir handled below */
		if (C_ISBLK(hdr->cmh_type) || C_ISCHR(hdr->cmh_type))  {
			spec = (struct ct_vertree_spec *)ver;
			spec->cvs_rdev = hdr->cmh_rdev;
		} else if (C_ISLINK(hdr->cmh_type)){
			/* hardlink/symlink */
			linkver = (struct ct_vertree_link *)ver;
			linkver->cvl_linkname = e_strdup(hdrlnk->cmh_filename);
			linkver->cvl_hardlink = !C_ISLINK(hdrlnk->cmh_type);
		} else if (C_ISREG(hdr->cmh_type)) {
			file = (struct ct_vertree_file *)ver;
			file->cvf_nr_shas = -1;
		}
		if (allfiles) {
			TAILQ_INSERT_HEAD(&entry->cve_versions, ver, cvv_link);
		} else {
			TAILQ_INSERT_TAIL(&entry->cve_versions, ver, cvv_link);
		}
	}

	/*
	 * Each ctfile only has each directory referenced once, so put it
	 * in the cache regardless of whether it was known of before, that
	 * will be a previous run and the cache will have been wiped since
	 * then.
	 */
	if (C_ISDIR(hdr->cmh_type)) {
		fb_dnode = e_calloc(1, sizeof(*fb_dnode));
		fb_dnode->cvd_dnode.d_name = e_strdup(entry->cve_name);
		fb_dnode->cvd_dir = entry;
		if ((dnode = ctfile_parse_insertdir(parse_state,
		    &fb_dnode->cvd_dnode)) != NULL)
			CABORTX("duplicate dentry");
		TAILQ_INSERT_TAIL(dnode_cache, fb_dnode, cvd_link);
	} else if (C_ISREG(hdr->cmh_type)) {
		/*
		 * Allfiles ctfiles may have shas == -1, so in some cases we
		 * may wish to update an existing file when we find the actual
		 * shas. It is an error to have a file node with -1 for shas
		 * after all metadata have been parsed. it means one was
		 * missing.
		 */
		file = (struct ct_vertree_file *)ver;

		/*
		 * bugs in previous editions with incremental selection and
		 * off_t on linux mean that there are ctfiles in the wild which
		 * provide a list of shas in a later level when the file is
		 * defined in an earlier level file, also. For example for the 
		 * same filename and date we have level 0: 3 shas, level 1: -1
		 * shas (i.e. in a previous level), level 2: 3 shas (same as
		 * level * 0). In that case we just assume that if we already
		 * have sha data for a file * then it is correct and we skip
		 * previous versions.
		 */ 
		if (file->cvf_nr_shas != -1) {
			goto out;
		}

		/*
		 * previous linux off_t bugs with files over 2gb mean that there
		 * are sign extended ctfiles in the wild, so we count those as
		 * zero length for purposes of the version tree.
		 */
		if (hdr->cmh_nr_shas < -1) {
			hdr->cmh_nr_shas = 0;
		}
		if (hdr->cmh_nr_shas != -1)  {
			file->cvf_nr_shas = hdr->cmh_nr_shas;
			file->cvf_sha_offs = fileoffset;
			file->cvf_file = ctfile;
			if (ctfile_parse_seek(parse_state)) {
				CNDBG(CT_LOG_VERTREE,
				    "failed to skip shas in %s",
				    ctfile->cvc_path);
				goto err;
			}
		}
		if (ctfile_parse(parse_state) != XS_RET_FILE_END) {
			CNDBG(CT_LOG_VERTREE, "no file trailer found");
			goto err;
		}

		file->cvf_file_size = parse_state->xs_trl.cmt_orig_size;
	}

out:
	return (entry);

err:
	if (entry != NULL)
		e_free(&entry);
	return (NULL);
}

int
ct_version_tree_build(const char *filename, const char *ctfile_basedir,
    struct ct_version_tree **version_tree)
{
	struct ct_version_tree		*tree = NULL;
	struct ct_extract_head		 extract_head;
	struct ctfile_parse_state	 parse_state;
	struct ct_vertree_dnode_cache	 dnode_cache;
	struct ct_vertree_dnode		*dnode_entry;
	struct ct_vertree_ctfile	*ctfile = NULL;
	struct ct_vertree_dir		*root_dir;
	struct ct_vertree_ver		*root_version;
	off_t				 offset;
	int				 allfiles;
	int				 rv = 0;

	TAILQ_INIT(&extract_head);
	TAILQ_INIT(&dnode_cache);

	if ((rv = ct_extract_setup(&extract_head, &parse_state, filename,
	    ctfile_basedir, &allfiles))) {
		CNDBG(CT_LOG_VERTREE,
		    "failed to setup extract for filename %s: %s",
		    filename, ct_strerror(rv));
		goto out;
	}


	/* Create and init ctfile cache */
	tree = e_calloc(1, sizeof(*tree));
	TAILQ_INIT(&tree->cvt_ctfiles);
	TAILQ_INIT(&tree->cvt_head.cve_versions);
	RB_INIT(&tree->cvt_head.cve_children);
	tree->cvt_head.cve_name = e_strdup("/");

nextfile:
	root_dir = e_calloc(1, sizeof(*root_dir));
	root_version = &root_dir->cvd_base;
	root_version->cvv_type = C_TY_DIR;
	root_version->cvv_uid = 0;
	root_version->cvv_gid = 0;
	root_version->cvv_mode = 0777;
	root_version->cvv_atime = parse_state.xs_gh.cmg_created;
	root_version->cvv_mtime = parse_state.xs_gh.cmg_created;
	TAILQ_INSERT_HEAD(&tree->cvt_head.cve_versions, root_version, cvv_link);

	/*
	 * Create only one struct for each ctfile.  Each entry in the version
	 * tree references the appropriate one.  These are added to a cache list
	 * so they can be freed during tree cleanup.
	 */
	ctfile = e_calloc(1, sizeof(*ctfile));
	strlcpy(ctfile->cvc_path, parse_state.xs_filename,
	    sizeof(ctfile->cvc_path));
	offset = ctfile_parse_tell(&parse_state);
	TAILQ_INSERT_TAIL(&tree->cvt_ctfiles, ctfile, cvc_link);

	while (((rv = ctfile_parse(&parse_state)) != XS_RET_EOF) &&
	    (rv != XS_RET_FAIL)) {
		switch(rv) {
		case XS_RET_FILE:
			if (ct_vertree_add(&dnode_cache, &tree->cvt_head,
			    &parse_state, ctfile, offset, allfiles) == NULL) {
				rv = CTE_CTFILE_CORRUPT;
				goto out;
			}
			break;
		case XS_RET_FILE_END:
			break;
		case XS_RET_SHA:
			if ((rv = ctfile_parse_seek(&parse_state))) {
				goto out;
			}
			break;
		default:
			rv = CTE_CTFILE_CORRUPT;
			goto out;
		}
		offset = ctfile_parse_tell(&parse_state);
	}
	if (rv == XS_RET_EOF) {
		ctfile_parse_close(&parse_state);
		if (!TAILQ_EMPTY(&extract_head)) {
			ct_extract_open_next(&extract_head, &parse_state);
			goto nextfile;
		}
		rv = 0;
		/* free state */
	} else {
		rv = CTE_CTFILE_CORRUPT;
		goto out;
	}

	*version_tree = tree;

out:
	/* Free dnode_cache entries. */
	while ((dnode_entry = TAILQ_FIRST(&dnode_cache)) != NULL) {
		TAILQ_REMOVE(&dnode_cache, dnode_entry, cvd_link);
		if (dnode_entry->cvd_dnode.d_name != NULL)
			e_free(&dnode_entry->cvd_dnode.d_name);
		e_free(&dnode_entry);
	}

	return rv;
}

/*
 * Frees the passed list of ctfile cache entries that are referenced by a
 * version tree.
 */
static void
ct_version_tree_free_ctfile_cache(struct ct_vertree_ctfile_cache *cache)
{
	struct ct_vertree_ctfile		*entry;

	while ((entry = TAILQ_FIRST(cache)) != NULL) {
		TAILQ_REMOVE(cache, entry, cvc_link);
		e_free(&entry);
	}
}

static void
ct_version_tree_free_version(struct ct_vertree_ver *entry)
{
	struct ct_vertree_dir		*dir;
	struct ct_vertree_spec		*spec;
	struct ct_vertree_link		*flink;
	struct ct_vertree_file		*file;

	if (C_ISDIR(entry->cvv_type)) {
		dir = (struct ct_vertree_dir *)entry;
		e_free(&dir);
	} else if (C_ISBLK(entry->cvv_type) ||
	    C_ISCHR(entry->cvv_type)) {
		spec = (struct ct_vertree_spec *)entry;
		e_free(&spec);
	} else  if (C_ISLINK(entry->cvv_type)) {
		flink = (struct ct_vertree_link *)entry;
		if (flink->cvl_linkname != NULL)
			e_free(&flink->cvl_linkname);
		e_free(&flink);
	} else if (C_ISREG(entry->cvv_type)) {
		file = (struct ct_vertree_file *)entry;
		e_free(&file);
	}

	return;
}

/* recursively free a vertree_entry. caller frees entry itself */
static void
ct_version_tree_free_entry(struct ct_vertree_entry *entry)
{
	struct ct_vertree_ver		*ventry;
	struct ct_vertree_entry		*child;

	if (entry == NULL) {
		return;
	}

	if (entry->cve_name != NULL)
		e_free(&entry->cve_name);

	/* Clean up version entries */
	while ((ventry = TAILQ_FIRST(&entry->cve_versions)) != NULL) {
		TAILQ_REMOVE(&entry->cve_versions, ventry, cvv_link);
		ct_version_tree_free_version(ventry);
	}

	/* Clean up children */
	while ((child = RB_ROOT(&entry->cve_children)) != NULL) {
		RB_REMOVE(ct_vertree_entries, &entry->cve_children, child);
		ct_version_tree_free_entry(child);
		e_free(&child);
	}
}

void
ct_version_tree_free(struct ct_version_tree *tree)
{
	/* Clean up children */
	ct_version_tree_free_entry(&tree->cvt_head);
	ct_version_tree_free_ctfile_cache(&tree->cvt_ctfiles);

	e_free(&tree);
}
