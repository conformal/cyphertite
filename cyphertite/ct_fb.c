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
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <inttypes.h>
#include <libgen.h>
#include <glob.h>
#include <err.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <paths.h>

#include <histedit.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"
#include "ct_fb.h"

#ifndef nitems
#define nitems(_a)      (sizeof((_a)) / sizeof((_a)[0]))
#endif /* !nitems */

/* Cli commands */
typedef	void	(ctfb_cmd)(int, const char **);

ctfb_cmd	ctfb_cd;
ctfb_cmd	ctfb_get;
ctfb_cmd	ctfb_ls;
ctfb_cmd	ctfb_pwd;
ctfb_cmd	ctfb_lcd;
ctfb_cmd	ctfb_lpwd;
ctfb_cmd	ctfb_lmkdir;
ctfb_cmd	ctfb_lumask;
ctfb_cmd	ctfb_lls;
ctfb_cmd	ctfb_shell;

/* State function for current location in the version tree. */
struct ct_fb_state {
	struct ct_fb_entry	 cfs_tree;
	struct ct_fb_entry	*cfs_cwd;
	char			 cfs_curpath[PATH_MAX];
};

/* Subclass of dnode for faster lookup. */
struct ct_fb_dnode {
	struct dnode		 dnode;
	struct ct_fb_entry	*dir;
};

struct ct_fb_state	*ctfb_cfs;
char			*ct_fb_filename;

__dead void		 ctfb_usage(void);
struct ct_fb_entry	*ct_add_tree(struct ct_fb_entry *,
			     struct ct_xdr_state *, struct ct_fb_mdfile *,
			     off_t);
struct ct_fb_entry	*ctfb_follow_path(struct ct_fb_state *, const char *,
			     char[PATH_MAX]);
int			 glob_mdfile(const char *, int,
			     int (*)(const char *, int), glob_t *, int);
/* completion code */
unsigned char		 complete(EditLine *el, int cb);
unsigned char		 complete_file(EditLine *, const char *, int,
			     char , int, int, int);
static void		 complete_display(char **, u_int);
static int		 complete_cmd_parse(EditLine *, const char *, int,
			     char, int);
static char		*complete_ambiguous(const char *, char **, size_t);

static inline int
ct_cmp_entry(struct ct_fb_entry *a, struct ct_fb_entry *b)
{
	return strcmp(a->cfb_name, b->cfb_name);
}

RB_PROTOTYPE_STATIC(ct_fb_entries, ct_fb_entry, cfb_entry, ct_cmp_entry);
RB_GENERATE_STATIC(ct_fb_entries, ct_fb_entry, cfb_entry, ct_cmp_entry);

/*
 * Main guts of  ct_build tree. Factored out to avoid deep nesting.
 * Insert or update an entry in the tree with the information gotten from
 * the md file.
 */
struct ct_fb_entry *
ct_add_tree(struct ct_fb_entry *head, struct ct_xdr_state *xdr_ctx,
    struct ct_fb_mdfile *mdfile, off_t fileoffset)
{
	extern int64_t			 ct_ex_dirnum;
	struct ct_md_header		*hdr = &xdr_ctx->xs_hdr;
	struct ct_md_header		*hdrlnk= &xdr_ctx->xs_lnkhdr;
	struct dnode 			*dnode;
	struct ct_fb_dnode		*fb_dnode;
	struct ct_fb_entry		*parent = NULL, sentry, *entry;
	struct ct_fb_key		*lastkey, *key;
	struct ct_fb_file		*file;
	struct ct_fb_spec		*spec;
	struct ct_fb_link		*linkkey;
	size_t				 sz;

	/* First find parent directory if any */
	if (hdr->cmh_parent_dir != -1) {
		if ((dnode = gen_finddir(hdr->cmh_parent_dir)) == NULL)
			CFATALX("can't find dir %" PRId64 ,
			    hdr->cmh_parent_dir);
		fb_dnode = (struct ct_fb_dnode *)dnode;
		parent = fb_dnode->dir;
	} else {
		parent = head;
	}

	/*
	 * Have parent node, search children to see if we already exist.
	 * Else make a new one and insert.
	 */
	CDBG("filename = %s", hdr->cmh_filename);
	sentry.cfb_name = e_strdup(hdr->cmh_filename);
	if ((entry = RB_FIND(ct_fb_entries, &parent->cfb_children,
	    &sentry)) == NULL) {
		/* new name, insert node */
		entry = e_calloc(1, sizeof(*entry));

		TAILQ_INIT(&entry->cfb_versions);
		RB_INIT(&entry->cfb_children);
		entry->cfb_parent = parent;
		entry->cfb_name = sentry.cfb_name;
		if (RB_INSERT(ct_fb_entries, &parent->cfb_children,
		    entry) != NULL)
			CFATALX("entry %s already exists", sentry.cfb_name);
	} else {
		e_free(&sentry.cfb_name);
	}

	/*
	 * then check version tags -> head/tail if mtime and type match, we're
	 * good else prepare version key.
	 */
	if (ct_multilevel_allfiles) {
		lastkey = TAILQ_FIRST(&entry->cfb_versions);
	} else {
		lastkey = TAILQ_LAST(&entry->cfb_versions, ct_fb_vers);
	}
	/* Don't check atime, it doesn't matter */
	if (lastkey != NULL && lastkey->cfb_type == hdr->cmh_type &&
	    lastkey->cfb_mtime == hdr->cmh_mtime &&
	    lastkey->cfb_uid == hdr->cmh_uid &&
	    lastkey->cfb_gid == hdr->cmh_gid &&
	    lastkey->cfb_mode == hdr->cmh_mode) {
		key = lastkey;
		CDBG("found existing key");
	} else { /* something changed. make a new one */
		CDBG("making new key");
		if (C_ISDIR(hdr->cmh_type)) {
			sz = sizeof(struct ct_fb_dir);
		} else if (C_ISBLK(hdr->cmh_type) ||
		    C_ISCHR(hdr->cmh_type)) {
			sz = sizeof(struct ct_fb_spec);
		} else  if (C_ISLINK(hdr->cmh_type)) {
			sz = sizeof(struct ct_fb_link);
		} else if (C_ISREG(hdr->cmh_type)) {
			sz = sizeof(struct ct_fb_file);
		} else {
			CFATALX("invalid type %d", hdr->cmh_type);
		}
		key = e_calloc(1, sz);
		key->cfb_type = hdr->cmh_type;
		key->cfb_mtime = hdr->cmh_mtime;
		key->cfb_atime = hdr->cmh_atime;
		key->cfb_uid = hdr->cmh_uid;
		key->cfb_gid = hdr->cmh_gid;
		key->cfb_mode = hdr->cmh_mode;
		/* dir handled below */
		if (C_ISBLK(hdr->cmh_type) || C_ISCHR(hdr->cmh_type))  {
			spec = (struct ct_fb_spec *)key;
			spec->cfb_rdev = hdr->cmh_rdev;
		} else if (C_ISLINK(hdr->cmh_type)){
			/* hardlink/symlink */
			linkkey = (struct ct_fb_link *)key;
			linkkey->cfb_linkname = e_strdup(hdrlnk->cmh_filename);
			linkkey->cfb_hardlink = !C_ISLINK(hdrlnk->cmh_type);
		} else if (C_ISREG(hdr->cmh_type)) {
			file = (struct ct_fb_file *)key;
			file->cfb_nr_shas = -1;
		}
		if (ct_multilevel_allfiles) {
			TAILQ_INSERT_HEAD(&entry->cfb_versions, key, cfb_link);
		} else {
			TAILQ_INSERT_TAIL(&entry->cfb_versions, key, cfb_link);
		}
	}

	/*
	 * Each MD file only has each directory referenced once, so put it
	 * in the cache irregardless of whether it was known of before, that
	 * will be a previous run and the cache will have been wiped since
	 * then..
	 */
	if (C_ISDIR(hdr->cmh_type)) {
		fb_dnode = e_calloc(1,sizeof (*fb_dnode));
		fb_dnode->dnode.d_name = e_strdup(entry->cfb_name);
		fb_dnode->dnode.d_num = ct_ex_dirnum++;
		fb_dnode->dir = entry;
		CDBG("inserting %s as %" PRId64, fb_dnode->dnode.d_name,
		    fb_dnode->dnode.d_num );
		dnode = RB_INSERT(d_num_tree, &ct_dnum_head, &fb_dnode->dnode);
		if (dnode != NULL)
			CFATALX("duplicate dentry");
	} else if (C_ISREG(hdr->cmh_type)) {
		/*
		 * Allfiles md files may have shas == -1, so in some cases we
		 * may wish to update an existing file when we find the actual
		 * shas. It is an error to have a file node with -1 for shas
		 * after all metadata have been parsed. it means one was
		 * missing.
		 */
		file = (struct ct_fb_file *)key;
		if (file->cfb_nr_shas != -1 && file->cfb_nr_shas !=
		    hdr->cmh_nr_shas) {
			CFATALX("sha mismatch before %" PRIu64 " now %" PRIu64,
			    file->cfb_nr_shas, hdr->cmh_nr_shas);
		}
		if (hdr->cmh_nr_shas != -1)  {
			file->cfb_nr_shas = hdr->cmh_nr_shas;
			file->cfb_sha_offs = fileoffset;
			file->cfb_file = mdfile;
			if (ct_xdr_parse_seek(xdr_ctx))
				CFATALX("failed to skip shas in %s",
				    mdfile->cff_path);
		}
		if (ct_xdr_parse(xdr_ctx) != XS_RET_FILE_END)
			CFATALX("no file trailer found");
		file->cfb_file_size = xdr_ctx->xs_trl.cmt_orig_size;
	}

	return (entry);
}

/*
 * Build version tree on ``head'' from mfile (and dependant files).
 */
void
ct_build_tree(const char *mfile, struct ct_fb_entry *head)
{
	struct ct_extract_head	 extract_head;
	struct ct_xdr_state	 xdr_ctx;
	struct ct_fb_mdfile	*mdfile = NULL;
	off_t			 offset;
	int			 ret;

	CDBG("entry");

	TAILQ_INIT(&extract_head);
	ct_extract_setup(&extract_head, &xdr_ctx, mfile);

	/* head has no name or parent */
	TAILQ_INIT(&head->cfb_versions);
	RB_INIT(&head->cfb_children);

nextfile:
	/* XXX keep these in a list? Right now they leak */
	mdfile = calloc(1, sizeof(*mdfile));
	strlcpy(mdfile->cff_path, xdr_ctx.xs_filename,
	    sizeof(mdfile->cff_path));
	offset = ct_xdr_parse_tell(&xdr_ctx);

	while ((ret = ct_xdr_parse(&xdr_ctx)) != XS_RET_EOF &&
	    ret != XS_RET_FAIL) {
		switch(ret) {
		case XS_RET_FILE:
			(void)ct_add_tree(head, &xdr_ctx,
			    mdfile, offset);
			break;
		case XS_RET_FILE_END:
			break;
		default:
			CFATALX("invalid state in %s: %d", __func__, ret);
		}
		offset = ct_xdr_parse_tell(&xdr_ctx);
	}
	if (ret == XS_RET_EOF) {
		CDBG("done, closing file");
		ct_xdr_parse_close(&xdr_ctx);
		if (!TAILQ_EMPTY(&extract_head)) {
			CDBG("opening next one");
			ct_extract_open_next(&extract_head, &xdr_ctx);
			goto nextfile;
		}
		/* free state */
	} else {
		CFATALX("failed to parse metadata file");
	}
}

/*
 * Functions for manipulating ct_fb_state.
 */


/*
 * walk the directory tree to the relative or absolute path provided by
 * ``path''.  paths containing nonexistant/../rest/of/path won't work unlike
 * on some filesystems or shells because we walk each path component.
 *
 * if newcwd is non null then it will be updated to contain the new path
 * after expansion. If we fail it will be unchanged.
 */
struct ct_fb_entry *
ctfb_follow_path(struct ct_fb_state *cfs, const char *path,
    char newcwd[PATH_MAX])
{
	struct ct_fb_entry	*cwd;
	char			*next, *cur, cwdbuf[PATH_MAX], pbuf[PATH_MAX];
	int			 absolute = 0, home = 0;

	if (path == NULL || path[0] == '\0') {
		CDBG("should go back to /");
		home = 1;
	} else if (path[0] == '/') {
		CDBG("absolute path %s", path); 
		absolute = 1;
	}

	if (absolute || home) {
		cwd = &cfs->cfs_tree;
		cwdbuf[0] = '\0';
		if (absolute) /* Skip initial / */
			path++;
			
	} else {
		cwd = cfs->cfs_cwd;
		if (newcwd != NULL)
			strlcpy(cwdbuf, newcwd, sizeof(cwdbuf));
	}
		
	if (path != NULL) {
		strlcpy(pbuf, path, sizeof(pbuf));
	} else {
		pbuf[0] = '\0';
	}
	next = (char *)pbuf;
	/*
	 * We walk the whole tree here, could probably be short circuited to
	 * do the whole thing in jumps.
	 */
	while (next != NULL) {
		cur = next;

		/* XXX directory separator */
		if ((next = strchr(cur, '/')) != NULL)
			*(next++) = '\0';
		CDBG("next segment = %s", cur);

		if (*cur == '\0')
			continue;
		else if (strcmp(cur, "..") == 0) {
			char		*end;

			CDBG("goback");
			/* ignore .. from root */
			if (cwd->cfb_parent == NULL) {
				CDBG("at root");
				continue;
			}
			cwd = cwd->cfb_parent;

			if (newcwd == NULL)
				continue;

			/* update our buffer */
			if ((end = strrchr(cwdbuf, '/')) == NULL)
				CFATALX("cfs_curpath is corrupted: %s", cwdbuf);
			*(end) = '\0'; /* Amend curpath */
		} else if (strcmp(cur, ".") == 0) {
			CDBG(".: doing nothing");
		} else {
			struct ct_fb_entry	sentry;
			CDBG("next dir = %s", cur);

			sentry.cfb_name = cur;
			if ((cwd = RB_FIND(ct_fb_entries, &cwd->cfb_children,
			    &sentry)) == NULL) {
				CDBG("can't find directory %s", cur);
				errno = ENOENT;
				return (NULL);
			}
			if (newcwd == NULL)
				continue;

			/* update our buffer */
			if (cwdbuf[0] != '\0')
				strlcat(cwdbuf, "/", sizeof(cwdbuf));
			strlcat(cwdbuf, cur, sizeof(cwdbuf));
		}
	}

	if (newcwd != NULL)
		strlcpy(newcwd, cwdbuf, sizeof(newcwd));

	return (cwd);
}

int
ctfb_get_version(struct ct_fb_state *state, const char *path, int preferdir,
    struct ct_fb_entry **entryp, struct ct_fb_key **keyp)
{
	struct ct_fb_entry		*entry;
	struct ct_fb_key		*key = NULL;
	char				*postfix;
	struct tm			 tm;
	time_t				 mtime = 0;
	int				 noversion = 0;

	/* Get version out of the filename. */
	if ((postfix = strrchr(path, '.')) == NULL) {
		CDBG("can't find version postfix");
		noversion = 1;
		goto search;
	}

	/* parse file name. path/name.date */
	if (strptime(postfix, ".%Y%m%d%H%M%S", &tm) == NULL) {
		CDBG("can't parse version from filename %s", path);
		noversion = 1;
		goto search;
	}
	tm.tm_isdst = -1;
	mtime = mktime(&tm);
	CDBG("mtime = %" PRIi64, (int64_t)mtime);


	*postfix = '\0'; /* trim off version now we have it parsed out */

search:
	if ((entry = ctfb_follow_path(ctfb_cfs, path, NULL)) == NULL) {
		if (noversion == 0)
			*postfix = '.';
		return (-1);
	}
		
	if (noversion) {
		if (preferdir) {
			/* See if we have a directory, pick the latest */
			TAILQ_FOREACH_REVERSE(key, &entry->cfb_versions,
			    ct_fb_vers, cfb_link)
				if (C_ISDIR(key->cfb_type))
					break;
		}
		/* no directory? pick the most recent type */
		if (key == NULL)
			key = TAILQ_LAST(&entry->cfb_versions, ct_fb_vers);
	} else {
		TAILQ_FOREACH(key, &entry->cfb_versions, cfb_link)
			if (key->cfb_mtime == mtime)
				break;
		*postfix = '.'; /* put string back how it was */
	}

	if (key == NULL) {
		errno = ENOENT;
		return (-1);
	}

	*entryp = entry;
	*keyp = key;

	return (0);
}

/*
 * Change the current working directory to ``path''.
 */
int
ctfb_chdir(struct ct_fb_state *state, const char *path)
{
	struct ct_fb_entry *result;
	
	if ((result = ctfb_follow_path(state, path,
	    state->cfs_curpath)) == NULL)
		return (-1);
	state->cfs_cwd = result;

	return (0);
}

/*
 * Print out the node ``parent'', including children if it is a directory.
 */
void
ctfb_print_node(struct ct_fb_entry *parent, char *prefix)
{
	struct ct_fb_entry	*entry;
	struct ct_fb_key	*key;
	size_t			 sz;
	time_t			 mtime;
	char			 buf[PATH_MAX];

	if (!TAILQ_EMPTY(&parent->cfb_versions))
		printf("Versions:\n");
	TAILQ_FOREACH(key, &parent->cfb_versions, cfb_link) {
		if (prefix) {
			sz = snprintf(buf, sizeof(buf), "%s/", prefix);
			if (sz == -1 || sz >= sizeof(buf)) {
				CWARNX("string too long");
				continue;
			}
		} else {
			buf[0] = '\0';
		}
		if ((sz = strlcat(buf, parent->cfb_name, sizeof(buf))) >=
		    sizeof(buf)) {
			CWARNX("string too long");
			continue;
		}
		mtime = (time_t)key->cfb_mtime;

		if (strftime(buf + sz , sizeof(buf) - sz, ".%Y%m%d%H%M%S",
		    localtime(&mtime)) == 0) {
			CWARNX("can't format time");
			continue;
		}

		ct_fb_print_entry(buf, key, 2);
		printf("\n");
	}
	if (!RB_EMPTY(&parent->cfb_children))
		printf("Children:\n");
	RB_FOREACH(entry, ct_fb_entries, &parent->cfb_children) {
		if (prefix) {
			sz = snprintf(buf, sizeof(buf), "%s/", prefix);
			if (sz == -1 || sz >= sizeof(buf)) {
				CWARNX("string too long");
				continue;
			}
			if ((sz = strlcat(buf, entry->cfb_name,
			    sizeof(buf))) >= sizeof(buf)) {
				CWARNX("string too long");
				continue;
			}
		} else {
			strlcpy(buf, entry->cfb_name, sizeof(buf));
		}
		/* if an entry exists it should have at least 1 key */
		ct_fb_print_entry(buf,
		    TAILQ_LAST(&entry->cfb_versions, ct_fb_vers), 2);
		printf("\n");
	}
}

/*
 * Cli command implementations:
 */
void
ctfb_cd(int argc, const char **argv)
{
	if (argc > 2)
		CWARNX("%s: /path/to/directory", argv[0]);

	CDBG("%s: %s", __func__, argv[1]);
	if (ctfb_chdir(ctfb_cfs, argv[1]) != 0)
		CWARN("%s: %s", argv[0], argv[1]);
}

void
ctfb_get(int argc, const char **argv)
{
	struct ct_fb_entry		*entry;
	struct ct_fb_key		*key;
	struct ct_fb_file		*file;
	struct ct_file_extract_priv	*ex_priv;
	struct ct_op			*op;
	char				*dest, *name;
	struct stat			 sb;
	glob_t				 g;
	int		 		 ret, i, count = 0, isdir = 0;

	if (argc == 1 || argc > 3) {
		CWARNX("%s: src [dest]", argv[0]);
		return;
	}

	memset(&g, 0, sizeof(g));
	if (glob_mdfile(argv[1], GLOB_MARK, NULL, &g, 1)) {
		CWARNX("%s not found", argv[1]);
		goto out;
	}

	ct_init_eventloop();

	if (stat(argv[2], &sb) == 0 && (S_ISDIR(sb.st_mode)))
		isdir = 1;

	if (g.gl_matchc > 1 && argc == 3 && isdir == 0) {
		CWARNX("destination must be a directory for multiple "
		    "source paths");
		goto out;
	}

	for (i = 0; g.gl_pathv[i]; i++) {
		if (ctfb_get_version(ctfb_cfs, g.gl_pathv[i], 0,
		    &entry, &key) != 0) {
			CWARN("%s: %s", argv[0], g.gl_pathv[i]);
			continue;
		}

		if (!C_ISREG(key->cfb_type)) {
			CWARNX("version %s is not a file", g.gl_pathv[i]);
			continue;
		}
			
		file = (struct ct_fb_file *)key;
		ex_priv = e_calloc(1, sizeof(*ex_priv));
		ex_priv->md_filename = e_strdup(file->cfb_file->cff_path);
		ex_priv->md_offset = file->cfb_sha_offs;
		/* not a directory so shouldn't have a / at the end */
		if ((name = strrchr(g.gl_pathv[i], '/')) != NULL) {
			name++;
		} else {
			name = entry->cfb_name;
		}
		if (argc == 3) {
			if (isdir) {
				e_asprintf(&dest, "%s/%s", argv[2], name);
			} else {
				dest = e_strdup(argv[2]);
			}
		} else {
			dest = e_strdup(name); /* XXX version? */
		}
		CWARNX("getting %s to %s", g.gl_pathv[i], dest);
		op = ct_add_operation(ct_extract_file, ct_free_mdname, dest,
		    NULL, NULL, NULL, NULL, 0, 0);
		op->op_priv = ex_priv;
		count++;
	}

	if (count > 0) {
		ct_wakeup_file();
		if ((ret = ct_event_dispatch()) != 0) {
			CWARNX("event loop returned error %d, exiting", ret);
			goto out;
		}
	}
	ct_cleanup_eventloop();
	e_free(&ex_priv->md_filename);
	e_free(&ex_priv);

out:
	globfree(&g);
}

void
ctfb_ls(int argc, const char **argv)
{
	struct ct_fb_entry	*entry;
	char			*slash, *prefix;
	glob_t			 g;
	int			 i, j;

	CDBG("%s", __func__);


	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			memset(&g, 0, sizeof(g));

			if (glob_mdfile(argv[i],
			    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE, NULL, &g, 0) ||
			    (g.gl_pathc  && !g.gl_matchc)) {
				globfree(&g);
				CWARNX("can't ls: \"%s\"", argv[i]);
				continue;
			}
			for (j = 0; g.gl_pathv[j]; j++) {
				prefix = NULL;
				if ((entry = ctfb_follow_path(ctfb_cfs,
				    g.gl_pathv[j], NULL)) == NULL) {
					CWARN("%s: %s", argv[0], argv[i]);
					continue;
				}
				if ((slash = strrchr(g.gl_pathv[j], '/'))) {
					*slash = '\0';
					prefix = g.gl_pathv[j];
				}
				/* XXX prefix with path names */
				ctfb_print_node(entry, prefix);
			}
			globfree(&g);
		}
	} else {
		ctfb_print_node(ctfb_cfs->cfs_cwd, NULL);
	}
}

void
ctfb_pwd(int argc, const char **argv)
{
	CDBG("%s", __func__);
	if (ctfb_cfs->cfs_curpath[0] == '\0')
		printf("/\n");	/* XXX directory separator */
	else
		printf("%s\n", ctfb_cfs->cfs_curpath);
}

void
ctfb_lcd(int argc, const char **argv)
{
	if (argc != 2) {
		CWARNX("%s: path", argv[0]);
		return;
	}
	if (chdir(argv[1]) != 0)
		CWARN("%s", argv[0]);
}

void
ctfb_lpwd(int argc, const char **argv)
{
	char	path[PATH_MAX];

	if (argc != 1) {
		CWARNX("%s", argv[0]);
		return;
	}

	if (getcwd(path, sizeof(path)) == NULL)
		CWARN("%s", argv[0]);
	printf("Local directory: %s\n", path);
}

void
ctfb_lmkdir(int argc, const char **argv)
{
	if (argc != 2) {
		CWARNX("%s: path", argv[0]);
		return;
	}

	if (mkdir(argv[1], 0777) != 0) {
		CWARN("%s: couldn't make local directory \"%s\"",
		    argv[0], argv[1]);
	}
}

void
ctfb_lumask(int argc, const char **argv)
{
	char	*endp;
	long	 no;
	if (argc != 2) {
		CWARNX("%s: mask", argv[0]);
		return;
	}

	no = strtol(argv[1], &endp, 8);
	if (endp == argv[1] || *endp != '\0' ||
	    ((no == LONG_MIN || no == LONG_MAX) && errno == ERANGE) || no < 0) {
		CWARNX("invalid input");
		return;
	}

	umask(no);
	printf("local umask: %03lo\n", no);

}

#define _PATH_LS "ls"
void
ctfb_lls(int argc, const char **argv)
{
	const char	**nargv;
	int		 i;

	/*
	 * marshall arguments into a new array with first arg being !PATH_LS
	 * instead of lls
	 */
	nargv = e_calloc(argc + 1, sizeof(*nargv));
	e_asprintf((char **)&nargv[0], "!%s", _PATH_LS);
	for (i = 1; i < argc; i++)
		nargv[i] = e_strdup(argv[i]);
	nargv[argc] = NULL;

	/* Shell out to ls */
	ctfb_shell(argc, nargv);

	/* cleanup */
	for (i = 0; i < argc; i++)
		e_free(&nargv[i]);
	e_free(&nargv);
}
#undef _PATH_LS

void
ctfb_shell(int argc, const char **argv)
{
	int	 status, offset = 0, noargs = 0, returnbang = 0, i, cnt;
	char	*shell, args[_POSIX_ARG_MAX];
	pid_t	 pid;

	if (argv[0][0] == '!') {
		returnbang = 1;
		argv[0]++;
	}
	if (argv[0][0] == '\0')
		offset = 1;
	if (argc - offset <= 0) {
		noargs = 1;
	} else {
		/* XXX check overflow */
		for (i = offset, cnt = 0; i < argc; i++, cnt++) {
			if (cnt == 0) {
				strlcpy(args, argv[i], sizeof(args));
			} else {
				strlcat(args, " ", sizeof(args));
				strlcat(args, argv[i], sizeof(args));
			}
		}
	}

	if (returnbang)
		argv[0]--;

	if ((shell = getenv("SHELL")) == NULL || *shell == '\0')
		shell = _PATH_BSHELL;

	if ((pid = fork()) == -1)
		CFATAL("Can't fork");

	if (pid == 0) {
		if (noargs) {
			execl(shell, shell, (char *)NULL);
		} else {
			execl(shell, shell, "-c", args, (char *)NULL);
		}
		_exit(1);
	}
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			CFATAL("failed to wait for child");
	if (!WIFEXITED(status))
		CWARNX("Shell exited abnormally");
	else if (WEXITSTATUS(status))
		CWARNX("Shell exited with status %d", WEXITSTATUS(status));

}

/*
 * main() and assitance functions for the cyphertitefb filebrowser.
 */
struct ctfb_cmd {
	char		*name;
	ctfb_cmd	*cmd;
	/*
	 * for completion:
	 *	r: file in md
	 *	l: local fs
	 *	v: version in md (includes files too)
	 * Uppercase means multiple.
	 */
	char		*args;
} cmds[] = {
	{ "cd", ctfb_cd, "r" },
	{ "get", ctfb_get, "vl" },
	{ "ls", ctfb_ls, "R" },
	{ "pwd", ctfb_pwd, "" },
	{ "lcd", ctfb_lcd, "l" },
	{ "lpwd", ctfb_lpwd, "" },
	{ "lmkdir", ctfb_lmkdir, "l" },
	{ "lumask", ctfb_lumask, "" },
	{ "lls", ctfb_lls, "L" },
	{ "!", ctfb_shell, "" },
};

struct ctfb_cmd *
ctfb_find_cmd(struct ctfb_cmd *cmdlist, size_t ncmds, const char *search)
{
	struct ctfb_cmd	*found = NULL;
	int		 i;

	for (i = 0; i < ncmds; i++) {
		if (!strncmp(cmdlist[i].name, search,
		     strlen(cmdlist[i].name))) {
			if (found)
				return (NULL); /* disallow ambiguities */
			found = &cmdlist[i];
		}
	}

	return (found);
}

char *
prompt(EditLine *unused)
{
	return ("ct_fb> ");
}

__dead void
ctfb_usage(void)
{
	fprintf(stderr, "%s [-d][-F configfile] -f mdfile\n",
	    __progname);
	exit(1);
}

int
ctfb_main(int argc, char *argv[])
{
	struct ct_fb_state	 cfs;
	struct ctfb_cmd		*cmd;
	const char		**l_argv;
	const char		*buf;
	char			*ct_mfile = NULL;
	EditLine		*el = NULL;
	History			*hist;
	HistEvent		 hev;
	Tokenizer		*tokenizer;
	int		 	 c, cnt, l_argc, ret;

	bzero(&cfs, sizeof(cfs));
	while ((c = getopt(argc, argv, "dF:f:")) != -1) {
		switch (c) {
		case 'd':
			ct_debug = 1;
			cflags |= CLOG_F_DBGENABLE | CLOG_F_FILE | CLOG_F_FUNC |
			    CLOG_F_LINE | CLOG_F_DTIME;
			exude_enable();
			break;
		case 'F':
			ct_configfile = e_strdup(optarg);
			break;
		case 'f': /* metadata file */
			ct_mfile = optarg;
			break;
		default:
			CWARNX("must specify action");
			ctfb_usage();
			/* NOTREACHED */
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (ct_mfile == NULL)
		CFATALX("no file specified");

	/* please don't delete this line AGAIN! --mp */
	if (clog_set_flags(cflags))
		errx(1, "illegal clog flags");

	/* load config */
	if (ct_load_config(settings))
		CFATALX("config file not found.  Use the -F option to "
		    "specify its path.");

	/* We may have to download files later, always set up */
	ct_init(1, 1, 0);

	/* if we're in remote mode, try and grab the appropriate files */
	if (ct_md_mode == CT_MDMODE_REMOTE) {
		/* XXX how to get the name out of the event loop? */
		ct_add_operation(ct_find_md_for_extract,
		    ct_find_md_for_extract_complete, ct_mfile,
		    NULL, argv, NULL, NULL, 0, CT_A_JUSTDL);
		ct_wakeup_file();
		if ((ret = ct_event_dispatch()) != 0) {
			CWARNX("event loop returned error %d, exiting", ret);
			return (ret);

		}
		ct_cleanup_eventloop();
	} else {
		ct_fb_filename = e_strdup(ct_mfile);
	}
	/* now have name of the file we actually want to open... */
	ct_build_tree(ct_fb_filename, &cfs.cfs_tree);
	ctfb_cfs = &cfs;
	ctfb_cfs->cfs_cwd = &ctfb_cfs->cfs_tree;
	ctfb_cfs->cfs_curpath[0] = '\0';

	if ((el = el_init(__progname, stdin, stdout, stderr)) == NULL)
		CFATALX("can't init libedit");
	hist = history_init();
	history(hist, &hev, H_SETSIZE, 100);
	el_set(el, EL_ADDFN, "ctfb-complete", "tab completion for filebrowser",
	    complete);
	el_set(el, EL_BIND, "^I", "ctfb-complete", NULL);
	el_set(el, EL_HIST, history, hist);
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_SIGNAL, 1);
	tokenizer = tok_init(NULL);

	for (;;) {
		if ((buf = el_gets(el, &cnt)) == NULL || cnt == 0)
			break;
		/* XXX deal with positive returns lines (continuations) */
		history(hist, &hev, H_ENTER, buf);
		if (tok_line(tokenizer, el_line(el), &l_argc, &l_argv,
		    NULL, NULL) != 0 || l_argc == 0) {
			tok_reset(tokenizer);
			continue;
		}

		if ((cmd = ctfb_find_cmd(cmds, nitems(cmds), l_argv[0]))) {
			cmd->cmd(l_argc, l_argv);
		} else {
			CWARNX("command not recognized");
		}

		tok_reset(tokenizer);
	}

	e_free(&ct_fb_filename);
	tok_end(tokenizer);
	history_end(hist);
	el_end(el);

	return (0);
}

/*
 * Code for tab completion. 
 * All either original or adapted from sftp under the following license:
 *
 * Copyright (c) 2001-2004 Damien Miller <djm@openbsd.org>
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
 *
 * Additionally some ideas (but not code) from ftp(1) on OpenBSD.
 */
unsigned char
complete(EditLine *el, int cb)
{
	struct ctfb_cmd	*cmd;
	Tokenizer	*tok;
	const LineInfo	*li;
	const char	**argv;
	char		 *line = NULL;
	size_t		 argslen;
	u_int		 len;
	int		 argc, cursorc, cursoro, ret = CC_ERROR;


	tok = tok_init(NULL);

	li = el_line(el);

	len = li->cursor - li->buffer;
	line = e_malloc(len + 1);
	bcopy(li->buffer,  line, len);
	line[len] = '\0';
	
	/*
	 * XXX the problem with using tok_ here is that we don't get a proper
	 * return if we have a " or a ' unterminated in the line. This should
	 * be fixed so that tab completion can work correctly in these cases.
	 * Note: we can't do bad things and look at tok internal state because
	 * the struct definition is hidden from us.
	 */
	if (tok_line(tok, li, &argc, &argv, &cursorc, &cursoro) != 0)
		goto out;

	/* check cursor is at EOL or an argument boundary */
	if (argc != 0 && !(argv[cursorc] == NULL ||
	    argv[cursorc][cursoro] == '\0' || argv[cursorc][cursoro] == ' '))
		goto out;

	/* If we have no command yet, show all commands */
	if (argc == 0) {
		complete_cmd_parse(el, NULL, li->cursor == li->lastchar,
		    '\0', 1);
		ret = CC_REDISPLAY;
		goto out;
	} else if (cursorc == 0) {
		if (complete_cmd_parse(el, argv[0], li->cursor == li->lastchar,
		    '\0' /* XXX */, 1) != 0)
			ret = CC_REDISPLAY;
		goto out;
	}

	/* else look up command and what it expects. */
	if ((cmd = ctfb_find_cmd(cmds, nitems(cmds), argv[0])) == NULL)
		goto out;

	argslen = strlen(cmd->args);
	if (cursorc > argslen && argslen > 0 &&
	    isupper(cmd->args[argslen - 1]))
		cursorc = argslen;

	if (cursorc > argslen)
		goto out;

	switch(tolower(cmd->args[cursorc - 1])) {
	case 'l':
		ret = complete_file(el, argv[cursorc],
		    li->cursor == li->lastchar, '\0' /* XXX */, 1 /* XXX */,
		    0, 0);
		break;
	case 'r':
		ret = complete_file(el, argv[cursorc],
		    li->cursor == li->lastchar, '\0' /* XXX */, 1 /* XXX */,
		    1, 0);
		break;
	case 'v':
		ret = complete_file(el, argv[cursorc],
		    li->cursor == li->lastchar, '\0' /* XXX */, 1 /* XXX */,
		    1, 1);
		break;
	}
out:
	if (line)
		e_free(&line);
	tok_end(tok);
	return (ret);
}

unsigned char
complete_file(EditLine *el, const char *file, int lastarg, char quote,
    int terminated, int mdfile, int versions)
{
	glob_t g;
	char *tmp, *tmp2, ins[3];
	u_int i, hadglob, pwdlen, len, tmplen, filelen;
	const LineInfo *lf;
	
	/* Glob from "file" location */
	if (file == NULL)
		tmp = e_strdup("*");
	else
		e_asprintf(&tmp, "%s*", file);

	memset(&g, 0, sizeof(g));
	if (mdfile) {
		glob_mdfile(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g, versions);
	} else {
		glob(tmp, GLOB_DOOFFS|GLOB_MARK, NULL, &g);
	}
	
	/* Determine length of pwd so we can trim completion display */
	for (hadglob = tmplen = pwdlen = 0; tmp[tmplen] != 0; tmplen++) {
		/* Terminate counting on first unescaped glob metacharacter */
		if (tmp[tmplen] == '*' || tmp[tmplen] == '?') {
			if (tmp[tmplen] != '*' || tmp[tmplen + 1] != '\0')
				hadglob = 1;
			break;
		}
		if (tmp[tmplen] == '\\' && tmp[tmplen + 1] != '\0')
			tmplen++;
		if (tmp[tmplen] == '/')
			pwdlen = tmplen + 1;	/* track last seen '/' */
	}
	e_free(&tmp);

	if (g.gl_matchc == 0) 
		goto out;

	if (g.gl_matchc > 1)
		complete_display(g.gl_pathv, pwdlen);

	tmp = NULL;
	/* Don't try to extend globs */
	if (hadglob)
		goto out;

	if (file == NULL)
		file = "";
	tmp = complete_ambiguous(file, g.gl_pathv, g.gl_matchc);

	if (tmp == NULL)
		goto out;

	tmplen = strlen(tmp);
	filelen = strlen(file);

	if (tmplen > filelen)  {
		tmp2 = tmp + filelen;
		len = strlen(tmp2); 
		/* quote argument on way out */
		for (i = 0; i < len; i++) {
			ins[0] = '\\';
			ins[1] = tmp2[i];
			ins[2] = '\0';
			switch (tmp2[i]) {
			case '\'':
			case '"':
			case '\\':
			case '\t':
			case '[':
			case ' ':
				if (quote == '\0' || tmp2[i] == quote) {
					if (el_insertstr(el, ins) == -1)
						CFATALX("el_insertstr "
						    "failed.");
					break;
				}
				/* FALLTHROUGH */
			default:
				if (el_insertstr(el, ins + 1) == -1)
					CFATALX("el_insertstr failed.");
				break;
			}
		}
	}

	lf = el_line(el);
	if (g.gl_matchc == 1) {
		i = 0;
		if (!terminated)
			ins[i++] = quote;
		if (*(lf->cursor - 1) != '/' &&
		    (lastarg || *(lf->cursor) != ' '))
			ins[i++] = ' ';
		ins[i] = '\0';
		if (i > 0 && el_insertstr(el, ins) == -1)
			CFATALX("el_insertstr failed.");
	}
	e_free(&tmp);

 out:
	globfree(&g);
	return g.gl_matchc > 0 ? CC_REDISPLAY : CC_ERROR;
}

/* Display entries in 'list' after skipping the first 'len' chars */
static void
complete_display(char **list, u_int len)
{
	u_int y, m = 0, width = 80, columns = 1, colspace = 0, llen;
	struct winsize ws;
	char *tmp;

	/* Count entries for sort and find longest */
	for (y = 0; list[y]; y++) 
		m = MAX(m, strlen(list[y]));

	if (ioctl(fileno(stdin), TIOCGWINSZ, &ws) != -1)
		width = ws.ws_col;

	m = m > len ? m - len : 0;
	columns = width / (m + 2);
	columns = MAX(columns, 1);
	colspace = width / columns;
	colspace = MIN(colspace, width);

	printf("\n");
	m = 1;
	for (y = 0; list[y]; y++) {
		llen = strlen(list[y]);
		tmp = llen > len ? list[y] + len : "";
		printf("%-*s", colspace, tmp);
		if (m >= columns) {
			printf("\n");
			m = 1;
		} else
			m++;
	}
	printf("\n");
}

/*
 * Given a "list" of words that begin with a common prefix of "word",
 * attempt to find an autocompletion to extends "word" by the next
 * characters common to all entries in "list".
 */
static char *
complete_ambiguous(const char *word, char **list, size_t count)
{
	if (word == NULL)
		return NULL;

	if (count > 0) {
		u_int y, matchlen = strlen(list[0]);

		/* Find length of common stem */
		for (y = 1; list[y]; y++) {
			u_int x;

			for (x = 0; x < matchlen; x++) 
				if (list[0][x] != list[y][x]) 
					break;

			matchlen = x;
		}

		if (matchlen > strlen(word)) {
			char *tmp = e_strdup(list[0]);

			tmp[matchlen] = '\0';
			return tmp;
		}
	} 

	return e_strdup(word);
}

/* Autocomplete a sftp command */
static int
complete_cmd_parse(EditLine *el, const char *cmd, int lastarg, char quote,
    int terminated)
{
	u_int y, count = 0, cmdlen, tmplen;
	char *tmp, **list, argterm[3];
	const LineInfo *lf;

	list = e_calloc(nitems(cmds) + 1, sizeof(char *));

	/* No command specified: display all available commands */
	if (cmd == NULL) {
		for (y = 0; y < nitems(cmds); y++)
			list[count++] = e_strdup(cmds[y].name);
		
		list[count] = NULL;
		complete_display(list, 0);

		for (y = 0; list[y] != NULL; y++)  
			e_free(&list[y]);	
		e_free(&list);
		return count;
	}

	/* Prepare subset of commands that start with "cmd" */
	cmdlen = strlen(cmd);
	for (y = 0; y < nitems(cmds); y++)  {
		if (!strncasecmp(cmd, cmds[y].name, cmdlen)) 
			list[count++] = e_strdup(cmds[y].name);
	}
	list[count] = NULL;

	if (count == 0) {
		e_free(&list);
		return 0;
	}

	/* Complete ambigious command */
	tmp = complete_ambiguous(cmd, list, count);
	if (count > 1)
		complete_display(list, 0);

	for (y = 0; list[y]; y++)  
		e_free(&list[y]);	
	e_free(&list);

	if (tmp != NULL) {
		tmplen = strlen(tmp);
		cmdlen = strlen(cmd);
		/* If cmd may be extended then do so */
		if (tmplen > cmdlen)
			if (el_insertstr(el, tmp + cmdlen) == -1)
				CFATALX("el_insertstr failed.");
		lf = el_line(el);
		/* Terminate argument cleanly */
		if (count == 1) {
			y = 0;
			if (!terminated)
				argterm[y++] = quote;
			if (lastarg || *(lf->cursor) != ' ')
				argterm[y++] = ' ';
			argterm[y] = '\0';
			if (y > 0 && el_insertstr(el, argterm) == -1)
				CFATALX("el_insertstr failed.");
		}
		e_free(&tmp);
	}

	return count;
}

/*
 * Directory manipulation functions to be used with GLOB_ALTDIRFUNC.
 */
struct ctfb_opendir {
	struct ct_fb_entry	*cwd;
	struct ct_fb_key	*nextkey;
	struct ct_fb_entry	*curentry; /* valid only if nextkey != NULL */
	struct ct_fb_entry	*nextentry;
};

/*
 * Open a directory in the md file for reading.
 */
void *
ctfb_opendir(const char *path)
{
	struct ctfb_opendir		*dir;
	struct ct_fb_entry		*entry;

	CDBG("%s: %s", __func__, path);
	
	if ((entry = ctfb_follow_path(ctfb_cfs, path, NULL)) == NULL) {
		CWARNX("%s: %s not found", __func__, path);
		return (NULL);
	}

	dir = e_calloc(1, sizeof(*dir));
	dir->cwd = entry;
	dir->nextentry = RB_MIN(ct_fb_entries, &entry->cfb_children);

	return (dir);
}

/*
 * Get next entry in the directory taking ignoring versions.
 */
struct dirent *
ctfb_readdir(void *arg)
{
	struct ctfb_opendir	*ctx = arg;
	struct ct_fb_entry	*entry;
	static struct dirent	ret;

	if (ctx->nextkey == NULL && ctx->nextentry == NULL) {
		CDBG("%s: no more entries", __func__);
		return (NULL);
	}

	entry = ctx->nextentry;
	
	CDBG("%s: %s", __func__, entry->cfb_name);
	/*
	 * OpenBSD doesn't have d_ino, but does have d_type. posix only
	 * promises dirent has d_name and d_ino so just fill in d_name.
	 */
	strlcpy(ret.d_name, entry->cfb_name, sizeof(ret.d_name));
	ctx->nextentry = RB_NEXT(ct_fb_entries, &ctx->cwd, entry);
	return (&ret);
}

/*
 * Get next entry in the directory taking versions into account.
 */
struct dirent *
ctfb_readdir_versions(void *arg)
{
	struct ctfb_opendir	*ctx = arg;
	struct ct_fb_key	*key;
	struct ct_fb_entry	*entry;
	static struct dirent	 ret;
	time_t			 mtime;
	size_t			 sz;
	char			 buf[PATH_MAX];

	if (ctx->nextkey == NULL && ctx->nextentry == NULL) {
		CDBG("%s: no more entries", __func__);
		return (NULL);
	}

	if (ctx->nextkey != NULL) {
		key = ctx->nextkey;
		entry = ctx->curentry;
		ctx->nextkey = TAILQ_NEXT(key, cfb_link);

		if ((sz = strlcpy(buf, entry->cfb_name, sizeof(buf))) >=
		    sizeof(buf)) {
			CWARNX("name too long: %s", entry->cfb_name);
			return (NULL); /* Should never happen */
		}
		mtime = (time_t)key->cfb_mtime;

		if (strftime(buf + sz , sizeof(buf) - sz, ".%Y%m%d%H%M%S",
		    localtime(&mtime)) == 0) {
			CWARNX("can't format time %lld", (long long)mtime);
			return (NULL);
		}
		CDBG("%s: %s", __func__, buf);
		strlcpy(ret.d_name, buf, sizeof(ret.d_name));
		return (&ret);
	}
	entry = ctx->nextentry;

	CDBG("%s: %s", __func__, entry->cfb_name);

	/* set up for next version to be read */
	ctx->nextkey = TAILQ_FIRST(&entry->cfb_versions);
	ctx->curentry = entry;
	ctx->nextentry = RB_NEXT(ct_fb_entries, &ctx->cwd, entry);
	
	/* d_ino shouldn't matter here */
	strlcpy(ret.d_name, entry->cfb_name, sizeof(ret.d_name));
	return (&ret);
}

/*
 * Cleanup after previous opendir.
 */
void
ctfb_closerdir(void *arg)
{
	struct ctfb_opendir	*ctx = arg;

	e_free(&ctx);
}

/*
 * lstat a path in a md file.
 * XXX should have stat that follows symlinks but that is fiddly.
 */
int
ctfb_lstat(const char *path, struct stat *sb)
{
	struct ct_fb_entry		*entry;
	struct ct_fb_key		*key;
	struct ct_fb_spec		*spec;
	int				 ret = -1;

	CDBG("%s %s", __func__, path);

	/* ctfb_get_version sets errno */
	if (ctfb_get_version(ctfb_cfs, path, 1, &entry, &key) != 0)
		return (-1);

	/*
	 * fields ignored for now:
	 * st_dev, st_ino, st_nlink, st_blksize, st_blocks
	 */
	sb->st_dev = 0;
	sb->st_ino = 0;
	sb->st_nlink = 1;
	sb->st_blksize = 0;
	sb->st_blocks = 0;

	sb->st_mode = key->cfb_type | key->cfb_mode; /* XXX is this correct? */
	sb->st_uid = key->cfb_uid;
	sb->st_gid = key->cfb_gid;
	sb->st_mtime = key->cfb_mtime;
	sb->st_ctime = key->cfb_mtime;
	sb->st_atime = key->cfb_atime;
	if (C_ISCHR(key->cfb_type) || C_ISBLK(key->cfb_type)) {
		spec = (struct ct_fb_spec *)key;
		sb->st_rdev = spec->cfb_rdev;
	} else {
		sb->st_rdev = 0;
	}
	ret = 0;

	return (ret);
}

/*
 * Glob paths within a md file.
 *
 * If versions is non zero then we will also provide versions in the list of
 * paths, else just pathnames will be provided.
 * Other parameters are equal to glob(3).
 */
int
glob_mdfile(const char *pattern, int flags, int (*errfunc)(const char *, int),
    glob_t *pglob, int versions)
{
	pglob->gl_opendir = ctfb_opendir;
	if (versions)
		pglob->gl_readdir = ctfb_readdir_versions;
	else
		pglob->gl_readdir = ctfb_readdir;
	pglob->gl_closedir = ctfb_closerdir;
	pglob->gl_lstat = ctfb_lstat;
	pglob->gl_stat = ctfb_lstat;

	return (glob(pattern, flags | GLOB_ALTDIRFUNC, errfunc, pglob));
}
