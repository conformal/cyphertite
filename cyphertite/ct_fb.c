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

#include <clog.h>
#include <exude.h>

#include "ct.h"
#include "ct_fb.h"

int ctfb_quit = 0;

/* Subclass of dnode for faster lookup. */
struct ct_fb_dnode {
	struct dnode		 dnode;
	struct ct_fb_entry	*dir;
};

struct ct_global_state	*ctfb_state;
struct ct_fb_state	*ctfb_cfs;

__dead void		 ctfb_usage(void);
struct ct_fb_entry	*ct_add_tree(struct ct_fb_entry *,
			     struct ctfile_parse_state *, struct ct_fb_ctfile *,
			     off_t, int);
struct ct_fb_entry	*ctfb_follow_path(struct ct_fb_state *, const char *,
			     char *, size_t);
int			 glob_ctfile(const char *, int,
			     int (*)(const char *, int), glob_t *, int);

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
 * the ctfile.
 */
struct ct_fb_entry *
ct_add_tree(struct ct_fb_entry *head, struct ctfile_parse_state *xdr_ctx,
    struct ct_fb_ctfile *ctfile, off_t fileoffset, int allfiles)
{
	struct ctfile_header		*hdr = &xdr_ctx->xs_hdr;
	struct ctfile_header		*hdrlnk= &xdr_ctx->xs_lnkhdr;
	struct dnode 			*dnode;
	struct ct_fb_dnode		*fb_dnode;
	struct ct_fb_entry		*parent = NULL, sentry, *entry;
	struct ct_fb_key		*lastkey, *key;
	struct ct_fb_file		*file;
	struct ct_fb_spec		*spec;
	struct ct_fb_link		*linkkey;
	size_t				 sz;

	/* First find parent directory if any */
	if (hdr->cmh_parent_dir != -1 && hdr->cmh_parent_dir != -2) {
		if ((dnode = ctfile_parse_finddir(xdr_ctx,
		    hdr->cmh_parent_dir)) == NULL)
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
	CNDBG(CT_LOG_VERTREE, "filename = %s", hdr->cmh_filename);
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
	if (allfiles) {
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
		CNDBG(CT_LOG_VERTREE, "found existing key");
	} else { /* something changed. make a new one */
		CNDBG(CT_LOG_VERTREE, "making new key");
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
		if (allfiles) {
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
		fb_dnode->dir = entry;
		CNDBG(CT_LOG_VERTREE, "inserting %s as %" PRId64,
		    fb_dnode->dnode.d_name, fb_dnode->dnode.d_num );
		if ((dnode = ctfile_parse_insertdir(xdr_ctx,
		    &fb_dnode->dnode)) != NULL)
			CFATALX("duplicate dentry");
	} else if (C_ISREG(hdr->cmh_type)) {
		/*
		 * Allfiles ctfiles may have shas == -1, so in some cases we
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
			file->cfb_file = ctfile;
			if (ctfile_parse_seek(xdr_ctx))
				CFATALX("failed to skip shas in %s",
				    ctfile->cff_path);
		}
		if (ctfile_parse(xdr_ctx) != XS_RET_FILE_END)
			CFATALX("no file trailer found");
		file->cfb_file_size = xdr_ctx->xs_trl.cmt_orig_size;
	}

	return (entry);
}

/*
 * Build version tree on ``head'' from ``filename'' (and dependant files).
 */
void
ct_build_tree(const char *filename, struct ct_fb_entry *head,
    const char *ctfile_basedir)
{
	struct ct_extract_head		 extract_head;
	struct ctfile_parse_state	 xdr_ctx;
	struct ct_fb_ctfile		*ctfile = NULL;
	struct ct_fb_dir		*root_dir;
	struct ct_fb_key		*root_version;
	off_t				 offset;
	int				 ret;
	int				 allfiles;

	CNDBG(CT_LOG_FILE, "entry");

	TAILQ_INIT(&extract_head);
	ct_extract_setup(&extract_head, &xdr_ctx, filename, ctfile_basedir,
	    &allfiles, 0);

	TAILQ_INIT(&head->cfb_versions);
	RB_INIT(&head->cfb_children);
	head->cfb_name = "/";

nextfile:
	root_dir = e_calloc(1, sizeof(*root_dir));
	root_version = &root_dir->cfb_base;
	root_version->cfb_type = C_TY_DIR;
	root_version->cfb_uid = 0;
	root_version->cfb_gid = 0;
	root_version->cfb_mode = 0777;
	root_version->cfb_atime = xdr_ctx.xs_gh.cmg_created;
	root_version->cfb_mtime = xdr_ctx.xs_gh.cmg_created;
	TAILQ_INSERT_HEAD(&head->cfb_versions, root_version, cfb_link);

	/* XXX keep these in a list? Right now they leak */
	ctfile = calloc(1, sizeof(*ctfile));
	strlcpy(ctfile->cff_path, xdr_ctx.xs_filename,
	    sizeof(ctfile->cff_path));
	offset = ctfile_parse_tell(&xdr_ctx);

	while ((ret = ctfile_parse(&xdr_ctx)) != XS_RET_EOF &&
	    ret != XS_RET_FAIL) {
		switch(ret) {
		case XS_RET_FILE:
			(void)ct_add_tree(head, &xdr_ctx,
			    ctfile, offset, allfiles);
			break;
		case XS_RET_FILE_END:
			break;
		default:
			CFATALX("invalid state in %s: %d", __func__, ret);
		}
		offset = ctfile_parse_tell(&xdr_ctx);
	}
	if (ret == XS_RET_EOF) {
		CNDBG(CT_LOG_FILE, "done, closing file");
		ctfile_parse_close(&xdr_ctx);
		if (!TAILQ_EMPTY(&extract_head)) {
			CNDBG(CT_LOG_FILE, "opening next one");
			ct_extract_open_next(&extract_head, &xdr_ctx, 0);
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
    char *newcwd, size_t newcwdsz)
{
	struct ct_fb_entry	*cwd;
	char			*next, *cur, cwdbuf[PATH_MAX], pbuf[PATH_MAX];
	int			 absolute = 0, home = 0;

	if (path == NULL || path[0] == '\0') {
		CNDBG(CT_LOG_VERTREE, "should go back to /");
		home = 1;
	} else if (ct_absolute_path(path)) {
		CNDBG(CT_LOG_VERTREE, "absolute path %s", path);
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
		CNDBG(CT_LOG_VERTREE, "next segment = %s", cur);

		if (*cur == '\0')
			continue;
		else if (strcmp(cur, "..") == 0) {
			char		*end;

			CNDBG(CT_LOG_VERTREE, "goback");
			/* ignore .. from root */
			if (cwd->cfb_parent == NULL) {
				CNDBG(CT_LOG_VERTREE, "at root");
				continue;
			}
			cwd = cwd->cfb_parent;

			if (newcwd == NULL)
				continue;

			/* update our buffer */
			if ((end = strrchr(cwdbuf, '/')) == NULL)
				end = cwdbuf; /* first directory */
			*(end) = '\0'; /* Amend curpath */
		} else if (strcmp(cur, ".") == 0) {
			CNDBG(CT_LOG_VERTREE, ".: doing nothing");
		} else {
			struct ct_fb_entry	sentry;
			CNDBG(CT_LOG_VERTREE, "next dir = %s", cur);

			sentry.cfb_name = cur;
			if ((cwd = RB_FIND(ct_fb_entries, &cwd->cfb_children,
			    &sentry)) == NULL) {
				CNDBG(CT_LOG_VERTREE,
				    "can't find directory %s", cur);
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
		strlcpy(newcwd, cwdbuf, newcwdsz);

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
		CNDBG(CT_LOG_VERTREE, "can't find version postfix");
		noversion = 1;
		goto search;
	}

	/* parse file name. path/name.date */
	if (strptime(postfix, ".%Y%m%d%H%M%S", &tm) == NULL) {
		CNDBG(CT_LOG_VERTREE, "can't parse version from filename %s",
		    path);
		noversion = 1;
		goto search;
	}
	tm.tm_isdst = -1;
	mtime = mktime(&tm);
	CNDBG(CT_LOG_VERTREE, "mtime = %" PRIi64, (int64_t)mtime);


	*postfix = '\0'; /* trim off version now we have it parsed out */

search:
	if ((entry = ctfb_follow_path(state, path, NULL, 0)) == NULL) {
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
	    state->cfs_curpath, sizeof(state->cfs_curpath))) == NULL)
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

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, argv[1]);
	if (ctfb_chdir(ctfb_cfs, argv[1]) != 0)
		CWARN("%s: %s", argv[0], argv[1]);
}

void
ctfb_get(int argc, const char **argv)
{
	struct ct_fb_entry		*entry;
	struct ct_fb_key		*key;
	struct ct_fb_file		*file;
	struct ct_extract_file_args	*cefa;
	char				*dest, *name;
	struct stat			 sb;
	glob_t				 g;
	int		 		 ret, i, count = 0, isdir = 0;

	if (argc == 1 || argc > 3) {
		CWARNX("%s: src [dest]", argv[0]);
		return;
	}

	memset(&g, 0, sizeof(g));
	if (glob_ctfile(argv[1], GLOB_MARK, NULL, &g, 1)) {
		CWARNX("%s not found", argv[1]);
		goto out;
	}

	ct_init_eventloop(ctfb_state);

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
		cefa = e_calloc(1, sizeof(*cefa));
		cefa->cefa_ctfile = e_strdup(file->cfb_file->cff_path);
		cefa->cefa_ctfile_off = file->cfb_sha_offs;
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
		cefa->cefa_filename = dest;
		ct_add_operation(ctfb_state, ct_extract_file,
		    ct_extract_file_cleanup, cefa);
		count++;
	}

	if (count > 0) {
		ct_wakeup_file(ctfb_state->event_state);
		if ((ret = ct_event_dispatch(ctfb_state->event_state)) != 0) {
			CWARNX("event loop returned error %d, exiting", ret);
			goto out;
		}
	}
	ct_cleanup_eventloop(ctfb_state);

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

	CNDBG(CT_LOG_VERTREE, "%s", __func__);


	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			memset(&g, 0, sizeof(g));

			if (glob_ctfile(argv[i],
			    GLOB_MARK|GLOB_NOCHECK|GLOB_BRACE, NULL, &g, 0) ||
			    (g.gl_pathc  && !g.gl_matchc)) {
				globfree(&g);
				CWARNX("can't ls: \"%s\"", argv[i]);
				continue;
			}
			for (j = 0; g.gl_pathv[j]; j++) {
				prefix = NULL;
				if ((entry = ctfb_follow_path(ctfb_cfs,
				    g.gl_pathv[j], NULL, 0)) == NULL) {
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
	CNDBG(CT_LOG_VERTREE, "%s", __func__);
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
	char *path;
	if (argc != 2) {
		CWARNX("%s: path", argv[0]);
		return;
	}

	e_asprintf(&path, "%s/", argv[1]);

	if (ct_make_full_path(path, 0777) != 0) {
		CWARN("%s: couldn't make local directory \"%s\"",
		    argv[0], argv[1]);
	}

	e_free(&path);
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

void
ctfb_exit(int argc, const char **argv)
{
	ctfb_quit = 1;
}

void
ctfb_help(int argc, const char **argv)
{
	printf("Available commands:\n"
	    "cd path				Change working directory to 'path'\n"
	    "exit				Quit the program\n"
	    "get path [localname]		Download file\n"
	    "help				Display this help text\n"
	    "ls [path]			Display directory listing\n"
	    "pwd				Display working directory\n"
	    "lcd path			Change filesystem working directory\n"
	    "lpwd				Display filesystem working directory\n"
	    "lmkdir path			Create filesystem directory\n"
	    "lumask umask			Set local umask to 'umask'\n"
	    "lls				Display filesystem directory listing\n"
	    "quit				Quit the program\n"
	    "!command			Execute 'command' in local shell\n"
	    "!				Escape to local shell\n"
	    "?				Display this help text\n");
}

__dead void
ctfb_usage(void)
{
	fprintf(stderr, "%s [-D debugstring][-F configfile] ctfile\n",
	    __progname);
	exit(1);
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
 * Open a directory in the ctfile file for reading.
 */
void *
ctfb_opendir(const char *path)
{
	struct ctfb_opendir		*dir;
	struct ct_fb_entry		*entry;

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, path);

	if ((entry = ctfb_follow_path(ctfb_cfs, path, NULL, 0)) == NULL) {
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
		CNDBG(CT_LOG_VERTREE, "%s: no more entries", __func__);
		return (NULL);
	}

	entry = ctx->nextentry;

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, entry->cfb_name);
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
		CNDBG(CT_LOG_VERTREE, "%s: no more entries", __func__);
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
			CWARNX("can't format time %" PRId64, (int64_t)mtime);
			return (NULL);
		}
		CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, buf);
		strlcpy(ret.d_name, buf, sizeof(ret.d_name));
		return (&ret);
	}
	entry = ctx->nextentry;

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, entry->cfb_name);

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
 * Glob paths within a ctfile.
 *
 * If versions is non zero then we will also provide versions in the list of
 * paths, else just pathnames will be provided.
 * Other parameters are equal to glob(3).
 */
int
glob_ctfile(const char *pattern, int flags, int (*errfunc)(const char *, int),
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
