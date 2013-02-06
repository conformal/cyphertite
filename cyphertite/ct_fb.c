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
#include <grp.h>

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include <ct_version_tree.h>
#include "ct.h"
#include "ct_fb.h"

int ctfb_quit = 0;

struct ct_global_state	*ctfb_state;
struct ct_fb_state	*ctfb_cfs;

__dead void		 ctfb_usage(void);
struct ct_vertree_entry	*ctfb_follow_path(struct ct_fb_state *, const char *,
			     char *, size_t);
int			 glob_ctfile(const char *, int,
			     int (*)(const char *, int), glob_t *, int);

extern char		*ct_getloginbyuid(uid_t);

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
struct ct_vertree_entry *
ctfb_follow_path(struct ct_fb_state *cfs, const char *path,
    char *newcwd, size_t newcwdsz)
{
	struct ct_vertree_entry	*cwd, *tcwd;
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
		cwd = &cfs->cfs_tree->cvt_head;
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
		struct ct_vertree_entry	sentry;
		cur = next;

		/* XXX directory separator */
		if ((next = strchr(cur, '/')) != NULL)
			*(next++) = '\0';
		if (*cur == '\0')
			continue;

		CNDBG(CT_LOG_VERTREE, "next dir = %s", cur);

		/*
		 * first search for the name in the list.
		 * ctfiles may contain "." and "..", so search those first.
		 * If they dont' exist then treat "." and ".." specially.
		 */
		sentry.cve_name = cur;
		if ((tcwd = RB_FIND(ct_vertree_entries, &cwd->cve_children,
		    &sentry)) == NULL) {
			if (strcmp(cur, ".") == 0) {
				CNDBG(CT_LOG_VERTREE, ".: doing nothing");
				continue;
			} else if (strcmp(cur, "..") == 0) {
				char		*end;

				CNDBG(CT_LOG_VERTREE, "goback");
				/* ignore .. from root */
				if (cwd->cve_parent == NULL) {
					CNDBG(CT_LOG_VERTREE, "at root");
					continue;
				}
				cwd = cwd->cve_parent;

				if (newcwd == NULL)
					continue;

				/* update our buffer */
				if ((end = strrchr(cwdbuf, '/')) == NULL)
					end = cwdbuf; /* first directory */
				*(end) = '\0'; /* Amend curpath */
				continue;
			}
			CNDBG(CT_LOG_VERTREE, "can't find directory %s", cur);
			errno = ENOENT;
			return (NULL);
		}
		cwd = tcwd;
		if (newcwd == NULL)
			continue;

		/* update our buffer */
		if (cwdbuf[0] != '\0')
			strlcat(cwdbuf, "/", sizeof(cwdbuf));
		strlcat(cwdbuf, cur, sizeof(cwdbuf));
	}

	if (newcwd != NULL)
		strlcpy(newcwd, cwdbuf, newcwdsz);

	return (cwd);
}

int
ctfb_get_version(struct ct_fb_state *state, const char *path, int preferdir,
    struct ct_vertree_entry **entryp, struct ct_vertree_ver **keyp)
{
	struct ct_vertree_entry		*entry;
	struct ct_vertree_ver		*key = NULL;
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
			TAILQ_FOREACH_REVERSE(key, &entry->cve_versions,
			    ct_vertree_vers, cvv_link)
				if (C_ISDIR(key->cvv_type))
					break;
		}
		/* no directory? pick the most recent type */
		if (key == NULL)
			key = TAILQ_LAST(&entry->cve_versions, ct_vertree_vers);
	} else {
		TAILQ_FOREACH(key, &entry->cve_versions, cvv_link)
			if (key->cvv_mtime == mtime)
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
	struct ct_vertree_entry *result;

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
ctfb_print_node(struct ct_vertree_entry *parent, char *prefix)
{
	struct ct_vertree_entry	*entry;
	struct ct_vertree_ver	*key;
	size_t			 sz;
	time_t			 mtime;
	char			 buf[PATH_MAX];

	if (!TAILQ_EMPTY(&parent->cve_versions))
		printf("Versions:\n");
	TAILQ_FOREACH(key, &parent->cve_versions, cvv_link) {
		if (prefix) {
			sz = snprintf(buf, sizeof(buf), "%s/", prefix);
			if (sz == -1 || sz >= sizeof(buf)) {
				CWARNX("string too long");
				continue;
			}
		} else {
			buf[0] = '\0';
		}
		if ((sz = strlcat(buf, parent->cve_name, sizeof(buf))) >=
		    sizeof(buf)) {
			CWARNX("string too long");
			continue;
		}
		mtime = (time_t)key->cvv_mtime;

		if (strftime(buf + sz , sizeof(buf) - sz, ".%Y%m%d%H%M%S",
		    localtime(&mtime)) == 0) {
			CWARNX("can't format time");
			continue;
		}

		ct_fb_print_entry(buf, key, 2);
		printf("\n");
	}
	if (!RB_EMPTY(&parent->cve_children))
		printf("Children:\n");
	RB_FOREACH(entry, ct_vertree_entries, &parent->cve_children) {
		if (prefix) {
			sz = snprintf(buf, sizeof(buf), "%s/", prefix);
			if (sz == -1 || sz >= sizeof(buf)) {
				CWARNX("string too long");
				continue;
			}
			if ((sz = strlcat(buf, entry->cve_name,
			    sizeof(buf))) >= sizeof(buf)) {
				CWARNX("string too long");
				continue;
			}
		} else {
			strlcpy(buf, entry->cve_name, sizeof(buf));
		}
		/* if an entry exists it should have at least 1 key */
		ct_fb_print_entry(buf,
		    TAILQ_LAST(&entry->cve_versions, ct_vertree_vers), 2);
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
	struct ct_vertree_entry		*entry;
	struct ct_vertree_ver		*key;
	struct ct_vertree_file		*file;
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

	ct_init_eventloop(ctfb_state, ct_info_sig, CT_NEED_SECRETS);

	if (argc == 3 && stat(argv[2], &sb) == 0 && (S_ISDIR(sb.st_mode)))
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

		if (!C_ISREG(key->cvv_type)) {
			CWARNX("version %s is not a file", g.gl_pathv[i]);
			continue;
		}

		file = (struct ct_vertree_file *)key;
		cefa = e_calloc(1, sizeof(*cefa));
		cefa->cefa_ctfile = e_strdup(file->cvf_file->cvc_path);
		cefa->cefa_ctfile_off = file->cvf_sha_offs;
		/* not a directory so shouldn't have a / at the end */
		if ((name = strrchr(g.gl_pathv[i], '/')) != NULL) {
			name++;
		} else {
			name = entry->cve_name;
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
		if ((ret = ct_run_eventloop(ctfb_state)) != 0) {
			if (ctfb_state->ct_errmsg[0] != '\0')
				CWARNX("%s: %s", ctfb_state->ct_errmsg,
				    ct_strerror(ret));
			else	
				CWARNX("%s", ct_strerror(ret));
		}

	}
	ct_cleanup_eventloop(ctfb_state);

out:
	globfree(&g);
}

void
ctfb_ls(int argc, const char **argv)
{
	struct ct_vertree_entry	*entry;
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
	struct ct_vertree_entry	*cwd;
	struct ct_vertree_ver	*nextkey;
	struct ct_vertree_entry	*curentry; /* valid only if nextkey != NULL */
	struct ct_vertree_entry	*nextentry;
};

/*
 * Open a directory in the ctfile file for reading.
 */
void *
ctfb_opendir(const char *path)
{
	struct ctfb_opendir		*dir;
	struct ct_vertree_entry		*entry;

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, path);

	if ((entry = ctfb_follow_path(ctfb_cfs, path, NULL, 0)) == NULL) {
		CWARNX("%s: %s not found", __func__, path);
		return (NULL);
	}

	dir = e_calloc(1, sizeof(*dir));
	dir->cwd = entry;
	dir->nextentry = RB_MIN(ct_vertree_entries, &entry->cve_children);

	return (dir);
}

/*
 * Get next entry in the directory taking ignoring versions.
 */
struct dirent *
ctfb_readdir(void *arg)
{
	struct ctfb_opendir	*ctx = arg;
	struct ct_vertree_entry	*entry;
	static struct dirent	ret;

	if (ctx->nextkey == NULL && ctx->nextentry == NULL) {
		CNDBG(CT_LOG_VERTREE, "%s: no more entries", __func__);
		return (NULL);
	}

	entry = ctx->nextentry;

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, entry->cve_name);
	/*
	 * OpenBSD doesn't have d_ino, but does have d_type. posix only
	 * promises dirent has d_name and d_ino so just fill in d_name.
	 */
	strlcpy(ret.d_name, entry->cve_name, sizeof(ret.d_name));
	ctx->nextentry = RB_NEXT(ct_vertree_entries, &ctx->cwd, entry);
	return (&ret);
}

/*
 * Get next entry in the directory taking versions into account.
 */
struct dirent *
ctfb_readdir_versions(void *arg)
{
	struct ctfb_opendir	*ctx = arg;
	struct ct_vertree_ver	*key;
	struct ct_vertree_entry	*entry;
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
		ctx->nextkey = TAILQ_NEXT(key, cvv_link);

		if ((sz = strlcpy(buf, entry->cve_name, sizeof(buf))) >=
		    sizeof(buf)) {
			CWARNX("name too long: %s", entry->cve_name);
			return (NULL); /* Should never happen */
		}
		mtime = (time_t)key->cvv_mtime;

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

	CNDBG(CT_LOG_VERTREE, "%s: %s", __func__, entry->cve_name);

	/* set up for next version to be read */
	ctx->nextkey = TAILQ_FIRST(&entry->cve_versions);
	ctx->curentry = entry;
	ctx->nextentry = RB_NEXT(ct_vertree_entries, &ctx->cwd, entry);

	/* d_ino shouldn't matter here */
	strlcpy(ret.d_name, entry->cve_name, sizeof(ret.d_name));
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

/*
 * 99% stolen from ct_pr_fmt_file, should amalgamate
 */
void
ct_fb_print_entry(char *name, struct ct_vertree_ver *key, int verbose)
{
	char *loginname;
	struct group *group;
	char *link_ty;
	char filemode[11];
	char uid[11];
	char gid[11];
	time_t ltime;
	char lctime[26];
	char *pchr;

	if (verbose > 1) {
		switch(key->cvv_type & C_TY_MASK) {
		case C_TY_DIR:
			filemode[0] = 'd'; break;
		case C_TY_CHR:
			filemode[0] = 'c'; break;
		case C_TY_BLK:
			filemode[0] = 'b'; break;
		case C_TY_REG:
			filemode[0] = '-'; break;
		case C_TY_FIFO:
			filemode[0] = 'f'; break;
		case C_TY_LINK:
			filemode[0] = 'l'; break;
		case C_TY_SOCK:
			filemode[0] = 's'; break;
		default:
			filemode[0] = '?';
		}
		filemode[1] = (key->cvv_mode & 0400) ? 'r' : '-';
		filemode[2] = (key->cvv_mode & 0100) ? 'w' : '-';
		filemode[3] = (key->cvv_mode & 0200) ? 'x' : '-';
		filemode[4] = (key->cvv_mode & 0040) ? 'r' : '-';
		filemode[5] = (key->cvv_mode & 0020) ? 'w' : '-';
		filemode[6] = (key->cvv_mode & 0010) ? 'x' : '-';
		filemode[7] = (key->cvv_mode & 0004) ? 'r' : '-';
		filemode[8] = (key->cvv_mode & 0002) ? 'w' : '-';
		filemode[9] = (key->cvv_mode & 0001) ? 'x' : '-';
		filemode[10] = '\0';

		loginname = ct_getloginbyuid(key->cvv_uid);
		if (loginname && (strlen(loginname) < sizeof(uid)))
			snprintf(uid, sizeof(uid), "%10s", loginname);
		else
			snprintf(uid, sizeof(uid), "%-10d", key->cvv_uid);
		group = getgrgid(key->cvv_gid);


		if (group && (strlen(group->gr_name) < sizeof(gid)))
			snprintf(gid, sizeof(gid), "%10s", group->gr_name);
		else
			snprintf(gid, sizeof(gid), "%-10d", key->cvv_gid);
		ltime = key->cvv_mtime;
		ctime_r(&ltime, lctime);
		pchr = strchr(lctime, '\n');
		if (pchr != NULL)
			*pchr = '\0'; /* stupid newline on ctime */

		printf("%s %s %s %s ", filemode, uid, gid, lctime);
	}
	printf("%s", name);

	if (verbose > 1) {

		/* XXX - translate to guid name */
		if (C_ISLINK(key->cvv_type))  {
			struct ct_vertree_link *lnk =
			    (struct ct_vertree_link *)key;

			if (lnk->cvl_hardlink)  {
				link_ty = "==";
			} else {
				link_ty = "->";
			}
			printf(" %s %s", link_ty, lnk->cvl_linkname);
		} else if (C_ISREG(key->cvv_type)) {
			if (verbose > 1) {
			}
		}
	}
}
