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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <fts.h>
#include <pwd.h>
#include <limits.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"

/*
 * flist is a structure that keeps track of the files that still need to be
 * accessed. Turned into a fnode by populate_fnode_from_flist() when it is
 * time to process the file fully.
 */
struct flist {
	TAILQ_ENTRY(flist)	fl_list;
	RB_ENTRY(flist)		fl_inode_entry;
	struct dnode		*fl_parent_dir;
	struct flist		*fl_hlnode;
	char			*fl_fname;
	struct fnode		*fl_node;
	dev_t			fl_dev;
	ino_t			fl_ino;
#define C_FF_FORCEDIR	0x1
#define C_FF_CLOSEDIR	0x2
#define C_FF_WASDIR	0x4
	int			fl_flags;
};
RB_HEAD(fl_tree, flist);
TAILQ_HEAD(flist_head, flist);

/* tree for hardlink calculations */
int		 	 fl_inode_sort(struct flist *, struct flist *);
RB_PROTOTYPE(fl_tree, flist, fl_inode_entry, fl_inode_sort);
RB_GENERATE(fl_tree, flist, fl_inode_entry, fl_inode_sort);

/* Directory traversal and transformation of generated data */
static void		 ct_traverse(char **, struct flist_head *);
static int		 ct_sched_backup_file(struct stat *, char *, int, int,
			     struct flist_head *, struct fl_tree *);
static struct fnode	*ct_populate_fnode_from_flist(struct flist *);
static char		*ct_name_to_safename(char *);

/* Helper functions for the above */
static char		*eat_double_dots(char *, char *);
static int		 backup_prefix(char *, struct flist_head *,
			     struct fl_tree *);
static char		*gen_fname(struct flist *);
static int		 s_to_e_type(int);


int                      ct_dname_cmp(struct dnode *, struct dnode *);

int			 ct_open(struct fnode *, int , int);
int			 ct_stat(struct fnode *, struct stat *, int, int);
int			 ct_mkdir(struct fnode *, mode_t);
int			 ct_mknod(struct fnode *);
int			 ct_link(struct fnode *, char *);
int			 ct_symlink(struct fnode *);
int			 ct_readlink(struct fnode *, char *, size_t);
int			 ct_rename(struct fnode *);
int			 ct_chown(struct fnode *, int);
int			 ct_chmod(struct fnode *, mode_t);
int			 ct_utimes(struct fnode *);
int			 ct_unlink(struct fnode *);


extern int		 ct_follow_symlinks;
int			 ct_extract_fd = -1;
struct dnode		 ct_rootdir;


/* Directory tree by name */
struct d_name_tree ct_dname_head = RB_INITIALIZER(&ct_dname_head);

RB_GENERATE(d_name_tree, dnode, d_rb_name, ct_dname_cmp);

int
ct_dname_cmp(struct dnode *d1, struct dnode *d2)
{
	return strcmp(d2->d_name, d1->d_name);
}


static void
ct_flnode_cleanup(struct flist_head *head)
{
	struct flist *flnode;

	while (!TAILQ_EMPTY(head)) {
		flnode = TAILQ_FIRST(head);
		TAILQ_REMOVE(head, flnode, fl_list);
		if (flnode->fl_fname)
			e_free(&flnode->fl_fname);
		e_free(&flnode);
	}
}

void
ct_dnode_cleanup(void)
{
	struct dnode *dnode;

	while ((dnode = RB_ROOT(&ct_dname_head)) != NULL) {
		RB_REMOVE(d_name_tree, &ct_dname_head, dnode);
		e_free(&dnode->d_name);
		e_free(&dnode);
	}
}

void
ct_free_fnode(struct fnode *fnode)
{
	if (fnode->fl_hlname != NULL)
		e_free(&fnode->fl_hlname);
	if (fnode->fl_sname != NULL)
		e_free(&fnode->fl_sname);
	if (fnode->fl_fname)
		e_free(&fnode->fl_fname);
	if (fnode->fl_name)
		e_free(&fnode->fl_name);
	e_free(&fnode);

}

int
fl_inode_sort(struct flist *f1, struct flist *f2)
{
	int rv;

	if ((rv = f2->fl_dev - f1->fl_dev) != 0)
		return (rv);
	if ((rv = f2->fl_ino - f1->fl_ino) != 0)
		return (rv);

	return (0);
}

static char *
ct_name_to_safename(char *filename)
{
	char		*safe;

	/* compute 'safe' name */
	safe = filename;
	if (ct_strip_slash && safe[0] == '/') {
		safe++;
		if (safe[0] == '\0') {
			return NULL;
		}
	}
	while (!(strncmp(safe, "../", 3)))
		safe += 3;
	if (!strcmp(safe, ".."))
		return NULL;
	/* skip '.' */
	if (!strcmp(filename, ".")) {
		return NULL;
	}
	return safe;
}

static char *
gen_fname(struct flist *flnode)
{
	char *name;

	if (flnode->fl_parent_dir && flnode->fl_parent_dir->d_num != -3) {
		e_asprintf(&name, "%s/%s", flnode->fl_parent_dir->d_name,
		    flnode->fl_fname);
	} else {
		name = e_strdup(flnode->fl_fname);
	}

	return name;
}

char *
gen_sname(struct flist *flnode)
{
	char		*name, *sname;

	name = gen_fname(flnode);
	sname = e_strdup(ct_name_to_safename(name));
	e_free(&name);

	return sname;
}

struct fnode *
ct_get_next_fnode(struct flist_head *head, struct flist **flist,
    struct ct_match *include, struct ct_match *exclude)
{
	struct fnode	*fnode;
again:
	if (*flist == NULL)
		*flist = TAILQ_FIRST(head);
	else
		*flist = TAILQ_NEXT(*flist, fl_list);
	if (*flist == NULL)
		return (NULL);
	/*
	 * Deleted files will return NULL here, so keep looking until
	 * we find a valid file or we run out of options.
	 */
	while ((fnode = ct_populate_fnode_from_flist(*flist)) == NULL &&
	    (*flist = TAILQ_NEXT(*flist, fl_list)) != NULL)
		;
	if (fnode == NULL)
		return (NULL);

	if (include && ct_match(include, fnode->fl_sname)) {
		CNDBG(CT_LOG_FILE, "%s not in include list, skipping",
		    fnode->fl_sname);
		ct_free_fnode(fnode);
		goto again;
	}
	if (exclude && !ct_match(exclude, fnode->fl_sname)) {
		CNDBG(CT_LOG_FILE, "%s in exclude list, skipping",
		    fnode->fl_sname);
		ct_free_fnode(fnode);
		goto again;
	}

	return (fnode);
}

static struct fnode *
ct_populate_fnode_from_flist(struct flist *flnode)
{
	struct fnode		*fnode;
	struct stat		*sb, sbstore;
	struct dnode		dsearch, *dfound;
	char			*fname;
#ifndef CT_NO_OPENAT
	int			dopenflags;
#endif
	int			ret;

	if (flnode->fl_flags & C_FF_CLOSEDIR) {
		dsearch.d_name = gen_fname(flnode);
		if ((dfound = RB_FIND(d_name_tree, &ct_dname_head,
		    &dsearch)) == NULL)
			CFATALX("close entry for non existant directory %s",
			    dsearch.d_name);
		e_free(&dsearch.d_name);
#ifndef CT_NO_OPENAT
		if (dfound->d_fd != -1)
			close(dfound->d_fd);
#endif
		dfound->d_fd = -1;
		return (NULL);
	}

	sb = &sbstore;
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	fname = gen_fname(flnode);

	if (fname[0] == '/') {
		strlcpy(path, fname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fname);
	}

	if (ct_follow_symlinks)
		ret = stat(path, sb);
	else
		ret = lstat(path, sb);
#else
	fname = e_strdup(flnode->fl_fname);
	ret = fstatat(flnode->fl_parent_dir->d_fd, flnode->fl_fname,
	    sb, ct_follow_symlinks ? 0 : AT_SYMLINK_NOFOLLOW);
#endif
	if (ret != 0) {
		e_free(&fname);
		/* file no longer available return failure */
		return NULL;
	}

	fnode = e_calloc(1, sizeof(*fnode));

	/*
	 * ct_name_to_safename has run before and not returned failure
	 * so safe to not check for failure of gen_sname() here.
	 */
	fnode->fl_fname = fname;
	fnode->fl_sname = gen_sname(flnode);
	fnode->fl_dev = sb->st_dev;
	fnode->fl_rdev = sb->st_rdev;
	fnode->fl_ino = sb->st_ino;
	fnode->fl_uid = sb->st_uid;
	fnode->fl_gid = sb->st_gid;
	fnode->fl_mode = sb->st_mode;
	fnode->fl_atime = sb->st_atime;
	fnode->fl_mtime = sb->st_mtime;
	fnode->fl_type = s_to_e_type(sb->st_mode);
	fnode->fl_size = sb->st_size;
	fnode->fl_offset = 0;

	if (flnode->fl_flags & C_FF_FORCEDIR)
		fnode->fl_type = C_TY_DIR;
	/*
	 * If we someone tries to perform a symlink race and it happens before
	 * we stat the directory this second time then we may hit the case
	 * where we think a file is a directory, but it is a symlink,
	 * allowing evil path manipulation games. Therefore, if we think it is
	 * a directory then check that it is, in case we have children.
	 */
	if (flnode->fl_flags & C_FF_WASDIR && fnode->fl_type != C_TY_DIR) {
		CWARNX("%s is no longer a directory", fnode->fl_sname);
		ct_free_fnode(fnode);
		return (NULL);
	}

	/* either the parent is NULL (which is fine) or is our parent */
	fnode->fl_parent_dir = flnode->fl_parent_dir;

	fnode->fl_state = CT_FILE_START;
	ct_sha1_setup(&fnode->fl_shactx);

	if (C_ISDIR(fnode->fl_type)) {
		dsearch.d_name = gen_fname(flnode);
		dfound = RB_FIND(d_name_tree, &ct_dname_head, &dsearch);
		if (dfound == NULL)
			CFATALX("directory not found in d_name_tree %s",
			    fnode->fl_fname);
		e_free(&dsearch.d_name);
		fnode->fl_curdir_dir = dfound;

#ifndef CT_NO_OPENAT
		/* XXX O_SEARCH */
		dopenflags = O_DIRECTORY | O_RDONLY | O_NOFOLLOW;
		if ((flnode->fl_flags & C_FF_FORCEDIR) || ct_follow_symlinks)
			dopenflags &= ~O_NOFOLLOW;

		if ((dfound->d_fd = openat(fnode->fl_parent_dir->d_fd,
		    fnode->fl_fname, dopenflags)) == -1) {
			CWARN("can't open directory %s", fnode->fl_sname);
		}
#endif
	}

	if (flnode->fl_hlnode != NULL) {
		fnode->fl_hardlink = 1;
		fnode->fl_type = C_TY_LINK;
		fnode->fl_hlname = gen_sname(flnode->fl_hlnode);
	} else if (C_ISLINK(fnode->fl_type) && fnode->fl_hardlink == 0) {
		char			 mylink[PATH_MAX];

		ret = ct_readlink(fnode, mylink, sizeof(mylink));
		if (ret == -1 || ret == sizeof(mylink)) {
			CWARN("can't read link for %s", fnode->fl_sname);
			ct_free_fnode(fnode);
			return (NULL);
		}
		/*
		 * readlink(2) does not append a NUL.
		 */
		mylink[ret] = '\0';
		fnode->fl_hlname = e_strdup(mylink);
	}

	return fnode;
}

void
ct_setup_root_dir(const char *tdir)
{
	ct_rootdir.d_num = -3;
	ct_rootdir.d_parent = NULL;
	if (tdir != NULL)
		ct_rootdir.d_name = e_strdup(tdir);
	else
		ct_rootdir.d_name = e_strdup(".");

#ifndef CT_NO_OPENAT
	if ((ct_rootdir.d_fd = open(tdir ? tdir : ".",
	    O_RDONLY | O_DIRECTORY)) == -1) {
		CFATAL("can't open %s directory", tdir ? tdir : "current");
	}
#endif
}

void
ct_cleanup_root_dir(void)
{
	if (ct_rootdir.d_name != NULL)
		e_free(ct_rootdir.d_name);
#ifndef CT_NO_OPENAT
	struct dnode	*dnode;
	/*
	 * ct -cf foo.md foo/bar/baz will have foo and foo/bar open at this
	 * point (no fts postorder visiting), close them since we have just
	 * finished with the filesystem.
	 */
	RB_FOREACH(dnode, d_name_tree, &ct_dname_head) {
		if (dnode->d_fd != -1) {
			CNDBG(CT_LOG_FILE, "%s wasn't closed", dnode->d_name);
			close(dnode->d_fd);
			dnode->d_fd = -1;
		}
	}
	close(ct_rootdir.d_fd);
#endif
	ct_rootdir.d_fd = -1;
}

static int
ct_sched_backup_file(struct stat *sb, char *filename, int forcedir,
    int closedir, struct flist_head *flist, struct fl_tree *ino_tree)
{
	struct flist		*flnode;
	const char		*safe;
	struct flist		*flnode_exists;
	struct dnode		dsearch, *dfound;
	struct dnode		*dnode = NULL, *e_dnode;
	char			fname_buf[PATH_MAX];

	/* compute 'safe' name */
	safe = ct_name_to_safename(filename);
	if (safe == NULL)
		return 0;

	if (closedir) {
		dsearch.d_name = (char *)filename;
		dnode = RB_FIND(d_name_tree, &ct_dname_head, &dsearch);
		if (dnode == NULL)
			CFATALX("close directory for nonexistant dir %s",
			    filename);
	} else if (forcedir || S_ISDIR(sb->st_mode)) {
		dnode = e_calloc(1, sizeof(*dnode));
		dnode->d_name = e_strdup(filename);
		dnode->d_num = -1; /* numbers are allocated on xdr write */
		e_dnode = RB_INSERT(d_name_tree, &ct_dname_head, dnode);
		if (e_dnode != NULL) {
			/* this directory already exists, do not record twice */
			e_free(&dnode->d_name);
			e_free(&dnode);
			return 0;
		} else
			CNDBG(CT_LOG_CTFILE, "inserted %s", filename);
		/* The rest of the intialisation happens below */
	}

	//ct_numalloc++;
	flnode = e_calloc(1, sizeof (*flnode));

	flnode->fl_dev = sb->st_dev;
	flnode->fl_ino = sb->st_ino;
	flnode->fl_parent_dir = NULL;

	strlcpy(fname_buf, filename, sizeof(fname_buf));
	dsearch.d_name = dirname(fname_buf);
	dfound = RB_FIND(d_name_tree, &ct_dname_head, &dsearch);
	if (dfound != NULL) {
		flnode->fl_parent_dir = dfound;
		CNDBG(CT_LOG_CTFILE, "parent of %s is %s", filename,
		    dfound->d_name);
		strlcpy(fname_buf, filename, sizeof(fname_buf));
		flnode->fl_fname = e_strdup(basename(fname_buf));
		CNDBG(CT_LOG_CTFILE, "setting name of %s as %s", filename,
		    flnode->fl_fname);
	} else {
		flnode->fl_fname = e_strdup(filename);
		flnode->fl_parent_dir = &ct_rootdir;
		CNDBG(CT_LOG_CTFILE, "parent of %s is not found [%s]",
		    flnode->fl_fname, dsearch.d_name);
	}

	if (closedir) {
		flnode->fl_flags |= C_FF_CLOSEDIR;
		goto insert;
	}

	/* fill in directory data now that we have the parent information */
	if (dnode != NULL) {
		dnode->d_parent = flnode->fl_parent_dir;
		dnode->d_sname = e_strdup(flnode->fl_fname);
		dnode->d_fd = -1;
		dnode->d_mode = sb->st_mode;
		dnode->d_atime = sb->st_atime;
		dnode->d_mtime = sb->st_mtime;
		dnode->d_uid = sb->st_uid;
		dnode->d_gid = sb->st_gid;
		 /* we may have children, enforce this being a directory. */
		flnode->fl_flags |= C_FF_WASDIR;
	}

	if (forcedir)
		flnode->fl_flags |= C_FF_FORCEDIR;

	flnode->fl_hlnode = NULL;
	/* deal with hardlink */
	flnode_exists = RB_INSERT(fl_tree, ino_tree, flnode);
	if (flnode_exists != NULL) {
		flnode->fl_hlnode = flnode_exists;
		CNDBG(CT_LOG_CTFILE, "found %s as hardlink of %s", safe,
		    ct_name_to_safename(flnode->fl_hlnode->fl_fname));
	} else {
		if (S_ISREG(sb->st_mode))
			ct_stats->st_bytes_tot += sb->st_size;
	}
	ct_stats->st_files_scanned++;

insert:
	TAILQ_INSERT_TAIL(flist, flnode, fl_list);

	return 0;
}

struct ct_archive_priv {
	struct flist_head		 cap_flist;
	struct ctfile_write_state	*cap_cws;
	struct ct_match			*cap_include;
	struct ct_match			*cap_exclude;
	struct fnode			*cap_curnode;
	struct flist			*cap_curlist;
	time_t				 cap_prev_backup_time;
	int				 cap_fd;
};

void
ct_archive(struct ct_op *op)
{
	struct ct_archive_args	*caa = op->op_args;
	const char		*ctfile = caa->caa_local_ctfile;
	char			**filelist = caa->caa_filelist;
	const char		*basisbackup = caa->caa_basis;
	ssize_t			rlen;
	off_t			rsz;
	struct stat		sb;
	struct ct_trans		*ct_trans;
	struct ct_archive_priv	*cap = op->op_priv;
	char			cwd[PATH_MAX];
	int			new_file = 0;
	int			error;
	int			nextlvl = 0;

	CNDBG(CT_LOG_TRANS, "processing");
	if (ct_state->ct_file_state == CT_S_STARTING) {
		if (*filelist == NULL) {
			CFATALX("no files specified");
		}

		cap = e_calloc(1, sizeof(*cap));
		cap->cap_fd = -1;
		TAILQ_INIT(&cap->cap_flist);
		op->op_priv = cap;
		if (caa->caa_includefile)
			cap->cap_include =
			    ct_match_fromfile(caa->caa_includefile,
			    caa->caa_matchmode);
		if (caa->caa_excllist)
			cap->cap_exclude = ct_match_compile(caa->caa_matchmode,
			    caa->caa_excllist);

		if (basisbackup != NULL &&
		    (nextlvl = ct_basis_setup(basisbackup, filelist,
		    &cap->cap_prev_backup_time)) == 0)
			e_free(&basisbackup);

		if (getcwd(cwd, PATH_MAX) == NULL)
			CFATAL("can't get current working directory");

		ct_setup_root_dir(caa->caa_tdir);
		if (caa->caa_tdir && chdir(caa->caa_tdir) != 0)
			CFATALX("can't chdir to %s", caa->caa_tdir);
		ct_traverse(filelist, &cap->cap_flist);
		if (caa->caa_tdir && chdir(caa->caa_tdir) != 0)
			CFATALX("can't chdir back to %s", cwd);
		/*
		 * Get the first file we must operate on.
		 * Do this before we open the ctfile for writing so
		 * if all are excluded we don't then have to unlink it.
		 */
		cap->cap_curlist = NULL;
		if ((cap->cap_curnode = ct_get_next_fnode(&cap->cap_flist,
		    &cap->cap_curlist, cap->cap_include,
		    cap->cap_exclude)) == NULL)
			CFATALX("all files specified excluded or nonexistant");


		/* XXX - deal with stdin */
		/* XXX - if basisbackup should the type change ? */
		if ((cap->cap_cws = ctfile_write_init(ctfile, CT_MD_REGULAR,
		    basisbackup, nextlvl, cwd, filelist,
		    caa->caa_encrypted, caa->caa_allfiles)) == NULL)
			CFATAL("can't create %s", ctfile);

		if (basisbackup != NULL)
			e_free(&basisbackup);
	} else if (ct_state->ct_file_state == CT_S_FINISHED)
		return;

	ct_set_file_state(CT_S_RUNNING);

	if (cap->cap_curnode == NULL)
		goto done;
loop:
	CNDBG(CT_LOG_CTFILE, "file %s state %d", cap->cap_curnode->fl_sname,
	    cap->cap_curnode->fl_state);
	new_file = (cap->cap_curnode->fl_state == CT_FILE_START);

	/* allocate transaction */
	ct_trans = ct_trans_alloc();
	if (ct_trans == NULL) {
		/* system busy, return */
		CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	/*
	 * Only regular files that haven't just been opened need to talk
	 * to the server. don't waste slots.
	 */
	if (!C_ISREG(cap->cap_curnode->fl_type) || new_file)
		ct_trans = ct_trans_realloc_local(ct_trans);

	/* handle special files */
	if (!C_ISREG(cap->cap_curnode->fl_type)) {
		if (C_ISDIR(cap->cap_curnode->fl_type)) {
			/*
			 * we do want to skip old directories with
			 * no (new) files in them
			 */
			if (ct_stat(cap->cap_curnode, &sb,
			    ct_follow_symlinks, 0) != 0) {
				CWARN("archive: dir %s stat error",
				    cap->cap_curnode->fl_sname);
			} else {
				if (sb.st_mtime < cap->cap_prev_backup_time) {
					CNDBG(CT_LOG_FILE, "skipping dir"
					    " based on mtime %s",
					    cap->cap_curnode->fl_sname);
					ct_free_fnode(cap->cap_curnode);
					ct_trans_free(ct_trans);
					goto skip;
				}
			}
		}
		ct_trans->tr_ctfile = cap->cap_cws;;
		ct_trans->tr_fl_node = cap->cap_curnode;
		cap->cap_curnode->fl_state = CT_FILE_FINISHED;
		cap->cap_curnode->fl_size = 0;
		ct_trans->tr_state = TR_S_SPECIAL;
		ct_trans->tr_type = TR_T_SPECIAL;
		ct_trans->tr_trans_id = ct_trans_id++;
		ct_trans->tr_eof = 0;
		ct_queue_transfer(ct_trans);
		goto next_file;
	}

	/* do not open zero length files */
	if (new_file) {
		cap->cap_curnode->fl_state = CT_FILE_PROCESSING;
		if (cap->cap_fd != -1) {
			CFATALX("state error, new file open,"
			    " sz %" PRId64 " offset %" PRId64,
			    (int64_t) cap->cap_curnode->fl_size,
			    (int64_t) cap->cap_curnode->fl_offset);
		}

		if ((cap->cap_fd = ct_open(cap->cap_curnode, O_RDONLY,
		    ct_follow_symlinks)) == -1) {
			CWARN("archive: unable to open file '%s'",
			    cap->cap_curnode->fl_sname);
			ct_trans_free(ct_trans);
			cap->cap_curnode->fl_state = CT_FILE_FINISHED;
			goto next_file;
		}

		error = fstat(cap->cap_fd, &sb);
		if (error) {
			CWARN("archive: file %s stat error",
			    cap->cap_curnode->fl_sname);
		} else {
			if (sb.st_mtime < cap->cap_prev_backup_time) {
				if (ct_verbose > 1)
					CINFO("skipping file based on mtime %s",
					    cap->cap_curnode->fl_sname);
				cap->cap_curnode->fl_skip_file = 1;
			}
		}
		/*
		 * Now we have actually statted the file atomically
		 * confirm the permissions bits that we got with the last
		 * stat.
		 */
		if (!S_ISREG(sb.st_mode)) {
			CWARNX("%s is no longer a regular file, skipping",
			    cap->cap_curnode->fl_sname);
			cap->cap_curnode->fl_skip_file = 1;
		}
		cap->cap_curnode->fl_dev = sb.st_dev;
		cap->cap_curnode->fl_rdev = sb.st_rdev;
		cap->cap_curnode->fl_ino = sb.st_ino;
		cap->cap_curnode->fl_uid = sb.st_uid;
		cap->cap_curnode->fl_gid = sb.st_gid;
		cap->cap_curnode->fl_mode = sb.st_mode;
		cap->cap_curnode->fl_atime = sb.st_atime;
		cap->cap_curnode->fl_mtime = sb.st_mtime;
		cap->cap_curnode->fl_size = sb.st_size;

		ct_trans->tr_ctfile = cap->cap_cws;;
		ct_trans->tr_fl_node = cap->cap_curnode;
		ct_trans->tr_state = TR_S_FILE_START;
		ct_trans->tr_type = TR_T_WRITE_HEADER;
		if (cap->cap_curnode->fl_size == 0 ||
		    cap->cap_curnode->fl_skip_file) {
			close(cap->cap_fd);
			cap->cap_fd = -1;
			ct_trans->tr_eof = 1;
			cap->cap_curnode->fl_state = CT_FILE_FINISHED;
		} else {
			ct_trans->tr_eof = 0;
		}

		/*
		 * Allfiles backups needs to still record skipped files.
		 * Non allfiles backups don't need to do anything with them
		 * so we can dump them here.
		 */
		if (cap->cap_curnode->fl_skip_file && caa->caa_allfiles == 0) {
			ct_free_fnode(cap->cap_curnode);
			ct_trans_free(ct_trans);
			goto skip;
		}

		/* must not allocate trans_id if not skipped */
		ct_trans->tr_trans_id = ct_trans_id++;
		ct_queue_transfer(ct_trans);
		if (cap->cap_curnode->fl_size == 0 ||
		    cap->cap_curnode->fl_skip_file) {
			goto next_file;
		}
		goto loop;
	} else {
		if (cap->cap_fd == -1) {
			CFATALX("state error, old file not open,"
			    " sz %" PRId64 " offset %" PRId64,
			    (int64_t) cap->cap_curnode->fl_size,
			    (int64_t) cap->cap_curnode->fl_offset);
		}
	}

	/* perform read */
	rsz = cap->cap_curnode->fl_size - cap->cap_curnode->fl_offset;
	CNDBG(CT_LOG_FILE, "rsz %lu max %d", (unsigned long) rsz,
	    ct_max_block_size);
	if (rsz > ct_max_block_size) {
		rsz = ct_max_block_size;
	}
	ct_trans->tr_dataslot = 0;
	rlen = 0;
	if (rsz > 0)
		rlen = read(cap->cap_fd, ct_trans->tr_data[0], rsz);

	if (rlen > 0)
		ct_stats->st_bytes_read += rlen;

	ct_trans->tr_ctfile = cap->cap_cws;;
	ct_trans->tr_fl_node = cap->cap_curnode;
	ct_trans->tr_size[0] = rlen;
	ct_trans->tr_chsize = rlen;
	ct_trans->tr_state = TR_S_READ;
	ct_trans->tr_type = TR_T_WRITE_CHUNK;
	ct_trans->tr_trans_id = ct_trans_id++;
	ct_trans->tr_eof = 0;
	ct_trans->hdr.c_flags = caa->caa_encrypted ? C_HDR_F_ENCRYPTED : 0;
	CNDBG(CT_LOG_FILE, "read %ld for block %" PRIu64, (long) rlen,
	    ct_trans->tr_trans_id);

	/* update offset */
	if (rsz != rlen || rlen == 0 || ((cap->cap_curnode->fl_offset + rlen) ==
	        cap->cap_curnode->fl_size)) {
		/* short read, file truncated, or end of file */
		/* restat file for modifications */
		error = fstat(cap->cap_fd, &sb);

		close(cap->cap_fd);
		cap->cap_fd = -1;
		ct_trans->tr_eof = 1;
		cap->cap_curnode->fl_state = CT_FILE_FINISHED;

		if (error) {
			CWARN("archive: file %s stat error",
			    cap->cap_curnode->fl_sname);
		} else if (sb.st_size != cap->cap_curnode->fl_size) {
			CWARNX("\"%s\" %s during backup",
			    cap->cap_curnode->fl_sname,
			    (sb.st_size > cap->cap_curnode->fl_size) ? "grew" :
				"truncated");
			ct_trans->tr_state = TR_S_WMD_READY;
			ct_trans->tr_eof = 2;
		}
		CNDBG(CT_LOG_FILE, "going to next file %s",
		    cap->cap_curnode->fl_sname);
		CNDBG(CT_LOG_TRANS, "setting eof on trans %" PRIu64 " %s",
		    ct_trans->tr_trans_id, cap->cap_curnode->fl_sname);
	} else {
		cap->cap_curnode->fl_offset += rlen;
	}
	ct_queue_transfer(ct_trans);

	/* if file finished, update curnode to next node in list */
	/* XXX is there other file metadata that needs to be saved?  */
next_file:
	/* XXX should node be removed from list at this time? */
	if (cap->cap_curnode->fl_state == CT_FILE_FINISHED) {
skip:
		if ((cap->cap_curnode = ct_get_next_fnode(&cap->cap_flist,
		    &cap->cap_curlist, cap->cap_include,
		    cap->cap_exclude)) == NULL) {
			CNDBG(CT_LOG_FILE, "no more files");
		} else {
			CNDBG(CT_LOG_FILE, "going to next file %s",
			    cap->cap_curnode->fl_sname);
		}
	}

	if (cap->cap_curnode != NULL)
		goto loop;

done:
	CNDBG(CT_LOG_FILE, "last file read");
	/* done with backup */
	ct_set_file_state(CT_S_FINISHED);

	ct_trans = ct_trans_alloc();
	if (ct_trans == NULL) {
		/* system busy, return */
		CNDBG(CT_LOG_TRANS, "ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}
	ct_trans->tr_ctfile = cap->cap_cws;;
	ct_trans->tr_fl_node = NULL;
	ct_trans->tr_state = TR_S_DONE;
	ct_trans->tr_eof = 0;
	ct_trans->tr_trans_id = ct_trans_id++;

	/* We're done, cleanup local state. */
	if (cap->cap_include)
		ct_match_unwind(cap->cap_include);
	if (cap->cap_exclude)
		ct_match_unwind(cap->cap_exclude);
	ct_flnode_cleanup(&cap->cap_flist);
	//ct_cleanup_root_dir();
	/* cws is cleaned up by the completion handler */
	e_free(&cap);

	ct_queue_transfer(ct_trans);
}

static void
ct_traverse(char **paths, struct flist_head *files)
{
	FTS			*ftsp;
	FTSENT			*fe;
	struct fl_tree		 ino_tree;
	char			 clean[PATH_MAX];
	int			 fts_options;
	int			 cnt;
	int			 forcedir;
	extern int		 ct_root_symlink;

	RB_INIT(&ino_tree);
	fts_options = FTS_NOCHDIR;
	if (ct_follow_symlinks)
		fts_options |= FTS_LOGICAL;
	else
		fts_options |= FTS_PHYSICAL;
	if (ct_root_symlink) {
		CWARNX("-H");
		fts_options |= FTS_COMFOLLOW;
	}
	if (ct_no_cross_mounts)
		fts_options |= FTS_XDEV;
	ftsp = fts_open(paths, fts_options, NULL);
	if (ftsp == NULL)
		CFATAL("fts_open failed");

	if (ct_verbose)
		CINFO("Generating filelist, this may take a few minutes...");

	cnt = 0;
	while ((fe = fts_read(ftsp)) != NULL) {
		forcedir = 0;
		switch (fe->fts_info) {
		case FTS_D:
		case FTS_DEFAULT:
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
			cnt++;
			/* these are ok */
			/* FALLTHROUGH */
		case FTS_DP: /* Setup for close dir, no stats */
			/* sanitize path */
			if (eat_double_dots(fe->fts_path, clean) == NULL)
				CFATAL("can't sanitize %s", fe->fts_path);
			if (fe->fts_info == FTS_DP)
				goto sched;
			break;
		case FTS_DC:
			CWARNX("file system cycle found");
			continue;
		case FTS_DNR:
		case FTS_NS:
			errno = fe->fts_errno;
			CWARN("unable to access %s", fe->fts_path);
			continue;
		default:
			CFATALX("bad fts_info (%d)", fe->fts_info);
		}

		/* backup dirs above fts starting point */
		if (fe->fts_level == 0) {
			/* XXX technically this should apply to files too */
			if (ct_root_symlink && fe->fts_info == FTS_D)
				forcedir = 1;
			if (backup_prefix(clean, files, &ino_tree))
				CFATAL("backup_prefix failed");
		}

		CNDBG(CT_LOG_FILE, "scheduling backup of %s", clean);
		/* backup all other files */
sched:
		if (ct_sched_backup_file(fe->fts_statp, clean, forcedir,
		    fe->fts_info == FTS_DP ? 1 : 0, files, &ino_tree))
			CFATAL("backup_file failed: %s", clean);

	}

	if (cnt == 0)
		CFATALX("can't access any of the specified file(s)");

	if (fe == NULL && errno)
		CFATAL("fts_read failed");
	if (fts_close(ftsp))
		CFATAL("fts_close failed");
	gettimeofday(&ct_stats->st_time_scan_end, NULL);
	if (ct_verbose)
		CINFO("Done! Initiating backup...");
}

static char *
eat_double_dots(char *path, char *resolved)
{
	char	**tab = NULL, *buf = NULL, *rv = NULL, *cp, **ntab;
	int	sz = 0, bufsz, i;

	/* emulate realpath(3) for those cases */
	if (path == NULL || *path == '\0') {
		strlcpy(resolved, ".", PATH_MAX);
		return (resolved);
	}

	/*
	 * append dummy component that will be eventually ignored;
	 * greatly simplifies the splitting code below.
	 */
	bufsz = e_asprintf(&buf, "%s/dummy", path);

	/* split path into components */
	for (;;) {
		cp = dirname(buf);
		if (cp == NULL)
			goto done;
		else
			strlcpy(buf, cp, bufsz);

		cp = basename(buf);
		if (cp == NULL)
			goto done;

		ntab = e_realloc(tab, (sz + 1) * sizeof(char *));
		tab = ntab;
		tab[sz++] = e_strdup(cp);

		if (!strcmp(buf, ".") || !strcmp(buf, "/"))
			break; /* reached the top */
	}

	/* walk path components top to bottom */
	for (i = sz - 1; i >= 0; i--) {
		cp = tab[i];

		/* topmost component is always either / or . */
		if (i == sz - 1) {
			strlcpy(resolved, cp, PATH_MAX);
			continue;
		}

		/* '.' component is redundant */
		if (!strcmp(cp, "."))
			continue;

		/* '..' component is special */
		if (!strcmp(cp, "..")) {
			if (!strcmp(resolved, "/"))
				continue; /* cannot go beyond fs root */

			/* remove last component if other than '..' */
			if (strcmp(basename(resolved), ".") != 0 &&
			    strcmp(basename(resolved), "..") != 0)
				strlcpy(resolved, dirname(resolved), PATH_MAX);
			else
				strlcat(resolved, "/..", PATH_MAX);
			continue;
		}

		/* append regular component */
		if (strcmp(resolved, "/") != 0)
			strlcat(resolved, "/", PATH_MAX);
		strlcat(resolved, cp, PATH_MAX);
	}

	if (!strncmp(resolved, "./", 2))
		memmove(resolved, resolved + 2, PATH_MAX - 2);

	rv = resolved;
done:
	if (buf)
		e_free(&buf);
	for (i = 0; i < sz; i++)
		e_free(&tab[i]);
	e_free(&tab);
	return (rv);
}

static int
backup_prefix(char *root, struct flist_head *flist, struct fl_tree *ino_tree)
{
	char			dir[PATH_MAX], rbuf[PATH_MAX], pfx[PATH_MAX];
	char			*cp, *p;
	struct stat		sb;

	/* it is just the prefix that needs to be parsed */
	strlcpy(rbuf, root, sizeof rbuf);
	strlcpy(pfx, dirname(rbuf), sizeof pfx);

	/* archive each leading dir */
	p = pfx;
	bzero(&dir, sizeof dir);
	for (;; strlcat(dir, "/", sizeof dir)) {
		cp = strsep(&p, "/");
		if (cp == NULL)
			break; /* parsed it all */
		if (*cp == '\0')
			continue; /* beginning of absolute path */

		/* extend prefix */
		strlcat(dir, cp, sizeof dir);

		/* XXX racy? */
		if (stat(dir, &sb))
			return (1);

		/* file type changed since fts_open */
		if (!S_ISDIR(sb.st_mode)) {
			errno = ENOTDIR;
			return (1);
		}

		if (ct_sched_backup_file(&sb, dir, 1, 0, flist, ino_tree))
			return (1);
	}

	return (0);
}

static int
s_to_e_type(int mode)
{
	int rv = C_TY_INVALID;

	if (S_ISREG(mode))
		rv = C_TY_REG;
	else if (S_ISDIR(mode))
		rv = C_TY_DIR;
	else if (S_ISCHR(mode))
		rv = C_TY_CHR;
	else if (S_ISBLK(mode))
		rv = C_TY_BLK;
	else if (S_ISFIFO(mode))
		rv = C_TY_FIFO;
	else if (S_ISLNK(mode))
		rv = C_TY_LINK;
	else if (S_ISSOCK(mode))
		rv = C_TY_SOCK;

	return (rv);
}

void ct_file_extract_nextdir(struct fnode *);

#ifndef CT_NO_OPENAT
#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(sizeof(TEMPCHARS) - 1)

/*
 * mkstemp() using openat in the specified directory fd. Semantics remain the
 * same.
 * Code borrowed from OpenBSD libc under the following license:
*
 * Copyright (c) 1996-1998, 2008 Theo de Raadt
 * Copyright (c) 1997, 2008-2009 Todd C. Miller
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
static int
mkstemp_at(int dir, char *path)
{
	char *start, *cp, *ep;
	const char *tempchars = TEMPCHARS;
	unsigned int r, tries;
	size_t len;
	int fd;

	len = strlen(path);
	if (len == 0) {
		errno = EINVAL;
		return(-1);
	}
	ep = path + len;

	tries = 1;
	for (start = ep; start > path && start[-1] == 'X'; start--) {
		if (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	do {
		for (cp = start; cp != ep; cp++) {
			r = arc4random_uniform(NUM_CHARS);
			*cp = tempchars[r];
		}

		fd = openat(dir, path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
		if (fd != -1 || errno != EEXIST)
			return(fd);
	} while (--tries);

	errno = EEXIST;
	return(-1);
}
#endif


int
ct_file_extract_open(struct fnode *fnode)
{
	if (ct_extract_fd != -1) {
		CFATALX("file open on extract_open");
	}

	ct_file_extract_nextdir(fnode);

	CNDBG(CT_LOG_FILE, "opening %s for writing", fnode->fl_sname);

	if (fnode->fl_fname)
		e_free(&fnode->fl_fname);
	/*
	 * All previous directories should have been created when we changed
	 * directory above. If this is not the case then something changed
	 * after we made them. just warn and continue.
	 */
#ifdef CT_NO_OPENAT
	char tpath[PATH_MAX], dirpath[PATH_MAX], *dirp;

	if (fnode->fl_sname[0] == '/') {
		strlcpy(tpath, fnode->fl_sname, sizeof(tpath));
	} else {
		snprintf(tpath, sizeof(tpath), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	strlcpy(dirpath, tpath, sizeof(dirpath));
	if ((dirp = dirname(dirpath)) == NULL)
		CFATALX("can't get dirname of %s", tpath);

	e_asprintf(&fnode->fl_fname, "%s/%s", dirp, "cyphertite.XXXXXXXXXX");
	ct_extract_fd = mkstemp(fnode->fl_fname);
#else
	fnode->fl_fname = e_strdup("cyphertite.XXXXXXXXXX");
	ct_extract_fd = mkstemp_at(fnode->fl_parent_dir->d_fd,
	    fnode->fl_fname);
#endif
	if (ct_extract_fd == -1) {
		CWARN("unable to open file for writing %s", fnode->fl_sname);
		return (1);
	}

	return (0);
}

void
ct_file_extract_write(struct fnode *fnode, uint8_t *buf, size_t size)
{
	ssize_t len;

	len = write(ct_extract_fd, buf, size);

	if (len != size)
		CFATAL("unable to write file %s",
		    fnode ? fnode->fl_sname : "[not open]" );
}

void
ct_file_extract_close(struct fnode *fnode)
{
	struct timeval          tv[2];
	int                     safe_mode;

	safe_mode = S_IRWXU | S_IRWXG | S_IRWXO;
	if (ct_attr) {
		if (fchown(ct_extract_fd, fnode->fl_uid, fnode->fl_gid) == -1) {
			if (errno == EPERM && geteuid() != 0) {
				if (ct_verbose)
					CWARN("chown failed: %s",
					    fnode->fl_sname);
			} else {
				CFATAL("chown failed %s", fnode->fl_sname);
			}
		} else
			safe_mode = ~0;
	}

	if (fchmod(ct_extract_fd, fnode->fl_mode & safe_mode) == -1)
		CFATAL("chmod failed on %s", fnode->fl_sname);

	if (ct_attr) {
		tv[0].tv_sec = fnode->fl_atime;
		tv[1].tv_sec = fnode->fl_mtime;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (futimes(ct_extract_fd, tv) == -1)
			CFATAL("utimes failed");
	}
	if (ct_rename(fnode) != 0)
		CFATAL("rename to %s failed", fnode->fl_sname);

	close(ct_extract_fd);
	ct_extract_fd = -1;
}

void
ct_file_extract_special(struct fnode *fnode)
{
	char			apath[PATH_MAX];
	char			*appath;
	int			ret = 0;
	int                     safe_mode;

	/*
	 * Create dependant directories and open/close any relvevant directory
	 * filedescriptors.
	 */
	ct_file_extract_nextdir(fnode);

	CNDBG(CT_LOG_FILE, "special %s mode %d", fnode->fl_sname,
	    fnode->fl_mode);

	if (C_ISDIR(fnode->fl_type)) {
		if (ct_mkdir(fnode, 0700)) {
			if (errno != EEXIST) /* XXX check it is a dir */
				CWARN("can't create directory %s",
				    fnode->fl_sname);
		}
	} else if (C_ISBLK(fnode->fl_type) || C_ISCHR(fnode->fl_type))  {
		if (ct_mknod(fnode) != 0) {
			if (errno != EEXIST) /* XXX check it is a spec node */
				CWARN("can't create special file %s",
				    fnode->fl_sname);
		}
	} else if (C_ISLINK(fnode->fl_type)){
		if (fnode->fl_hardlink && fnode->fl_hlname[0] != '/') {
			snprintf(apath, sizeof(apath), "%s/%s",
			    ct_rootdir.d_name, fnode->fl_hlname);
			appath = apath;
		} else {
			appath = fnode->fl_hlname;
		}

link_again:
		if (fnode->fl_hardlink) {
			/*
			 * XXX AT_FDCWD is dangerous here but we don't have
			 * sufficient information.
			 * We pass SYMLINK_FOLLOW to give the same semantics
			 * as link()
			 */
			ret = ct_link(fnode, appath);
		} else {
			ret = ct_symlink(fnode);
		}
		if (ret && errno == EEXIST) {
			if (fnode->fl_hardlink) {
				struct stat	tsb, lsb;

				/*
				 * XXX don't necessarily have the cwd of
				 * the hardlink open.
				 */
				if (lstat(appath, &tsb) != 0) {
					CWARN("can't stat %s", appath);
					goto link_out;
				}
				if (ct_stat(fnode, &lsb,
				    ct_follow_symlinks, 1) != 0) {
					CWARN("can't stat %s", fnode->fl_sname);
					goto link_out;
				}
				if (tsb.st_dev != lsb.st_dev) {
					CWARNX("%s and %s no longer on same "
					    "device: can't link",
					    appath, fnode->fl_sname);
					goto link_out;
				}
				/*
				 * If inodes match, then carry on, we're
				 * already ok
				 */
				if (tsb.st_ino == lsb.st_ino) {
					ret = 0;
					goto link_out;
				}
			}

			if (ct_unlink(fnode) == 0)
				goto link_again;
			CWARN("can't remove old link %s", fnode->fl_sname);
		}
link_out:
		if (ret) {
			CWARN("%s failed: %s to %s", fnode->fl_hardlink ?
			    "link" : "symlink", fnode->fl_sname, appath);
			return;
		}
	} else {
		CFATALX("illegal file %s of type %d", fnode->fl_sname,
		    fnode->fl_mode);
	}

	if (C_ISDIR(fnode->fl_type)) {
		/*
		 * Directory permissions are handled at directory close
		 * time when all dependancies are finished.
		 */
		;
	} else if (C_ISLINK(fnode->fl_type)){
		if (!fnode->fl_hardlink) {
			/* symlinks have no 'real' permissions */
			if (ct_attr) {
				/* set the link's ownership */
				if (ct_chown(fnode, 0) != 0) {
					if (errno == EPERM && geteuid() != 0) {
						if (ct_verbose)
							CWARN("lchown failed:"
							    " %s",
							    fnode->fl_sname);
					} else {
						CFATAL("lchown failed %s",
						    fnode->fl_sname);
					}
				}
			}
		} else  {
			/* hardlinks have no mode/permissions */
			;
		}
	} else {
		safe_mode = S_IRWXU | S_IRWXG | S_IRWXO;
		if (ct_attr) {
			/* XXX should this depend on ct_follow_symlinks? */
			if (ct_chown(fnode, 1) != 0) {
				if (errno == EPERM && geteuid() != 0) {
					if (ct_verbose)
						CWARN("chown failed: %s",
						    fnode->fl_sname);
				} else {
					CFATAL("chown failed %s",
					    fnode->fl_sname);
				}
			} else
				safe_mode = ~0;
		}

		if (ct_chown(fnode, fnode->fl_mode & safe_mode) != 0)
			CFATAL("chmod failed on %s", fnode->fl_sname);

		if (ct_attr) {
			if (ct_utimes(fnode) != 0)
				CFATAL("utimes failed");
		}
	}
}

void	ct_file_extract_closefrom(struct dnode *, struct dnode *);
void	ct_file_extract_opento(struct dnode *, struct dnode *);
struct dnode	*ct_ex_prevdir = NULL;
struct dnode	**ct_ex_prevdir_list = NULL;

void
ct_file_extract_setup_dir(const char *tdir)
{
	char	tpath[PATH_MAX];
	int	tries = 0;
	ct_rootdir.d_num = -3;
	ct_rootdir.d_parent = NULL;
try_again:
	/* ct_make_full_path can mess with the string we are using */
	if (tdir != NULL) {
		strlcpy(tpath, tdir, sizeof(tpath));
	} else {
		strlcpy(tpath, ".", sizeof(tpath));
	}
	/* Open the root directory fd node */
#ifdef CT_NO_OPENAT
	struct stat sb;

	if (stat(tpath, &sb) == -1) {
#else
	if ((ct_rootdir.d_fd = open(tpath, O_RDONLY | O_DIRECTORY)) == -1) {
#endif
		/*
		 * We will only hit this case for tdir.
		 * XXX a more restrictive mask wanted?
		 */
		if (errno == ENOENT && tries++ == 0 &&
		    ct_make_full_path(tpath, 0777) == 0 &&
		    mkdir(tdir, 0777) == 0)
			goto try_again;
		CFATAL("can't open %s directory", tdir ? "-C" : "current");
	}
	ct_rootdir.d_name = e_strdup(tpath);
}

void
ct_file_extract_cleanup_dir(void)
{
	if (ct_rootdir.d_name)
		e_free(&ct_rootdir.d_name);
#ifndef CT_NO_OPENAT
	close(ct_rootdir.d_fd);
#endif
}

void
ct_file_extract_nextdir(struct fnode *fnode)
{
	struct dnode	*newdir = fnode->fl_parent_dir, *tdir;
	struct dnode	**newdirlist;
	int		 ndirs, i;

	/* If we're in the same directory, we're done */
	if (newdir == ct_ex_prevdir) {
		return;
	}

	/* count number of directories. */
	for (tdir = newdir, ndirs = 0; tdir != NULL;
	    (tdir = tdir->d_parent), ndirs++)
		;

	/* should never happen */
	if (ndirs == 0) {
		CFATALX("no dirs");
	}

	newdirlist = e_calloc(ndirs + 1, sizeof(*newdirlist));

	/* newdirlist is NULL terminated, build it backwards */
	for (tdir = newdir, i = ndirs - 1; tdir != NULL; tdir = tdir->d_parent)
		newdirlist[i--] = tdir;
	if (ct_ex_prevdir_list == NULL) {
		i = 0;
		goto open;
	}

	/*
	 * find the common parent
	 * we know the directories are not the same, so this should halt
	 */
	for (i = 0; ; i++) {
		if (newdirlist[i + 1] != ct_ex_prevdir_list[i + 1])
			break;
	}

	/* close all children from common parent up to old dir */
	ct_file_extract_closefrom(ct_ex_prevdir_list[i], ct_ex_prevdir);
open:
	/* open all children from common parent up to new dir */
	ct_file_extract_opento(newdirlist[i], newdir);

	ct_ex_prevdir = newdir;
	if (ct_ex_prevdir_list != NULL)
		e_free(&ct_ex_prevdir_list);
	ct_ex_prevdir_list = newdirlist;
}

void
ct_file_extract_enddir()
{
	if (ct_ex_prevdir == NULL)
		return;
	/* Close all open directories, we are switching files */
	ct_file_extract_closefrom(ct_ex_prevdir_list[0], ct_ex_prevdir);
	e_free(&ct_ex_prevdir_list);
	ct_ex_prevdir = NULL;
}

void
ct_file_extract_closefrom(struct dnode *parent, struct dnode *child)
{
#ifdef CT_NO_OPENAT
	struct timeval		tv[2];
	char			path[PATH_MAX];

#else
	struct timespec		ts[2];
#endif
	int                     safe_mode;

	if (child == parent)
		return;

	/* Set directory permissions to what they should be, then close it. */
	safe_mode = S_IRWXU | S_IRWXG | S_IRWXO;

#ifdef CT_NO_OPENAT
	snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
	    child->d_name);
	if (ct_attr) {
		if (chown(path, child->d_uid, child->d_gid) == -1) {
			if (errno == EPERM && geteuid() != 0) {
				if (ct_verbose)
					CWARN("can't chown directory: %s",
					    child->d_name);
			} else {
				CFATAL("can't chown directory \"%s\"",
				    child->d_name);
			}
		} else {
			safe_mode = ~0;
		}
	}
	if (chmod(path, child->d_mode & safe_mode) == -1) {
		CFATAL("can't chmod directory \"%s\"", child->d_name);
	}
	if (ct_attr) {
		tv[0].tv_sec = child->d_atime;
		tv[1].tv_sec = child->d_mtime;
		tv[0].tv_usec = tv[1].tv_usec = 0;
		if (utimes(path, tv) == -1)
			CFATAL("utimes on \"%s\" failed", child->d_name);
	}
#else
	if (ct_attr) {
		if (fchown(child->d_fd, child->d_uid, child->d_gid) == -1) {
			if (errno == EPERM && geteuid() != 0) {
				if (ct_verbose)
					CWARN("can't chown directory: %s",
					    child->d_name);
			} else {
				CFATAL("can't chown directory \"%s\"",
				    child->d_name);
			}
		} else {
			safe_mode = ~0;
		}
	}
	if (fchmod(child->d_fd, child->d_mode & safe_mode) == -1)
		CFATAL("can't chmod directory \"%s\"", child->d_name);
	if (ct_attr) {
		ts[0].tv_sec = child->d_atime;
		ts[1].tv_sec = child->d_mtime;
		ts[0].tv_nsec = ts[1].tv_nsec = 0;
		if (futimens(child->d_fd, ts) == -1)
			CFATAL("futimens on \"%s\" failed", child->d_name);
	}
	close(child->d_fd);
#endif
	child->d_fd = -2;

	ct_file_extract_closefrom(parent, child->d_parent);
}

void
ct_file_extract_opento(struct dnode *parent, struct dnode *child)
{
	int			createtries = 0, chmodtries = 0, savederrno;
#ifdef CT_NO_OPENAT
	struct stat		sb;
	char			path[PATH_MAX];
	int			ret;
#endif

	if (child == parent)
		return;

	ct_file_extract_opento(parent, child->d_parent);
	/* check it exists, if it does not, create it */
try_again:
	/* XXX O_SEARCH would be applicable here but openbsd doesn't have it */
#ifdef CT_NO_OPENAT
	if (child->d_name[0] == '/') {
		strlcpy(path, child->d_name, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    child->d_name);
	}
	if (ct_follow_symlinks) {
		ret = stat(path, &sb);
	} else {
		ret = lstat(path, &sb);
	}

	if (ret != 0) {
		savederrno = errno;
		/* if it doesn't exist, make the file with safe permissions */
		if (errno == ENOENT && createtries++ == 0 &&
		    mkdir(path, S_IRWXU) == 0)
			goto try_again;
		/* if it exists but we can't access it, try and chmod the dir */
		if (errno == EACCES && chmodtries++ == 0 &&
		    chmod(path, S_IRWXU) == 0)
			goto try_again;
		errno = savederrno;
		CWARN("can't open directory %s", child->d_name);
	}
#else
	if ((child->d_fd = openat(child->d_parent->d_fd, child->d_sname,
	    O_DIRECTORY | O_RDONLY |
	    ct_follow_symlinks ? 0 : O_NOFOLLOW)) == -1) {
		savederrno = errno;
		/* if it doesn't exist, make the file with safe permissions */
		if (errno == ENOENT && createtries++ == 0 &&
		    mkdirat(child->d_parent->d_fd, child->d_sname,
		    S_IRWXU) == 0)
			goto try_again;
		/* if it exists but we can't access it, try and chmod the dir */
		if (errno == EACCES && chmodtries++ == 0 &&
		    fchmodat(child->d_parent->d_fd, child->d_sname,
			S_IRWXU, ct_follow_symlinks ? 0 :
			AT_SYMLINK_NOFOLLOW) == 0)
			goto try_again;
		errno = savederrno;
		CWARN("can't open directory %s", child->d_name);
	}
#endif
}

int
ct_stat(struct fnode *fnode, struct stat *sb, int follow_symlinks, int extract)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if ((extract ? fnode->fl_sname : fnode->fl_fname)[0] == '/') {
		strlcpy(path, extract ? fnode->fl_sname : fnode->fl_fname,
		    sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    extract ? fnode->fl_sname : fnode->fl_fname);
	}
	if (ct_follow_symlinks)
		return (stat(path, sb));
	else
		return (lstat(path, sb));
#else
	return (fstatat(fnode->fl_parent_dir->d_fd,
	    fnode->fl_fname, sb, follow_symlinks ? 0 :
	    AT_SYMLINK_NOFOLLOW));
#endif
}

int
ct_open(struct fnode *fnode, int flags, int follow_symlinks)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_fname[0] == '/') {
		strlcpy(path, fnode->fl_fname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_fname);
	}

	return (open(path, flags | follow_symlinks ? 0 : O_NOFOLLOW));
#else
	return (openat(fnode->fl_parent_dir->d_fd, fnode->fl_fname,
	    flags | follow_symlinks ? 0 : O_NOFOLLOW));
#endif
}

int
ct_mkdir(struct fnode *fnode, mode_t mode)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	return (mkdir(path, mode));
#else
	return (mkdirat(fnode->fl_parent_dir->d_fd, fnode->fl_name, mode));
#endif
}

int
ct_mknod(struct fnode *fnode)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	return (mknod(path, fnode->fl_mode, fnode->fl_dev));
#else
	return (mknodat(fnode->fl_parent_dir->d_fd, fnode->fl_name,
	    fnode->fl_mode, fnode->fl_dev));
#endif
}

int
ct_link(struct fnode *fnode, char *destination)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	return (link(destination, path));
#else
	return (linkat(AT_FDCWD, destination, fnode->fl_parent_dir->d_fd,
	    fnode->fl_name, AT_SYMLINK_FOLLOW));
#endif
}

int
ct_readlink(struct fnode *fnode, char *mylink, size_t mylinksz)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_fname[0] == '/') {
		strlcpy(path, fnode->fl_fname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_fname);
	}

	return (readlink(path, mylink, mylinksz));
#else
	return (readlinkat(fnode->fl_parent_dir->d_fd, fnode->fl_fname,
	    mylink, mylinksz));
#endif
}

int
ct_symlink(struct fnode *fnode)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	return (symlink(fnode->fl_hlname, path));
#else
	return (symlinkat(fnode->fl_hlname, fnode->fl_parent_dir->d_fd,
	    fnode->fl_name));
#endif
}

int
ct_rename(struct fnode *fnode)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	return (rename(fnode->fl_fname, path));
#else
	return (renameat(fnode->fl_parent_dir->d_fd, fnode->fl_fname,
	    fnode->fl_parent_dir->d_fd, fnode->fl_name));
#endif
}

int
ct_chmod(struct fnode *fnode, mode_t mode)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	return (chmod(path, mode));
#else
	return (fchmodat(fnode->fl_parent_dir->d_fd, fnode->fl_name, mode, 0));
#endif
}

int
ct_chown(struct fnode *fnode, int follow_symlinks)
{
#ifdef CT_NO_OPENAT
	char	path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}
	if (follow_symlinks)
		return (chown(path, fnode->fl_uid,
		    fnode->fl_gid));
	else
		return (lchown(path, fnode->fl_uid,
		   fnode->fl_gid));
#else
	return (fchownat(fnode->fl_parent_dir->d_fd,
	    fnode->fl_name, fnode->fl_uid,
	    fnode->fl_gid, follow_symlinks ? 0 : AT_SYMLINK_NOFOLLOW));
#endif
}

int
ct_utimes(struct fnode *fnode)
{
#ifdef CT_NO_OPENAT
	char		path[PATH_MAX];
	struct timeval	tv[2];

	tv[0].tv_sec = fnode->fl_atime;
	tv[1].tv_sec = fnode->fl_mtime;
	tv[0].tv_usec = tv[1].tv_usec = 0;

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}

	return (utimes(path, tv));
#else
	struct timespec	ts[2];

	ts[0].tv_sec = fnode->fl_atime;
	ts[1].tv_sec = fnode->fl_mtime;
	ts[0].tv_nsec = ts[1].tv_nsec = 0;

	return (utimensat(fnode->fl_parent_dir->d_fd,
	    fnode->fl_name, ts, 0));
#endif
}

int
ct_unlink(struct fnode *fnode)
{
#ifdef CT_NO_OPENAT
	char		path[PATH_MAX];

	if (fnode->fl_sname[0] == '/') {
		strlcpy(path, fnode->fl_sname, sizeof(path));
	} else {
		snprintf(path, sizeof(path), "%s/%s", ct_rootdir.d_name,
		    fnode->fl_sname);
	}

	return (unlink(path));
#else
	return (unlinkat(fnode->fl_parent_dir->d_fd, fnode->fl_name, 0));
#endif
}
