/* $cyphertite$ */
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
#include <sys/tree.h>
#include <sys/queue.h>

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <libgen.h>
#include <fts.h>
#include <pwd.h>
#include <limits.h>
#include <readpassphrase.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"

__attribute__((__unused__)) static const char *cvstag = "$cyphertite$";

struct flist_head	fl_list_head = TAILQ_HEAD_INITIALIZER(fl_list_head);
struct fnode		*fl_curnode;
struct flist		*fl_lcurnode;

struct dir_stat;

int			 ct_cmp_dirlist(struct dir_stat *, struct dir_stat *);
struct fnode		*ct_populate_fnode_from_flist(struct flist *);
char			*ct_name_to_safename(char *);
void			 ct_traverse(char **, char **, int);

RB_HEAD(ct_dir_lookup, dir_stat) ct_dir_rb_head =
    RB_INITIALIZER(&ct_dir_rb_head);

/* dir stat data */
struct dir_stat {
	SIMPLEQ_ENTRY(dir_stat) ds_list;
	RB_ENTRY(dir_stat)	ds_rb;
	char                    *ds_name;
	uint32_t                ds_uid;         /* user id */
	uint32_t                ds_gid;         /* group id */
	uint32_t                ds_mode;        /* file mode */
	int                     ds_atime;       /* last access time */
	int                     ds_mtime;       /* last modification time */
};

void			ct_insert_dir(struct dir_stat *);

RB_GENERATE(ct_dir_lookup, dir_stat, ds_rb, ct_cmp_dirlist);

int
ct_cmp_dirlist(struct dir_stat *d1, struct dir_stat *d2)
{
	return strcmp(d1->ds_name, d2->ds_name);
}

RB_PROTOTYPE(ct_dir_lookup, dir_stat, ds_rb, ct_cmp_dirlist);

int                      ct_dname_cmp(struct dnode *, struct dnode *);
int                      ct_dnum_cmp(struct dnode *, struct dnode *);

struct d_name_tree ct_dname_head = RB_INITIALIZER(&ct_dname_head);
struct d_num_tree ct_dnum_head = RB_INITIALIZER(&ct_dnum_head);

RB_GENERATE(d_name_tree, dnode, d_rb_name, ct_dname_cmp);
RB_GENERATE(d_num_tree, dnode, d_rb_num, ct_dnum_cmp);

int
ct_dname_cmp(struct dnode *d1, struct dnode *d2)
{
	return strcmp(d2->d_name, d1->d_name);
}

int
ct_dnum_cmp(struct dnode *d1, struct dnode *d2)
{
	return (d1->d_num < d2->d_num ? -1 : d1->d_num > d2->d_num);
}

SIMPLEQ_HEAD(, dir_stat) dirlist;

void
ct_insert_dir(struct dir_stat *ds)
{
	struct dir_stat *oldds;
	oldds = RB_INSERT(ct_dir_lookup, &ct_dir_rb_head, ds);
	if (oldds) {
		if (ct_multilevel_allfiles == 0) {
			oldds->ds_mode = ds->ds_mode;
			oldds->ds_atime = ds->ds_atime;
			oldds->ds_mtime = ds->ds_mtime;
			oldds->ds_uid = ds->ds_uid;
			oldds->ds_gid = ds->ds_gid;
		}
		e_free(&ds);
	} else {
		SIMPLEQ_INSERT_HEAD(&dirlist, ds, ds_list);
	}
}

void
ct_flnode_cleanup(void)
{
	struct flist *flnode;
	struct dnode *dnode;

	while (!TAILQ_EMPTY(&fl_list_head)) {
		flnode = TAILQ_FIRST(&fl_list_head);
		TAILQ_REMOVE(&fl_list_head, flnode, fl_list);
		if (flnode->fl_fname)
			e_free(&flnode->fl_fname);
		e_free(&flnode);
	}

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
	e_free(&fnode);

}

int				stop;

char *eat_double_dots(char *, char *);
int backup_prefix(char *);
int ct_sched_backup_file(struct stat *, char *);
int s_to_e_type(int);

int current_fd = -1;
int ct_extract_fd = -1;
struct fnode *ct_ex_curnode;
char	tpath[PATH_MAX];

struct fl_tree		fl_rb_head = RB_INITIALIZER(&fl_rb_head);

RB_GENERATE(fl_tree, flist, fl_inode_entry, fl_inode_sort);

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

char *
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

char *
gen_fname(struct flist *flnode)
{
	char *name;

	if (flnode->fl_parent_dir) {
		e_asprintf(&name, "%s/%s", flnode->fl_parent_dir->d_name,
		    flnode->fl_fname);
	} else {
		name = e_strdup(flnode->fl_fname);
	}

	return name;
}

struct dnode *
gen_finddir(int64_t idx)
{
	struct dnode dsearch;

	dsearch.d_num = idx;
	return RB_FIND(d_num_tree, &ct_dnum_head, &dsearch);
}


struct fnode *
ct_populate_fnode_from_flist(struct flist *flnode)
{
	struct fnode		*fnode;
	const char		*safe;
	struct stat		*sb, sbstore;
	struct dnode		dsearch, *dfound;
	char			*hlname;
	int			 rc;
	char			*fname;

	fname = gen_fname(flnode);
	CINFO("alloc1 %p", fname);

	sb = &sbstore;
	rc = lstat(fname, sb);

	if (rc == -1) {
		/* file no longer available return failure */
		return NULL;
	}

	fnode = e_calloc(1, sizeof(*fnode));

	/*
	 * ct_name_to_safename has run before and not returned failure
	 * so safe to not check for failure here
	 */

	fnode->fl_fname = fname;
	fnode->fl_sname = e_strdup(ct_name_to_safename(fnode->fl_fname));
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

	/* either the parent is NULL (which is fine) or is our parent */
	fnode->fl_parent_dir = flnode->fl_parent_dir;

	fnode->fl_state = CT_FILE_START;
	ct_sha1_setup(&fnode->fl_shactx);

	if (C_ISDIR(fnode->fl_type)) {
		dsearch.d_name = fnode->fl_fname;
		dfound = RB_FIND(d_name_tree, &ct_dname_head, &dsearch);
		if (dfound == NULL)
			CFATALX("directory not found in d_name_tree %s",
			    fnode->fl_fname);
		fnode->fl_curdir_dir = dfound;
	}

	if (flnode->fl_hlnode != NULL) {
		fnode->fl_hardlink = 1;
		fnode->fl_type = C_TY_LINK;
		hlname = gen_fname(flnode->fl_hlnode);
		CINFO("alloc2 %p", hlname);
		safe = ct_name_to_safename(hlname);
		fnode->fl_hlname = e_strdup(safe);
		e_free(&hlname);
	}

	return fnode;
}

int
ct_sched_backup_file(struct stat *sb, char *filename)
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

	if (S_ISDIR(sb->st_mode)) {
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
			CDBG("inserted %s", filename);
	}

	//ct_numalloc++;
	flnode = e_calloc(1, sizeof (*flnode));

	flnode->fl_dev = sb->st_dev;
	flnode->fl_ino = sb->st_ino;
	flnode->fl_parent_dir = NULL;

	if (dnode != NULL) {
		dnode->d_flnode = flnode;
	}

	strlcpy(fname_buf, filename, sizeof(fname_buf));
	dsearch.d_name = dirname(fname_buf);
	dfound = RB_FIND(d_name_tree, &ct_dname_head, &dsearch);
	if (dfound != NULL) {
		flnode->fl_parent_dir = dfound;
		CDBG("parent of %s is %s", filename, dfound->d_name);
		strlcpy(fname_buf, filename, sizeof(fname_buf));
		flnode->fl_fname = e_strdup(basename(fname_buf));
		CDBG("setting name of %s as %s", filename, flnode->fl_fname);
	} else {
		flnode->fl_fname = e_strdup(filename);
		CDBG("parent of %s is not found [%s]", flnode->fl_fname,
		    dsearch.d_name);
	}

	flnode->fl_hlnode = NULL;

	/* deal with hardlink */
	flnode_exists = RB_INSERT(fl_tree, &fl_rb_head, flnode);
	if (flnode_exists != NULL) {
		flnode->fl_hlnode = flnode_exists;
		CDBG("found %s as hardlink of %s", safe,
		    ct_name_to_safename(flnode->fl_hlnode->fl_fname));
	} else {
		if (S_ISREG(sb->st_mode))
			ct_stats->st_bytes_tot += sb->st_size;
	}
	ct_stats->st_files_scanned++;

	TAILQ_INSERT_TAIL(&fl_list_head, flnode, fl_list);

	return 0;
}

void
ct_archive(struct ct_op *op)
{
	const char		*mfile = op->op_local_fname;
	char			**filelist = op->op_filelist;
	const char		*basisbackup = op->op_basis;
	size_t			rsz, rlen;
	struct stat		sb;
	struct ct_trans		*ct_trans;
	char			cwd[PATH_MAX];
	int			new_file = 0;
	int			error;
	int			skip_file;
	int			nextlvl = 0;

	CDBG("processing");
	/* XXX if state finished jump to done */
	if (ct_state->ct_file_state == CT_S_STARTING) {
		if (*filelist == NULL) {
			CFATALX("no files specified");
		}

		if (basisbackup != NULL &&
		    (nextlvl = ct_basis_setup(basisbackup, filelist)) == 0)
			e_free(&basisbackup);

		if (getcwd(cwd, PATH_MAX) == NULL)
			CFATAL("can't get current working directory");
		/* XXX - deal with stdin */
		/* XXX - if basisbackup should the type change ? */
		ct_setup_write_md(mfile, CT_MD_REGULAR, basisbackup, nextlvl,
		    cwd, filelist);

		if (basisbackup != NULL)
			e_free(&basisbackup);

		ct_traverse(filelist, op->op_excludelist, op->op_matchmode);

		/*
		 * it is possible the first files may have been deleted
		 * before the scan completes, in that case skip
		 * to the first existing node for fl_lcurnode/fl_curnode
		 */
		fl_lcurnode = TAILQ_FIRST(&fl_list_head);
		do {
			fl_curnode = ct_populate_fnode_from_flist(fl_lcurnode);
			if (fl_curnode == NULL)
				fl_lcurnode = TAILQ_NEXT(fl_lcurnode, fl_list);
		} while (fl_lcurnode != NULL && fl_curnode == NULL);
	} else if (ct_state->ct_file_state == CT_S_FINISHED)
		return;

	ct_set_file_state(CT_S_RUNNING);

	if (fl_curnode == NULL)
		goto done;
loop:
	CDBG("file %s state %d", fl_curnode->fl_sname, fl_curnode->fl_state);
	new_file = (fl_curnode->fl_state == CT_FILE_START);

	/* allocate transaction */
	ct_trans = ct_trans_alloc();
	if (ct_trans == NULL) {
		/* system busy, return */
		CDBG("ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}

	/* handle special files */
	if (!C_ISREG(fl_curnode->fl_type)) {
		if (C_ISDIR(fl_curnode->fl_type)) {
			/*
			 * we do want to skip old directories with
			 * no (new) files in them
			 */
			error = lstat(fl_curnode->fl_fname, &sb);
			if (error) {
				CWARN("archive: dir %s stat error",
				    fl_curnode->fl_sname);
			} else {
				if (sb.st_mtime < ct_prev_backup_time) {
					if (ct_verbose > 1)
						CDBG("skipping dir"
						    " based on mtime %s",
						    fl_curnode->fl_sname);
					fl_curnode->fl_skip_file = 1;
				}
			}
		}
		ct_trans->tr_fl_node = fl_curnode;
		fl_curnode->fl_state = CT_FILE_FINISHED;
		fl_curnode->fl_size = 0;
		ct_trans->tr_state = TR_S_SPECIAL;
		ct_trans->tr_type = TR_T_SPECIAL;
		ct_trans->tr_trans_id = ct_trans_id++;
		ct_trans->tr_eof = 0;
		ct_queue_transfer(ct_trans);
		goto next_file;
	}

	/* do not open zero length files */
	if (new_file) {
		fl_curnode->fl_state = CT_FILE_PROCESSING;
		if (current_fd != -1) {
			CFATALX("state error, new file open,"
			    " sz %zu offset %zu",
			    fl_curnode->fl_size,
			    fl_curnode->fl_offset);
		}
		current_fd = open(fl_curnode->fl_fname, O_RDONLY);

		if (current_fd == -1) {
			CWARN("archive: unable to open file '%s'",
			    fl_curnode->fl_sname);
			ct_trans_free(ct_trans);
			fl_curnode->fl_state = CT_FILE_FINISHED;
			goto next_file;
		}

		skip_file = 0;
		error = fstat(current_fd, &sb);
		if (error) {
			CWARN("archive: file %s stat error",
			    fl_curnode->fl_sname);
		} else {
			if (sb.st_mtime < ct_prev_backup_time) {
				if (ct_verbose > 1)
					CINFO("skipping file based on mtime %s",
					    fl_curnode->fl_sname);
				skip_file = 1;
				fl_curnode->fl_skip_file = skip_file;
			}
		}
		ct_trans->tr_fl_node = fl_curnode;
		ct_trans->tr_state = TR_S_FILE_START;
		ct_trans->tr_type = TR_T_WRITE_HEADER;
		ct_trans->tr_trans_id = ct_trans_id++;
		if (fl_curnode->fl_size == 0 || skip_file) {
			close(current_fd);
			current_fd = -1;
			ct_trans->tr_eof = 1;
			fl_curnode->fl_state = CT_FILE_FINISHED;
		} else {
			ct_trans->tr_eof = 0;
		}
		ct_queue_transfer(ct_trans);
		if (fl_curnode->fl_size == 0 || skip_file) {
			goto next_file;
		}
		goto loop;
	} else {
		if (current_fd == -1) {
			CFATALX("state error, old file not open,"
			    " sz %zu offset %zu",
			    fl_curnode->fl_size,
			    fl_curnode->fl_offset);
		}
	}

	/* perform read */
	rsz = fl_curnode->fl_size - fl_curnode->fl_offset;
	CDBG("rsz %zu max %d", rsz, ct_max_block_size);
	if (rsz > ct_max_block_size) {
		rsz = ct_max_block_size;
	}
	ct_trans->tr_dataslot = 0;
	rlen = read(current_fd, ct_trans->tr_data[0], rsz);

	ct_stats->st_bytes_read += rlen;

	ct_trans->tr_fl_node = fl_curnode;
	ct_trans->tr_size[0] = rlen;
	ct_trans->tr_chsize = rlen;
	ct_trans->tr_state = TR_S_READ;
	ct_trans->tr_type = TR_T_WRITE_CHUNK;
	ct_trans->tr_trans_id = ct_trans_id++;
	ct_trans->tr_eof = 0;
	ct_trans->hdr.c_flags = 0;
	CDBG("read %zd for block %" PRIu64, rlen, ct_trans->tr_trans_id);

	/* update offset */
	if (rsz != rlen || rlen == 0 ||
	    ((rlen + fl_curnode->fl_offset) == fl_curnode->fl_size)) {
		/* short read, file truncated, or end of file */
		/* restat file for modifications */
		error = fstat(current_fd, &sb);
		if (error) {
			CWARN("archive: file %s stat error",
			    fl_curnode->fl_sname);
		} else if (sb.st_size != fl_curnode->fl_size) {
			CWARNX("file truncated during backup");
			/*
			 * may need to perform special nop processing
			 * to pad archive file to right number of chunks
			 */
		}
		CDBG("going to next file %s", fl_curnode->fl_sname);
		CDBG("setting eof on trans %" PRIu64 " %s",
		    ct_trans->tr_trans_id, fl_curnode->fl_sname);
		close(current_fd);
		current_fd = -1;
		ct_trans->tr_eof = 1;

		fl_curnode->fl_offset = fl_curnode->fl_size;
		fl_curnode->fl_state = CT_FILE_FINISHED;
	} else {
		fl_curnode->fl_offset += rlen;
	}
	ct_queue_transfer(ct_trans);

	/* if file finished, update curnode to next node in list */
	/* XXX is there other file metadata that needs to be saved?  */
next_file:
	/* XXX should node be removed from list at this time? */
	if (fl_curnode->fl_state == CT_FILE_FINISHED) {
		/*
		 * if files are deleted ct_populate_fnode_from_flist()
		 * will return NULL, so keep walking the list
		 */
		do {
			fl_lcurnode = TAILQ_NEXT(fl_lcurnode, fl_list);
			if (fl_lcurnode == NULL) {
				CDBG("no more files");
				fl_curnode = NULL;
			} else {
				fl_curnode =
				    ct_populate_fnode_from_flist(fl_lcurnode);
			}
		} while (fl_lcurnode != NULL && fl_curnode == NULL);
		if (fl_curnode != NULL)
			CDBG("going to next file %s", fl_curnode->fl_sname);
	}

	if (fl_curnode != NULL)
		goto loop;

done:
	CDBG("last file read");
	/* done with backup */
	ct_set_file_state(CT_S_FINISHED);

	ct_trans = ct_trans_alloc();
	if (ct_trans == NULL) {
		/* system busy, return */
		CDBG("ran out of transactions, waiting");
		ct_set_file_state(CT_S_WAITING_TRANS);
		return;
	}
	ct_trans->tr_fl_node = NULL;
	ct_trans->tr_state = TR_S_DONE;
	ct_trans->tr_eof = 0;
	ct_trans->tr_trans_id = ct_trans_id++;
	ct_queue_transfer(ct_trans);
}

void
ct_traverse(char **paths, char **exclude, int match_mode)
{
	FTS			*ftsp;
	FTSENT			*fe;
	struct ct_match		*include_match = NULL, *exclude_match = NULL;
	char			 clean[PATH_MAX];
	int			 fts_options;

	if (ct_includefile)
		include_match = ct_match_fromfile(ct_includefile, match_mode);
	if (exclude)
		exclude_match = ct_match_compile(match_mode, exclude);

	fts_options = FTS_PHYSICAL | FTS_NOCHDIR;
	if (ct_no_cross_mounts)
		fts_options |= FTS_XDEV;
	ftsp = fts_open(paths, fts_options, NULL);
	if (ftsp == NULL)
		CFATAL("fts_open failed");

	while ((fe = fts_read(ftsp)) != NULL) {
		switch (fe->fts_info) {
		case FTS_D:
		case FTS_DEFAULT:
		case FTS_F:
		case FTS_SL:
		case FTS_SLNONE:
			/* these are ok */
			break;
		case FTS_DP:
			continue;
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

		/* sanitize path */
		if (eat_double_dots(fe->fts_path, clean) == NULL)
			CFATAL("can't sanitize %s", fe->fts_path);

		/* backup dirs above fts starting point */
		if (fe->fts_level == 0)
			if (backup_prefix(clean))
				CFATAL("backup_prefix failed");

		/*
		 * First check to see if it matches any include file we have
		 * Then, if it is matched by the exclude file then ignore it
		 * anyway.
		 */
		if (include_match && ct_match(include_match, clean)) {
			CDBG("failing %s: not in include list", clean);
			continue;
		}
		if (exclude_match && !ct_match(exclude_match, clean)) {
			CINFO("failing %s: in exclude list", clean);
			continue;
		}

		/* backup all other files */
		if (ct_sched_backup_file(fe->fts_statp, clean))
			CFATAL("backup_file failed: %s", clean);

	}

	if (fe == NULL && errno)
		CFATAL("fts_read failed");
	if (fts_close(ftsp))
		CFATAL("fts_close failed");
	if (include_match)
		ct_match_unwind(include_match);
	if (exclude_match)
		ct_match_unwind(exclude_match);
	gettimeofday(&ct_stats->st_time_scan_end, NULL);
}

char *
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

int
backup_prefix(char *root)
{
	char			dir[PATH_MAX], pfx[PATH_MAX], *cp, *p;
	struct stat		sb;

	/* it is just the prefix that needs to be parsed */
	strlcpy(pfx, dirname(root), sizeof pfx);

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

		if (stat(dir, &sb))
			return (1);

		/* file type changed since fts_open */
		if (!S_ISDIR(sb.st_mode)) {
			errno = ENOTDIR;
			return (1);
		}

		if (ct_sched_backup_file(&sb, dir))
			return (1);
	}

	return (0);
}

int
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

int
ct_file_extract_open(struct fnode *fnode)
{
	char		dirpath[PATH_MAX], *dirp;
	int		tries = 0;
	/*
	 * XXX - this should open a temporary file and rename
	 * XXX - on EX_FILE_END
	 */
	CDBG("opening %s for writing", fnode->fl_sname);
	if (ct_extract_fd != -1) {
		CFATALX("file open on extract_open");
	}
	snprintf(tpath, sizeof tpath, "%s%s%s",
	    ct_tdir ? ct_tdir : "", ct_tdir ? "/" : "", fnode->fl_sname);
	ct_ex_curnode = fnode;

	strlcpy(dirpath, tpath, sizeof(dirpath));
	if ((dirp = dirname(dirpath)) == NULL)
		CFATALX("can't get dirname of secrets file");
	if (fnode->fl_fname)
		e_free(&fnode->fl_fname);
	e_asprintf(&fnode->fl_fname, "%s/%s", dirp, "cyphertite.XXXXXXXXXX");
again:
	if ((ct_extract_fd = mkstemp(fnode->fl_fname)) == -1) {
		/*
		 * with -C or regex we may not have dependant directories in
		 * our list of paths to operate on. ENOENT here means we're
		 * lacking one of the path elements, so try to recursively
		 * create the directory.
		 */
		if (errno == ENOENT && tries++ == 0 &&
		    ct_make_full_path(tpath, 0777) == 0)
			goto again;
		/* XXX make_full_path may modify the path we want */
		CWARN("unable to open file for writing %s%s%s", 
		    ct_tdir ? ct_tdir : "", ct_tdir ? "/" : "",
		    fnode->fl_sname);
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

	if (fchmod(ct_extract_fd, fnode->fl_mode) == -1)
		CFATAL("chmod failed on %s", tpath);

	if (ct_attr) {
		if (fchown(ct_extract_fd, fnode->fl_uid, fnode->fl_gid) == -1) {
			if (errno == EPERM && geteuid() != 0) {
				if (ct_verbose)
					CWARN("chown failed: %s", tpath);
			} else {
				CFATAL("chown failed %s", tpath);
			}
		}

		tv[0].tv_sec = fnode->fl_atime;
		tv[1].tv_sec = fnode->fl_mtime;
		if (futimes(ct_extract_fd, tv) == -1)
			CFATAL("utimes failed");
	}
	if (rename(fnode->fl_fname, tpath) != 0)
		CFATAL("rename to %s failed", tpath);

	close(ct_extract_fd);
	ct_ex_curnode = NULL;
	ct_extract_fd = -1;
}

void
ct_file_extract_special(struct fnode *fnode)
{
	struct timeval          tv[2];
	char			apath[PATH_MAX];
	char			*appath;
	char			ltpath[PATH_MAX];
	int			tries = 0, ret = 0;

	snprintf(ltpath, sizeof ltpath, "%s%s%s",
	    ct_tdir ? ct_tdir : "", ct_tdir ? "/" : "", fnode->fl_sname);
	CDBG("special %s mode %d", ltpath, fnode->fl_mode);

	if(C_ISDIR(fnode->fl_type)) {
mkdir_again:
		if (mkdir(ltpath, 0700) != 0) {
			if (errno == ENOENT && tries == 0 &&
			    ct_make_full_path(ltpath, 0777) == 0) {
				tries++;
				goto mkdir_again;
			}
			if (errno != EEXIST) /* XXX check it is a dir */
				CWARN("can't create directory %s",
				    fnode->fl_sname);
		}
	} else if (C_ISBLK(fnode->fl_type) || C_ISCHR(fnode->fl_type))  {
mknod_again:
		if (mknod(ltpath, fnode->fl_mode, fnode->fl_dev) != 0) {
			if (errno == ENOENT && tries == 0 &&
			    ct_make_full_path(ltpath, 0777) == 0) {
				tries++;
				goto mknod_again;
			}
			if (errno != EEXIST) /* XXX check it is a spec node */
				CWARN("can't create special file %s",
				    fnode->fl_sname);
		}
	} else if (C_ISLINK(fnode->fl_type)){
		if (fnode->fl_hardlink && ct_tdir != NULL) {
			snprintf(apath, sizeof(apath), "%s/%s", ct_tdir,
			    fnode->fl_hlname);
			appath = apath;
		} else {
			appath = fnode->fl_hlname;
		}

link_again:
		if (fnode->fl_hardlink) {
			ret = link(appath, ltpath);
		} else {
			ret = symlink(appath, ltpath);
		}
		if (ret && errno == ENOENT && tries == 0 &&
		    ct_make_full_path(ltpath, 0777) == 0) {
			tries++;
			goto link_again;
		}
		if (ret)
			CWARN("%s failed: %s", fnode->fl_hardlink ?
			    "link" : "symlink", ltpath);
	} else {
		CFATALX("illegal file %s of type %d", ltpath, fnode->fl_mode);
	}

	if(C_ISDIR(fnode->fl_type)) {
		/* XXX - copy this data or just have pointer to fnode? */
		struct dir_stat *ds;
		ds = e_malloc(sizeof(struct dir_stat) +
		    strlen(fnode->fl_sname) + 1);

		ds->ds_name = (char *)ds + sizeof(struct dir_stat);
		strlcpy(ds->ds_name, fnode->fl_sname,
		    strlen(fnode->fl_sname) + 1);
		ds->ds_mode = fnode->fl_mode;
		ds->ds_atime = fnode->fl_atime;
		ds->ds_mtime = fnode->fl_mtime;
		ds->ds_uid = fnode->fl_uid;
		ds->ds_gid = fnode->fl_gid;

		/* insert at head to process in reverse order */
		ct_insert_dir(ds);
	} else if (C_ISLINK(fnode->fl_type)){
		if (!fnode->fl_hardlink) {
			/* symlinks have no 'real' permissions */
			if (ct_attr) {
				/* set the link's ownership */
				if (lchown(ltpath, fnode->fl_uid, fnode->fl_gid)
				    == -1) {
					if (errno == EPERM && geteuid() != 0) {
						if (ct_verbose)
							CWARN("lchown failed:"
							    " %s", ltpath);
					} else {
						CFATAL("lchown failed %s",
						    ltpath);
					}
				}
			}
		} else  {
			/* hardlinks have no mode/permissions */
			;
		}
	} else {
		if (chmod(ltpath, fnode->fl_mode) == -1)
			CFATAL("chmod failed on %s", ltpath);

		if (ct_attr) {
			if (chown(ltpath, fnode->fl_uid, fnode->fl_gid) == -1) {
				if (errno == EPERM && geteuid() != 0) {
					if (ct_verbose)
						CWARN("chown failed: %s",
						    ltpath);
				} else {
					CFATAL("chown failed %s", ltpath);
				}
			}

			tv[0].tv_sec = fnode->fl_atime;
			tv[1].tv_sec = fnode->fl_mtime;
			if (utimes(ltpath, tv) == -1)
				CFATAL("utimes failed");
		}
	}
}

void
ct_file_extract_fixup(void)
{
	struct dir_stat		*dsn;
	struct timeval		tv[2];
	char			tpath[PATH_MAX];

	while(!SIMPLEQ_EMPTY(&dirlist)) {
		dsn = SIMPLEQ_FIRST(&dirlist);
		SIMPLEQ_REMOVE_HEAD(&dirlist, ds_list);
		RB_REMOVE(ct_dir_lookup, &ct_dir_rb_head, dsn);

		snprintf(tpath, sizeof tpath, "%s%s%s",
		    ct_tdir ? ct_tdir : "", ct_tdir ? "/" : "", dsn->ds_name);

		if (chmod(tpath, dsn->ds_mode) == -1)
			CFATAL("chmod failed on %s", dsn->ds_name);

		if (ct_attr) {
			if (chown(tpath, dsn->ds_uid,
			    dsn->ds_gid) == -1) {
				if (errno == EPERM && geteuid() != 0) {
					if (ct_verbose)
						CWARN("chown failed: %s",
						    tpath);
				} else {
					CFATAL("chown failed %s", tpath);
				}
			}

			tv[0].tv_sec = dsn->ds_atime;
			tv[1].tv_sec = dsn->ds_mtime;
			if (utimes(tpath, tv) == -1)
				CFATAL("futimes failed");
		}
		e_free(&dsn);
	}

}

char *
ct_system_config(void)
{
	char			*conf;

	e_asprintf(&conf, "%s", "/etc/cyphertite/cyphertite.conf");

	return (conf);
}

char *
ct_user_config(void)
{
	char			*conf;
	struct			passwd *pwd;

	pwd = getpwuid(getuid());
	if (pwd == NULL)
		CFATALX("invalid user %d", getuid());

	e_asprintf(&conf, "%s/.cyphertite.conf", pwd->pw_dir);
	return (conf);
}

int
ct_get_answer(char *prompt, char *a1, char *a2, char *default_val,
    char *answer, size_t answer_len, int secret)
{
	char			*p;

	if (answer == NULL)
		return (-1);

	for (;;) {
		p = readpassphrase(prompt, answer, answer_len,
		    secret ? RPP_ECHO_OFF : RPP_ECHO_ON);
		if (p == NULL)
			CFATAL("readpassphrase");

		if (default_val && !strcmp(answer, "")) {
			strlcpy(answer, default_val, answer_len);
		}

		if (a1 == NULL && a2 == NULL)
			return (0); /* just get the string */

		/* check for proper answer */
		if (a1 && !strcasecmp(answer, a1))
			return (1);
		if (a2 && !strcasecmp(answer, a2))
			return (2);
		printf("please answer %s or %s\n", a1, a2);
	}

	return (-1);
}

int
ct_prompt_password(char *prompt, char *answer, size_t answer_len,
    char *answer2, size_t answer2_len)
{
	int			i;

	if (answer == NULL || answer2 == NULL)
		return (-1);

	for (i = 0 ; i < 2;) {
		switch (i) {
		case 0:
			if (ct_get_answer(prompt, NULL, NULL, NULL, answer,
			    answer_len, 1))
				CFATALX("password");

			if (strlen(answer) != 0 && strlen(answer) < 7) {
				printf("invalid password length\n");
				continue;
			}
			i++;
			break;
		case 1:
			if (ct_get_answer("confirm: ",
			    NULL, NULL, NULL, answer2, answer2_len, 1))
				CFATALX("password");

			if (strlen(answer2) != 0 && strlen(answer2) < 7) {
				printf("invalid password length\n");
				continue;
			}
			if (strcmp(answer, answer2)) {
				printf("passwords don't match\n");
				i = 0;
				continue;
			}

			i++;
			break;
		}
	}
	return (0);
}

void
ct_create_config(void)
{
	char			prompt[1024];
	char			answer[1024], answer2[1024];
	uint8_t			ad[SHA512_DIGEST_LENGTH];
	char			b64d[128];
	char			*conf_buf = NULL;
	char			*conf = NULL, *dir = NULL;
	char			*user = NULL, *password = NULL;
	char			*crypto_password = NULL;
	char			*md_mode = NULL, *md_cachedir = NULL;
	int			md_remote_diff = 0;
	int			rv, fd;
	FILE			*f = NULL;

	/* help user create config file */
	snprintf(prompt, sizeof prompt,
	    "%s config file not found. Create one? [yes]: ", __progname);
	if (ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0) != 1)
		CFATALX("%s requires a config file", __progname);

	conf_buf = ct_user_config();
	snprintf(prompt, sizeof prompt,
	    "Target conf file [%s]: ", conf_buf);
	ct_get_answer(prompt, NULL, NULL, conf_buf, answer,
	    sizeof answer, 0);
	if (conf_buf != NULL)
		e_free(&conf_buf);
	conf = e_strdup(answer);
	if (conf == NULL)
		CFATALX("conf");

	/*
	 * Make path and create conf file early so permission failures are
	 * are caught before the user fills out all of the information.
	 */
	conf_buf = strdup(conf);
	if (conf_buf == NULL)
		CFATALX("strdup conf");
	if (ct_make_full_path(conf_buf, 0700))
		CFATAL("unable to create directory %s", conf_buf);
	if (conf_buf != NULL)
		free(conf_buf);

	if ((fd = open(conf, O_RDWR | O_CREAT, 0400)) == -1)
		CFATAL("unable to open file for writing %s", conf);
	if ((f = fdopen(fd, "r+")) == NULL)
		CFATAL("unable to open file %s", conf);

	while (user == NULL) {
		snprintf(prompt, sizeof prompt,
		    "%s login username: ", __progname);
		if (ct_get_answer(prompt,
		    NULL, NULL, NULL, answer, sizeof answer, 0)) {
			printf("must supply username\n");
			continue;
		}
		if (strlen(answer) < 3) {
			printf("invalid username length\n");
			continue;
		}
		user = strdup(answer);
		if (user == NULL)
			CFATALX("strdup");
	}

	snprintf(prompt, sizeof prompt,
	    "Save %s login password to configuration file? [yes]: ",
	    __progname);
	rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0);

	if (rv == 1) {
		if (ct_prompt_password("login password: ", answer,
		    sizeof answer, answer2, sizeof answer2))
			CFATALX("password");

		if (strlen(answer)) {
			password = strdup(answer);
			if (password == NULL)
				CFATALX("strdup");
		}
		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	snprintf(prompt, sizeof prompt,
	    "Save %s crypto passphrase to configuration file? [yes]: ",
	    __progname);
	rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
	    sizeof answer, 0);

	if (rv == 1) {
		snprintf(prompt, sizeof prompt,
		    "Automatically generate crypto passphrase? [yes]: ");
		rv = ct_get_answer(prompt, "yes", "no", "yes", answer,
		    sizeof answer, 0);

		if (rv == 1) {
			arc4random_buf(answer2, sizeof answer2);
			ct_sha512((uint8_t *)answer2, ad, sizeof answer2);
			if (ct_base64_encode(CT_B64_ENCODE, ad,
			    sizeof ad, (uint8_t *)b64d, sizeof b64d))
				CFATALX("can't base64 encode "
				    "crypto passphrase");

			crypto_password = strdup(b64d);
			if (crypto_password == NULL)
				CFATALX("strdup");
		}
		else {
			if (ct_prompt_password("crypto passphrase: ", answer,
			    sizeof answer, answer2, sizeof answer2))
				CFATALX("password");

			if (strlen(answer)) {
				crypto_password = strdup(answer);
				if (crypto_password == NULL)
					CFATALX("strdup");
			}
		}

		bzero(answer, sizeof answer);
		bzero(answer2, sizeof answer2);
	}

	conf_buf = strdup(conf);
	if (conf_buf == NULL)
		CFATALX("strdup");
	dir = dirname(conf_buf);
	if (asprintf(&md_cachedir, "%s/.cyphertite_md_cachedir", dir) == -1)
		CFATALX("default md_cachedir");

	snprintf(prompt, sizeof prompt,
	    "Choose a metadata operation mode (remote/local) [remote]: ");
	rv = ct_get_answer(prompt, "remote", "local", "remote", answer,
	    sizeof answer, 0);
	md_mode = strdup(answer);
	if (md_mode == NULL)
		CFATALX("md_mode");

	if (rv == 1) {
		snprintf(prompt, sizeof prompt,
		    "Target metadata cache directory [%s]: ", md_cachedir);
		ct_get_answer(prompt, NULL, NULL, md_cachedir, answer,
		    sizeof answer, 0);
		if (md_cachedir != NULL)
			free(md_cachedir);
		md_cachedir = strdup(answer);
		if (md_cachedir == NULL)
			CFATALX("md_cachedir");

		snprintf(prompt, sizeof prompt,
		    "Use automatic remote differentials? [no]: ");
		rv = ct_get_answer(prompt, "yes", "no", "no", answer,
		    sizeof answer, 0);
		if (rv == 1)
			md_remote_diff = 1;
	}

	fprintf(f, "username\t\t\t= %s\n", user);
	if (password)
		fprintf(f, "password\t\t\t= %s\n", password);
	else
		fprintf(f, "#password\t\t\t=\n");
	if (crypto_password)
		fprintf(f, "crypto_password\t\t\t= %s\n", crypto_password);
	else
		fprintf(f, "#crypto_password\t\t=\n");

	fprintf(f, "cache_db\t\t\t= %s/.cyphertite.db\n", dir);
	fprintf(f, "session_compression\t\t= lzo\n");
	fprintf(f, "host\t\t\t\t= beta.cyphertite.com\n");
	fprintf(f, "hostport\t\t\t= 31337\n");
	fprintf(f, "crypto_secrets\t\t\t= %s/.cyphertite.crypto\n", dir);
	fprintf(f, "ca_cert\t\t\t\t= %s/cyphertite/ct_ca.crt\n", dir);
	fprintf(f, "cert\t\t\t\t= %s/cyphertite/ct_%s.crt\n", dir, user);
	fprintf(f, "key\t\t\t\t= %s/cyphertite/private/ct_%s.key\n", dir, user);

	fprintf(f, "md_mode\t\t\t\t= %s\n", md_mode);
	if (strcmp(md_mode, "remote") == 0) {
		fprintf(f, "md_cachedir\t\t\t= %s\n", md_cachedir);
		fprintf(f, "md_remote_auto_differential\t= %d", md_remote_diff);
	}
	else
	{
		fprintf(f, "#md_cachedir\t\t\t= %s\n", md_cachedir);
		fprintf(f, "#md_remote_auto_differential\t= %d",
		    md_remote_diff);
	}

	printf("Configuration file created.\n");

	if (conf_buf)
		free(conf_buf);
	if (user)
		free(user);
	if (password) {
		bzero(password, strlen(password));
		free(password);
	}
	if (crypto_password) {
		bzero(crypto_password, strlen(crypto_password));
		free(crypto_password);
	}
	if (md_mode)
		free(md_mode);
	if (md_cachedir)
		free(md_cachedir);
	if (f)
		fclose(f);
}
