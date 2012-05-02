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

#ifndef CT_TYPES_H
#define CT_TYPES_H

#include <sys/tree.h>
#include <sys/queue.h>
#include <stdint.h>
#include <openssl/sha.h>

#include <ctutil.h>

#define CT_KEY_LEN	(256>>3)
#define CT_IV_LEN	(256>>3)

struct fnode {
	/* TAILQ_ENTRY(fnode)	fl_list; */
	char			*fl_hlname;
	struct dnode		*fl_parent_dir;
	struct dnode		*fl_curdir_dir;
	int			fl_hardlink;
	dev_t			fl_dev;
	ino_t			fl_ino;
	uint64_t		fl_idx;
	dev_t			fl_rdev;
	uint32_t		fl_uid;
	uint32_t		fl_gid;
	int			fl_mode;
	int64_t			fl_atime;
	int64_t			fl_mtime;
	int			fl_type;
	off_t			fl_size;
	off_t			fl_offset;
	off_t			fl_comp_size;
	char			*fl_fname;
	char			*fl_name; /* name without directory */
	char			*fl_sname;
	int			fl_state;
#define CT_FILE_START		(0)
#define CT_FILE_PROCESSING	(1)
#define CT_FILE_FINISHED	(2)
	SHA_CTX			fl_shactx;
	int			fl_skip_file;
};

struct dnode {
	RB_ENTRY(dnode)		 d_rb_name;
	RB_ENTRY(dnode)		 d_rb_num;
	int64_t			 d_num;
	struct dnode		*d_parent;
	char			*d_name;
	char			*d_sname;
	int			 d_fd; /* valid if processing */
	uint32_t                 d_uid;         /* user id */
	uint32_t                 d_gid;         /* group id */
	uint32_t                 d_mode;        /* file mode */
	int                      d_atime;       /* last access time */
	int                      d_mtime;       /* last modification time */
};

void			ct_free_fnode(struct fnode *);

/*
 * remote listing structures.
 */
SIMPLEQ_HEAD(ctfile_list, ctfile_list_file);
RB_HEAD(ctfile_list_tree, ctfile_list_file);
RB_PROTOTYPE(ctfile_list_tree, ctfile_list_file, next, ct_cmp_ctfile);

struct ctfile_list_file {
	union {
		RB_ENTRY(ctfile_list_file)	nxt;
		SIMPLEQ_ENTRY(ctfile_list_file)	lnk;
	}					mlf_entries;
#define mlf_next	mlf_entries.nxt
#define mlf_link	mlf_entries.lnk
	char					mlf_name[CT_CTFILE_MAXLEN];
	off_t					mlf_size;
	time_t					mlf_mtime;
	int					mlf_keep;
};

/* debug log levels */
/* 0x1 and 0x2 taken by ctutil */
#define CT_LOG_SOCKET	(CTUTIL_LOG_SOCKET)
#define	CT_LOG_CONFIG	(CTUTIL_LOG_CONFIG)
#define	CT_LOG_EXUDE	(0x004)
#define	CT_LOG_NET	(0x008)
#define	CT_LOG_TRANS	(0x010)
#define	CT_LOG_SHA	(0x020)
#define	CT_LOG_CTFILE	(0x040)
#define	CT_LOG_DB	(0x080)
#define	CT_LOG_CRYPTO	(0x100)
#define	CT_LOG_FILE	(0x200)
#define	CT_LOG_XML	(0x400)
#define	CT_LOG_VERTREE	(0x800)

#endif /* ! CT_TYPES_H */
