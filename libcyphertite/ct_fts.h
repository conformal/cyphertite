/*	$OpenBSD: fts.h,v 1.14 2012/12/05 23:19:57 deraadt Exp $	*/
/*	$NetBSD: fts.h,v 1.5 1994/12/28 01:41:50 mycroft Exp $	*/

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)fts.h	8.3 (Berkeley) 8/14/94
 */

#ifndef	_CT_FTS_H_
#define	_CT_FTS_H_

typedef struct {
	struct _ftsent *fts_cur;	/* current node */
	struct _ftsent *fts_child;	/* linked list of children */
	struct _ftsent **fts_array;	/* sort array */
	dev_t fts_dev;			/* starting device # */
	char *fts_path;			/* path for this descent */
	int fts_rfd;			/* fd for root */
	size_t fts_pathlen;		/* sizeof(path) */
	int fts_nitems;			/* elements in the sort array */
	int (*fts_compar)();		/* compare function */

#define	CT_FTS_COMFOLLOW	0x0001	/* follow command line symlinks */
#define	CT_FTS_LOGICAL		0x0002	/* logical walk */
#define	CT_FTS_NOCHDIR		0x0004	/* don't change directories */
#define	CT_FTS_NOSTAT		0x0008	/* don't get stat info */
#define	CT_FTS_PHYSICAL		0x0010	/* physical walk */
#define	CT_FTS_SEEDOT		0x0020	/* return dot and dot-dot */
#define	CT_FTS_XDEV		0x0040	/* don't cross devices */
#define	CT_FTS_OPTIONMASK	0x00ff	/* valid user option mask */

#define	CT_FTS_NAMEONLY	0x1000		/* (private) child names only */
#define	CT_FTS_STOP	0x2000		/* (private) unrecoverable error */
	int fts_options;		/* fts_open options, global flags */
} CT_FTS;

typedef struct _ftsent {
	struct _ftsent *fts_cycle;	/* cycle node */
	struct _ftsent *fts_parent;	/* parent directory */
	struct _ftsent *fts_link;	/* next file in directory */
	long fts_number;	        /* local numeric value */
	void *fts_pointer;	        /* local address value */
	char *fts_accpath;		/* access path */
	char *fts_path;			/* root path */
	int fts_errno;			/* errno for this node */
	int fts_symfd;			/* fd for symlink */
	size_t fts_pathlen;		/* strlen(fts_path) */
	size_t fts_namelen;		/* strlen(fts_name) */

	ino_t fts_ino;			/* inode */
	dev_t fts_dev;			/* device */
	nlink_t fts_nlink;		/* link count */

#define	CT_FTS_ROOTPARENTLEVEL	-1
#define	CT_FTS_ROOTLEVEL	 0
#define	CT_FTS_MAXLEVEL		 0x7fffffff
	int fts_level;		/* depth (-1 to N) */

#define	CT_FTS_D	 1		/* preorder directory */
#define	CT_FTS_DC	 2		/* directory that causes cycles */
#define	CT_FTS_DEFAULT	 3		/* none of the above */
#define	CT_FTS_DNR	 4		/* unreadable directory */
#define	CT_FTS_DOT	 5		/* dot or dot-dot */
#define	CT_FTS_DP	 6		/* postorder directory */
#define	CT_FTS_ERR	 7		/* error; errno is set */
#define	CT_FTS_F	 8		/* regular file */
#define	CT_FTS_INIT	 9		/* initialized only */
#define	CT_FTS_NS	10		/* stat(2) failed */
#define	CT_FTS_NSOK	11		/* no stat(2) requested */
#define	CT_FTS_SL	12		/* symbolic link */
#define	CT_FTS_SLNONE	13		/* symbolic link without target */
	unsigned short fts_info;	/* user flags for FTSENT structure */

#define	CT_FTS_DONTCHDIR	 0x01		/* don't chdir .. to the parent */
#define	CT_FTS_SYMFOLLOW	 0x02		/* followed a symlink to get here */
	unsigned short fts_flags;	/* private flags for FTSENT structure */

#define	CT_FTS_AGAIN	 1		/* read node again */
#define	CT_FTS_FOLLOW	 2		/* follow symbolic link */
#define	CT_FTS_NOINSTR	 3		/* no instructions */
#define	CT_FTS_SKIP	 4		/* discard node */
	unsigned short fts_instr;	/* fts_set() instructions */

	unsigned short fts_spare;	/* unused */

	struct stat *fts_statp;		/* stat(2) information */
	char fts_name[1];		/* file name */
} CT_FTSENT;

__BEGIN_DECLS
CT_FTSENT	*ct_fts_children(CT_FTS *, int);
int	 	 ct_fts_close(CT_FTS *);
CT_FTS		*ct_fts_open(char * const *, int,
	    	 int (*)(const CT_FTSENT **, const CT_FTSENT **));
CT_FTSENT	*ct_fts_read(CT_FTS *);
int	 	 ct_fts_set(CT_FTS *, CT_FTSENT *, int);
__END_DECLS

#endif /* !_CT_FTS_H_ */
