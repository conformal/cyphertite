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
#ifndef CT_CTFILE_H
#define CT_CTFILE_H

#include "ct_types.h"

/* XDR for metadata global header */
struct ctfile_gheader {
	int			cmg_beacon;	/* magic marker */
#define CT_MD_BEACON		(0x43595048)
	int			cmg_version;	/* version of the archive */
#define CT_MD_V1		(1)
#define CT_MD_V2		(2)
#define CT_MD_V3		(3)
#define CT_MD_VERSION		CT_MD_V3
	int			cmg_chunk_size;	/* chunk size */
	int64_t			cmg_created;	/* date created */
	int			cmg_type;	/* normal, stdin or crypto */
#define CT_MD_REGULAR		(0)
#define CT_MD_STDIN		(1)
	int			cmg_flags;	/* save digest and iv */
#define CT_MD_NOCRYPTO		(0)
#define CT_MD_CRYPTO		(1)
#define CT_MD_MLB_ALLFILES	(2)
	char			*cmg_prevlvl_filename;
	int			cmg_cur_lvl;
	char			*cmg_cwd;
	int			cmg_num_paths;
	char			**cmg_paths;
};

/* XDR for metadata header */
struct ctfile_header {
	int			cmh_beacon;	/* magic marker */
#define CT_HDR_BEACON		(0x4d4f306f)
#define CT_HDR_EOF		(0x454f4621)
	int64_t			cmh_nr_shas;	/* total shas */
	int64_t			cmh_parent_dir;	/* path file num */
	uint32_t		cmh_uid;	/* user id */
	uint32_t		cmh_gid;	/* group id */
	uint32_t		cmh_mode;	/* file mode */
	int32_t			cmh_rdev;	/* major and minor */
	int64_t			cmh_atime;	/* last access time */
	int64_t			cmh_mtime;	/* last modification time */
	u_char			cmh_type;
#define C_TY_INVALID		(0)
#define C_TY_DIR		(1)
#define C_TY_CHR		(2)
#define C_TY_BLK		(3)
#define C_TY_REG		(4)
#define C_TY_FIFO		(5)
#define C_TY_LINK		(6)
#define C_TY_SOCK		(7)
#define C_TY_MASK		(0xf)		/* extra bit for future */
	char			*cmh_filename;	/* original filename */
};

#define C_ISDIR(h) (((h) & C_TY_MASK) == C_TY_DIR)
#define C_ISCHR(h) (((h) & C_TY_MASK) == C_TY_CHR)
#define C_ISBLK(h) (((h) & C_TY_MASK) == C_TY_BLK)
#define C_ISREG(h) (((h) & C_TY_MASK) == C_TY_REG)
#define C_ISFIFO(h) (((h) & C_TY_MASK) == C_TY_FIFO)
#define C_ISLINK(h) (((h) & C_TY_MASK) == C_TY_LINK)
#define C_ISSOCK(h) (((h) & C_TY_MASK) == C_TY_SOCK)

struct ctfile_stdin {
	int			cms_beacon;	/* magic marker */
#define CT_SIN_BEACON		(0x5354494e)
	uint8_t			cms_sha[SHA_DIGEST_LENGTH];
};

/* XDR for metadata trailer */
struct ctfile_trailer {
	uint64_t		cmt_orig_size;	/* original size */
	uint64_t		cmt_comp_size;	/* deduped + comp size */
	uint8_t			cmt_sha[SHA_DIGEST_LENGTH];
};


/* XXX this should be hidden */
#include <rpc/types.h>
#include <rpc/xdr.h>
/* parser for cyphertite ctfile archives */
RB_HEAD(d_num_tree, dnode);
struct ctfile_parse_state {
	FILE			*xs_f;
	const char		*xs_filename;
	XDR			 xs_xdr;
	struct ctfile_gheader	 xs_gh;
	struct ctfile_header	 xs_hdr;
	struct ctfile_header	 xs_lnkhdr;
	struct ctfile_trailer	 xs_trl;
	struct d_num_tree	 xs_dnum_head;
	int			 xs_dnum;
	int			 xs_state;
	int			 xs_wasfile;
	int64_t			 xs_sha_cnt;
	size_t			 xs_sha_sz;

	uint8_t			 xs_sha[SHA_DIGEST_LENGTH];
	uint8_t			 xs_csha[SHA_DIGEST_LENGTH];
	uint8_t			 xs_iv[CT_IV_LEN];
#define	XS_STATE_FILE		0
#define	XS_STATE_SHA		1
#define	XS_STATE_EOF		2
#define	XS_STATE_FAIL		3

#define	XS_RET_FILE		0
#define	XS_RET_SHA		1
#define	XS_RET_FILE_END		2
#define	XS_RET_EOF		3
#define	XS_RET_FAIL		4
	int			xs_errno;	/* valid if XS_RET_FAIL */
};

int ctfile_parse_init_at(struct ctfile_parse_state *, const char *,
    const char *, off_t);
int ctfile_parse_init_f(struct ctfile_parse_state *, FILE *, const char *);
#define ctfile_parse_init(ctx, file, basedir)		\
	ctfile_parse_init_at(ctx, file, basedir, 0)
int ctfile_parse(struct ctfile_parse_state *);
int ctfile_parse_seek(struct ctfile_parse_state *);
void ctfile_parse_close(struct ctfile_parse_state *);
off_t ctfile_parse_tell(struct ctfile_parse_state *);
struct dnode *ctfile_parse_finddir(struct ctfile_parse_state *, int);
struct dnode *ctfile_parse_insertdir(struct ctfile_parse_state *, struct dnode *);

struct ctfile_write_state;
int	 ctfile_write_init(struct ctfile_write_state **, const char *,
	     const char *, int, const char *, int, char *, char **, int, int,
	     int);
int	 ctfile_write_special(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_file_start(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_file_sha(struct ctfile_write_state *, uint8_t *,
	     uint8_t *, uint8_t *);
int	 ctfile_write_file_pad(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_file_end(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_close(struct ctfile_write_state *);
void	 ctfile_write_abort(struct ctfile_write_state *);

char	*ctfile_get_previous(const char *);

#endif /* ! CT_CTFILE_H */
