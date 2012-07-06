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

/* error codes */
#define CTE_ERRNO			1
#define CTE_EMPTY_XML			2
#define CTE_SHORT_READ			3
#define CTE_SHORT_WRITE			4
#define CTE_INVALID_REPLY_LEN		5
#define CTE_INVALID_REPLY_TYPE		6
#define CTE_XML_PARSE_FAIL		7
#define CTE_INVALID_XML_TYPE		8
#define CTE_NO_SECRETS_FILE		9
#define CTE_INVALID_SECRETS_FILE	10
#define CTE_INVALID_PASSPHRASE		11
#define CTE_INVALID_REPLY_VERSION	12
#define CTE_CANT_BASE64			13
#define CTE_INVALID_CREDENTIALS		14
#define CTE_ACCOUNT_DISABLED		15
#define CTE_OUT_OF_SPACE		16
#define CTE_OPERATION_FAILED		17	/* XXX unknown error ? */
#define CTE_INVALID_CTFILE_PROTOCOL	18
#define CTE_INVALID_CTFILE_FOOTER	19
#define CTE_INVALID_CTFILE_CHUNKNO	20
#define CTE_INVALID_CULL_TYPE		21
#define CTE_LOAD_CERTS			22
#define CTE_ASSL_CONTEXT		23
#define CTE_CONNECT_FAILED		24
#define CTE_INVALID_PATH		25
#define CTE_XDR				26
#define CTE_REGEX			27
#define CTE_UNEXPECTED_OPCODE		28
#define CTE_UNEXPECTED_TRANS		29
#define CTE_SHRINK_INIT			30
#define CTE_DECOMPRESS_FAILED		31
#define CTE_INVALID_IV_LENGTH		32
#define CTE_DECRYPT_FAILED		33
#define CTE_ENCRYPT_FAILED		34
#define CTE_ALL_FILES_EXCLUDED		35
#define CTE_ARCHIVE_FULLNAME		36
#define CTE_NO_SUCH_BACKUP		37
#define CTE_NO_SECRETS_ON_SERVER	38
#define CTE_BACKUP_ALREADY_EXISTS	39
#define CTE_SECRETS_FILE_SIZE_MISMATCH	40
#define CTE_SECRETS_FILE_DIFFERS	41
#define CTE_SECRETS_FILE_SHORT_READ	42
#define CTE_NO_FILES_SPECIFIED		43
#define CTE_NO_FILES_ACCESSIBLE		44
#define CTE_CRAZY_PATH			45
#define CTE_CANT_OPEN_REMOTE		46
#define CTE_INVALID_CONFIG_VALUE	47
#define CTE_MISSING_CONFIG_VALUE	48
#define CTE_CTFILE_CORRUPT		49
#define CTE_INVALID_CTFILE_NAME		50
#define CTE_MAX				51

const char	*ct_strerror(int);

#endif /* ! CT_TYPES_H */
