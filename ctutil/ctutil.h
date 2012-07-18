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

#ifndef CTUTIL_H
#define CTUTIL_H

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#include <sys/types.h>
#include <openssl/sha.h>

#define CT_CHUNK_MAXSZ		(1024 * 1024)
#define CT_QUEUE_DEPTH		(10)
#define CT_QUEUE_DEPTH_MAX	(100)

struct ct_settings;

struct ct_special {
	int		(*csp_set)(struct ct_settings *, char *);
	char		*(*csp_get)(struct ct_settings *);
};
struct ct_settings {
	char			*cs_name;
	int			cs_type;
#define CT_S_INVALID		(0)
#define CT_S_INT		(1)
#define CT_S_STR		(2)
#define CT_S_FLOAT		(3)
#define CT_S_DIR		(4) /* string with ~ expansion */
#define CT_S_SIZE		(5) /* size with postfix */
	int			*cs_ival;
	char			**cs_sval;
	double			*cs_fval;
	long long		*cs_szval;
	struct ct_special	*cs_s;
	int			cs_secure;
};

struct ct_header {
	u_char			c_version;
#define C_HDR_VERSION		(2)
	u_char			c_opcode;
#define C_HDR_O_INVALID		(0)
#define C_HDR_O_NEG		(2)
#define C_HDR_O_NEG_REPLY	(3)
	u_char			c_status;
#define C_HDR_S_OK		(0)
#define C_HDR_S_FAIL		(1)
#define C_HDR_S_EXISTS		(2)
#define C_HDR_S_DOESNTEXIST	(3)
#define C_HDR_S_INVALIDDIGEST	(4)
#define C_HDR_S_LOGINFAILED	(5)
#define C_HDR_S_PERMISSION	(6)
#define C_HDR_S_BADXML		(7)
#define C_HDR_S_ADMINCMDFAILED	(8)
#define C_HDR_S_INVALIDCOMP	(9)
	u_char			c_ex_status; /* command specific */
	uint32_t		c_tag;
	uint32_t		c_size;
	uint16_t		c_flags;
#define C_HDR_F_UNUSED0		(1<<0)
#define C_HDR_F_VERIFYDIGEST	(1<<1)
#define C_HDR_F_METADATA	(1<<2)
#define C_HDR_F_CB_OWN		(1<<3)
#define C_HDR_F_XML_REPLY	(1<<4)
#define C_HDR_F_ENCRYPTED	(1<<5)
#define C_HDR_F_UNUSED6		(1<<6)
#define C_HDR_F_UNUSED7		(1<<7)
#define C_HDR_F_UNUSED8		(1<<8)
#define C_HDR_F_UNUSED9		(1<<9)
#define C_HDR_F_UNUSED10	(1<<10)
#define C_HDR_F_UNUSED11	(1<<11)
/* bit 15..12 indicate the compression type */
#define C_HDR_F_COMP_LZO	(1<<12)
#define C_HDR_F_COMP_LZW	(2<<12)
#define C_HDR_F_COMP_LZMA	(3<<12)
#define C_HDR_F_COMPRESSED_MASK	(0xf000)
#define C_HDR_F_VALIDMASK	(0xf03e)
	uint16_t		c_unused;
} __packed;

/*
 * C_HDR_O_NOP: send no-operation request to server
 * returns: en_id + 1
 */
#define C_HDR_O_NOP		(10)
struct ct_nop {
	uint32_t		cn_id;
} __packed;

#define C_HDR_O_NOP_REPLY	(11)
struct ct_nop_reply {
	uint32_t		cnr_id;
} __packed;

/*
 * C_HDR_O_LOGIN: login with username/password provided in payload
 * returns: e_status C_HDR_S_LOGINFAILED if login failed
 *
 * there is no return body
 */
#define C_HDR_O_LOGIN		(4)
#define C_HDR_O_LOGIN_REPLY	(5)
#define C_HDR_O_LOGIN_EXS_DISABLED	(1)
extern char	*c_hdr_login_reply_ex_errstrs[];

/*
 * C_O_EXISTS: ask server if digest exists
 * returns:	e_status C_HDR_S_DOESNTEXIST or C_HDR_S_INVALIDDIGEST
 *		    if digest integrity fails verify this is only checked
 *		    if C_HDR_F_VERIFYDIGEST is set
 *		e_flags C_HDR_F_COMPRESSED if compressed
 *		e_flags C_HDR_F_ENCRYPTED if encrypted
 *		e_flags C_HDR_F_METADATA if it is metadata
 *
 * there is no return body
 */
#define C_HDR_O_EXISTS		(12)
struct ct_exists {
	u_char			ce_digest[SHA_DIGEST_LENGTH];
} __packed;
#define C_HDR_O_EXISTS_REPLY	(13)

/*
 * C_OPC_O_READ: retrieve digest
 * returns:	e_status C_HDR_S_EXISTS or C_HDR_S_DOESNTEXIST or
 *		    C_HDR_S_INVALIDDIGEST if digest integrity fails verify
 *		    this is only checked if C_HDR_F_VERIFYDIGEST is set
 *		e_flags C_HDR_F_COMPRESSED if compressed
 *		e_flags C_HDR_F_METADATA if it is metadata
 *		e_size size of chunk
 *
 * return body contains the raw data if the digest existed
 */
#define C_HDR_O_READ		(14)
struct ct_read {
	u_char			cr_digest[SHA_DIGEST_LENGTH];
} __packed;
#define C_HDR_O_READ_REPLY	(15)

/*
 * C_OPC_O_WRITE: write chunk
 * returns:	e_status C_HDR_S_EXISTS if the digest already exists
 *		    C_HDR_S_NONE on success
 *		e_flags C_HDR_F_COMPRESSED if compressed
 *		e_flags C_HDR_F_METADATA if it is metadata
 *		e_size size of chunk
 *
 * return body contains the server computed digest
 */
#define C_HDR_O_WRITE		(16)
#define C_HDR_O_WRITE_REPLY	(17)
#define C_HDR_O_WRITE_EXS_ENOSPACE	(0)
extern char	*c_hdr_write_reply_ex_errstr[];
struct ct_write_reply {
	u_char			cwr_digest[SHA_DIGEST_LENGTH];
} __packed;

#define C_HDR_O_XML		(18)
#define C_HDR_O_XML_REPLY	(19)

struct ct_metadata_footer {
	uint32_t	cmf_chunkno;
	uint32_t	cmf_size;
} __packed;

/* stuff */
#define CT_PASS_MAX	(128)
int	ct_get_password(char *, size_t, char *, int);
int	ct_savecore(void);
size_t	ct_str_repeat(char *dest, size_t buf_size, const char *src, int repeat);

/* compression */
struct ct_compress_ctx;
struct ct_compress_ctx
		*ct_init_compression(uint16_t);
void		ct_cleanup_compression(struct ct_compress_ctx *);
int		ct_uncompress(struct ct_compress_ctx *, uint8_t *, uint8_t *,
		    size_t, size_t *);
int		ct_compress(struct ct_compress_ctx *, uint8_t *, uint8_t *,
		    size_t, size_t *);
uint16_t	ct_compress_type(struct ct_compress_ctx *);
size_t		ct_compress_bounds(struct ct_compress_ctx *, size_t);

/* digest */
void		ct_sha1(uint8_t *, uint8_t *, size_t);
void		ct_sha1_encode(uint8_t *, char *);
int		ct_text2sha(const char *, uint8_t *);
void		ct_sha512(uint8_t *, uint8_t *, size_t);
void		ct_sha512_encode(uint8_t *, char *);

#define SHA_DIGEST_STRING_LENGTH ((SHA_DIGEST_LENGTH *2) + 1)
void		ct_sha1_setup(SHA_CTX *);
void		ct_sha1_add(uint8_t *, SHA_CTX *, size_t);
void		ct_sha1_final(uint8_t *, SHA_CTX *);

#define SHA512_DIGEST_STRING_LENGTH ((SHA512_DIGEST_LENGTH *2) + 1)
void		ct_sha512_setup(SHA512_CTX *);
void		ct_sha512_add(uint8_t *, SHA512_CTX *, size_t);
void		ct_sha512_final(uint8_t *, SHA512_CTX *);

/* error handling */
char		*ct_header_strerror(struct ct_header *);

/* protocol */
void		ct_wire_header(struct ct_header *);
void		ct_unwire_header(struct ct_header *);
void		ct_unwire_nop(struct ct_nop *);
void		ct_wire_nop_reply(struct ct_nop_reply *);

/* config */
int		ct_config_parse(struct ct_settings *, const char *);

/* event polltype */
void		ct_polltype_setup(const char *);

/* debug */
void		ct_dump_block(uint8_t *p, size_t sz);

/* base64 */
#define CT_B64_INVALID		(0)
#define CT_B64_ENCODE		(1)
#define CT_B64_DECODE		(2)
#define CT_B64_M_ENCODE		(3)
#define CT_B64_M_DECODE		(4)

int		ct_base64_encode(int, uint8_t *, size_t, uint8_t *, size_t);

/* Metadata */
#define	CT_MAX_MD_FILENAME	(256)	/* 255 + terminating NUL */
#define	CT_CTFILE_MAXLEN	CT_MAX_MD_FILENAME
#define	CT_CTFILE_REJECTCHRS	"?!*/\\\'\""

/* filename handling */
char	*ct_remove_ext(char *path);

/* directory handling */
int     ct_make_full_path(char *, mode_t);

/* pipe handling */
int	 ct_set_pipe_nonblock(int);

#ifndef CT_PATHSEP
#define CT_PATHSEP	'/'
#endif
#ifndef CT_PATHSEP_STR
#define CT_PATHSEP_STR	"/"
#endif

/* cli parsing */
struct ct_cli_cmd {
	char			*cc_cmd;	/* command name */
	struct ct_cli_cmd	*cc_subcmd;	/* subcommand structure */
	int			cc_paramc;	/* number of parameters */
#define CLI_CMD_SUBCOMMAND	(-2)	/* dereference cmd in substructure */
#define CLI_CMD_UNKNOWN		(-1)    /* unknown number of parameters */
	char			*cc_usage;	/* command usage string */
	void			(*cc_cb)(struct ct_cli_cmd *, int, char **);
	int			cc_auth;	/* need authentication */
};

struct ct_cli_cmd	*ct_cli_cmd_find(struct ct_cli_cmd *, char *);
__dead void		ct_cli_usage(struct ct_cli_cmd *, struct ct_cli_cmd *);
struct ct_cli_cmd	*ct_cli_validate(struct ct_cli_cmd *, int *, char ***);
void			ct_cli_execute(struct ct_cli_cmd *, int *, char ***);

/* cert bundle */
#define CT_CERT_BUNDLE_LOGIN_FAILED	(-1000)
int			ct_get_cert_bundle(const char *, const char *, char **,
			    size_t *);

/* Debug log levels */
#define CTUTIL_LOG_SOCKET	(0x1)
#define CTUTIL_LOG_CONFIG	(0x2)

#endif /* CTUTIL_H */
