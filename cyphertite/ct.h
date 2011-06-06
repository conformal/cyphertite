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

#include <limits.h>

#include <sys/tree.h>
#include <sys/queue.h>

#include <openssl/sha.h>

#include <ctutil.h>
#include <ct_socket.h>

extern int		ct_debug;
extern int		ct_compress_enabled;
extern int		ct_encrypt_enabled;
extern int		ct_multilevel_allfiles;
extern char		*ct_basisbackup;
extern char		*ct_tdir;
extern int		ct_attr;
extern int		ct_match_mode;
extern int		ct_strip_slash;
extern int		ct_verbose;
extern int		ct_verbose_ratios;
extern int		ct_cur_compress_mode;
extern struct ct_stat	*ct_stats;
extern int		ct_no_cross_mounts;
extern int		ct_all_files;
extern int		ct_metadata;
extern time_t		ct_prev_backup_time;
extern int		ct_trans_id;
extern int		md_backup_fd;
extern int		ct_md_mode;
extern char *		__progname;

/* crypto */
#define CT_KEY_LEN		(256>>3)
#define CT_IV_LEN		(256>>3)

extern unsigned char		ct_iv[CT_IV_LEN];
extern unsigned char		ct_crypto_key[CT_KEY_LEN];

#define CT_ALLOC_NORMAL		(0)
#define CT_ALLOC_CLEAR		(1)

void			ct_shutdown(void);
void			ct_unload_config(void);

void ct_traverse(char **paths);
void ct_process_input(void *vctx);
void ct_process_file(void *vctx);
void ct_process_md(void *vctx);
void ct_compute_sha(void *vctx);
void ct_compute_compress(void *vctx);
void ct_compute_encrypt(void *vctx);
void ct_compute_csha(void *vctx);
void ct_process_complete(void *vctx);
void ct_process_wmd(void *vctx);
void ct_process_wfile(void *vctx);
void ct_md_wmd(void *vctx);
void ct_md_wfile(void *vctx);

struct flist;

RB_HEAD(fl_tree, flist);

/* XXX - seperate allocation for path len, or part of struct? */
/* XXX - create RB tree of matching inodes at the same time */
struct flist {
	TAILQ_ENTRY(flist)	fl_list;
	RB_ENTRY(flist)		fl_inode_entry;
	char			*fl_hlname;
	int			fl_hardlink;
	dev_t			fl_dev;
	ino_t			fl_ino;
	dev_t			fl_rdev;
	uint32_t		fl_uid;
	uint32_t		fl_gid;
	int			fl_mode;
	uint64_t		fl_atime;
	uint64_t		fl_mtime;
	int			fl_type;
	size_t			fl_size;
	size_t			fl_offset;
	size_t			fl_comp_size;
	char			*fl_fname;
	char			*fl_sname;
	int			fl_state;
#define CT_FILE_START		(0)
#define CT_FILE_PROCESSING	(1)
#define CT_FILE_FINISHED	(2)
	SHA_CTX			fl_shactx;
	int			fl_skip_file;
};
#if 0
struct fnode {
	TAILQ_ENTRY(flist)	fl_list;
	char fnode		*fl_hardlink_node;
	char			*fl_fname;
	int			fl_hardlink;
	dev_t			fl_dev;
	ino_t			fl_ino;
	struct fnode_live	*fl_live;
};
struct fnode_live {
	uint32_t		fl_uid;
	uint32_t		fl_gid;
	int			fl_mode;
	uint64_t		fl_atime;
	uint64_t		fl_mtime;
	int			fl_type;
	size_t			fl_size;
	size_t			fl_offset;
	size_t			fl_comp_size;
	char			*fl_sname;
	int			fl_state;
#define CT_FILE_START		(0)
#define CT_FILE_PROCESSING	(1)
#define CT_FILE_FINISHED	(2)
	SHA_CTX			fl_shactx;
};
#endif

int fl_inode_sort(struct flist *, struct flist *);

RB_PROTOTYPE(fl_tree, flist, fl_inode_entry, fl_inode_sort);

TAILQ_HEAD(flist_head, flist);

extern struct flist_head	fl_list_head;

/* FILE STATUS */

#define CT_S_RUNNING		(0)
#define CT_S_WAITING_TRANS	(1)
#define CT_S_FINISHED		(2)

void				ct_set_file_state(int);

/* crypt - XXX in ct_crypto.h */
#define E_KEY_LEN		(256>>3)
#define E_IV_LEN		(256>>3)

/* Transaction  */

struct ct_trans;

RB_HEAD(ct_trans_head, ct_trans);

struct ct_trans {
	struct ct_header	hdr;		/* must be first element */
	TAILQ_ENTRY(ct_trans)	tr_next;
	RB_ENTRY(ct_trans)	tr_trans_rbnode;

	struct flist		*tr_fl_node;
	uint64_t tr_trans_id;
	int tr_type;
/* DIR is another special */
#define TR_T_SPECIAL		(1)
#define TR_T_WRITE_CHUNK	(2)
#define TR_T_WRITE_HEADER	(3)
#define TR_T_READ_CHUNK		(4)
#define TR_T_READ_TRAILER	(5)
	int tr_state;
#define TR_S_FREE		(0)
#define TR_S_SPECIAL		(1)
#define TR_S_FILE_START		(2)
#define TR_S_SHORTREAD		(3)
#define TR_S_READ		(4)
#define TR_S_UNCOMPSHA_ED	(5)
#define TR_S_COMPRESSED		(6)
#define TR_S_COMPSHA_ED		(7)
#define TR_S_ENCRYPTED		(8)
#define TR_S_EXISTS		(9)
#define TR_S_NEXISTS		(10)
#define TR_S_WRITTEN		(11)
#define TR_S_WMD_READY		(12)
#define TR_S_WAITING		(13)
#define TR_S_DONE		(14)
#define TR_S_EX_SHA		(15)
#define TR_S_EX_READ		(16)
#define TR_S_EX_DECRYPTED	(17)
#define TR_S_EX_UNCOMPRESSED	(18)
#define TR_S_EX_FILE_START	(19)
#define TR_S_EX_SPECIAL		(20)
#define TR_S_EX_FILE_END	(21)
#define TR_S_EX_DONE		(22)
#define TR_S_XML_OPEN		(23)
#define TR_S_XML_CLOSE		(24)
#define TR_S_XML_CLOSING	(25)
#define TR_S_XML_LIST		(26)
#define TR_S_XML_DELETE		(27)

	char			tr_dataslot;
	char			tr_eof;

	uint8_t			tr_sha[SHA_DIGEST_LENGTH];
	uint8_t			tr_csha[SHA_DIGEST_LENGTH];
	uint8_t			tr_iv[E_IV_LEN];


	int			tr_size[2];

	uint8_t			*tr_data[2];
};

struct ct_trans		*ct_trans_alloc(void);
void			ct_trans_free(struct ct_trans *trans);
void			ct_trans_cleanup(void);

void			ct_queue_transfer(struct ct_trans *);

/* config */
extern int		ct_max_trans;
extern int		ct_max_block_size;
extern int		ct_io_bw_limit;
extern char		*ct_host;
extern char		*ct_hostport;
extern char		*ct_localdb;
extern char		*ct_ca_cert;
extern char		*ct_cert;
extern char		*ct_key;
extern char		*ct_username;
extern char		*ct_password;
extern char		*ct_crypto_secrets;

/* what are we doing? */
extern int		ct_action;
#define CT_A_ARCHIVE	(1)
#define CT_A_LIST	(2)
#define CT_A_EXTRACT	(3)
#define CT_A_ERASE	(4)

/* assl */
void ct_setup_assl(void);
struct ct_assl_io_ctx	*ct_assl_ctx;


int			ct_archive(const char *, char **, const char *);
int			ct_extract(const char *, char **);
int			ct_list(const char *, char **);
int			ct_md_archive(const char *, const char *);
int			ct_md_extract(const char *, const char *);
char			**ct_md_list(char **);
int			ct_md_list_print(char **);
int			ct_md_delete(const char *);

/* CT context state */

#define STR_PAD(n) int pad ## n [8];

RB_HEAD(ct_trans_lookup, ct_trans);
RB_HEAD(ct_iotrans_lookup, ct_trans);

struct ct_global_state{
	/* PADs? */
	int				ct_sha_state;
	int				ct_csha_state;
	int				ct_file_state;
	int				ct_comp_state;
	int				ct_crypt_state;
	int				ct_write_state;
	STR_PAD(0);
	TAILQ_HEAD(, ct_trans)		ct_sha_queue;
	int				ct_sha_qlen;
	STR_PAD(1);
	TAILQ_HEAD(, ct_trans)		ct_comp_queue;
	int				ct_comp_qlen;
	STR_PAD(2);
	TAILQ_HEAD(, ct_trans)		ct_crypt_queue;
	int				ct_crypt_qlen;
	STR_PAD(3);
	TAILQ_HEAD(, ct_trans)		ct_csha_queue;
	int				ct_csha_qlen;
	STR_PAD(4);
	TAILQ_HEAD(, ct_trans)		ct_write_queue;
	int				ct_write_qlen;
	STR_PAD(5);
	TAILQ_HEAD(, ct_trans)		ct_queued;
	int				ct_queued_qlen;
	STR_PAD(6);
	struct ct_iotrans_lookup	ct_inflight;
	int				ct_inflight_rblen;
	STR_PAD(7);
	struct ct_trans_lookup		ct_complete;
	int				ct_complete_rblen;
};
extern struct ct_global_state		*ct_state;

void ct_event_init(void);
int ct_event_dispatch(void);
void ct_wakeup_file(void);
void ct_wakeup_sha(void);
void ct_wakeup_compress(void);
void ct_wakeup_csha(void);
void ct_wakeup_encrypt(void);
void ct_wakeup_write(void);
void ct_wakeup_decrypt(void);
void ct_wakeup_uncompress(void);
void ct_wakeup_filewrite(void);
void ct_wakeup_complete(void);

void ct_display_queues(void);
void ct_display_assl_stats(void);

typedef void (ct_func_cb)(void *);

struct ct_ctx;

void ct_setup_state(void);
void ct_setup_wakeup(struct ct_ctx *, void *, ct_func_cb *);
void ct_setup_wakeup_file(void *, ct_func_cb *);
void ct_setup_wakeup_sha(void *, ct_func_cb *);
void ct_setup_wakeup_compress(void *, ct_func_cb *);
void ct_setup_wakeup_csha(void *, ct_func_cb *);
void ct_setup_wakeup_encrypt(void *, ct_func_cb *);
void ct_setup_wakeup_write(void *, ct_func_cb *);
void ct_setup_wakeup_complete(void *, ct_func_cb *);
void ct_set_reconnect_timeout(void (*)(int, short, void*), void *,
    int);

msgdeliver_ty			ct_handle_msg;
msgcomplete_ty			ct_write_done;

ct_header_alloc_func		ct_header_alloc;
ct_header_free_func		ct_header_free;
ct_body_alloc_func		ct_body_alloc;
ct_body_free_func		ct_body_free;

void				ct_handle_xml_reply(struct ct_trans *trans,
				    struct ct_header *hdr, void *vbody);

/* db external interface */
void				ctdb_setup(const char *, int);
void				ctdb_shutdown(void);
int				ctdb_exists(struct ct_trans *);
int				ctdb_insert(struct ct_trans *trans);
#define CTDB_USE_SHA    (1)
#define CTDB_USE_CSHA   (2)

/* metadata */
int				ct_s_to_e_type(int);
FILE				*ct_metadata_create(const char *, int);
void				ct_metadata_close(FILE *);

struct dedup_digest {
	char		dd_digest[SHA_DIGEST_LENGTH];
	char		dd_digest_crypto[SHA_DIGEST_LENGTH];
	char		dd_iv[E_IV_LEN];
};
typedef struct dedup_digest dedup_digest;	/* ugh typedef, blame XDR */

/* XDR for metadata global hader */
struct ct_md_gheader {
	int			cmg_beacon;	/* magic marker */
#define CT_MD_BEACON		(0x43595048)
	int			cmg_version;	/* version of the archive */
#define CT_MD_VERSION		(1)
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
};

/* XDR for metadata header */
struct ct_md_header {
	int			cmh_beacon;	/* magic marker */
#define CT_HDR_BEACON		(0x4d4f306f)
#define CT_HDR_EOF		(0x454f4621)
	uint64_t		cmh_nr_shas;	/* total shas */
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

struct ct_md_stdin {
	int			cms_beacon;	/* magic marker */
#define CT_SIN_BEACON		(0x5354494e)
	uint8_t			cms_sha[SHA_DIGEST_LENGTH];
};

/* XDR for metadata trailer */
struct ct_md_trailer {
	uint64_t		cmt_orig_size;	/* original size */
	uint64_t		cmt_comp_size;	/* deduped + comp size */
	uint8_t			cmt_sha[SHA_DIGEST_LENGTH];
};

int			ct_write_header(struct ct_trans *, char *);
int			ct_write_sha(struct ct_trans *);
int			ct_write_sha_crypto(struct ct_trans *);
int			ct_write_trailer(struct ct_trans *);
void			ct_cleanup_md(void);
int			ct_read_header(struct ct_md_header *hdr);
struct ct_assl_io_ctx	*ct_assl_ctx;
void			ct_extract_setup(const char *);
void			ct_basis_setup(const char *);

/* ct_file.c: extract functions */
void ct_file_extract_open(struct flist *fnode);
void ct_file_extract_write(uint8_t *buf, size_t size);
void ct_file_extract_close(struct flist *fnode);
void ct_file_extract_special(struct flist *fnode);
void ct_file_extract_fixup(void);
char *ct_create_config(void);
char *ct_system_config(void);
char *ct_user_config(void);

/* print file data nicely */
void			ct_pr_fmt_file(struct flist *fnode);

RB_PROTOTYPE(ct_iotrans_lookup, ct_trans, tr_trans_id, ct_cmp_iotrans);
RB_PROTOTYPE(ct_trans_lookup, ct_trans, tr_trans_id, ct_cmp_trans);

/* statistics */

struct ct_stat {
	struct timeval		st_time_start;
	struct timeval		st_time_scan_end;

	uint64_t		st_files_scanned;
	uint64_t		st_bytes_tot;
	uint64_t		st_chunks_tot;

	uint64_t		st_bytes_read;
	uint64_t		st_bytes_written;
	uint64_t		st_bytes_compressed;
	uint64_t		st_bytes_crypted;
	uint64_t		st_bytes_dbexists;
	uint64_t		st_bytes_sent;
	uint64_t		st_chunks_completed;

	uint64_t		st_bytes_sha;
	uint64_t		st_bytes_crypt;
	uint64_t		st_bytes_csha;

	uint64_t		st_files_completed;
} ;

void			ct_dump_stats(void);
struct ct_assl_io_ctx	*ct_ssl_connect(int);
void			ct_reconnect(int, short, void *);
void			ct_load_certs(struct assl_context *);
int			ct_assl_negotiate_poll(struct ct_assl_io_ctx *);
void			ct_setup_write_md(const char *, int);
void			ct_cleanup_md(void);

/* limit extract and list by regex */
void			ct_build_regex(char **flist);
int			ct_match_regex(char *file);

/* match functionality */
#define CT_MATCH_INVALID	(0)
#define CT_MATCH_REGEX		(1)
#define CT_MATCH_RB		(2)
#define CT_MATCH_GLOB		(3)

void			ct_match_compile(int, char **);
int			ct_match(int, char *);
void			ct_match_unwind(int);

void			ct_ssl_init_bw_lim(struct ct_assl_io_ctx *);

/* MD mode handling */
#define CT_MDMODE_LOCAL		(0)
#define CT_MDMODE_REMOTE	(1)

char			*ct_md_cook_filename(const char *);
void			 ct_mdmode_setup(char *);
char			*ct_find_md_for_extract(const char *);
char                    *ct_find_md_for_archive(const char *);
int			 md_is_in_cache(const char *);
