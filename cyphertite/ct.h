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

/* versioning */
#define CT_VERSION_MAJOR	0
#define CT_VERSION_MINOR	4
#define CT_VERSION_PATCH	1
#define CT_VERSION		"0.4.1"

extern int		cflags;
extern int		ct_debug;
extern int		ct_compress_enabled;
extern int		ct_encrypt_enabled;
extern int		ct_multilevel_allfiles;
extern char		*ct_tdir;
extern int		ct_attr;
extern int		ct_strip_slash;
extern int		ct_verbose;
extern int		ct_verbose_ratios;
extern int		ct_cur_compress_mode;
extern struct ct_stat	*ct_stats;
extern int		ct_no_cross_mounts;
extern time_t		ct_prev_backup_time;
extern int		ct_trans_id;
extern int		md_backup_fd;
extern int		ct_md_mode;
extern char		*ct_md_cachedir;
extern int		ct_max_differentials;
extern char		*__progname;
extern char		*ct_includefile;
extern char		*ct_crypto_password;
extern char		*ct_configfile;

/* crypto */
#define CT_KEY_LEN		(256>>3)
#define CT_IV_LEN		(256>>3)

extern unsigned char		ct_iv[CT_IV_LEN];
extern unsigned char		ct_crypto_key[CT_KEY_LEN];

extern struct ct_settings	settings[];

#define CT_ALLOC_NORMAL		(0)
#define CT_ALLOC_CLEAR		(1)

void			ct_shutdown(void);
void			ct_unload_config(void);

int			ct_load_config(struct ct_settings *);
void			ct_process_input(void *);
void			ct_process_file(void *);
void			ct_process_md(void *);
void			ct_compute_sha(void *);
void			ct_compute_compress(void *);
void			ct_compute_encrypt(void *);
void			ct_compute_csha(void *);
void			ct_process_completions(void *);

struct fnode;
struct dnode;

struct fnode {
	/* TAILQ_ENTRY(fnode)	fl_list; */
	char			*fl_hlname;
	struct dnode		*fl_parent_dir;
	struct dnode		*fl_curdir_dir;
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

struct flist {
	TAILQ_ENTRY(flist)	fl_list;
	RB_ENTRY(flist)		fl_inode_entry;
	struct dnode		*fl_parent_dir;
	struct flist		*fl_hlnode;
	char			*fl_fname;
	struct fnode		*fl_node;
	dev_t			fl_dev;
	ino_t			fl_ino;
};

struct dnode * gen_finddir(int64_t idx);
char *gen_fname(struct flist *);

int fl_inode_sort(struct flist *, struct flist *);

RB_HEAD(fl_tree, flist);

RB_PROTOTYPE(fl_tree, flist, fl_inode_entry, fl_inode_sort);

TAILQ_HEAD(flist_head, flist);

struct dnode {
	RB_ENTRY(dnode)		 d_rb_name;
	RB_ENTRY(dnode)		 d_rb_num;
	int64_t			 d_num;
	struct dnode		*d_parent;
	char			*d_name;
	struct flist		*d_flnode;
};

int	ct_dname_cmp(struct dnode *, struct dnode *);
RB_HEAD(d_name_tree, dnode);
RB_PROTOTYPE(d_name_tree, dnode, ds_rb, ct_dname_cmp);

int	ct_dnum_cmp(struct dnode *, struct dnode *);
RB_HEAD(d_num_tree, dnode);
RB_PROTOTYPE(d_num_tree, dnode, ds_rb, ct_dnum_cmp);

struct fnode *ct_populate_fnode_from_flist(struct flist *);

extern struct d_num_tree	ct_dnum_head;
extern struct flist_head	fl_list_head;

/* FILE STATUS */

#define CT_S_STARTING		(0)
#define CT_S_RUNNING		(1)
#define CT_S_WAITING_TRANS	(2)
#define CT_S_FINISHED		(3)

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

	struct fnode		*tr_fl_node;
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
#define TR_S_READ		(3)
#define TR_S_UNCOMPSHA_ED	(4)
#define TR_S_COMPRESSED		(5)
#define TR_S_COMPSHA_ED		(6)
#define TR_S_ENCRYPTED		(7)
#define TR_S_EXISTS		(8)
#define TR_S_NEXISTS		(9)
#define TR_S_WRITTEN		(10)
#define TR_S_WMD_READY		(11)
#define TR_S_WAITING		(12)
#define TR_S_DONE		(13)
#define TR_S_EX_SHA		(14)
#define TR_S_EX_READ		(15)
#define TR_S_EX_DECRYPTED	(16)
#define TR_S_EX_UNCOMPRESSED	(17)
#define TR_S_EX_FILE_START	(18)
#define TR_S_EX_SPECIAL		(19)
#define TR_S_EX_FILE_END	(20)
#define TR_S_XML_OPEN		(21)
#define TR_S_XML_CLOSE		(22)
#define TR_S_XML_CLOSING	(23)
#define TR_S_XML_LIST		(24)
#define TR_S_XML_DELETE		(25)

	char			tr_dataslot;
	char			tr_eof;

	uint8_t			tr_sha[SHA_DIGEST_LENGTH];
	uint8_t			tr_csha[SHA_DIGEST_LENGTH];
	uint8_t			tr_iv[E_IV_LEN];


	int			tr_chsize;
	int			tr_size[2];

	uint8_t			*tr_data[2];
	uint32_t		tr_md_chunkno;
	const char		*tr_md_name;
};

struct ct_trans		*ct_trans_alloc(void);
void			ct_trans_free(struct ct_trans *trans);
void			ct_trans_cleanup(void);
void			ct_flnode_cleanup(void);
void			ct_free_fnode(struct fnode *);
void			ct_ssl_cleanup(void);

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

struct ct_op;

void			ct_archive(struct ct_op *);
void			ct_extract(struct ct_op *);
void			ct_list_op(struct ct_op *);
int			ct_list(const char *, char **, char **, int);
void			ct_md_archive(struct ct_op *);
void			ct_md_extract(struct ct_op *);
void			ct_md_list_start(struct ct_op *);
void			ct_md_list_print(struct ct_op *);
void			ct_md_delete(struct ct_op *);
void			ct_check_crypto_secrets_nextop(struct ct_op *);
void			ct_free_remotename(struct ct_op *);
void			ct_md_trigger_delete(struct ct_op *);

/* CT context state */

#define STR_PAD(n) int pad ## n [8];

RB_HEAD(ct_trans_lookup, ct_trans);
RB_HEAD(ct_iotrans_lookup, ct_trans);

typedef void (ct_op_cb)(struct ct_op *);

struct ct_op {
	TAILQ_ENTRY(ct_op)	 op_link;
	ct_op_cb		*op_start;
	ct_op_cb		*op_complete;
	char			*op_local_fname;
	char			**op_filelist;
	char			**op_excludelist;
	char			*op_remote_fname;
	char			*op_basis;
	int			 op_action;
	int			 op_matchmode;
	void			*op_priv;	/* operation private data */
};

void	ct_add_operation(ct_op_cb *, ct_op_cb *, char *, char *,
	    char **, char **, char *, int, int);
void	ct_add_operation_after(struct ct_op *, ct_op_cb *, ct_op_cb *,
	    char *, char *, char **, char **, char *, int, int);
void	ct_nextop(void *);
int	ct_op_complete(void);

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
	TAILQ_HEAD(ct_ops, ct_op)	ct_operations;
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
void ct_display_assl_stats(FILE *);

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
extern int ct_reconnect_pending;

msgdeliver_ty			ct_handle_msg;
msgcomplete_ty			ct_write_done;

ct_header_alloc_func		ct_header_alloc;
ct_header_free_func		ct_header_free;
ct_body_alloc_func		ct_body_alloc;
ct_body_free_func		ct_body_free;

void				ct_handle_xml_reply(struct ct_trans *trans,
				    struct ct_header *hdr, void *vbody);
void				ct_xml_file_open(struct ct_trans *,
				    const char *, int, uint32_t);
int				ct_xml_file_open_polled(struct ct_assl_io_ctx *,
				    const char *, int, uint32_t);
#define MD_O_READ	0
#define MD_O_WRITE	1
#define MD_O_APPEND	2
void				ct_xml_file_close(void);

/* db external interface */
void				ctdb_setup(const char *, int);
void				ctdb_shutdown(void);
int				ctdb_exists(struct ct_trans *);
int				ctdb_insert(struct ct_trans *trans);
#define CTDB_USE_SHA    (1)
#define CTDB_USE_CSHA   (2)

/* metadata */
int				ct_s_to_e_type(int);
FILE				*ct_metadata_create(const char *, int,
				    const char *, int, char *, char **);
void				ct_metadata_close(FILE *);
char				*ct_metadata_check_prev(const char *);

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
struct ct_md_header {
	int			cmh_beacon;	/* magic marker */
#define CT_HDR_BEACON		(0x4d4f306f)
#define CT_HDR_EOF		(0x454f4621)
	uint64_t		cmh_nr_shas;	/* total shas */
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

int			ct_write_header(struct fnode *, char *, int);
int			ct_write_sha(struct ct_trans *);
int			ct_write_sha_crypto(struct ct_trans *);
int			ct_write_trailer(struct ct_trans *);
void			ct_cleanup_md(void);
int			ct_read_header(struct ct_md_header *hdr);
struct ct_assl_io_ctx	*ct_assl_ctx;
void			ct_extract_setup(const char *);
int			ct_basis_setup(const char *, char **);

/* ct_file.c: extract functions */
int  ct_file_extract_open(struct fnode *fnode);
void ct_file_extract_write(struct fnode *, uint8_t *buf, size_t size);
void ct_file_extract_close(struct fnode *fnode);
void ct_file_extract_special(struct fnode *fnode);
void ct_file_extract_fixup(void);
void ct_create_config(void);
char *ct_system_config(void);
char *ct_user_config(void);

/* print file data nicely */
void			ct_pr_fmt_file(struct fnode *fnode);

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
	uint64_t		st_bytes_uncompressed;
	uint64_t		st_bytes_crypted;
	uint64_t		st_bytes_exists;
	uint64_t		st_bytes_sent;
	uint64_t		st_chunks_completed;

	uint64_t		st_bytes_sha;
	uint64_t		st_bytes_crypt;
	uint64_t		st_bytes_csha;

	uint64_t		st_files_completed;
} ;

void			ct_dump_stats(FILE *);
struct ct_assl_io_ctx	*ct_ssl_connect(int);
void			ct_reconnect(int, short, void *);
int			ct_reconnect_internal(void);
void			ct_load_certs(struct assl_context *);
int			ct_assl_negotiate_poll(struct ct_assl_io_ctx *);
void			ct_setup_write_md(const char *, int, const char *, int,
			    char *, char **);
void			ct_cleanup_md(void);

/* match functionality */
#define CT_MATCH_INVALID	(0)
#define CT_MATCH_REGEX		(1)
#define CT_MATCH_RB		(2)
#define CT_MATCH_GLOB		(3)

struct ct_match;
struct ct_match		*ct_match_compile(int, char **);
struct ct_match		*ct_match_fromfile(const char *, int);
char			**ct_matchlist_fromfile(const char *);
void			 ct_matchlist_free(char **);
int			 ct_match(struct ct_match *, char *);
void			 ct_match_unwind(struct ct_match *);

void			ct_ssl_init_bw_lim(struct ct_assl_io_ctx *);

/* MD mode handling */
#define CT_MDMODE_LOCAL		(0)
#define CT_MDMODE_REMOTE	(1)

char			*ct_md_cook_filename(const char *);
void			 ct_mdmode_setup(const char *);
void			 ct_find_md_for_extract(struct ct_op *);
void			 ct_find_md_for_extract_complete(struct ct_op *);
char                    *ct_find_md_for_archive(const char *);
int			 md_is_in_cache(const char *);
void			 ct_complete_metadata(struct ct_trans *);
void			 ct_mdcache_trim(const char *, long long);

/* misc */
int			ct_get_answer(char *, char *, char *, char *, char *,
			    size_t, int);
int			ct_prompt_password(char *, char *, size_t, char *,
			    size_t);
