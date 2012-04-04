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

#include <limits.h>

#include <sys/tree.h>
#include <sys/queue.h>

#include <openssl/sha.h>

#include <ctutil.h>
#include <ct_socket.h>
#include <ct_threads.h>

#include <event2/event.h>

#ifndef evutil_socket_t
#define evutil_socket_t int
#endif

#include "ct_crypto.h"

/* versioning */
#define CT_STRINGIFY(x)		#x
#define CT_STR(x)		CT_STRINGIFY(x)
#define CT_VERSION_MAJOR	1
#define CT_VERSION_MINOR	2
#define CT_VERSION_PATCH	1
#define CT_VERSION		CT_STR(CT_VERSION_MAJOR) "." \
				CT_STR(CT_VERSION_MINOR) "." \
				CT_STR(CT_VERSION_PATCH)

struct ct_config {
	char	*ct_host;
	char	*ct_hostport;
	char	*ct_username;
	char	*ct_password;
	char	*ct_localdb;
	char	*ct_ca_cert;
	char	*ct_cert;
	char	*ct_key;
	char	*ct_crypto_secrets;
	char	*ct_crypto_passphrase;
	char	*ct_polltype;
	char	*ct_ctfile_cachedir;

	int	ct_max_trans;
	int	ct_compress;
	int	ct_multilevel_allfiles;
	int	ct_auto_differential;
	int	ct_max_differentials;
	int	ct_ctfile_keep_days;
	int	ct_ctfile_mode;
	long long	ct_ctfile_max_cachesize;
	int	ct_secrets_upload;
	int	ct_io_bw_limit;
};

extern char		*__progname;
extern int		ct_skip_xml_negotiate;

struct ct_global_state;

void			ct_shutdown(struct ct_global_state *state);
void			ct_process_input(void *);
void			ct_process_file(void *);
void			ct_compute_sha(void *);
void			ct_compute_compress(void *);
void			ct_compute_encrypt(void *);
void			ct_compute_csha(void *);
void			ct_process_completions(void *);
void			ct_process_write(void *);

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

/* FILE STATUS */

#define CT_S_STARTING		(0)
#define CT_S_RUNNING		(1)
#define CT_S_WAITING_SERVER	(2)
#define CT_S_WAITING_TRANS	(3)
#define CT_S_FINISHED		(4)

void				ct_set_file_state(struct ct_global_state *,
				    int);
int				ct_get_file_state(struct ct_global_state *);

/* Transaction  */

struct ct_trans;

RB_HEAD(ct_trans_head, ct_trans);

struct ct_trans {
	struct ct_header	hdr;		/* must be first element */
	TAILQ_ENTRY(ct_trans)	tr_next;
	RB_ENTRY(ct_trans)	tr_trans_rbnode;

	/* is this a local or data transaction */
	int			tr_local;

	struct fnode		*tr_fl_node;
	struct ctfile_write_state *tr_ctfile;
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
#define TR_S_XML_OPENED		(22)
#define TR_S_XML_CLOSE		(23)
#define TR_S_XML_CLOSING	(24)
#define TR_S_XML_CLOSED		(25)
#define TR_S_XML_LIST		(26)
#define TR_S_XML_DELETE		(27)

#define TR_S_XML_CULL_SEND	(28)
#define TR_S_XML_CULL_REPLIED	(29)

	char			tr_dataslot;
	char			tr_eof;

	uint8_t			tr_sha[SHA_DIGEST_LENGTH];
	uint8_t			tr_csha[SHA_DIGEST_LENGTH];
	uint8_t			tr_iv[CT_IV_LEN];


	int			tr_chsize;
	int			tr_size[3];

	uint8_t			*tr_data[3];
	uint32_t		tr_ctfile_chunkno;
	const char		*tr_ctfile_name;
};

struct ct_trans		*ct_trans_alloc(struct ct_global_state *);
struct ct_trans		*ct_trans_realloc_local(struct ct_global_state *,
			    struct ct_trans *);
void			ct_trans_free(struct ct_global_state *,
			    struct ct_trans *);
void			ct_trans_cleanup(struct ct_global_state *);
void			ct_free_fnode(struct fnode *);

void			ct_queue_first(struct ct_global_state *,
			    struct ct_trans *);
void			ct_queue_transfer(struct ct_global_state *,
			    struct ct_trans *);

/* config */
struct ct_config	*ct_load_config(char **);
void			 ct_unload_config(char *, struct ct_config *);

void			 ct_prompt_for_login_password(struct ct_config *);
void			 ct_normalize_username(char *);
char			*ct_normalize_path(char *);
void			 ct_normalize_filelist(char **);

/* what are we doing? */
extern int		ct_action;
#define CT_A_ARCHIVE	(1)
#define CT_A_LIST	(2)
#define CT_A_EXTRACT	(3)
#define CT_A_ERASE	(4)
#define CT_A_JUSTDL	(5)	/* fake option for ctfb */

struct ct_op;

/* length of a ctfile tag's time string */
#define			TIMEDATA_LEN	17	/* including NUL */
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

int			ct_list(const char *, char **, char **, int,
			    const char *, int, int);
void			ctfile_list_complete(struct ctfile_list *, int,
			    char **, char **, struct ctfile_list_tree *);
int			ctfile_verify_name(char *);

/* CT context state */

#define STR_PAD(n) int pad ## n [8];

RB_HEAD(ct_trans_lookup, ct_trans);
RB_HEAD(ct_iotrans_lookup, ct_trans);

typedef void (ct_op_cb)(struct ct_global_state *, struct ct_op *);
struct ct_op {
	TAILQ_ENTRY(ct_op)	 op_link;
	ct_op_cb		*op_start;
	ct_op_cb		*op_complete;
	void			*op_args;
	void			*op_priv;	/* operation private data */
};

/*
 * shared between extract and list in remote mode
 */
struct ct_extract_args {
	char			*cea_local_ctfile;
	char			*cea_tdir;
	char			**cea_filelist;
	char			**cea_excllist;
	char			*cea_ctfile_basedir;
	int			 cea_matchmode;
	int			 cea_strip_slash;
	int			 cea_attr;
	int			 cea_follow_symlinks;
};

struct ct_archive_args {
	char			*caa_local_ctfile;
	char			*caa_includefile;
	char			*caa_tag;
	char			*caa_basis;
	char			*caa_tdir;
	char			*caa_ctfile_basedir;
	char			**caa_filelist;
	char			**caa_excllist;
	int			 caa_matchmode;
	int			 caa_encrypted;
	int			 caa_allfiles;
	int			 caa_no_cross_mounts;
	int			 caa_max_differentials;
	int			 caa_strip_slash;
	int			 caa_follow_root_symlink;
	int			 caa_follow_symlinks;
};

struct ct_extract_file_args {
	const char		*cefa_filename;
	const char		*cefa_ctfile;
	off_t			 cefa_ctfile_off;
};

struct ct_ctfile_list_args {
	char		**ccla_search;
	char		**ccla_exclude;
	int		 ccla_matchmode;
};

struct ct_ctfileop_args {
	char		*cca_localname;
	char		*cca_remotename;
	char		*cca_tdir;
	int		 cca_encrypted; /* for archive only */
	int		 cca_ctfile; /* is ctfile or other data */
};

struct ct_op	*ct_add_operation(struct ct_global_state *, ct_op_cb *,
		     ct_op_cb *, void *);
struct ct_op	*ct_add_operation_after(struct ct_global_state *,
		     struct ct_op *, ct_op_cb *, ct_op_cb *, void *);
void		 ct_do_operation(struct ct_config *, ct_op_cb *, ct_op_cb *,
		     void *, int);
void		 ct_nextop(void *);
int		 ct_op_complete(struct ct_global_state *state);
ct_op_cb	 ct_archive;
ct_op_cb	 ct_extract;
ct_op_cb	 ct_list_op;
ct_op_cb	 ctfile_archive;
ct_op_cb	 ctfile_extract;
ct_op_cb	 ctfile_op_cleanup;
ct_op_cb	 ctfile_list_start;
ct_op_cb	 ctfile_list_print;
ct_op_cb	 ct_check_secrets_extract;
ct_op_cb	 ct_check_secrets_upload;
ct_op_cb	 ctfile_delete;
ct_op_cb	 ct_free_remotename;

struct ct_global_state {
	/* PADs? */
	struct ct_assl_io_ctx		*ct_assl_ctx; /* Connection state */
	struct ct_config		*ct_config;

	struct ct_extract_state		*extract_state;
	struct ct_archive_state		*archive_state;
	struct ct_statistics		*ct_stats;
	TAILQ_HEAD(,ct_trans)		ct_trans_free_head;
	int				ct_trans_id; /* next transaction id */
	uint64_t			ct_packet_id; /* next complete id */
	int				ct_tr_tag; /* next packet tag */
	int				ct_max_block_size; /* negotiated */
	int				ct_alloc_block_size; /* trans data sz */
	int				ct_max_trans;
	int				ct_trans_alloc;
	int				ct_trans_free;
	int				ct_num_local_transactions;
	int				ct_sha_state;
	int				ct_csha_state;
	int				ct_file_state;
	int				ct_comp_state;
	int				ct_crypt_state;
	STR_PAD(0);
	TAILQ_HEAD(, ct_trans)		ct_sha_queue;
	int				ct_sha_qlen;
	CT_LOCK_STORE(ct_sha_lock);
	STR_PAD(1);
	TAILQ_HEAD(, ct_trans)		ct_comp_queue;
	int				ct_comp_qlen;
	CT_LOCK_STORE(ct_comp_lock);
	STR_PAD(2);
	TAILQ_HEAD(, ct_trans)		ct_crypt_queue;
	int				ct_crypt_qlen;
	CT_LOCK_STORE(ct_crypt_lock);
	STR_PAD(3);
	TAILQ_HEAD(, ct_trans)		ct_csha_queue;
	int				ct_csha_qlen;
	CT_LOCK_STORE(ct_csha_lock);
	STR_PAD(4);
	TAILQ_HEAD(, ct_trans)		ct_write_queue;
	int				ct_write_qlen;
	CT_LOCK_STORE(ct_write_lock);
	STR_PAD(5);
	TAILQ_HEAD(, ct_trans)		ct_queued;
	int				ct_queued_qlen;
	CT_LOCK_STORE(ct_queued_lock);
	STR_PAD(6);
	struct ct_iotrans_lookup	ct_inflight;
	int				ct_inflight_rblen;
	STR_PAD(7);
	struct ct_trans_lookup		ct_complete;
	int				ct_complete_rblen;
	CT_LOCK_STORE(ct_complete_lock);
	TAILQ_HEAD(ct_ops, ct_op)	ct_operations;
	struct ctdb_state		*ct_db_state;

	/* Reconnect state */
	int				ct_disconnected;
	int				ct_reconnect_pending;
#define CT_RECONNECT_DEFAULT_TIMEOUT	30
	int				ct_reconnect_timeout;

	/* ctfile list state */
	struct ctfile_list		ctfile_list_files;

	/* Crypto state */
	unsigned char			ct_iv[CT_IV_LEN];
	unsigned char			ct_crypto_key[CT_KEY_LEN];

	int				ct_verbose;

	struct ct_compress_ctx		*ct_compress_state;
};

extern struct event_base *ct_evt_base;
void ct_event_init(struct ct_global_state *);
int ct_event_dispatch(void);
int ct_event_loopbreak(void);
void ct_event_cleanup(void);
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

void ct_display_queues(struct ct_global_state *);
void ct_display_assl_stats(struct ct_global_state *, FILE *);

typedef void (ct_func_cb)(void *);

struct ct_ctx;

struct ct_global_state *ct_setup_state(struct ct_config *);
void ct_setup_wakeup_file(void *, ct_func_cb *);
void ct_setup_wakeup_sha(void *, ct_func_cb *);
void ct_setup_wakeup_compress(void *, ct_func_cb *);
void ct_setup_wakeup_csha(void *, ct_func_cb *);
void ct_setup_wakeup_encrypt(void *, ct_func_cb *);
void ct_setup_wakeup_write(void *, ct_func_cb *);
void ct_setup_wakeup_complete(void *, ct_func_cb *);
void ct_set_reconnect_timeout(void (*)(evutil_socket_t, short, void*), void *,
    int);

msgdeliver_ty			ct_handle_msg;
msgcomplete_ty			ct_write_done;

ct_header_alloc_func		ct_header_alloc;
ct_header_free_func		ct_header_free;
ct_body_alloc_func		ct_body_alloc;
ct_body_free_func		ct_body_free;

void				*ct_body_alloc_xml(size_t);

void				ct_handle_xml_reply(struct ct_global_state *,
				    struct ct_trans *trans,
				    struct ct_header *hdr, void *vbody);
void				ct_xml_file_open(struct ct_global_state *,
				    struct ct_trans *, const char *,
				    int, uint32_t);
int				ct_xml_file_open_polled(
				    struct ct_global_state *,
				    const char *, int, uint32_t);
#define MD_O_READ	0
#define MD_O_WRITE	1
#define MD_O_APPEND	2
void				ct_xml_file_close(struct ct_global_state *);

#include "ct_db.h"

char				*ctfile_get_previous(const char *);

struct dedup_digest {
	char		dd_digest[SHA_DIGEST_LENGTH];
	char		dd_digest_crypto[SHA_DIGEST_LENGTH];
	char		dd_iv[CT_IV_LEN];
};
typedef struct dedup_digest dedup_digest;	/* ugh typedef, blame XDR */

/* XDR for metadata global hader */
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

int			ct_read_header(struct ctfile_header *hdr);
int			ct_basis_setup(const char *, char **, int, time_t *,
			    int);
/* archive state functions: */
struct ct_archive_state;
struct ct_archive_state	*ct_archive_init(const char *);
struct dnode		*ct_archive_get_rootdir(struct ct_archive_state *);
struct dnode		*ct_archive_lookup_dir(struct ct_archive_state *,
			     const char *);
struct dnode		*ct_file_archive_insert_dir(struct ct_archive_state *,
			     struct dnode *);
void			 ct_archive_cleanup(struct ct_archive_state *);


/* ct_file.c: extract functions */
struct ct_extract_state;
struct ct_extract_state	*ct_file_extract_init(const char *, int, int, int);
struct dnode		*ct_file_extract_get_rootdir(struct ct_extract_state *);
struct dnode		*ct_file_extract_insert_dir(struct ct_extract_state *,
			     struct dnode *);
struct dnode		*ct_file_extract_lookup_dir(struct ct_extract_state *,
			     const char *);
int			 ct_file_extract_open(struct ct_extract_state *,
			     struct fnode *fnode);
void			 ct_file_extract_write(struct ct_extract_state *,
			     struct fnode *, uint8_t *buf, size_t size);
void			 ct_file_extract_close(struct ct_extract_state *,
			     struct fnode *fnode);
void			 ct_file_extract_special(struct ct_extract_state *,
			     struct fnode *fnode);
void			 ct_file_extract_cleanup(struct ct_extract_state *);

void	ct_create_config(void);
char *ct_system_config(void);
char *ct_user_config(void);
char *ct_user_config_old(void);

/* ct_files.c: path functions */
char	*ct_dirname(const char *);
char	*ct_basename(const char *);

/* ct_ctl.c */
void			secrets_generate(struct ct_cli_cmd *, int, char **);

/* print file data nicely */
void			ct_pr_fmt_file(struct fnode *fnode, int);
void			ct_print_file_start(struct fnode *, int);
void			ct_print_file_end(struct fnode *, int, int);
void			ct_print_ctfile_info(const char *,
			    struct ctfile_gheader *);

RB_PROTOTYPE(ct_iotrans_lookup, ct_trans, tr_trans_id, ct_cmp_iotrans);
RB_PROTOTYPE(ct_trans_lookup, ct_trans, tr_trans_id, ct_cmp_trans);

/* statistics */

struct ct_statistics {
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

void			ct_dump_stats(struct ct_global_state *, FILE *);
struct ct_assl_io_ctx	*ct_ssl_connect(struct ct_global_state *, int);
void			ct_ssl_cleanup(struct ct_assl_io_ctx *);
void			ct_reconnect(evutil_socket_t, short, void *);
int			ct_reconnect_internal(struct ct_global_state *);
int			ct_assl_negotiate_poll(struct ct_global_state *);

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
void			 ct_match_insert_rb(struct ct_match *, char *);
int			 ct_match_rb_is_empty(struct ct_match *);

void			ct_ssl_init_bw_lim(struct ct_assl_io_ctx *, int);
void			ct_ssl_cleanup_bw_lim();

/* MD mode handling */
#define CT_MDMODE_LOCAL		(0)
#define CT_MDMODE_REMOTE	(1)

void			 ctfile_mode_setup(const char *);

typedef void	(ctfile_find_callback)(struct ct_global_state *,
		    char *, void *);
void		 ctfile_find_for_operation(struct ct_global_state *, char *,
		    ctfile_find_callback *, void *, int, int);
		
void		 ct_upload_secrets_file(struct ct_config *);
void		 ct_download_secrets_file(struct ct_config *);
int		 ct_have_remote_secrets_file(struct ct_config *);

ctfile_find_callback	 ctfile_nextop_extract;
ctfile_find_callback	 ctfile_nextop_list;
ctfile_find_callback	 ctfile_nextop_archive;
ctfile_find_callback	 ctfile_nextop_justdl;


void			 ct_complete_metadata(struct ct_global_state *,
			     struct ct_trans *);
void			 ctfile_trim_cache(const char *, long long);

char			*ctfile_cook_name(const char *);
int			 ctfile_in_cache(const char *, const char *);
char			*ctfile_get_cachename(const char *, const char *);

/* misc */
int			ct_get_answer(char *, char *, char *, char *, char *,
			    size_t, int);
int			ct_prompt_password(char *, char *, size_t, char *,
			    size_t, int);

/* init/cleanup */
struct ct_global_state	*ct_init(struct ct_config *, int, int);
void			ct_init_eventloop(struct ct_global_state *);
void			ct_update_secrets(void);
void			ct_cleanup(struct ct_global_state *);
void			ct_cleanup_eventloop(struct ct_global_state *);
void			ct_cleanup_login_cache(void);

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
	int			 xs_sha_cnt;
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
struct ctfile_write_state
	*ctfile_write_init(const char *, const char *, int, const char *, int,
	    char *, char **, int, int, int);
void	 ctfile_write_special(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_file_start(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_file_sha(struct ctfile_write_state *, uint8_t *,
	     uint8_t *, uint8_t *);
int	 ctfile_write_file_pad(struct ctfile_write_state *, struct fnode *);
int	 ctfile_write_file_end(struct ctfile_write_state *, struct fnode *);
void	 ctfile_write_close(struct ctfile_write_state *);


/*
 * Functions for queueing differentials for extract or similar.
 */
TAILQ_HEAD(ct_extract_head, ct_extract_stack);
struct ct_extract_stack   {
	TAILQ_ENTRY(ct_extract_stack)	next;
	char		*filename;
};
void	ct_extract_setup(struct ct_extract_head *, struct ctfile_parse_state *,
	    const char *, const char *, int *, int);
void	ct_extract_setup_dir(const char *);
void	ct_extract_open_next(struct ct_extract_head *,
	    struct ctfile_parse_state *, int);
void	ct_extract_cleanup_queue(struct ct_extract_head *);

/* cull  */
int ct_cull_add_shafile(const char *, const char *);
void ct_cull_sha_insert(const uint8_t *);
void ct_cull_kick(struct ct_global_state *);

/*
 * Extract an individual file from ctfile at ctfile_off, op_localname is
 * the local filename to save it as
 */
ct_op_cb	ct_extract_file;
ct_op_cb	ct_extract_file_cleanup;



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

uint64_t ct_get_debugmask(char *);

/* FreeBSD 7 doesn't have openat() */
#if defined(__FreeBSD__) &&  (__FreeBSD_version < 800000)
#define CT_NO_OPENAT
#endif

/* OpenBSD prior to 5.0 doesn't have openat() */
#if defined(__OpenBSD__) && (OpenBSD < 201111)
#define CT_NO_OPENAT
#endif

