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
#ifndef CT_LIB_H
#define CT_LIB_H

#include <ct_types.h>
#include <ct_socket.h>
#include <ct_threads.h>

/* versioning */
#define CT_STRINGIFY(x)		#x
#define CT_STR(x)		CT_STRINGIFY(x)

#define CT_VERSION_MAJOR	1
#define CT_VERSION_MINOR	2
#define CT_VERSION_PATCH	2
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
	char	*ct_config_file;

	int	ct_max_trans;
	int	ct_compress;
	int	ct_multilevel_allfiles;
	int	ct_auto_differential;
	int	ct_max_differentials;
	int	ct_ctfile_keep_days;
#define CT_MDMODE_LOCAL		(0)
#define CT_MDMODE_REMOTE	(1)
	int	ct_ctfile_mode;
	long long	ct_ctfile_max_cachesize;
	int	ct_secrets_upload;
	int	ct_io_bw_limit;
};

struct ct_config	*ct_load_config(char **);
void			 ct_unload_config(char *, struct ct_config *);
char *ct_system_config(void);
char *ct_user_config(void);
char *ct_user_config_old(void);
void ct_write_config(struct ct_config *, FILE *, int, int);
void ct_default_config(struct ct_config *);
void ct_download_decode_and_save_certs(struct ct_config *);

/* Statistics */
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



#define STR_PAD(n) int pad ## n [8];

RB_HEAD(ct_iotrans_lookup, ct_trans);
RB_PROTOTYPE(ct_iotrans_lookup, ct_trans, tr_trans_id, ct_cmp_iotrans);
RB_HEAD(ct_trans_lookup, ct_trans);
RB_PROTOTYPE(ct_trans_lookup, ct_trans, tr_trans_id, ct_cmp_trans);


struct ctfile_gheader;
typedef		void	(ct_log_ctfile_info_fn)(void *, const char *,
			    struct ctfile_gheader *);
typedef		void	(ct_log_file_start_fn)(void *, struct fnode *);
typedef		void	(ct_log_file_end_fn)(void *, struct fnode *, int);
typedef		void	(ct_log_file_skip_fn)(void *, struct fnode *);
typedef		void	(ct_log_traverse_start_fn)(void *, char **);
typedef		void	(ct_log_traverse_end_fn)(void *, char **);
typedef		void	(ct_log_chown_failed_fn)(void *, struct fnode *,
			    struct dnode *);

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

	struct ct_compress_ctx		*ct_compress_state;
	struct ct_event_state		*event_state;
	struct bw_limit_ctx		*bw_limit;


	void				*ct_print_state;
	ct_log_ctfile_info_fn		*ct_print_ctfile_info;
	ct_log_file_start_fn		*ct_print_file_start;
	ct_log_file_end_fn		*ct_print_file_end;
	ct_log_file_skip_fn		*ct_print_file_skip;
	ct_log_traverse_start_fn	*ct_print_traverse_start;
	ct_log_traverse_start_fn	*ct_print_traverse_end;

	/* User data (opaque). */
	void				*ct_userptr;
};

struct ct_global_state *ct_setup_state(struct ct_config *);

/* Simplified API */
int
ct_do_remotelist(struct ct_global_state *state, char **search, char **exclude,
    int matchmode,
    void (*printfn) (struct ct_global_state *state, struct ct_op *op));

int
ct_do_remotearchive(struct ct_global_state *state, char *ctfile, char **flist,
    char *tdir, char **excludelist, char **includelist, int match_mode,
    int no_cross_mounts, int strip_slash, int follow_root_symlink,
    int follow_symlinks, struct ct_config *conf);

int
ct_do_remoteextract(struct ct_global_state *state, char *ctfile, char *tdir,
    char **excludelist, char **includefile, int match_mode, int strip_slash,
    int follow_symlinks, int preserve_attr,  struct ct_config *conf);

/* File status */
#define CT_S_STARTING		(0)
#define CT_S_RUNNING		(1)
#define CT_S_WAITING_SERVER	(2)
#define CT_S_WAITING_TRANS	(3)
#define CT_S_FINISHED		(4)

void				ct_set_file_state(struct ct_global_state *,
				    int);
int				ct_get_file_state(struct ct_global_state *);


void			ct_queue_first(struct ct_global_state *,
			    struct ct_trans *);
void			ct_queue_transfer(struct ct_global_state *,
			    struct ct_trans *);


struct bw_limit_ctx	*ct_ssl_init_bw_lim(struct event_base *,
			    struct ct_assl_io_ctx *, int);
void			ct_ssl_cleanup_bw_lim(struct bw_limit_ctx *);

int			ct_ssl_connect(struct ct_global_state *);
void			ct_ssl_cleanup(struct ct_global_state *);
void			ct_reconnect(evutil_socket_t, short, void *);
int			ct_assl_negotiate_poll(struct ct_global_state *);

int			ct_init(struct ct_global_state **, struct ct_config *,
			     int,
			     void  (*info_cb)(evutil_socket_t, short, void *));
int			ct_set_log_fns(struct ct_global_state *, void *,
			     ct_log_ctfile_info_fn *, 
			     ct_log_file_start_fn *, ct_log_file_end_fn *,
			     ct_log_file_skip_fn *, ct_log_traverse_start_fn *,
			     ct_log_traverse_end_fn *);
int			ct_init_eventloop(struct ct_global_state *,
			     void (*info_cb)(evutil_socket_t, short, void *));
void			ct_cleanup(struct ct_global_state *);
void			ct_cleanup_eventloop(struct ct_global_state *);

void			ct_compute_sha(void *);
void			ct_compute_compress(void *);
void			ct_compute_encrypt(void *);
void			ct_compute_csha(void *);
void			ct_process_completions(void *);
void			ct_process_write(void *);


/* CT context state */
struct ct_event_state;
struct ct_event_state	*ct_event_init(struct ct_global_state *,
    void (*)(evutil_socket_t, short, void *),
    void (*)(evutil_socket_t, short, void *));
int ct_event_dispatch(struct ct_event_state *);
int ct_event_loopbreak(struct ct_event_state *);
struct event_base	*ct_event_get_base(struct ct_event_state *);
void ct_event_shutdown(struct ct_event_state *);
void ct_event_cleanup(struct ct_event_state *);
void ct_wakeup_file(struct ct_event_state *);
void ct_wakeup_sha(struct ct_event_state *);
void ct_wakeup_compress(struct ct_event_state *);
void ct_wakeup_csha(struct ct_event_state *);
void ct_wakeup_encrypt(struct ct_event_state *);
void ct_wakeup_write(struct ct_event_state *);
void ct_wakeup_decrypt(struct ct_event_state *);
void ct_wakeup_uncompress(struct ct_event_state *);
void ct_wakeup_filewrite(struct ct_event_state *);
void ct_wakeup_complete(struct ct_event_state *);

/* break out of event loop */
void	ct_shutdown(struct ct_global_state *state);


/* Transaction  */
struct ct_trans;

RB_HEAD(ct_trans_head, ct_trans);
typedef int (ct_complete_fn)(struct ct_global_state *, struct ct_trans *);


struct ct_trans {
	struct ct_header	hdr;		/* must be first element */
	TAILQ_ENTRY(ct_trans)	tr_next;
	RB_ENTRY(ct_trans)	tr_trans_rbnode;
	ct_complete_fn		*tr_complete;

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
#define TR_S_XML_CULL_SHA_SEND	(29)
#define TR_S_XML_CULL_COMPLETE_SEND	(30)
#define TR_S_XML_CULL_REPLIED	(31)

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

/* Util path functions */
char	*ct_dirname(const char *);
char	*ct_basename(const char *);
int	 ct_absolute_path(const char *);
char			*ctfile_cook_name(const char *);
int			 ctfile_in_cache(const char *, const char *);
char			*ctfile_get_cachename(const char *, const char *);
int			 ctfile_verify_name(char *);
void			 ctfile_trim_cache(const char *, long long);

void			 ct_prompt_for_login_password(struct ct_config *);
void			 ct_normalize_username(char *);
char			*ct_normalize_path(char *);
void			 ct_normalize_filelist(char **);

/* Operation API */
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
	void			*cea_log_state;
	ct_log_chown_failed_fn	*cea_log_chown_failed;

};

struct ct_archive_args {
	char			*caa_local_ctfile;
	char			*caa_tag;
	char			*caa_basis;
	char			*caa_tdir;
	char			*caa_ctfile_basedir;
	char			**caa_filelist;
	char			**caa_includelist;
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
int		 ct_do_operation(struct ct_config *, ct_op_cb *, ct_op_cb *,
		     void *, int);
void		 ct_nextop(void *);
int		 ct_op_complete(struct ct_global_state *state);
ct_op_cb	 ct_archive;
ct_op_cb	 ct_extract;
ct_op_cb	 ctfile_archive;
ct_op_cb	 ctfile_extract;
ct_op_cb	 ctfile_op_cleanup;
ct_op_cb	 ctfile_list_start;
ct_op_cb	 ctfile_list_print;
void		 ctfile_list_complete(struct ctfile_list *, int, char **,
		     char **, struct ctfile_list_tree *);
ct_op_cb	 ct_check_secrets_extract;
ct_op_cb	 ctfile_delete;
ct_op_cb	 ct_free_remotename;

ct_op_cb	ct_extract_file;
ct_op_cb	ct_extract_file_cleanup;

/* return boolean whether or not the last ctfile_list contained the filename */
int	ct_file_on_server(struct ct_global_state *, char *);

int	ct_cull_add_shafile(const char *, const char *);
void	ct_cull_sha_insert(const uint8_t *);
void	ct_cull_kick(struct ct_global_state *);


int		 ct_have_remote_secrets_file(struct ct_config *);


/*
 * For remote mode, adds the operations obtain the provided ctfile from the
 * server then calls the callback to add your dependant op.
 */
typedef void	(ctfile_find_callback)(struct ct_global_state *,
		    char *, void *);
void		 ctfile_find_for_operation(struct ct_global_state *, char *,
		    ctfile_find_callback *, void *, int, int);

ctfile_find_callback	 ctfile_nextop_extract;
ctfile_find_callback	 ctfile_nextop_archive;
ctfile_find_callback	 ctfile_nextop_justdl;
		
/* Extract state api functions */
TAILQ_HEAD(ct_extract_head, ct_extract_stack);
struct ct_extract_stack   {
	TAILQ_ENTRY(ct_extract_stack)	next;
	char		*filename;
};

struct ctfile_parse_state;

void	ct_extract_setup(struct ct_extract_head *, struct ctfile_parse_state *,
	    const char *, const char *, int *);
void	ct_extract_open_next(struct ct_extract_head *,
	    struct ctfile_parse_state *);
void	ct_extract_cleanup_queue(struct ct_extract_head *);

struct ct_extract_state;
struct ct_extract_state	*ct_file_extract_init(const char *, int, int, int,
			     void *, ct_log_chown_failed_fn *);
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
int			 ct_populate_fnode(struct ct_extract_state *,
			     struct ctfile_parse_state *, struct fnode *,
			     int *, int, int);

/* archive state functions: */
struct ct_archive_state;
struct ct_archive_state	*ct_archive_init(const char *);
struct dnode		*ct_archive_get_rootdir(struct ct_archive_state *);
struct dnode		*ct_archive_insert_dir(struct ct_archive_state *,
			     struct dnode *);
struct dnode		*ct_archive_lookup_dir(struct ct_archive_state *,
			     const char *);
void			 ct_archive_cleanup(struct ct_archive_state *);


/* length of a ctfile tag's time string */
#define			TIMEDATA_LEN	17	/* including NUL */

int			ct_get_answer(char *, char *, char *, char *, char *,
			    size_t, int);
int			ct_prompt_password(char *, char *, size_t, char *,
			    size_t, int);





/* FreeBSD 7 doesn't have openat() */
#if defined(__FreeBSD__) &&  (__FreeBSD_version < 800000)
#define CT_NO_OPENAT
#endif

/* OpenBSD prior to 5.0 doesn't have openat() */
#if defined(__OpenBSD__) && (OpenBSD < 201111)
#define CT_NO_OPENAT
#endif

#endif /* ! CT_LIB_H */
