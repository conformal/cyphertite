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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#ifndef NO_UTIL_H
#include <util.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>

#include <clog.h>
#include <assl.h>
#include <exude.h>
#include <xmlsd.h>
#include <sqlite3.h>

#include <ctutil.h>
#include <ct_socket.h>
#include <ct_crypto.h>
#include <ct_proto.h>
#include <ct_db.h>
#include <ct_ctfile.h>
#include <ct_lib.h>
#include <ct_internal.h>
#include <ct_ext.h>

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

int			 ct_skip_xml_negotiate;
struct ct_io_queue	*ct_ioctx_alloc(void);
void			ct_ioctx_free(struct ct_io_queue *);
void			ct_print_scaled_stat(FILE *, const char *, int64_t,
			    int64_t, int);
char			*ct_getloginbyuid(uid_t);

/* XXX use message catalog when warranted. */
const char *ct_errmsgs[] = {
	[CTE_ERRNO] = " ",
	[CTE_EMPTY_XML] = "empty xml body",
	[CTE_SHORT_READ] = "short read",
	[CTE_SHORT_WRITE] = "short write",
	[CTE_INVALID_REPLY_LEN] = "invalid reply length",
	[CTE_INVALID_REPLY_TYPE] = "invalid reply type",
	[CTE_XML_PARSE_FAIL] = "XML parse failure",
	[CTE_INVALID_XML_TYPE]	 = "Invalid XML type",
	[CTE_NO_SECRETS_FILE] = "No crypto secrets file, please run "
	     "ctctl secrets generate or ctctl secrets download",
	[CTE_INVALID_SECRETS_FILE] = "Invalid secrets file",
	[CTE_INVALID_PASSPHRASE	] = "Invalid passphrase",
	[CTE_INVALID_REPLY_VERSION] = "Invalid reply version",
	[CTE_CANT_BASE64	] = "Can not base64",
	[CTE_INVALID_CREDENTIALS] = "Invalid credentials",
	[CTE_ACCOUNT_DISABLED	] = "Account Disabled - Please log in to your "
	    "cyphertite.com account or contact support@cyphertite.com",
	[CTE_OUT_OF_SPACE	] = "Account has run out of space - Please log "
	    "in to your cyphertite.com account or contact support@cyphertite.com",
	[CTE_OPERATION_FAILED	] = "Operation failed",
	[CTE_INVALID_CTFILE_PROTOCOL] = "Invalid ctfile protocol",
	[CTE_INVALID_CTFILE_FOOTER] = "Invalid ctfile footer",
	[CTE_INVALID_CTFILE_CHUNKNO] = "Invalid ctfile chunkno",
	[CTE_INVALID_CULL_TYPE] = "Invalid cull type",
	[CTE_LOAD_CERTS] = "Failed to load certs. Ensure that the ca_cert, "
	    "cert and key are set to valid paths in the configuration file",
	[CTE_ASSL_CONTEXT] = "Failed to allocate assl context",
	[CTE_CONNECT_FAILED] = "Failed to connect",
};

const char *
ct_strerror(int ct_errno)
{
	if (ct_errno == CTE_ERRNO)
		return (strerror(errno));

	if (ct_errno < 0 || ct_errno >= CTE_MAX)
		CABORTX("ct_errno out of range %d", ct_errno);

	return (ct_errmsgs[ct_errno]);
}



ct_log_ctfile_info_fn		ct_log_ctfile_info_default;
ct_log_file_start_fn		ct_log_file_start_default;
ct_log_file_end_fn		ct_log_file_end_default;
ct_log_file_skip_fn		ct_log_file_skip_default;
ct_log_traverse_start_fn	ct_log_traverse_start_default;
ct_log_traverse_end_fn		ct_log_traverse_end_default;

void
ct_log_ctfile_info_default(void *state, const char *file,
    struct ctfile_gheader *hdr)
{
}

void
ct_log_file_start_default(void *state, struct fnode *fnode)
{
}

void
ct_log_file_end_default(void *state, struct fnode *fnode, int blocksize)
{
}

void
ct_log_file_skip_default(void *state, struct fnode *fnode)
{
}

void
ct_log_traverse_start_default(void *state, char **filelist)
{
}

void
ct_log_traverse_end_default(void *state, char **filelist)
{
}

int
ct_init(struct ct_global_state **statep, struct ct_config *conf,
    int need_secrets, void (*info_cb)(evutil_socket_t, short, void *))
{
	struct ct_global_state *state = NULL;
	extern void		ct_reconnect(evutil_socket_t, short, void *);
	struct stat		sb;
	int			ret = 0;

	/* Run with restricted umask as we create numerous sensitive files. */
	umask(S_IRWXG|S_IRWXO);

	if ((state = ct_setup_state(conf)) == NULL) {
		ret = CTE_ERRNO;
		goto fail;
	}

	/* set defaults */
	if ((ret = ct_set_log_fns(state, NULL, NULL, NULL, NULL, NULL, NULL,
	    NULL)) != 0)
		goto fail;

	if (need_secrets != 0 && conf->ct_crypto_secrets != NULL) {
		if (stat(conf->ct_crypto_secrets, &sb) == -1) {
			ret = CTE_NO_SECRETS_FILE;
			goto fail;
		}
		/* we got crypto */
		if ((ret = ct_unlock_secrets(conf->ct_crypto_passphrase,
		    conf->ct_crypto_secrets,
		    state->ct_crypto_key, sizeof(state->ct_crypto_key),
		    state->ct_iv, sizeof(state->ct_iv))) != 0)
			goto fail;
	}

	if ((ret = ct_init_eventloop(state, info_cb)) != 0)
		goto fail;

	*statep = state;
	return (0);

fail:
	if (state != NULL) {
		e_free(&state->ct_stats);
		e_free(&state);
	}
	return (ret);
}

int
ct_set_log_fns(struct ct_global_state *state, void *logst,
    ct_log_ctfile_info_fn *ctfile_info, ct_log_file_start_fn *log_start,
    ct_log_file_end_fn *log_end, ct_log_file_skip_fn *log_skip,
    ct_log_traverse_start_fn *log_traverse_start,
    ct_log_traverse_end_fn *log_traverse_end)
{
	state->ct_print_state = logst;

	if (ctfile_info != NULL)
		state->ct_print_ctfile_info = ctfile_info;
	else
		state->ct_print_ctfile_info = ct_log_ctfile_info_default;

	if (log_start != NULL)
		state->ct_print_file_start = log_start;
	else
		state->ct_print_file_start = ct_log_file_start_default;

	if (log_end != NULL)
		state->ct_print_file_end = log_end;
	else
		state->ct_print_file_end = ct_log_file_end_default;

	if (log_skip != NULL)
		state->ct_print_file_skip = log_skip;
	else
		state->ct_print_file_skip = ct_log_file_skip_default;
		
	if (log_traverse_start != NULL) 
		state->ct_print_traverse_start = log_traverse_start;
	else
		state->ct_print_traverse_start = ct_log_traverse_start_default;

	if (log_traverse_end != NULL)
		state->ct_print_traverse_end = log_traverse_end;
	else
		state->ct_print_traverse_end = ct_log_traverse_end_default;

	return (0);
}


int
ct_init_eventloop(struct ct_global_state *state,
    void (*info_cb)(evutil_socket_t, short, void *))
{
	int ret, s_errno;

	state->event_state = ct_event_init(state, ct_reconnect, info_cb);

#if defined(CT_EXT_INIT)
	CT_EXT_INIT(state);
#endif

	state->ct_db_state = ctdb_setup(state->ct_config->ct_localdb,
	    state->ct_config->ct_crypto_secrets != NULL);

	gettimeofday(&state->ct_stats->st_time_start, NULL);
	if ((ret = ct_ssl_connect(state)) != 0)
		goto fail;
	if ((ret = ct_assl_negotiate_poll(state)) != 0)
		goto fail;

	CNDBG(CT_LOG_NET, "assl data: as bits %d, protocol [%s]",
	    state->ct_assl_ctx->c->as_bits,
	    state->ct_assl_ctx->c->as_protocol);

	ct_set_file_state(state, CT_S_STARTING);
	CT_LOCK_INIT(&state->ct_sha_lock);
	CT_LOCK_INIT(&state->ct_comp_lock);
	CT_LOCK_INIT(&state->ct_crypt_lock);
	CT_LOCK_INIT(&state->ct_csha_lock);
	CT_LOCK_INIT(&state->ct_write_lock);
	CT_LOCK_INIT(&state->ct_queued_lock);
	CT_LOCK_INIT(&state->ct_complete_lock);

	if ((ret = ct_setup_wakeup_file(state->event_state, state,
	    ct_nextop)) != 0)
		goto fail;
	if ((ret = ct_setup_wakeup_sha(state->event_state, state,
	    ct_compute_sha)) != 0)
		goto fail;
	if ((ret = ct_setup_wakeup_compress(state->event_state, state,
	    ct_compute_compress)) != 0)
		goto fail;
	if ((ret = ct_setup_wakeup_csha(state->event_state, state,
	    ct_compute_csha)) != 0)
		goto fail;
	if ((ret = ct_setup_wakeup_encrypt(state->event_state, state,
	    ct_compute_encrypt)) != 0)
		goto fail;
	if ((ret = ct_setup_wakeup_write(state->event_state, state,
	    ct_process_write)) != 0)
		goto fail;
	if ((ret = ct_setup_wakeup_complete(state->event_state, state,
	    ct_process_completions)) != 0)
		goto fail;
	return (0);

fail:
	/* Save errno in case CTE_ERRNO */
	s_errno = errno;
	ct_cleanup_eventloop(state);
	errno = s_errno;

	return (ret);
}

void
ct_cleanup_eventloop(struct ct_global_state *state)
{
	ct_trans_cleanup(state);
	ct_ssl_cleanup(state);
	ctdb_shutdown(state->ct_db_state);
	state->ct_db_state = NULL;
	// XXX: ct_lock_cleanup();
	CT_LOCK_RELEASE(&state->ct_sha_lock);
	CT_LOCK_RELEASE(&state->ct_comp_lock);
	CT_LOCK_RELEASE(&state->ct_crypt_lock);
	CT_LOCK_RELEASE(&state->ct_csha_lock);
	CT_LOCK_RELEASE(&state->ct_write_lock);
	CT_LOCK_RELEASE(&state->ct_queued_lock);
	CT_LOCK_RELEASE(&state->ct_complete_lock);

	ct_event_cleanup(state->event_state);
}

void
ct_cleanup(struct ct_global_state *state)
{
	ct_cleanup_eventloop(state);
	e_free(&state->ct_stats);
	e_free(&state);
}

struct ct_op *
ct_add_operation(struct ct_global_state *state, ct_op_cb *start,
    ct_op_cb *complete, void *args)
{
	struct ct_op	*op;

	op = e_calloc(1, sizeof(*op));
	op->op_start = start;
	op->op_complete = complete;
	op->op_args = args;

	TAILQ_INSERT_TAIL(&state->ct_operations, op, op_link);

	return (op);
}

struct ct_op *
ct_add_operation_after(struct ct_global_state *state, struct ct_op *after,
    ct_op_cb *start, ct_op_cb *complete, void *args)
{
	struct ct_op	*op;

	op = e_calloc(1, sizeof(*op));
	op->op_start = start;
	op->op_complete = complete;
	op->op_args = args;

	TAILQ_INSERT_AFTER(&state->ct_operations, after, op, op_link);

	return (op);
}

/* Do a complete ct operation from start to finish */
int
ct_do_operation(struct ct_config *conf,  ct_op_cb *start, ct_op_cb *complete,
    void *args, int need_secrets)
{
	struct ct_global_state	*state;
	int		 	 ret;

	ct_prompt_for_login_password(conf);

	if ((ret = ct_init(&state, conf, need_secrets, NULL)) != 0)
		return (ret);

	ct_add_operation(state, start, complete, args);
	ct_wakeup_file(state->event_state);
	ret = ct_event_dispatch(state->event_state);
	ct_cleanup(state);

	return (ret);
}

void
ct_nextop(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_op		*op;

	op = TAILQ_FIRST(&state->ct_operations);
	if (op == NULL)
		CABORTX("no operation in queue");

	op->op_start(state, op);
}

int
ct_op_complete(struct ct_global_state *state)
{
	struct ct_op *op;

	op = TAILQ_FIRST(&state->ct_operations);
	if (op == NULL)
		CABORTX("no operation in queue");

	if (op->op_complete)
		op->op_complete(state, op);

	TAILQ_REMOVE(&state->ct_operations, op, op_link);
	e_free(&op);

	if (TAILQ_EMPTY(&state->ct_operations))
		return (1);

	/* set up for the next loop */
	ct_set_file_state(state, CT_S_STARTING);
	ct_wakeup_file(state->event_state);
	return (0);
}

static int
ct_load_certs(struct ct_global_state *state, struct assl_context *c)
{
	if (assl_load_file_certs(c, state->ct_config->ct_ca_cert,
	    state->ct_config->ct_cert, state->ct_config->ct_key))
		return (CTE_LOAD_CERTS);
		assl_fatalx("Failed to load certs. Ensure that "
		    "the ca_cert, cert and key are set to valid paths in "
		    "the configuration file");
}

int
ct_ssl_connect(struct ct_global_state *state)
{
	struct ct_assl_io_ctx	*ctx;
	struct assl_context	*c;
	int			 ret;

	ctx = e_calloc(1, sizeof (*ctx));

	if ((c = assl_alloc_context(ASSL_M_TLSV1_CLIENT, 0)) == NULL) {
		e_free(&ctx);
		return (CTE_ASSL_CONTEXT);
	}

	if ((ret = ct_load_certs(state, c)) != 0) {
		/* free assl thingy */
		e_free(&ctx);
		return (ret);
	}

	ct_assl_io_ctx_init(ctx, c, ct_handle_msg, ct_write_done,
	    state, ct_header_alloc, ct_header_free, ct_body_alloc,
	    ct_body_free, ct_ioctx_alloc, ct_ioctx_free);

	if (assl_event_connect(c, state->ct_config->ct_host,
	    state->ct_config->ct_hostport,
	    ASSL_F_NONBLOCK|ASSL_F_KEEPALIVE|ASSL_F_THROUGHPUT,
	    ct_event_get_base(state->event_state), ct_event_assl_read,
	    ct_event_assl_write, ctx)) {
		ct_assl_disconnect(ctx);
		e_free(&ctx);
		ctx = NULL;
		return (CTE_CONNECT_FAILED);
	}

	state->ct_assl_ctx = ctx;

	if (state->ct_config->ct_io_bw_limit && ctx != NULL)
		state->bw_limit =
		    ct_ssl_init_bw_lim(ct_event_get_base(state->event_state),
		    ctx, state->ct_config->ct_io_bw_limit);

	return (0);
}

void
ct_ssl_cleanup(struct ct_global_state *state)
{
	if (state->bw_limit != NULL) {
		ct_ssl_cleanup_bw_lim(state->bw_limit);
		state->bw_limit = NULL;
	}
	if (state->ct_assl_ctx != NULL) {
		ct_assl_disconnect(state->ct_assl_ctx);
		e_free(&state->ct_assl_ctx);
	}
}

struct ct_io_queue *
ct_ioctx_alloc(void)
{
	struct ct_io_queue *ioq;
	ioq = e_calloc(1, sizeof(*ioq));
	return ioq;
}

void
ct_ioctx_free(struct ct_io_queue *ioq)
{
	e_free(&ioq);
}


struct ct_header *
ct_header_alloc(void *vctx)
{
	struct ct_header *hdr;
	hdr = e_calloc(1, sizeof(*hdr));
	return hdr;
}

void
ct_header_free(void *vctx, struct ct_header *hdr)
{
	e_free(&hdr);
}

#define ASSL_TIMEOUT 20
int
ct_assl_negotiate_poll(struct ct_global_state *state)
{
	void				 *body;
	struct ct_header		 hdr;
	ssize_t				 sz;
	int				 rv = 1;
	int				 payload_sz;
	uint8_t				 buf[20];

	/* send server request */
	if ((rv = ct_create_neg(&hdr, &body, state->ct_max_trans,
	    state->ct_max_block_size)) != 0)
		goto done;
	payload_sz = hdr.c_size;
	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(state->ct_assl_ctx, &hdr, sizeof hdr,
	    ASSL_TIMEOUT) != sizeof hdr) {
		rv = CTE_SHORT_WRITE;
		goto done;
	}
	if (ct_assl_io_write_poll(state->ct_assl_ctx, body, payload_sz,
	    ASSL_TIMEOUT) != payload_sz) {
		rv = CTE_SHORT_WRITE;
		goto done;
	}

	/* get server reply */
	sz = ct_assl_io_read_poll(state->ct_assl_ctx, &hdr, sizeof hdr,
	    ASSL_TIMEOUT);
	if (sz != sizeof hdr) {
		rv = CTE_SHORT_READ;
		CWARNX("invalid header size %ld", (long) sz);
		goto done;
	}
	ct_unwire_header(&hdr);
	/* negotiate reply is the same size as the request, so reuse the body */
	if (hdr.c_size != payload_sz)  {
		rv = CTE_INVALID_REPLY_LEN;
		CWARNX("invalid negotiate reply size %d", hdr.c_size);
		goto done;
	}

	if (ct_assl_io_read_poll(state->ct_assl_ctx, buf,
		    hdr.c_size, ASSL_TIMEOUT) != hdr.c_size) {
		CWARNX("couldn't read neg parameters");
		rv = CTE_SHORT_READ;
		goto done;
	}

	if ((rv = ct_parse_neg_reply(&hdr, buf, &state->ct_max_trans,
	    &state->ct_max_block_size)) != 0) {
		goto done;
	}
	e_free(&body);

	CNDBG(CT_LOG_NET, "negotiated queue depth: %u max chunk size: %u",
	    state->ct_max_trans, state->ct_max_block_size);

	if ((rv = ct_create_login(&hdr, &body, state->ct_config->ct_username,
	    state->ct_config->ct_password)) != 0)
		goto done;
	payload_sz = hdr.c_size;
	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(state->ct_assl_ctx, &hdr, sizeof hdr,
	    ASSL_TIMEOUT) != sizeof hdr) {
		rv = CTE_SHORT_WRITE;
		goto done;
	}
	if (ct_assl_io_write_poll(state->ct_assl_ctx, body, payload_sz,
	    ASSL_TIMEOUT) != payload_sz) {
		rv = CTE_SHORT_WRITE;
		goto done;
	}

	/* get server reply */
	sz = ct_assl_io_read_poll(state->ct_assl_ctx, &hdr, sizeof hdr,
	    ASSL_TIMEOUT);
	if (sz != sizeof hdr) {
		rv = CTE_SHORT_READ;
		goto done;
	}
	e_free(&body);
	ct_unwire_header(&hdr);

	/* XXX need a way to get error crud out, right now the function warns
	   for us. */
	if ((rv = ct_parse_login_reply(&hdr, NULL)) != 0)
		goto done;

	if (ct_skip_xml_negotiate) {
		rv = 0;
		goto out;
	}

	if ((rv = ct_create_xml_negotiate(&hdr, &body,
	    ctdb_get_genid(state->ct_db_state))) != 0) {
		goto done;
	}

	payload_sz = hdr.c_size;
	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(state->ct_assl_ctx, &hdr, sizeof hdr,
	    ASSL_TIMEOUT) != sizeof hdr) {
		rv = CTE_SHORT_WRITE;
		goto done;
	}
	if (ct_assl_io_write_poll(state->ct_assl_ctx, body, payload_sz,
	    ASSL_TIMEOUT)
	    != payload_sz) {
		rv = CTE_SHORT_WRITE;
		CWARNX("could not write body");
		goto done;
	}
	e_free(&body);

	/* get server reply */
	sz = ct_assl_io_read_poll(state->ct_assl_ctx, &hdr, sizeof hdr,
	    ASSL_TIMEOUT);
	if (sz != sizeof hdr) {
		rv = CTE_SHORT_READ;
		CWARNX("invalid header size %" PRId64, (int64_t)sz);
		goto done;
	}
	ct_unwire_header(&hdr);

	if (hdr.c_size == 0) {
		rv = 0;
		goto out;
	}
	/* get server reply body */
	body = e_calloc(1, hdr.c_size);
	sz = ct_assl_io_read_poll(state->ct_assl_ctx, body, hdr.c_size,
	    ASSL_TIMEOUT);
	if (sz != hdr.c_size) {
		rv = CTE_SHORT_READ;
		goto done;
	}
	/* XXX check xml data */
	if ((rv = ct_parse_xml_negotiate_reply(&hdr, body,
	    state->ct_db_state)) != 0) {
		e_free(&body);
		goto done;
	}

	e_free(&body);

out:
	CNDBG(CT_LOG_NET, "login successful");
	rv = 0;
done:
	return (rv);
}

void
ct_shutdown(struct ct_global_state *state)
{
	ctdb_shutdown(state->ct_db_state);
	state->ct_db_state = NULL;
	ct_event_shutdown(state->event_state);
	ct_event_loopbreak(state->event_state);
}

void
ct_prompt_for_login_password(struct ct_config *conf)
{
	char	answer[1024];

	if (conf->ct_username == NULL) {
		if (ct_get_answer("Login username: ", NULL, NULL, NULL,
			answer, sizeof answer, 0)) {
			CFATALX("invalid username");
		} else if (!strlen(answer)) {
			CFATALX("username must not be empty");
		}
		conf->ct_username = e_strdup(answer);
		bzero(answer, sizeof answer);
	}
	ct_normalize_username(conf->ct_username);

	if (conf->ct_password == NULL) {
		if (ct_get_answer("Login password: ", NULL, NULL, NULL,
			answer, sizeof answer, 1)) {
			CFATALX("invalid password");
		} else if (!strlen(answer)) {
			CFATALX("password must not be empty");
		}
		conf->ct_password = e_strdup(answer);
		bzero(answer, sizeof answer);
	}

}

void
ct_normalize_username(char *username)
{
	/* Assume ASCII. */
	for (; *username != '\0'; username++)
		*username = tolower(*username);
}

void
ct_normalize_filelist(char **filelist)
{
	char	**fptr;

	fptr = filelist;
	while (*fptr != NULL) {
		*fptr = ct_normalize_path(*fptr);
		fptr++;
	}
}
