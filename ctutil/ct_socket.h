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

#ifndef CT_SOCKET_H
#define CT_SOCKET_H

#include <event.h>

/* provide a typedef for the libevent callback type */
typedef void (eventcb_ty)(int, short, void *);

typedef void (msgdeliver_ty)(void *, struct ct_header *, void *);
typedef void (msgcomplete_ty)(void *, struct ct_header *, void *, int);
typedef void (limitio_ty)(void *, size_t);

struct ct_assl_io_ctx;

typedef void (ct_assl_io_over_bw_check_func) (void *,
		struct ct_assl_io_ctx *);

struct ct_io_queue {
	TAILQ_ENTRY(ct_io_queue) io_next;
	struct ct_header	*io_hdr;
	void			*io_data;
	int			iovcnt;
};

struct ct_iovec {
	void *iov_base;
	size_t iov_len;
};

typedef struct ct_header *(ct_header_alloc_func)(void *);
typedef void (ct_header_free_func)(void *, struct ct_header *);
typedef void *(ct_body_alloc_func)(void *, struct ct_header *);
typedef void (ct_body_free_func)(void *, void *, struct ct_header *);

typedef struct ct_io_queue *(ct_ioctx_alloc_func)(void);
typedef void (ct_ioctx_free_func)(struct ct_io_queue *);

struct ct_io_ctx {
	msgdeliver_ty			*io_rd_cb;
	msgcomplete_ty			*io_wrcomplete_cb;
	void				*io_cb_arg;
	struct ct_header		*io_i_hdr;
	void				*io_i_data;
	ct_header_alloc_func		*io_header_alloc;
	ct_header_free_func		*io_header_free;
	ct_body_alloc_func		*io_body_alloc;
	ct_body_free_func		*io_body_free;
	ct_ioctx_alloc_func		*io_ioctx_alloc;
	ct_ioctx_free_func		*io_ioctx_free;
	TAILQ_HEAD(, ct_io_queue)	io_o_q;
	struct event			io_ev_rd;
	struct event			io_ev_wr;
	int				io_i_fd;
	int				io_o_fd;
	int				io_i_state;
	int				io_i_resid;
	int				io_i_off;
	int				io_o_state;
	int				io_o_resid;
	int				io_o_off;
	int				io_o_written;

	int				io_user_flow_control;
	int				io_write_io_enabled;

	/* stats */
	uint64_t			io_write_bytes;				
	uint64_t			io_write_count;				
	uint64_t			io_read_bytes;				
	uint64_t			io_read_count;				
};

struct ct_assl_io_ctx {
	msgdeliver_ty			*io_rd_cb;
	msgcomplete_ty			*io_wrcomplete_cb;
	void				*io_cb_arg;
	struct assl_context		*c;
	struct ct_header		*io_i_hdr;
	void				*io_i_data;
	ct_header_alloc_func		*io_header_alloc;
	ct_header_free_func		*io_header_free;
	ct_body_alloc_func		*io_body_alloc;
	ct_body_free_func		*io_body_free;
	ct_ioctx_alloc_func		*io_ioctx_alloc;
	ct_ioctx_free_func		*io_ioctx_free;
	ct_assl_io_over_bw_check_func   *io_over_bw_check;
	TAILQ_HEAD(,ct_io_queue)	io_o_q;

	int				io_max_transfer;

	int				io_i_state;
	int				io_i_resid;
	int				io_i_off;
	int				io_o_state;
	int				io_o_resid;
	int				io_o_off;
	int				io_o_written;

	int				io_write_io_enabled;

	/* stats */
	uint64_t			io_write_bytes;				
	uint64_t			io_write_count;				
	uint64_t			io_read_bytes;				
	uint64_t			io_read_count;				
};

eventcb_ty		ct_event_assl_write, ct_event_assl_read;
eventcb_ty		ct_event_io_write, ct_event_io_read;

extern	pid_t		ct_pid;

void			ct_assl_io_ctx_init(struct ct_assl_io_ctx *,
			    struct assl_context *, msgdeliver_ty *,
			    msgcomplete_ty *, void *,
			    ct_header_alloc_func *, ct_header_free_func *,
			    ct_body_alloc_func *, ct_body_free_func *,
			    ct_ioctx_alloc_func *, ct_ioctx_free_func *);
void			ct_io_ctx_init(struct ct_io_ctx *,
			    msgdeliver_ty *, msgcomplete_ty *, void *,
			    ct_header_alloc_func *, ct_header_free_func *,
			    ct_body_alloc_func *, ct_body_free_func *);

void			ct_assl_write_op(struct ct_assl_io_ctx *,
			    struct ct_header *, void *);
void			ct_io_write_op(struct ct_io_ctx *, struct ct_header *,
			    void *);
int			ct_assl_writev_op(struct ct_assl_io_ctx *,
			    struct ct_header *, struct ct_iovec *, int);
int			ct_io_writev_op(struct ct_io_ctx *, struct ct_header *,
			    struct ct_iovec *, int);
int			ct_io_connect_fd_pair(struct ct_io_ctx *ctx, int, int);
int			ct_io_fork_child(struct ct_io_ctx *,
			int (*)(void *, int, int), void *);
void			ct_io_disconnect(struct ct_io_ctx *);
void			ct_assl_disconnect(struct ct_assl_io_ctx *);

void			ct_assl_io_block_writes(struct ct_assl_io_ctx *);
void			ct_assl_io_resume_writes(struct ct_assl_io_ctx *);
void			ct_io_block_writes(struct ct_io_ctx *);
void			ct_io_resume_writes(struct ct_io_ctx *);

/* limit write size on assl sockets */
void			ct_assl_io_ctx_set_maxtrans(struct ct_assl_io_ctx *,
			    size_t);
void			ct_assl_io_ctx_set_over_bw_func(struct ct_assl_io_ctx *,
			    ct_assl_io_over_bw_check_func *);

/* bypass queues and events - use with caution */
size_t			ct_assl_io_write_poll(struct ct_assl_io_ctx *, void *,
			    size_t, int);
size_t			ct_assl_io_read_poll(struct ct_assl_io_ctx *, void *,
			    size_t, int);

#endif /* CT_SOCKET_H */
