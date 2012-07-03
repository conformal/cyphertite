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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <event2/event.h>
#include <signal.h>
#include <ct_threads.h>

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include <ct_internal.h>


#ifdef __linux__
#define SIGINFO SIGUSR1
#endif

struct ct_ctx {
	struct event		*ctx_ev;
	ct_func_cb		*ctx_fn;
	void			(*ctx_wakeup)(struct ct_ctx *);
	void			(*ctx_shutdown)(struct ct_ctx *);
	void			*ctx_varg;
#if CT_ENABLE_PTHREADS
	pthread_mutex_t 	ctx_mtx;
	pthread_cond_t 		ctx_cv;
	pthread_t		ctx_thread;
	int			ctx_exiting;
#endif
	int			ctx_type;
	int                     ctx_pipe[2];

};


struct ct_event_state {
	struct event_base	*ct_evt_base;
	struct ct_ctx		 ct_ctx_file;
	struct ct_ctx		 ct_ctx_sha;
	struct ct_ctx		 ct_ctx_compress;
	struct ct_ctx		 ct_ctx_csha;
	struct ct_ctx		 ct_ctx_encrypt;
	struct ct_ctx		 ct_ctx_complete;
	struct ct_ctx		 ct_ctx_write;
	struct event		*ct_ev_sig_info;
	struct event		*ct_ev_sig_usr1;
	struct event		*ct_ev_sig_pipe;
	struct event		*recon_ev;

};

void ct_handle_wakeup(int, short, void *);
void ct_pipe_sig(int, short, void *);
void ct_wakeup_x_pipe(struct ct_ctx *);
void ct_shutdown_x_pipe(struct ct_ctx *);
#if CT_ENABLE_THREADS
void ct_wakeup_x_cv(struct ct_ctx *);
int ct_setup_wakeup_cv(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb);
#endif
int ct_setup_wakeup_pipe(struct event_base *, struct ct_ctx *ctx, void *vctx,
    ct_func_cb *func_cb);
void * ct_cb_thread(void *);

int
ct_setup_wakeup_pipe(struct event_base *base, struct ct_ctx *ctx, void *vctx,
    ct_func_cb *func_cb)
{
	int i;
	ctx->ctx_type = 0;
	ctx->ctx_varg = vctx;
	ctx->ctx_fn = func_cb;
	ctx->ctx_wakeup = ct_wakeup_x_pipe;
	ctx->ctx_shutdown = ct_shutdown_x_pipe;

	if (pipe(ctx->ctx_pipe))
		return (CTE_ERRNO);

	/* make pipes nonblocking - both sides of pipe */
	for (i= 0; i < 2; i++)
		ct_set_pipe_nonblock((ctx->ctx_pipe)[i]);

	/* master side of pipe - no config */
	/* client side of pipe */

	ctx->ctx_ev = event_new(base, (ctx->ctx_pipe)[0],
	    EV_READ|EV_PERSIST, ct_handle_wakeup, ctx);
	event_add(ctx->ctx_ev, NULL);

	return (0);
}

int
ct_setup_wakeup_file(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base, &ev_st->ct_ctx_file,
	    vctx, func_cb);
}

int
ct_setup_wakeup_sha(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	return ct_setup_wakeup_cv(&ev_st->ct_ctx_sha, vctx, func_cb);
#else
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base, &ev_st->ct_ctx_sha,
	    vctx, func_cb);
#endif
}

int
ct_setup_wakeup_compress(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	return ct_setup_wakeup_cv(&ev_st->ct_ctx_compress, vctx, func_cb);
#else
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base,
	    &ev_st->ct_ctx_compress, vctx, func_cb);
#endif
}

int
ct_setup_wakeup_csha(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	return ct_setup_wakeup_cv(&ev_st->ct_ctx_csha, vctx, func_cb);
#else
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base, &ev_st->ct_ctx_csha,
	    vctx, func_cb);
#endif
}

int
ct_setup_wakeup_encrypt(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	return ct_setup_wakeup_cv(&ev_st->ct_ctx_encrypt, vctx, func_cb);
#else
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base, &ev_st->ct_ctx_encrypt,
	    vctx, func_cb);
#endif
}

int
ct_setup_wakeup_complete(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base,
	    &ev_st->ct_ctx_complete, vctx, func_cb);
}

int
ct_setup_wakeup_write(struct ct_event_state *ev_st, void *vctx, ct_func_cb *func_cb)
{
	return ct_setup_wakeup_pipe(ev_st->ct_evt_base, &ev_st->ct_ctx_write,
	    vctx, func_cb);
}

void
ct_handle_wakeup(int fd, short event, void *vctx)
{
	char rbuf[16];
	ssize_t rlen;
	struct ct_ctx *ctx = vctx;

	/* drain wakeup pipe */
	do {
		rlen = read(fd, &rbuf, sizeof(rbuf));
	} while (rlen == sizeof (rbuf));
	ctx->ctx_fn(ctx->ctx_varg);
}

void
ct_wakeup_x_pipe(struct ct_ctx *ctx)
{
	char wbuf;

	wbuf = 'G';
	if (write(ctx->ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_shutdown_x_pipe(struct ct_ctx *ctx)
{
	event_free(ctx->ctx_ev);
	close(ctx->ctx_pipe[0]);
	ctx->ctx_pipe[0] = -1;
	close(ctx->ctx_pipe[1]);
	ctx->ctx_pipe[1] = -1;
	ctx->ctx_fn = NULL;
	ctx->ctx_wakeup = NULL;
	ctx->ctx_shutdown = NULL;
	ctx->ctx_ev = NULL;
}

void
ct_wakeup_file(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_file;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_sha(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_sha;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_compress(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_compress;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_csha(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_csha;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_encrypt(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_encrypt;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_complete(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_complete;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_write(struct ct_event_state *ev_st)
{
	struct ct_ctx *ctx = &ev_st->ct_ctx_write;

	ctx->ctx_wakeup(ctx);
}

void
ct_pipe_sig(int fd, short event, void *vctx)
{
	/* nothing to do */
}

/*
 * wrap the event code in this file.
 */
struct ct_event_state *
ct_event_init(struct ct_global_state *state,
    void (*cb)(evutil_socket_t, short, void *), void (*info_cb)(evutil_socket_t,
    short, void *))
{
	struct ct_event_state	*ev_st;

	ev_st = e_calloc(1, sizeof(*ev_st));

	ev_st->ct_evt_base = event_base_new();

	/* cache siginfo */
	if (info_cb != NULL) {
#if defined(SIGINFO) && SIGINFO != SIGUSR1
		ev_st->ct_ev_sig_info = evsignal_new(ev_st->ct_evt_base,
		    SIGINFO, info_cb, state);
		evsignal_add(ev_st->ct_ev_sig_info, NULL);
#endif
#if defined(SIGUSR1)
		ev_st->ct_ev_sig_usr1 = evsignal_new(ev_st->ct_evt_base,
		    SIGUSR1, info_cb, state);
		evsignal_add(ev_st->ct_ev_sig_usr1, NULL);
#endif
	}
#if defined(SIGPIPE)
	ev_st->ct_ev_sig_pipe = evsignal_new(ev_st->ct_evt_base, SIGPIPE,
	    ct_pipe_sig, state);
	evsignal_add(ev_st->ct_ev_sig_pipe, NULL);
#endif
	ev_st->recon_ev = evtimer_new(ev_st->ct_evt_base, cb, state);
	if (ev_st->recon_ev == NULL) {
		ct_event_cleanup(ev_st);
		return (NULL);
	}

	return (ev_st);
}

struct event_base *
ct_event_get_base(struct ct_event_state *ev_st)
{
	return (ev_st->ct_evt_base);
}

int
ct_event_dispatch(struct ct_event_state *ev_st)
{
	return event_base_dispatch(ev_st->ct_evt_base);
}

int
ct_event_loopbreak(struct ct_event_state *ev_st)
{
	return event_base_loopbreak(ev_st->ct_evt_base);
}

void
ct_event_shutdown(struct ct_event_state *ev_st)
{
	if (ev_st->ct_ctx_file.ctx_shutdown != NULL)
		ev_st->ct_ctx_file.ctx_shutdown(&ev_st->ct_ctx_file);
	if (ev_st->ct_ctx_complete.ctx_shutdown != NULL)
		ev_st->ct_ctx_complete.ctx_shutdown(&ev_st->ct_ctx_complete);
	if (ev_st->ct_ctx_write.ctx_shutdown != NULL)
		ev_st->ct_ctx_write.ctx_shutdown(&ev_st->ct_ctx_write);
	if (ev_st->ct_ctx_sha.ctx_shutdown != NULL)
		ev_st->ct_ctx_sha.ctx_shutdown(&ev_st->ct_ctx_sha);
	if (ev_st->ct_ctx_compress.ctx_shutdown != NULL)
		ev_st->ct_ctx_compress.ctx_shutdown(&ev_st->ct_ctx_compress);
	if (ev_st->ct_ctx_csha.ctx_shutdown != NULL)
		ev_st->ct_ctx_csha.ctx_shutdown(&ev_st->ct_ctx_csha);
	if (ev_st->ct_ctx_encrypt.ctx_shutdown != NULL)
		ev_st->ct_ctx_encrypt.ctx_shutdown(&ev_st->ct_ctx_encrypt);
}

void
ct_event_cleanup(struct ct_event_state *ev_st)
{
	if (ev_st == NULL)
		return;

	if (ev_st->ct_ev_sig_info != NULL)
		event_free(ev_st->ct_ev_sig_info);
	if (ev_st->ct_ev_sig_usr1 != NULL)
		event_free(ev_st->ct_ev_sig_usr1);
	if (ev_st->ct_ev_sig_pipe != NULL)
		event_free(ev_st->ct_ev_sig_pipe);
	if (ev_st->recon_ev != NULL)
		event_free(ev_st->recon_ev);
	if (ev_st->ct_evt_base != NULL)
		event_base_free(ev_st->ct_evt_base);
	e_free(&ev_st);
}

void
ct_set_reconnect_timeout(struct ct_event_state *ev_st, int delay)
{
	struct timeval tv;

	if (evtimer_pending(ev_st->recon_ev, NULL))
		evtimer_del(ev_st->recon_ev);
	bzero(&tv, sizeof(tv));
	tv.tv_sec = delay;
	evtimer_add(ev_st->recon_ev, &tv);
}

#if CT_ENABLE_PTHREADS
void
ct_wakeup_x_cv(struct ct_ctx *ctx)
{
	pthread_mutex_lock(&ctx->ctx_mtx);
	pthread_cond_signal(&ctx->ctx_cv);
	pthread_mutex_unlock(&ctx->ctx_mtx);
}

void
ct_shutdown_cv(struct ct_ctx *ctx)
{
	pthread_mutex_lock(&ctx->ctx_mtx);
	ctx->ctx_exiting = 1;
	ctx->ctx_fn = NULL;
	ctx->ctx_wakeup = NULL;
	ctx->ctx_shutdown = NULL;
	pthread_cond_signal(&ctx->ctx_cv);
	pthread_mutex_unlock(&ctx->ctx_mtx);

	if (ctx->ctx_thread != pthread_self() &&
	    pthread_join(ctx->ctx_thread, NULL) != 0)
		CABORT("can't join on thread");
}

int
ct_setup_wakeup_cv(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb)
{
	pthread_attr_t	 attr;

	ctx->ctx_type = 1;
	ctx->ctx_varg = vctx;
	ctx->ctx_fn = func_cb;
	ctx->ctx_wakeup = ct_wakeup_x_cv;
	ctx->ctx_shutdown = ct_shutdown_cv;

	pthread_mutex_init(&ctx->ctx_mtx, NULL);
	pthread_cond_init (&ctx->ctx_cv, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_create(&ctx->ctx_thread, &attr, ct_cb_thread, (void *)ctx);

	return (0);
}

void *
ct_cb_thread(void *vctx)
{
	struct ct_ctx *ctx = vctx;

	do {
		pthread_mutex_lock(&ctx->ctx_mtx);
		pthread_cond_wait(&ctx->ctx_cv, &ctx->ctx_mtx);
		if (ctx->ctx_exiting) {
			pthread_mutex_unlock(&ctx->ctx_mtx);
			break;
		}
		pthread_mutex_unlock(&ctx->ctx_mtx);

		ctx->ctx_fn(ctx->ctx_varg);

	} while (1);

	pthread_cond_destroy(&ctx->ctx_cv);
	pthread_mutex_destroy(&ctx->ctx_mtx);

	pthread_exit(NULL);
}
#endif /* CT_ENABLE_PTHREADS */
