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

#include "ct.h"


#ifdef __linux__
#define SIGINFO SIGUSR1
#endif

struct ct_ctx {
	struct event		*ctx_ev;
	ct_func_cb		*ctx_fn;
	void			(*ctx_wakeup)(struct ct_ctx *);
	void			*ctx_varg;
#if CT_ENABLE_PTHREADS
	pthread_mutex_t 	ctx_mtx;
	pthread_cond_t 		ctx_cv;
	pthread_t		ctx_thread;
#endif
	int			ctx_type;
	int                     ctx_pipe[2];

};

struct event_base *ct_evt_base;
struct ct_ctx ct_ctx_file;
struct ct_ctx ct_ctx_sha;
struct ct_ctx ct_ctx_compress;
struct ct_ctx ct_ctx_csha;
struct ct_ctx ct_ctx_encrypt;
struct ct_ctx ct_ctx_complete;
struct ct_ctx ct_ctx_write;
struct event *ct_ev_sig_info = NULL;
struct event *ct_ev_sig_usr1 = NULL;
struct event *ct_ev_sig_pipe = NULL;

void ct_handle_wakeup(int, short, void *);
void ct_info_sig(int, short, void *);
void ct_pipe_sig(int, short, void *);
void ct_wakeup_x_pipe(struct ct_ctx *);
#if CT_ENABLE_THREADS
void ct_wakeup_x_cv(struct ct_ctx *);
void ct_setup_wakeup_cv(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb);
#endif
void ct_setup_wakeup_pipe(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb);
void * ct_cb_thread(void *);


/* XXX -global to cause threads to exit on next wakup.*/
int ct_exiting;

struct event *recon_ev = NULL;

void
ct_setup_wakeup_pipe(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb)
{
	int i;
	ctx->ctx_type = 0;
	ctx->ctx_varg = vctx;
	ctx->ctx_fn = func_cb;
	ctx->ctx_wakeup = ct_wakeup_x_pipe;

	if (pipe(ctx->ctx_pipe))
		CFATAL("pipe create failed");

	/* make pipes nonblocking - both sides of pipe */
	for (i= 0; i < 2; i++)
		ct_set_pipe_nonblock((ctx->ctx_pipe)[i]);

	/* master side of pipe - no config */
	/* client side of pipe */

	ctx->ctx_ev = event_new(ct_evt_base, (ctx->ctx_pipe)[0],
	    EV_READ|EV_PERSIST, ct_handle_wakeup, ctx);
	event_add(ctx->ctx_ev, NULL);
}

void
ct_setup_wakeup_file(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup_pipe(&ct_ctx_file, vctx, func_cb);
}

void
ct_setup_wakeup_sha(void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	ct_setup_wakeup_cv(&ct_ctx_sha, vctx, func_cb);
#else
	ct_setup_wakeup_pipe(&ct_ctx_sha, vctx, func_cb);
#endif
}

void
ct_setup_wakeup_compress(void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	ct_setup_wakeup_cv(&ct_ctx_compress, vctx, func_cb);
#else
	ct_setup_wakeup_pipe(&ct_ctx_compress, vctx, func_cb);
#endif
}

void
ct_setup_wakeup_csha(void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	ct_setup_wakeup_cv(&ct_ctx_csha, vctx, func_cb);
#else
	ct_setup_wakeup_pipe(&ct_ctx_csha, vctx, func_cb);
#endif
}

void
ct_setup_wakeup_encrypt(void *vctx, ct_func_cb *func_cb)
{
#if CT_ENABLE_THREADS
	ct_setup_wakeup_cv(&ct_ctx_encrypt, vctx, func_cb);
#else
	ct_setup_wakeup_pipe(&ct_ctx_encrypt, vctx, func_cb);
#endif
}

void
ct_setup_wakeup_complete(void *vctx, ct_func_cb *func_cb)
{
	/* XXX - is this still pipe? */
	ct_setup_wakeup_pipe(&ct_ctx_complete, vctx, func_cb);
}

void
ct_setup_wakeup_write(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup_pipe(&ct_ctx_write, vctx, func_cb);
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
ct_wakeup_file(void)
{
	struct ct_ctx *ctx = &ct_ctx_file;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_sha(void)
{
	struct ct_ctx *ctx = &ct_ctx_sha;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_compress(void)
{
	struct ct_ctx *ctx = &ct_ctx_compress;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_csha(void)
{
	struct ct_ctx *ctx = &ct_ctx_csha;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_encrypt(void)
{
	struct ct_ctx *ctx = &ct_ctx_encrypt;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_complete()
{
	struct ct_ctx *ctx = &ct_ctx_complete;

	ctx->ctx_wakeup(ctx);
}

void
ct_wakeup_write()
{
	struct ct_ctx *ctx = &ct_ctx_write;

	ctx->ctx_wakeup(ctx);
}

void
ct_info_sig(int fd, short event, void *vctx)
{
	ct_display_queues(ct_state);
}

void
ct_pipe_sig(int fd, short event, void *vctx)
{
	/* nothing to do */
}

/*
 * wrap the event code in this file.
 */
void
ct_event_init(void)
{
	ct_evt_base = event_base_new();

	/* cache siginfo */
#if defined(SIGINFO) && SIGINFO != SIGUSR1
	ct_ev_sig_info = evsignal_new(ct_evt_base, SIGINFO, ct_info_sig, NULL);
	evsignal_add(ct_ev_sig_info, NULL);
#endif
#if defined(SIGUSR1)
	ct_ev_sig_usr1 = evsignal_new(ct_evt_base, SIGUSR1, ct_info_sig, NULL);
	evsignal_add(ct_ev_sig_usr1, NULL);
#endif
#if defined(SIGPIPE)
	ct_ev_sig_pipe = evsignal_new(ct_evt_base, SIGPIPE, ct_pipe_sig, NULL);
	evsignal_add(ct_ev_sig_pipe, NULL);
#endif
}

int
ct_event_dispatch(void)
{
	return event_base_dispatch(ct_evt_base);
}

int
ct_event_loopbreak(void)
{
	return event_base_loopbreak(ct_evt_base);
}

void
ct_event_cleanup(void)
{
	if (ct_ctx_complete.ctx_ev != NULL)
		event_free(ct_ctx_complete.ctx_ev);
	if (ct_ctx_write.ctx_ev != NULL)
		event_free(ct_ctx_write.ctx_ev);
	if (ct_ctx_sha.ctx_ev != NULL)
		event_free(ct_ctx_sha.ctx_ev);
	if (ct_ctx_compress.ctx_ev != NULL)
		event_free(ct_ctx_compress.ctx_ev);
	if (ct_ctx_csha.ctx_ev != NULL)
		event_free(ct_ctx_csha.ctx_ev);
	if (ct_ctx_encrypt.ctx_ev != NULL)
		event_free(ct_ctx_encrypt.ctx_ev);
	if (ct_ev_sig_info != NULL)
		event_free(ct_ev_sig_info);
	if (ct_ev_sig_usr1 != NULL)
		event_free(ct_ev_sig_usr1);
	if (ct_ev_sig_pipe != NULL)
		event_free(ct_ev_sig_pipe);
	if (recon_ev != NULL)
		event_free(recon_ev);
	if (ct_evt_base != NULL)
		event_base_free(ct_evt_base);
}

void
ct_set_reconnect_timeout(void (*cb)(int, short, void*), void *varg,
    int delay)
{
	struct timeval tv;
	if (recon_ev == NULL) {
		recon_ev = evtimer_new(ct_evt_base, cb, varg);
		if (recon_ev == NULL)
			CABORT("unable to allocate reconnect timer");
	} else {
		evtimer_del(recon_ev);
	}
	bzero(&tv, sizeof(tv));
	tv.tv_sec = delay;
	evtimer_add(recon_ev, &tv);
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
ct_setup_wakeup_cv(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb)
{
	pthread_attr_t	 attr;

	ctx->ctx_type = 1;
	ctx->ctx_varg = vctx;
	ctx->ctx_fn = func_cb;
	ctx->ctx_wakeup = ct_wakeup_x_cv;

	pthread_mutex_init(&ctx->ctx_mtx, NULL);
	pthread_cond_init (&ctx->ctx_cv, NULL);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
	pthread_create(&ctx->ctx_thread, &attr, ct_cb_thread, (void *)ctx);
}

void *
ct_cb_thread(void *vctx)
{
	struct ct_ctx *ctx = vctx;

	do {
		pthread_mutex_lock(&ctx->ctx_mtx);
		pthread_cond_wait(&ctx->ctx_cv, &ctx->ctx_mtx);
		if (ct_exiting)
			break;
		pthread_mutex_unlock(&ctx->ctx_mtx);

		ctx->ctx_fn(ctx->ctx_varg);

	} while (1);

	pthread_exit(NULL);
}
#endif /* CT_ENABLE_PTHREADS */
