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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>
#include <event.h>
#include <signal.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"


#ifdef __linux__
#define SIGINFO SIGUSR1
#endif

struct ct_ctx {
	struct event		ctx_ev;
	ct_func_cb		*ctx_fn;
	void			*ctx_varg;
	int			ctx_pipe[2];
};

struct ct_ctx ct_ctx_file;
struct ct_ctx ct_ctx_sha;
struct ct_ctx ct_ctx_compress;
struct ct_ctx ct_ctx_csha;
struct ct_ctx ct_ctx_encrypt;
struct ct_ctx ct_ctx_complete;
struct event ct_ev_sig_info;
struct event ct_ev_sig_usr1;
struct event ct_ev_sig_pipe;

void ct_handle_wakeup(int, short, void *);
void ct_info_sig(int, short, void *);
void ct_pipe_sig(int, short, void *);

void
ct_setup_wakeup(struct ct_ctx *ctx, void *vctx, ct_func_cb *func_cb)
{
	int i;
	ctx->ctx_varg = vctx;
	ctx->ctx_fn = func_cb;

	if (pipe(ctx->ctx_pipe))
		CFATAL("pipe create failed");

	/* make pipes nonblocking - both sides of pipe */
	for (i= 0; i < 2; i++)
		ct_set_pipe_nonblock((ctx->ctx_pipe)[i]);

	/* master side of pipe - no config */
	/* client side of pipe */

	ctx->ctx_fn = func_cb;
	event_set(&ctx->ctx_ev, (ctx->ctx_pipe)[0], EV_READ|EV_PERSIST,
		ct_handle_wakeup, ctx);
	event_add(&ctx->ctx_ev, NULL);
}

void
ct_setup_wakeup_file(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup(&ct_ctx_file, vctx, func_cb);
}

void
ct_setup_wakeup_sha(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup(&ct_ctx_sha, vctx, func_cb);
}

void
ct_setup_wakeup_compress(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup(&ct_ctx_compress, vctx, func_cb);
}

void
ct_setup_wakeup_csha(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup(&ct_ctx_csha, vctx, func_cb);
}

void
ct_setup_wakeup_encrypt(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup(&ct_ctx_encrypt, vctx, func_cb);
}

void
ct_setup_wakeup_complete(void *vctx, ct_func_cb *func_cb)
{
	ct_setup_wakeup(&ct_ctx_complete, vctx, func_cb);
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
ct_wakeup_file(void)
{
	char wbuf;

	/* check state first? -- locks */
	/* XXX - add code to prevent multiple pending wakeups */
	wbuf = 'G';
	if (write(ct_ctx_file.ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_wakeup_sha(void)
{
	char wbuf;

	/* check state first? -- locks */
	/* XXX - add code to prevent multiple pending wakeups */
	wbuf = 'G';
	if (write(ct_ctx_sha.ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_wakeup_compress(void)
{
	char wbuf;

	/* check state first? -- locks */
	/* XXX - add code to prevent multiple pending wakeups */
	wbuf = 'G';
	if (write(ct_ctx_compress.ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_wakeup_csha(void)
{
	char wbuf;

	/* check state first? -- locks */
	/* XXX - add code to prevent multiple pending wakeups */
	wbuf = 'G';
	if (write(ct_ctx_csha.ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_wakeup_encrypt(void)
{
	char wbuf;

	/* check state first? -- locks */
	/* XXX - add code to prevent multiple pending wakeups */
	wbuf = 'G';
	if (write(ct_ctx_encrypt.ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_wakeup_complete()
{
	char wbuf;

	/* check state first? -- locks */
	/* XXX - add code to prevent multiple pending wakeups */
	wbuf = 'G';
	if (write(ct_ctx_complete.ctx_pipe[1], &wbuf, 1) == -1) { /* ignore */ }
}

void
ct_info_sig(int fd, short event, void *vctx)
{
	ct_display_queues();
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
	event_init();

	/* cache siginfo */
#if defined(SIGINFO) && SIGINFO != SIGUSR1
	signal_set(&ct_ev_sig_info, SIGINFO, ct_info_sig, NULL);
	signal_add(&ct_ev_sig_info, NULL);
#endif
	signal_set(&ct_ev_sig_usr1, SIGUSR1, ct_info_sig, NULL);
	signal_add(&ct_ev_sig_usr1, NULL);
	signal_set(&ct_ev_sig_pipe, SIGPIPE, ct_pipe_sig, NULL);
	signal_add(&ct_ev_sig_pipe, NULL);

}

int
ct_event_dispatch(void)
{
	return event_dispatch();
}

struct event recon_ev;
int recon_ev_inited = 0;

void
ct_set_reconnect_timeout(void (*cb)(int, short, void*), void *varg,
    int delay)
{
	struct timeval tv;
	if (recon_ev_inited) {
		evtimer_del(&recon_ev);
	}
	evtimer_set(&recon_ev, cb, varg);
	recon_ev_inited = 1;

	bzero(&tv, sizeof(tv));
	tv.tv_sec = delay;
	evtimer_add(&recon_ev, &tv);
}
