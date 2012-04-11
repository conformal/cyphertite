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

#include <stdio.h>
#include <inttypes.h>
#include <clog.h>
#include <assl.h>
#include <exude.h>

#include <sys/queue.h>

#include <ctutil.h>
#include <ct_socket.h>

#include <ct_types.h>
#include <cyphertite.h>

struct bw_debug {
	struct timeval	io_time;
	struct timeval	prev_time;
	uint64_t	tot_trans;
	uint64_t	this_trans;
	uint32_t	bw_curslot;
	uint32_t	bw_total;
	char		op;
	int		sleeping;
};

#define BW_DEBUG_SLOTS	200
struct bw_limit_ctx {
	struct bw_debug	 trace[BW_DEBUG_SLOTS];
	struct timeval	 curslottime;
	struct timeval	 single_slot_time;
	struct timeval	 sleep_tv;
	struct event	*wakeuptimer_ev;
	uint64_t	 last_bw_total_trans;
	int		 traceslot /*= 0*/;
	int		 bw_slot, slot_max;

};
void dump_bw_stats(void);

#define US_PER_SEC 1000000
#define SLOTS_PER_SEC 100
#define BW_TIMESLOT	(US_PER_SEC/SLOTS_PER_SEC)

ct_assl_io_over_bw_check_func ct_ssl_over_bw_func;

void ct_ssl_over_bw_wakeup(evutil_socket_t, short, void *);

struct bw_limit_ctx *
ct_ssl_init_bw_lim(struct event_base *base, struct ct_assl_io_ctx *ctx,
    int io_bw_limit)
{
	struct bw_limit_ctx	*blc;
	int			 packet_len;

	blc = e_calloc(1, sizeof(*blc));
	blc->wakeuptimer_ev = evtimer_new(base, ct_ssl_over_bw_wakeup, ctx);
	if (blc->wakeuptimer_ev == NULL) {
		e_free(&blc);
		return (NULL);
	}
	/* 1/4 of the number of bytes to send per timeslot */
	packet_len = ((io_bw_limit * 1024) / (US_PER_SEC/BW_TIMESLOT))/4;
	CNDBG(CT_LOG_NET, "packet_len %d",  packet_len);
	ct_assl_io_ctx_set_maxtrans(ctx, packet_len);
	ct_assl_io_ctx_set_over_bw_func(ctx, ct_ssl_over_bw_func);

	blc->single_slot_time.tv_sec = 0;
	blc->single_slot_time.tv_usec = BW_TIMESLOT;

	blc->slot_max =  ((io_bw_limit * 1024) / (US_PER_SEC/BW_TIMESLOT));
	CNDBG(CT_LOG_NET, "slottime %d max_bw_total %d",
	    BW_TIMESLOT, blc->slot_max);
	return (blc);
}

void
ct_ssl_cleanup_bw_lim(struct bw_limit_ctx *blc)
{
	if (blc == NULL)
		return;
	if (blc->wakeuptimer_ev != NULL)
		event_free(blc->wakeuptimer_ev);
	e_free(&blc);
}

void
ct_ssl_over_bw_wakeup(evutil_socket_t fd_unused, short reason, void *varg)
{
	struct timeval		now;
	struct ct_assl_io_ctx	*ctx = varg;
	struct ct_global_state	*state = ctx->io_cb_arg;
	struct bw_limit_ctx	*blc = state->bw_limit;
	struct bw_debug		*curdbg = &blc->trace[blc->traceslot];

	blc->traceslot = (blc->traceslot + 1) % BW_DEBUG_SLOTS;

	curdbg->op = 'W';

	if (gettimeofday(&now,NULL))
		CABORT("bw wakeup gettimeofday");
	curdbg->io_time = now;
	curdbg->prev_time = blc->sleep_tv;
	curdbg->tot_trans = 0;
	curdbg->this_trans = 0;
	curdbg->bw_curslot = 0;
	curdbg->bw_total = 0;
	curdbg->sleeping = -1;

	ct_assl_io_resume_writes(ctx);
}

void
ct_trunc_slot_time(struct timeval *tv)
{
	/* XXX - assumes BW_TIMESLOT < 1sec */
	tv->tv_usec = (tv->tv_usec / BW_TIMESLOT) * BW_TIMESLOT;
}

void
ct_ssl_over_bw_func(void *cbarg, struct ct_assl_io_ctx *ioctx)
{
	struct ct_global_state	*state = ioctx->io_cb_arg;
	struct bw_limit_ctx	*blc = state->bw_limit;
	struct timeval		 now, diff, nextslot;
	uint64_t		 newbytes;
	struct bw_debug		*curdbg = &blc->trace[blc->traceslot];

	blc->traceslot = (blc->traceslot +1) % BW_DEBUG_SLOTS;

	curdbg->op = 'O';

	/*
	 * Create a sliding window of 5 slots, if the upload speed
	 * over those 5 slots is greater than the bandwidth allowed,
	 * delay for one slot window.
	 * Ideally the maxtrans value is set to be between 1 slot worth
	 * or 1/4 slot worth (XXX -figure this magic value)
	 *
	 * Initially trying to set a slot to 1/100th of a second.
	 * this is in part due to some OSs not being able to sleep
	 * for < '1 tick' ie 1/100th of a second.
	 * It it were possible, it would make sense to sleep until
	 * the beginning of the next 1/100th of a second.
	 */

	if (gettimeofday(&now, NULL))
		CABORT("bw limit gettimeofday");

	curdbg->io_time = now;
	curdbg->prev_time = blc->curslottime;

	timersub(&now, &blc->curslottime, &diff);

	newbytes = ioctx->io_write_bytes - blc->last_bw_total_trans;
	blc->last_bw_total_trans = ioctx->io_write_bytes;

	/* truncate time to beginning of slot */
	timeradd(&blc->curslottime, &blc->single_slot_time, &nextslot);

	if (timercmp(&now, &nextslot, >)) {
		blc->bw_slot = 0;
		blc->curslottime = now;
		ct_trunc_slot_time(&blc->curslottime);
	}

	curdbg->tot_trans = ioctx->io_write_bytes;
	curdbg->this_trans = newbytes;

	blc->bw_slot += newbytes;

	curdbg->bw_curslot = blc->bw_slot;
	curdbg->bw_total = 0;

	curdbg->sleeping = 0;

	if (blc->bw_slot >= blc->slot_max) {
#if 0
		CINFO("cnt %d max %d newbytes %" PRIu64 "last %" PRIu64,
		    cur_bw_total, ((ct_io_bw_limit*1024) / slots_per_sec),
		    newbytes, last_bw_total_trans);
		for (i = 0; i < nslots; i++) {
			CINFO("slot %d contents %d", i, bw_slots[i]);
		}
		CINFO("curbytetotal %d cslot %d", cur_bw_total, cur_bw_slot);
#endif
		curdbg->sleeping = 1;

		ct_assl_io_block_writes(ioctx);

		if (!event_pending(blc->wakeuptimer_ev, EV_TIMEOUT,
		    &blc->sleep_tv))  {
			timersub(&nextslot, &now, &blc->sleep_tv);
			event_add(blc->wakeuptimer_ev, &blc->sleep_tv);
		}
	}

	CNDBG(CT_LOG_NET, "cbarg bytes %" PRIu64, ioctx->io_write_bytes);
	if (blc->traceslot == 0) {
		dump_bw_stats();
	}
}

void
dump_bw_stats(void)
{
#if 0
	int i;
	struct bw_debug *d;
	for (i = 0; i < BW_DEBUG_SLOTS; i++) {
		d = &trace[i];
		CINFO("%03d: %c %08ld.%06ld  %08ld.%06ld  %" PRIu64" %" PRIu64
		    " %d %d %d",
		i,
		d->op,
		d->io_time.tv_sec, d->io_time.tv_usec,
		d->prev_time.tv_sec, d->prev_time.tv_usec,
		d->tot_trans, d->this_trans,
		d->bw_curslot, d->bw_total, d->sleeping);
	}
#endif
}
