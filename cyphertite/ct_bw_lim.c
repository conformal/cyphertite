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

#include <stdio.h>
#include <clog.h>
#include <assl.h>
#include "ct.h"

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
struct bw_debug	trace[BW_DEBUG_SLOTS];
int traceslot = 0;
int dump_debug = BW_DEBUG_SLOTS;
void dump_bw_stats(void);

#define US_PER_SEC 1000000
#define SLOTS_PER_SEC 100
#define BW_TIMESLOT	(US_PER_SEC/SLOTS_PER_SEC)

int		bw_slot, slot_max;
struct timeval	curslottime, single_slot_time, sleep_tv;
uint64_t	last_bw_total_trans;

ct_assl_io_over_bw_check_func ct_ssl_over_bw_func;

struct event	wakeuptimer_ev;

void ct_ssl_over_bw_wakeup(int, short, void *);

void
ct_ssl_init_bw_lim(struct ct_assl_io_ctx *ctx)
{
	int packet_len;

	/* 1/4 of the number of bytes to send per timeslot */
	packet_len = ((ct_io_bw_limit * 1024) / (US_PER_SEC/BW_TIMESLOT))/4;
	CINFO("packet_len %d",  packet_len);
	ct_assl_io_ctx_set_maxtrans(ctx, packet_len);
	ct_assl_io_ctx_set_over_bw_func(ctx, ct_ssl_over_bw_func);
	evtimer_set(&wakeuptimer_ev, ct_ssl_over_bw_wakeup, ctx);

	single_slot_time.tv_sec = 0;
	single_slot_time.tv_usec = BW_TIMESLOT;

	slot_max =  ((ct_io_bw_limit * 1024) / (US_PER_SEC/BW_TIMESLOT));
	CINFO("slottime %d max_bw_total %d",
	    BW_TIMESLOT, slot_max);
}

void
ct_ssl_over_bw_wakeup(int fd_unused, short reason, void *varg)
{
	struct timeval		now;
	struct ct_assl_io_ctx	*ctx = varg;
	struct bw_debug		*curdbg = &trace[traceslot];
	traceslot = (traceslot +1) % BW_DEBUG_SLOTS;

	curdbg->op = 'W';

	if (gettimeofday(&now,NULL)) {
		CWARN("gettimeofday failed in over_bw_lim");
		return;
	}
	curdbg->io_time = now;
	curdbg->prev_time = sleep_tv;
	curdbg->tot_trans = 0;
	curdbg->this_trans = 0;
	curdbg->bw_curslot = 0;
	curdbg->bw_total = 0;
	curdbg->sleeping = -1;

	assl_event_enable_write(ctx->c);
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
	struct timeval		now, diff, nextslot;
	uint64_t		newbytes;
	struct bw_debug		*curdbg = &trace[traceslot];

	traceslot = (traceslot +1) % BW_DEBUG_SLOTS;

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

	if (gettimeofday(&now,NULL)) {
		CWARN("gettimeofday failed in over_bw_lim");
		return;
	}

	curdbg->io_time = now;
	curdbg->prev_time = curslottime;

	timersub(&now, &curslottime, &diff);

	newbytes = ioctx->io_write_bytes - last_bw_total_trans;
	last_bw_total_trans = ioctx->io_write_bytes;

	/* truncate time to beginning of slot */
	timeradd(&curslottime, &single_slot_time, &nextslot);

	if (timercmp(&now, &nextslot, >)) {
		bw_slot = 0;
		curslottime = now;
		ct_trunc_slot_time(&curslottime);
	}

	curdbg->tot_trans = ioctx->io_write_bytes;
	curdbg->this_trans = newbytes;

	bw_slot += newbytes;

	curdbg->bw_curslot = bw_slot;
	curdbg->bw_total = 0;

	curdbg->sleeping = 0;

	if (bw_slot >= slot_max) {
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

		assl_event_disable_write(ioctx->c);

		if (!event_pending(&wakeuptimer_ev, EV_TIMEOUT, &sleep_tv))  {
			timersub(&nextslot, &now, &sleep_tv);
			event_add(&wakeuptimer_ev, &sleep_tv);
		}
	}
		
	CDBG("cbarg bytes %" PRIu64, ioctx->io_write_bytes);
	if (traceslot == 0 || traceslot == 0) {
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
