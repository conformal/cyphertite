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
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"
#include "ct_crypto.h"


void ct_handle_exists_reply(struct ct_global_state *,  struct ct_trans *,
    struct ct_header *, void *);
void ct_handle_write_reply(struct ct_global_state *, struct ct_trans *,
    struct ct_header *, void *);
void ct_handle_read_reply(struct ct_global_state *, struct ct_trans *,
    struct ct_header *, void *);

void ct_complete_normal(struct ct_global_state *, struct ct_trans *);

/* ct flags - these are named wrongly, should come from config */

/* RedBlack completion queue, also used for wait queue. */

int ct_cmp_trans(struct ct_trans *c1, struct ct_trans *c2);

RB_GENERATE(ct_trans_lookup, ct_trans, tr_trans_rbnode, ct_cmp_trans);

int
ct_cmp_trans(struct ct_trans *c1, struct ct_trans *c2)
{
	return ((c1->tr_trans_id < c2->tr_trans_id)
	    ? -1 : (c1->tr_trans_id > c2->tr_trans_id));
}

int ct_cmp_iotrans(struct ct_trans *c1, struct ct_trans *c2);

RB_GENERATE(ct_iotrans_lookup, ct_trans, tr_trans_rbnode, ct_cmp_iotrans);

int
ct_cmp_iotrans(struct ct_trans *c1, struct ct_trans *c2)
{
	return ((c1->hdr.c_tag < c2->hdr.c_tag)
	    ? -1 : (c1->hdr.c_tag > c2->hdr.c_tag));
}

/* structure to push data to next cache line - cache isolation */
struct ct_global_state  ct_int_state;
struct ct_stat ct_int_stats;
int ct_cur_compress_mode = 0;


struct ct_global_state *ct_state = &ct_int_state;
struct ct_stat *ct_stats = &ct_int_stats;

struct ct_global_state *
ct_setup_state(void)
{
	struct ct_global_state *state;

	/* unless we have shared memory, init is simple */
	state = ct_state = &ct_int_state;

	ct_stats = &ct_int_stats;

	TAILQ_INIT(&state->ct_trans_free_head);
	state->ct_trans_id = 0;
	state->ct_packet_id = 0;
	state->ct_tr_tag = 0;
	state->ct_trans_free = 0;
	state->ct_trans_alloc = 0;
	 /* default block size, modified on server negotiation */
	state->ct_max_block_size = 256 * 1024;

	if (ct_compress_enabled)
		state->ct_alloc_block_size = s_compress_bounds(
		    state->ct_max_block_size);
	else
		state->ct_alloc_block_size = state->ct_max_block_size;

	state->ct_alloc_block_size += ct_crypto_blocksz();

	state->ct_file_state = CT_S_STARTING;
	state->ct_comp_state = CT_S_WAITING_TRANS;
	state->ct_crypt_state = CT_S_WAITING_TRANS;
	/* XXX: We need this? */
	/* state->ct_write_state = CT_S_WAITING_TRANS; */

	TAILQ_INIT(&state->ct_sha_queue);
	TAILQ_INIT(&state->ct_comp_queue);
	TAILQ_INIT(&state->ct_crypt_queue);
	TAILQ_INIT(&state->ct_csha_queue);
	TAILQ_INIT(&state->ct_write_queue);
	TAILQ_INIT(&state->ct_queued);
	RB_INIT(&state->ct_inflight);
	RB_INIT(&state->ct_complete);
	TAILQ_INIT(&state->ct_operations);

	state->ct_sha_qlen = 0;
	state->ct_comp_qlen = 0;
	state->ct_crypt_qlen = 0;
	state->ct_csha_qlen = 0;
	state->ct_write_qlen = 0;
	state->ct_inflight_rblen = 0;
	state->ct_complete_rblen = 0;

	state->ct_disconnected = 0;
	state->ct_reconnect_pending = 0;
	state->ct_reconnect_timeout = CT_RECONNECT_DEFAULT_TIMEOUT;

	SIMPLEQ_INIT(&state->ctfile_list_files);

	return (state);
}

void
ct_set_file_state(struct ct_global_state *state, int newstate)
{
	state->ct_file_state = newstate;
}

int
ct_get_file_state(struct ct_global_state *state)
{
	return (state->ct_file_state);
}

void
ct_queue_sha(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_sha_lock);
	TAILQ_INSERT_TAIL(&state->ct_sha_queue, trans, tr_next);
	state->ct_sha_qlen++;
	ct_wakeup_sha();
	CT_UNLOCK(&state->ct_sha_lock);
}

void
ct_queue_compress(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_comp_lock);
	TAILQ_INSERT_TAIL(&state->ct_comp_queue, trans, tr_next);
	state->ct_comp_qlen++;
	ct_wakeup_compress();
	CT_UNLOCK(&state->ct_comp_lock);
}

void
ct_queue_encrypt(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_crypt_lock);
	TAILQ_INSERT_TAIL(&state->ct_crypt_queue, trans, tr_next);
	state->ct_crypt_qlen++;
	ct_wakeup_encrypt();
	CT_UNLOCK(&state->ct_crypt_lock);
}

void
ct_queue_csha(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_csha_lock);
	TAILQ_INSERT_TAIL(&state->ct_csha_queue, trans, tr_next);
	state->ct_csha_qlen++;
	ct_wakeup_csha();
	CT_UNLOCK(&state->ct_csha_lock);
}

void
ct_queue_write(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_write_lock);
	TAILQ_INSERT_TAIL(&state->ct_write_queue, trans, tr_next);
	state->ct_write_qlen++;
	ct_wakeup_write();
	CT_UNLOCK(&state->ct_write_lock);
}

void
ct_queue_queued(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_queued_lock);
	TAILQ_INSERT_TAIL(&state->ct_queued, trans, tr_next);
	state->ct_queued_qlen++;
	CT_UNLOCK(&state->ct_queued_lock);
	/* XXX - mark socket write enabled */
}

void
ct_queue_complete(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_complete_lock);
	RB_INSERT(ct_trans_lookup, &state->ct_complete, trans);
	state->ct_complete_rblen++;
	ct_wakeup_complete();
	CT_UNLOCK(&state->ct_complete_lock);
}

/*
 * Enqueue a new transaction, setting up the transaction id etc.
 */
void
ct_queue_first(struct ct_global_state *state, struct ct_trans *trans)
{
	trans->tr_trans_id = state->ct_trans_id++;
	ct_queue_transfer(state, trans);
}

/*
 * Move a transaction to the next state.
 */
void
ct_queue_transfer(struct ct_global_state *state, struct ct_trans *trans)
{
	CNDBG(CT_LOG_TRANS, "queuing transaction %" PRIu64 " %d",
	    trans->tr_trans_id, trans->tr_state);
	switch (trans->tr_state) {
	case TR_S_READ:
	case TR_S_WRITTEN: /* written goes back to this queue for local db */
	case TR_S_EXISTS:
		if (trans->hdr.c_flags & C_HDR_F_METADATA)
			goto skip_sha;
		ct_queue_sha(state, trans);
		break;
	case TR_S_UNCOMPSHA_ED:
skip_sha:	/* metadata skips shas */
		/* try to compress trans body, if compression enabled */
		if (ct_compress_enabled) {
			ct_queue_compress(state, trans);
			break;
		}
		/* fallthru if compress not enabled */
	case TR_S_COMPRESSED:
		/* try to encrypt trans body, if encryption enabled */
		if (trans->hdr.c_flags & C_HDR_F_ENCRYPTED) {
			ct_queue_encrypt(state, trans);
			break;
		}
		/* fallthru if compress not enabled */
	case TR_S_COMPSHA_ED:
	case TR_S_NEXISTS:
		/* packet is compressed/crypted/SHAed as necessary, send */
skip_csha:
		ct_queue_write(state, trans);
		break;
	case TR_S_ENCRYPTED:
		if (trans->hdr.c_flags & C_HDR_F_METADATA)
			goto skip_csha;
		/* after encrypting packet, create csha */
		ct_queue_csha(state, trans);
		break;

	case TR_S_FILE_START:
	case TR_S_SPECIAL:
	case TR_S_WMD_READY:
		ct_queue_complete(state, trans);
		break;

	/* extract path */
	case TR_S_EX_SHA:
		/* XXX - atomic increment */
		ct_stats->st_chunks_tot++;
		ct_queue_write(state, trans);
		break;
	case TR_S_EX_READ:
		/* smash trans header with received header, flags, sz, op */
		if (trans->hdr.c_flags & C_HDR_F_ENCRYPTED) {
			ct_queue_encrypt(state, trans);
			break;
		}
		/* FALLTHRU */
	case TR_S_EX_DECRYPTED:
		if (trans->hdr.c_flags & C_HDR_F_COMPRESSED_MASK) {
			ct_queue_compress(state, trans);
			break;
		}
		/* FALLTHRU */
	case TR_S_EX_UNCOMPRESSED:
	case TR_S_EX_FILE_START:
	case TR_S_EX_SPECIAL:
	case TR_S_EX_FILE_END:
	case TR_S_DONE:
	case TR_S_XML_OPENED:
	case TR_S_XML_CLOSE:
	case TR_S_XML_CLOSED:
	case TR_S_XML_CULL_REPLIED:
		ct_queue_complete(state, trans);
		break;
	case TR_S_XML_OPEN:
	case TR_S_XML_LIST:
	case TR_S_XML_CLOSING:
	case TR_S_XML_DELETE:
	case TR_S_XML_CULL_SEND:
		ct_queue_write(state, trans);
		break;
	default:
		CFATALX("state %d, not handled in ct_queue_transfer()",
		    trans->tr_state);
	}
}

/*
 * Local transaction allocator.
 *
 * When we wish to start a new transaction we must always use ct_trans_alloc()
 * in case the operation in question needs to talk to the server. When we
 * determine that no server communication is needed (a local file open for
 * example) then we can free that transaction and use a local one which are not
 * limited by the negotiated size of the server queue.
 *
 * Otherwise we can get in the situation where we have a lot of small files
 * (1 chunk each) so we use one transaction for open, one for close and one for
 * the sha, meaning that one file took 3 transactions of which only one went to
 * the server. theoretically dividing our throughput by 3.
 */
/*
 * we have a cap on the maximum number of transactions to prevent things
 * getting silly. For example if you had an archive of 100000 directories you
 * would try and allocate 100000  local transactions and probably start hitting
 * memory limits.
 *
 * this number probably wants some careful tuning.
 */
#define CT_MAX_LOCAL_TRANSACTIONS	(100)
static int ct_num_local_transactions;
static struct ct_trans *
ct_trans_alloc_local(struct ct_global_state *state)
{

	struct ct_trans *trans;

	if (ct_num_local_transactions >= CT_MAX_LOCAL_TRANSACTIONS)
		return (NULL);
	ct_num_local_transactions++;

	/*
	 * This should come from preallocated shared memory
	 * however for now since this is unneeded just allocate on demand.
	 */
	trans = e_calloc(1, sizeof(*trans));

	/*
	 * No tag, body or compressed body. If they are needed then trans
	 * is not local.
	 */
	trans->tr_data[0] = NULL;
	trans->tr_data[1] = NULL;

	trans->tr_local = 1;

	return trans;
}

/*
 * Replace an allocated transaction with a local one.
 * No fields saved, just the right to do some work.
 */
struct ct_trans *
ct_trans_realloc_local(struct ct_global_state *state, struct ct_trans *trans)
{
	struct ct_trans		*tmp;

	/*
	 * If we have too many local transactions on the go then just return
	 * the non local trans, we'll eventually starve those too and
	 * wait for some to finish.
	 */
	if ((tmp = ct_trans_alloc_local(state)) == NULL)
		return (trans);

	ct_trans_free(state, trans);

	return (tmp);
}

struct ct_trans *
ct_trans_alloc(struct ct_global_state *state)
{
	struct ct_trans *trans;
	void *tr_data[2];
	uint16_t tag;

	/* This should come from preallocated shared memory */
	if (!TAILQ_EMPTY(&state->ct_trans_free_head)) {
		trans = TAILQ_FIRST(&state->ct_trans_free_head);
		TAILQ_REMOVE(&state->ct_trans_free_head, trans, tr_next);
		tr_data[0] = trans->tr_data[0];
		tr_data[1] = trans->tr_data[1];
		tag = trans->hdr.c_tag;
		bzero(trans, sizeof(*trans));
		trans->tr_data[0] = tr_data[0];
		trans->tr_data[1] = tr_data[1];
		trans->hdr.c_tag = tag;
		state->ct_trans_free--;
	} else {
		if (state->ct_trans_alloc > ct_max_trans)
			return NULL;

		state->ct_trans_alloc++;

		trans = e_calloc(1, state->ct_alloc_block_size * 2
		    + sizeof(*trans));
		/* need to allocate body and compressed body */
		trans->tr_data[0] = (uint8_t *)trans + sizeof(*trans);
		trans->tr_data[1] = (uint8_t *)trans + sizeof(*trans)
		    + state->ct_alloc_block_size;

		trans->hdr.c_tag = state->ct_tr_tag++;
		if (state->ct_tr_tag >= 0x10000)
			CFATALX("too many transactions allocated");
	}

	return trans;
}

void
ct_trans_free(struct ct_global_state *state, struct ct_trans *trans)
{
	/* This should come from preallocated shared memory freelist */
	if (trans->tr_local) {
		/* just chuck local trans for now. */
		ct_num_local_transactions--;
		e_free(&trans);

		return;
	} else {
		TAILQ_INSERT_HEAD(&state->ct_trans_free_head, trans, tr_next);
	}
	state->ct_trans_free++;
	if (trans->tr_dataslot == 2) {
		ct_body_free(NULL, trans->tr_data[2], &trans->hdr);
		trans->tr_data[2] = NULL;
	}

	/* XXX - should this wait for a low threshold? */
	if (ct_get_file_state(state) == CT_S_WAITING_TRANS) {
		CNDBG(CT_LOG_TRANS, "send wakeup");
		ct_wakeup_file();
	}
}

void
ct_trans_cleanup(struct ct_global_state *state)
{
	struct ct_trans *trans;
	int count = 0;

	CNDBG(CT_LOG_TRANS, "trans num free  %d", state->ct_trans_free);
	/* free the transaction data block/or each element */
	while (!TAILQ_EMPTY(&state->ct_trans_free_head)) {
		trans = TAILQ_FIRST(&state->ct_trans_free_head);
		TAILQ_REMOVE(&state->ct_trans_free_head, trans, tr_next);
		e_free(&trans);
		count++;
	}
	state->ct_trans_free = state->ct_trans_alloc = 0;
	CNDBG(CT_LOG_TRANS, "freed %d transactions", count);
}

int
ct_reconnect_internal(struct ct_global_state *state)
{
	struct ct_trans		*trans, *ttrans;

	if ((state->ct_assl_ctx = ct_ssl_connect(state, 1)) != NULL) {
		if (ct_assl_negotiate_poll(state)) {
			CFATALX("negotiate failed");
		}

		if (state->ct_disconnected > 2)
			CINFO("Reconnected");
		state->ct_disconnected = 0;

		CT_LOCK(&state->ct_write_lock);
		TAILQ_FOREACH_SAFE(trans, &state->ct_write_queue, tr_next,
		    ttrans) {
			CT_UNLOCK(&state->ct_write_lock);
			if ((trans->hdr.c_flags & C_HDR_F_METADATA) == 0)
				continue;

			if (trans->hdr.c_opcode == C_HDR_O_XML) {
				/*
				 * Already an open first thing in the queue,
				 * don't worry.
				 */
				if (trans->tr_state == TR_S_XML_OPEN) {
					CNDBG(CT_LOG_NET,
					    "found open in queue, ignoring");
					break;
				}
				/*
				 * Close without a read or write
				 * restart will have closed it for us, so
				 * just complete it and stop worrying
				 */
				if (trans->tr_state == TR_S_XML_CLOSING) {
					CNDBG(CT_LOG_NET,
					    "found close in queue, completing");
					/*
					 * Don't try and close again,
					 * complete it and stop worrying.
					 */
					CT_LOCK(&state->ct_write_lock);
					TAILQ_REMOVE(&state->ct_write_queue,
					    trans, tr_next);
					state->ct_write_qlen--;
					CT_UNLOCK(&state->ct_write_lock);
					ct_queue_complete(state, trans);
					break;
				}
				/*
				 * List or delete, we can let them go on
				 * without further comment. Check for more
				 */
				continue;
			} else if (trans->tr_state == TR_S_NEXISTS ||
			    trans->tr_state == TR_S_COMPRESSED ||
			    trans->tr_state == TR_S_ENCRYPTED ||
			    trans->tr_state == TR_S_READ) {
				CNDBG(CT_LOG_NET, "write in queue chunkno %d",
				    trans->tr_ctfile_chunkno);
				/*
				 * Reopen the file at the point we are.
				 * we do this polled to prevent races with
				 * messages hitting the server while the open
				 * is still in progress (these will fail).
				 * so it is less painful all around to
				 * not have to worry about the transaction
				 * queue being full and how much we have in
				 * the queue after us and just do this polled.
				 */
				if (ct_xml_file_open_polled(state,
				    trans->tr_ctfile_name, MD_O_APPEND,
				    trans->tr_ctfile_chunkno))
					CFATALX("can't reopen metadata file");
				break;
			} else if (trans->tr_state == TR_S_EX_SHA) {
				CNDBG(CT_LOG_NET, "read in queue chunkno %d",
				    trans->tr_ctfile_chunkno);
				/*
				 * We had a read in progress. reinject
				 * the right open at chunkno
				 * For how this works see above.
				 */
				if (ct_xml_file_open_polled(state,
				    trans->tr_ctfile_name, MD_O_READ,
				    trans->tr_ctfile_chunkno))
					CFATALX("can't reopen metadata file");
				break;
			}
		}
	} else {
		if (state->ct_disconnected == 2)
			CWARNX("Lost connection to server will attempt "
			    "to reconnect");
		if (state->ct_disconnected == 10) {
			CWARNX("Unable to contact server, continuing to retry "
			    "connection");
			state->ct_reconnect_timeout *= 2;
		}
		state->ct_disconnected++;
	}
	return (state->ct_assl_ctx == NULL);
}

void
ct_reconnect(evutil_socket_t unused, short event, void *varg)
{
	struct ct_global_state *state = varg;

	if (ct_reconnect_internal(state) == 0) {
		state->ct_reconnect_timeout = CT_RECONNECT_DEFAULT_TIMEOUT;
		/* XXX - wakeup everyone */
		ct_wakeup_sha();
		ct_wakeup_compress();
		ct_wakeup_encrypt();
		ct_wakeup_csha();
// XXX - Remove		ct_wakeup_complete();
		ct_wakeup_write();
		ct_wakeup_complete();
		ct_wakeup_file();
	} else {
		ct_set_reconnect_timeout(ct_reconnect, state,
		     state->ct_reconnect_timeout);
	}

}

void
ct_handle_disconnect(struct ct_global_state *state)
{
	struct ct_trans		*trans = NULL;
	int			 idle = 1;

	state->ct_disconnected = 1;
	ct_ssl_cleanup(state->ct_assl_ctx);
	state->ct_assl_ctx = NULL;

	while(!RB_EMPTY(&state->ct_inflight)) {
		trans = RB_MAX(ct_iotrans_lookup,
		    &state->ct_inflight);
		CNDBG(CT_LOG_NET,
		    "moving trans %" PRIu64 " back to queued",
		    trans->tr_trans_id);
		RB_REMOVE(ct_iotrans_lookup, &state->ct_inflight,
		    trans);
		/* put on the head so write queue is still ordered. */
		ct_queue_write(state, trans);
		state->ct_inflight_rblen--;
		idle = 0;
	}
	if (idle) {
		state->ct_reconnect_pending = 1;
	} else {
		ct_set_reconnect_timeout(ct_reconnect, state,
		    state->ct_reconnect_timeout);
	}
}

void
ct_handle_msg(void *ctx, struct ct_header *hdr, void *vbody)
{
	struct ct_global_state	*state = ctx;
	struct ct_trans		ltrans, *trans = NULL;
	int			lookup_body = 0;

	if (hdr == NULL) {
		ct_handle_disconnect(state);
		return;
	}
	ltrans.hdr.c_tag = hdr->c_tag;

	/* if a reply, lookup transaction */
	    /* update state */
	    /* requeue transaction */
	/* else */
	    /* handle request */

	if (hdr->c_opcode & 1)
		lookup_body = 1;
	if (lookup_body) {
		CNDBG(CT_LOG_NET,
		    "handle message iotrans %u opcode %u status %u",
		    hdr->c_tag, hdr->c_opcode, hdr->c_status);
		trans = RB_FIND(ct_iotrans_lookup, &state->ct_inflight,
		    &ltrans);

		if (trans == NULL)
			CFATALX("invalid io transaction reply(1)");

		RB_REMOVE(ct_iotrans_lookup, &state->ct_inflight, trans);
		state->ct_inflight_rblen--;
	}

	if (trans)
		CNDBG(CT_LOG_NET,
		    "trans %" PRIu64 " found", trans->tr_trans_id);
	switch(hdr->c_opcode) {
	case C_HDR_O_EXISTS_REPLY:
		ct_handle_exists_reply(state, trans, hdr, vbody);
		break;
	case C_HDR_O_WRITE_REPLY:
		ct_handle_write_reply(state, trans, hdr, vbody);
		break;
	case C_HDR_O_READ_REPLY:
		ct_handle_read_reply(state, trans, hdr, vbody);
		break;
	case C_HDR_O_XML_REPLY:
		ct_handle_xml_reply(state, trans, hdr, vbody);
		break;
	default:
		CFATALX("unexpected message received 0x%x",
		    hdr->c_opcode);
	}
}

void
ct_write_done(void *vctx, struct ct_header *hdr, void *vbody, int cnt)
{
	struct ct_global_state	*state = vctx;
	/* the header is first in the structure for this reason */
	struct ct_trans		*trans = (struct ct_trans *)hdr;

	if (hdr == NULL) {
		ct_handle_disconnect(state);
		return;
	}

	if (cnt != 0 && (hdr->c_opcode != C_HDR_O_WRITE ||
	    (hdr->c_flags & C_HDR_F_METADATA) == 0))
		CFATALX("not expecting vbody");

	CNDBG(CT_LOG_NET, "write done, trans %" PRIu64 " op %u",
	    trans->tr_trans_id, hdr->c_opcode);

	if (state->ct_disconnected) {
		/*
		 * this transaction is already in the inflight rb tree
		 * move back to to write_queue
		 */
		trans = (struct ct_trans *)hdr; /* cast to parent struct */
		CNDBG(CT_LOG_NET, "moving trans %" PRIu64" back to write queue",
		    trans->tr_trans_id);
		CT_LOCK(&state->ct_queued_lock);
		TAILQ_REMOVE(&state->ct_queued, trans, tr_next);
		state->ct_queued_qlen--;
		CT_UNLOCK(&state->ct_queued_lock);
		ct_queue_write(state, trans);
		return;
	}

	switch (hdr->c_opcode) {
	case C_HDR_O_EXISTS:
	case C_HDR_O_WRITE:
	case C_HDR_O_READ:
	case C_HDR_O_XML:
		trans = (struct ct_trans *)hdr; /* cast to parent struct */
		CT_LOCK(&state->ct_queued_lock);
		TAILQ_REMOVE(&state->ct_queued, trans, tr_next);
		CT_UNLOCK(&state->ct_queued_lock);
		RB_INSERT(ct_iotrans_lookup, &state->ct_inflight, trans);
		state->ct_queued_qlen--;
		state->ct_inflight_rblen++;
		/* XXX no nice place to put this */
		if (hdr->c_opcode == C_HDR_O_WRITE &&
		    hdr->c_flags & C_HDR_F_METADATA) {
			/* free iovec and footer data */
			struct ct_iovec	*iov = vbody;

			e_free(&iov[1].iov_base);
			/* real body was in iov[0] and is part of the trans */
			e_free(&iov);
		}
		/* no need to free body */
		break;
	default:
		CWARNX("freeing body for hdr opcode %u tag %u trans %" PRIu64,
		    hdr->c_opcode, hdr->c_tag, trans->tr_trans_id);
		e_free(&vbody);
	}
}

void *
ct_body_alloc(void *vctx, struct ct_header *hdr)
{
	struct ct_global_state	*state = vctx;
	uint8_t			*body;
	struct ct_trans		ltrans, *trans = NULL;
	int			slot;
	int			lookup_body = 0;

	/* if a reply, */
	   /* lookup transaction and return alternate data payload */
	/* else */
	   /* allocate buffer of hdr->c_size */
	CNDBG(CT_LOG_TRANS, "body alloc on iotrans %u", hdr->c_tag);

	if (hdr->c_opcode & 1) {
		/* not all replies have bodies preallocated */
		switch(hdr->c_opcode) {
		case C_HDR_O_XML_REPLY:
			break;
		default:
			lookup_body = 1;
		}
	}
	if (lookup_body) {
		ltrans.hdr.c_tag = hdr->c_tag;
		trans = RB_FIND(ct_iotrans_lookup, &state->ct_inflight,
		    &ltrans);

		if (trans == NULL)
			CFATALX("invalid io transaction reply(2)");

		slot = !(trans->tr_dataslot); /* alternate slot */
		body = trans->tr_data[slot];
	} else {
		body = e_calloc(1, hdr->c_size);
		CNDBG(CT_LOG_TRANS, "body allocated %p", body);
	}

	return body;
}

/*
 * For use with xmlsd_generate for allocating xml bodies.
 * The body alloc is done directly instead of in another path so as to
 * decouple xml size from chunk size.
 */
void *
ct_body_alloc_xml(size_t sz)
{
	struct ct_header	 hdr;

	hdr.c_opcode = C_HDR_O_XML;
	hdr.c_size = sz;
	/* don't need state here because we're not using shm */
	return (ct_body_alloc(NULL, &hdr));
}

void
ct_body_free(void *vctx, void *body, struct ct_header *hdr)
{
	/* is this body one that was allocated or part of a reply? */
	if (hdr->c_opcode & 1) {
		/* not all replies have bodies preallocated */
		switch(hdr->c_opcode) {
		case C_HDR_O_XML_REPLY:
			break;
		default:
			return;
		}
	}

	e_free(&body);
}

void
ct_compute_sha(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	struct fnode		*fnode;
	char			shat[SHA_DIGEST_STRING_LENGTH];
	int			slot;

	CT_LOCK(&state->ct_sha_lock);
	while (!TAILQ_EMPTY(&state->ct_sha_queue)) {
		trans = TAILQ_FIRST(&state->ct_sha_queue);
		TAILQ_REMOVE(&state->ct_sha_queue, trans, tr_next);
		state->ct_sha_qlen--;
		CT_UNLOCK(&state->ct_sha_lock);
		fnode = trans->tr_fl_node;

		switch (trans->tr_state) {
		case TR_S_READ:
			/* compute sha */
			break;
		case TR_S_WRITTEN:
		case TR_S_EXISTS:
			if (ct_debug) {
				ct_sha1_encode(trans->tr_sha, shat);
				CNDBG(CT_LOG_SHA,
				    "entering sha into db %" PRIu64 " %s",
				    trans->tr_trans_id, shat);
			}
			ctdb_insert(state->ct_db_state, trans);
			trans->tr_state = TR_S_WMD_READY;
			ct_queue_transfer(state, trans);
			CT_LOCK(&state->ct_sha_lock);
			continue;
		default:
			CFATALX("unexpected transaction state %d",
			    trans->tr_state);
		}
		ct_stats->st_chunks_tot++;
		slot = trans->tr_dataslot;
		CNDBG(CT_LOG_SHA,
		    "computing sha for trans %" PRIu64 " slot %d, size %d",
		    trans->tr_trans_id, slot, trans->tr_size[slot]);
		ct_sha1(trans->tr_data[slot], trans->tr_sha,
		    trans->tr_size[slot]);
		ct_sha1_add(trans->tr_data[slot], &fnode->fl_shactx,
		    trans->tr_size[slot]);

		ct_stats->st_bytes_sha += trans->tr_size[slot];

		if (ct_debug) {
			ct_sha1_encode(trans->tr_sha, shat);
			CNDBG(CT_LOG_SHA,
			    "block tr_id %" PRIu64 " sha %s sz %d",
			    trans->tr_trans_id, shat, trans->tr_size[slot]);
		}
		if (ctdb_exists(state->ct_db_state, trans)) {
			ct_stats->st_bytes_exists += trans->tr_chsize;
			trans->tr_state = TR_S_WMD_READY;
		} else {
			trans->tr_state = TR_S_UNCOMPSHA_ED;
		}
		ct_queue_transfer(state, trans);
		CT_LOCK(&state->ct_sha_lock);
	}
	CT_UNLOCK(&state->ct_sha_lock);
}

void
ct_compute_csha(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	char			shat[SHA_DIGEST_STRING_LENGTH];
	int			slot;

	CT_LOCK(&state->ct_csha_lock);
	while (!TAILQ_EMPTY(&state->ct_csha_queue)) {
		trans = TAILQ_FIRST(&state->ct_csha_queue);
		TAILQ_REMOVE(&state->ct_csha_queue, trans, tr_next);
		state->ct_csha_qlen--;
		CT_UNLOCK(&state->ct_csha_lock);

		slot = trans->tr_dataslot;
		ct_sha1(trans->tr_data[slot], trans->tr_csha,
		    trans->tr_size[slot]);

		ct_stats->st_bytes_csha += trans->tr_size[slot];

		if (ct_debug) {
			ct_sha1_encode(trans->tr_sha, shat);
			CNDBG(CT_LOG_SHA, "block tr_id %" PRIu64 " sha %s",
			    trans->tr_trans_id, shat);
		}
		trans->tr_state = TR_S_COMPSHA_ED;
		ct_queue_transfer(state, trans);
		CT_LOCK(&state->ct_csha_lock);
	}
	CT_UNLOCK(&state->ct_csha_lock);
}

/* completion handler for states for non-metadata actions. */
void
ct_complete_normal(struct ct_global_state *state, struct ct_trans *trans)
{
	int			slot;
	struct fnode		*fnode = trans->tr_fl_node;
	int			release_fnode = 0;

	switch (trans->tr_state) {
	case TR_S_DONE:
		if (trans->tr_ctfile) {
			ctfile_write_close(trans->tr_ctfile);
		}
		ct_dnode_cleanup();
		/* do we have more operations queued up? */
		if (ct_op_complete(state) == 0)
			return;
		if (ct_verbose_ratios)
			ct_dump_stats(state, stdout);
		ct_shutdown(state);
		break;
	case TR_S_SPECIAL:
		if (ct_verbose)
			printf("%s\n", fnode->fl_sname);
		ctfile_write_special(trans->tr_ctfile, fnode);
		release_fnode = 1;
		break;
	case TR_S_FILE_START:
		if (ctfile_write_file_start(trans->tr_ctfile, fnode))
			CWARNX("header write failed");

		if (ct_verbose) {
			printf("%s", fnode->fl_sname);
			fflush(stdout);
		}

		if (trans->tr_eof == 1 || fnode->fl_skip_file) {
			ctfile_write_file_end(trans->tr_ctfile,
			    trans->tr_fl_node);
			ct_stats->st_files_completed++;
			release_fnode = 1;
		}
		break;
	case TR_S_WMD_READY:
		ct_stats->st_chunks_completed++;
		if (trans->tr_eof < 2) {
			CNDBG(CT_LOG_CTFILE, "XoX sha sz %d eof %d",
			    trans->tr_size[(int)trans->tr_dataslot],
			    trans->tr_eof);

			ctfile_write_file_sha(trans->tr_ctfile, trans->tr_sha,
			    trans->tr_csha, trans->tr_iv);
		}

		if (trans->tr_eof) {
			if (trans->tr_eof == 2)
				ctfile_write_file_pad(trans->tr_ctfile,
				    trans->tr_fl_node);
			ctfile_write_file_end(trans->tr_ctfile,
			    trans->tr_fl_node);
			release_fnode = 1;
		}
		break;
	case TR_S_EX_FILE_START:
		ct_sha1_setup(&trans->tr_fl_node->fl_shactx);
		if (ct_file_extract_open(trans->tr_fl_node) == 0) {
			if (ct_verbose) {
				ct_pr_fmt_file(trans->tr_fl_node);
				printf("\n");
			}
		} else {
			trans->tr_fl_node->fl_skip_file = 1;
		}
		break;
	case TR_S_EX_FILE_END:
		if (trans->tr_fl_node->fl_skip_file == 0) {
			ct_sha1_final(trans->tr_csha,
			    &trans->tr_fl_node->fl_shactx);
			if (bcmp(trans->tr_csha, trans->tr_sha,
			    sizeof(trans->tr_sha)) != 0)
				CWARNX("extract sha mismatch on %s",
				    trans->tr_fl_node->fl_sname);
			ct_file_extract_close(trans->tr_fl_node);
		}
		release_fnode = 1;
		ct_stats->st_files_completed++;
		break;
	case TR_S_EX_READ:
	case TR_S_EX_DECRYPTED:
	case TR_S_EX_UNCOMPRESSED:
		ct_stats->st_chunks_completed++;
		if (trans->tr_fl_node->fl_skip_file == 0) {
			slot = trans->tr_dataslot;
			ct_sha1_add(trans->tr_data[slot],
			    &trans->tr_fl_node->fl_shactx,
			    trans->tr_size[slot]);
			ct_file_extract_write(trans->tr_fl_node,
			    trans->tr_data[slot], trans->tr_size[slot]);
			ct_stats->st_bytes_written += trans->tr_size[slot];
		}
		break;
	case TR_S_EX_SPECIAL:
		ct_file_extract_special(trans->tr_fl_node);
		if (ct_verbose) {
			ct_pr_fmt_file(trans->tr_fl_node);
			printf("\n");
		}
		release_fnode = 1;
		break;
	case TR_S_XML_CULL_SEND:
		slot = trans->tr_dataslot;
		printf("message back state [%s]", (char *)trans->tr_data[slot]);

	default:
		CFATALX("process_normal unexpected state %d", trans->tr_state);
	}

	if (release_fnode) {
		ct_free_fnode(fnode);
	}
}

void
ct_process_completions(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans 	*trans;

	CT_LOCK(&state->ct_complete_lock);
	trans = RB_MIN(ct_trans_lookup, &state->ct_complete);
	if (trans)
		CNDBG(CT_LOG_TRANS,
		    "completing trans %" PRIu64 " pkt id: %" PRIu64"",
		    trans->tr_trans_id, state->ct_packet_id);

	while (trans != NULL && trans->tr_trans_id == state->ct_packet_id) {
		RB_REMOVE(ct_trans_lookup, &state->ct_complete, trans);
		state->ct_complete_rblen--;
		CT_UNLOCK(&state->ct_complete_lock);

		CNDBG(CT_LOG_TRANS, "writing file trans %" PRIu64 " eof %d",
		    trans->tr_trans_id, trans->tr_eof);

		state->ct_packet_id++;

		if (trans->hdr.c_flags & C_HDR_F_METADATA) {
			ct_complete_metadata(state, trans);
		} else {
			ct_complete_normal(state, trans);
		}
		ct_trans_free(state, trans);

		/*
		 * XXX this is needed while the ctfile download protocol
		 * works as it does, we don't know the size of the file so
		 * we keep reading until we run out of chunks
		 */
		if (ct_get_file_state(state) != CT_S_FINISHED)
			ct_wakeup_file();

		CT_LOCK(&state->ct_complete_lock);
		trans = RB_MIN(ct_trans_lookup, &state->ct_complete);
	}
	CT_UNLOCK(&state->ct_complete_lock);
	if (trans != NULL && trans->tr_trans_id < state->ct_packet_id) {
		CFATALX("old transaction found in completion queue %" PRIu64
		    " %" PRIu64, trans->tr_trans_id, state->ct_packet_id);
	}
}

void
ct_process_write(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	struct ct_header	*hdr;
	void			*data;
	int			slot;

	/* did we idle out? */
	if (state->ct_reconnect_pending) {
		if (ct_reconnect_internal(state) != 0)
			ct_set_reconnect_timeout(ct_reconnect, NULL,
			     state->ct_reconnect_timeout);
		state->ct_reconnect_pending = 0;
	}

	CNDBG(CT_LOG_NET, "wakeup write");
	CT_LOCK(&state->ct_write_lock);
	while (state->ct_disconnected == 0 &&
	    !TAILQ_EMPTY(&state->ct_write_queue)) {
		trans = TAILQ_FIRST(&state->ct_write_queue);
		TAILQ_REMOVE(&state->ct_write_queue, trans, tr_next);
		state->ct_write_qlen--;
		CT_UNLOCK(&state->ct_write_lock);

		CNDBG(CT_LOG_NET, "wakeup write going");
		hdr = &trans->hdr;

		hdr->c_version = C_HDR_VERSION;

		/* this extra assignment here allows exists to be fallthru */
		data = trans->tr_sha;

		switch(trans->tr_state) {
		case TR_S_NEXISTS:
		case TR_S_COMPRESSED:
		case TR_S_ENCRYPTED: /* if dealing with metadata */
		case TR_S_READ: /* if dealing with ctfile non-comp/non-crypt */
			/* doesn't exist in backend, need to send chunk */
			slot = trans->tr_dataslot;
			data = trans->tr_data[slot];
			hdr->c_opcode = C_HDR_O_WRITE;
			hdr->c_size = trans->tr_size[slot];
			ct_stats->st_bytes_sent += trans->tr_size[slot];
			break;
		case TR_S_COMPSHA_ED:
			data = trans->tr_csha;
			/* fallthru */
		case TR_S_UNCOMPSHA_ED:
			/* data = trans->tr_sha; - done above,allows fallthru */
			hdr->c_opcode = C_HDR_O_EXISTS;
			hdr->c_size = (sizeof trans->tr_sha);
			break;
		case TR_S_EX_SHA:
			hdr->c_opcode = C_HDR_O_READ;
			hdr->c_size = sizeof(trans->tr_sha);
			data = trans->tr_sha;
			break;
		case TR_S_XML_OPEN:
		case TR_S_XML_CLOSING:
		case TR_S_XML_LIST:
		case TR_S_XML_DELETE:
		case TR_S_XML_CULL_SEND:
			hdr->c_opcode = C_HDR_O_XML;
			hdr->c_flags = C_HDR_F_METADATA;
			hdr->c_size = trans->tr_size[2];
			data = trans->tr_data[2];
			break;
		default:
			CFATALX("unexpected state in wakeup_write %d",
			    trans->tr_state);
		}
		/* hdr->c_tag - set once when trans was originally created */
		hdr->c_version = C_HDR_VERSION;

		CNDBG(CT_LOG_NET, "queuing write of op %u trans %" PRIu64
		    " iotrans %u tstate %d flags 0x%x",
		    hdr->c_opcode, trans->tr_trans_id, hdr->c_tag,
		    trans->tr_state, hdr->c_flags);

		/* move transaction to pending RB tree */
		ct_queue_queued(state, trans);

		/* XXX there really isn't a better place to do this */
		if (hdr->c_opcode == C_HDR_O_WRITE &&
		    (hdr->c_flags & C_HDR_F_METADATA) != 0) {
			struct ct_metadata_footer	*cmf;
			struct ct_iovec			*iov;

			iov = e_calloc(2, sizeof(*iov));
			cmf = e_calloc(1, sizeof(*cmf));
			cmf->cmf_chunkno = htonl(trans->tr_ctfile_chunkno);
			cmf->cmf_size = htonl(hdr->c_size);

			iov[0].iov_base = data;
			iov[0].iov_len = hdr->c_size;
			iov[1].iov_base = cmf;
			iov[1].iov_len = sizeof(*cmf);

			hdr->c_size += sizeof(*cmf);

			ct_assl_writev_op(state->ct_assl_ctx, hdr, iov, 2);
			CT_LOCK(&state->ct_write_lock);
			continue;
		}

		ct_assl_write_op(state->ct_assl_ctx, hdr, data);
		CT_LOCK(&state->ct_write_lock);
	}
	CT_UNLOCK(&state->ct_write_lock);
}

void
ct_handle_exists_reply(struct ct_global_state *state, struct ct_trans *trans,
    struct ct_header *hdr, void *vbody)
{
	int slot;

	CNDBG(CT_LOG_NET, "exists_reply %" PRIu64 " status %u",
	    trans->tr_trans_id, hdr->c_status);

	switch(hdr->c_status) {
	case C_HDR_S_FAIL:
		CFATALX("server connection failed");
	case C_HDR_S_EXISTS:
		/* enter shas into local db */
		trans->tr_state = TR_S_EXISTS;
		ct_stats->st_bytes_exists += trans->tr_chsize;
		ct_queue_transfer(state, trans);
		break;
	case C_HDR_S_DOESNTEXIST:
		trans->tr_state = TR_S_NEXISTS;
		slot = trans->tr_dataslot;
		trans->tr_fl_node->fl_comp_size += trans->tr_size[slot];
		ct_queue_transfer(state, trans);
		break;
	default:
		CFATALX("handle_exists_reply unexpected status %u",
		    hdr->c_status);
	}

	if (vbody != NULL) {
		CWARNX("exists reply with body");
		/* should point to alternate body, do not free */
	}

	ct_header_free(NULL, hdr);
}

void
ct_handle_write_reply(struct ct_global_state *state, struct ct_trans *trans,
    struct ct_header *hdr, void *vbody)
{
	CNDBG(CT_LOG_NET, "handle_write_reply");
	CNDBG(CT_LOG_NET, "hdr op %u status %u size %u",
	    hdr->c_opcode, hdr->c_status, hdr->c_size);

	if (hdr->c_status == C_HDR_S_OK) {
		if (trans->hdr.c_flags & C_HDR_F_METADATA)
			trans->tr_state = TR_S_WMD_READY; /* XXX */
		else
			trans->tr_state = TR_S_WRITTEN;
		ct_queue_transfer(state, trans);
		ct_header_free(NULL, hdr);
	} else {
		CFATALX("chunk write failed: %s", ct_header_strerror(hdr));
	}
}

void
ct_handle_read_reply(struct ct_global_state *state, struct ct_trans *trans,
    struct ct_header *hdr, void *vbody)
{
	struct ct_metadata_footer	*cmf;
	char				 shat[SHA_DIGEST_STRING_LENGTH];
	int				 slot;

	/* data was written to the 'alternate slot' so switch it */
	slot = trans->tr_dataslot = !(trans->tr_dataslot);
	if (hdr->c_status == C_HDR_S_OK) {
		trans->tr_state = TR_S_EX_READ;
		/*
		 * Check the chunk number for sanity.
		 * The server will only send ctfileproto version 1
		 * (ex_status == 0) or v3 (ex_status == 2). v3 fixed a
		 * byteswapping problem in v2, thus v2 will not be sent to any
		 * client that understands v3.
		 */
		if (hdr->c_flags & C_HDR_F_METADATA &&
		    ((hdr->c_ex_status != 0) && (hdr->c_ex_status != 2)))
			CFATALX("invalid metadata prootcol (v%d)",
			    hdr->c_ex_status + 1);

		if (hdr->c_flags & C_HDR_F_METADATA &&
		    hdr->c_ex_status == 2) {
			cmf = (struct ct_metadata_footer *)
			    (trans->tr_data[slot] + hdr->c_size - sizeof(*cmf));
			cmf->cmf_size = ntohl(cmf->cmf_size);
			cmf->cmf_chunkno = ntohl(cmf->cmf_chunkno);

			if (cmf->cmf_size != hdr->c_size - sizeof(*cmf))
				CFATALX("invalid chunkfile footer");
			if (cmf->cmf_chunkno != trans->tr_ctfile_chunkno)
				CFATALX("invalid chunkno %u %u",
				    cmf->cmf_chunkno, trans->tr_ctfile_chunkno);
			hdr->c_size -= sizeof(*cmf);
		}
	} else {
		CNDBG(CT_LOG_NET, "c_flags on reply %x", hdr->c_flags);
		if (hdr->c_flags & C_HDR_F_METADATA) {
			/* FAIL on metadata read is 'eof' */
			if (ct_get_file_state(state) != CT_S_FINISHED) {
				ct_set_file_state(state, CT_S_FINISHED);
				trans->tr_state = TR_S_EX_FILE_END;
			} else {
				/*
				 * We had two ios in flight when we hit eof.
				 * We're already closing so just carry on
				 */
				trans->tr_state = TR_S_XML_CLOSED;
			}
		} else {
			ct_sha1_encode(trans->tr_sha, shat);
			CFATALX("Data missing on server return %u shat %s",
			    hdr->c_status, shat);
		}
	}

	if (ct_debug) {
		ct_sha1_encode(trans->tr_sha, shat);
		CNDBG(CT_LOG_NET, "chunk received for %s len %u flags %u", shat,
		    hdr->c_size, hdr->c_flags);
	}
	trans->tr_size[slot] = trans->hdr.c_size = hdr->c_size;
	trans->hdr.c_flags = hdr->c_flags;
	ct_stats->st_bytes_read += trans->tr_size[slot];

	ct_queue_transfer(state, trans);
	ct_header_free(NULL, hdr);
}

void
ct_compute_compress(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	uint8_t			*src, *dst;
	size_t			newlen;
	int			slot;
	int			compress;
	int			rv;
	int			len;
	int			ncompmode;

	CT_LOCK(&state->ct_comp_lock);
	while (!TAILQ_EMPTY(&state->ct_comp_queue)) {
		trans = TAILQ_FIRST(&state->ct_comp_queue);
		TAILQ_REMOVE(&state->ct_comp_queue, trans, tr_next);
		state->ct_comp_qlen--;
		CT_UNLOCK(&state->ct_comp_lock);

		switch(trans->tr_state) {
		case TR_S_EX_DECRYPTED:
		case TR_S_EX_READ:
			/* uncompress */
			compress = 0;
			ncompmode = (trans->hdr.c_flags &
			    C_HDR_F_COMPRESSED_MASK);
			break;
		case TR_S_READ: /* if metadata */
		case TR_S_UNCOMPSHA_ED:
			compress = 1;
			ncompmode = ct_compress_enabled;
			break;
		default:
			CFATALX("unexpected state for compress %d",
			    trans->tr_state);
		}

		if (ct_cur_compress_mode != ncompmode) {
			/* initial or (change in the middle!) mode */
			ct_init_compression(ncompmode);
			ct_cur_compress_mode = ncompmode;
		}

		if (ct_cur_compress_mode == 0)
			CFATALX("compression mode 0?");

		slot = trans->tr_dataslot;
		if (slot > 1) {
			CFATALX("transaction with special slot in compress: %d",
			    slot);
		}
		src = trans->tr_data[slot];
		len = trans->tr_size[slot];
		dst =  trans->tr_data[!slot];

		if (compress) {
			/*
			 * XXX - we dont want compression to grow buffer so
			 * limit to block size, s_compress_bounds(block_size)
			 * however some compression algorithms appear to ignore
			 * the dest size, so check for newlen after.
			 */
			newlen = len;
			rv = ct_compress(src, dst, len, &newlen);
			if (newlen >= len) {
				CNDBG(CT_LOG_TRANS,
				    "use uncompressed buffer %d %lu", len,
				    (unsigned long) newlen);
				rv = 1; /* act like compression failed */
				newlen = len;
			}
			if (rv == 0)
				trans->hdr.c_flags |= ncompmode;
			ct_stats->st_bytes_compressed += newlen;
			ct_stats->st_bytes_uncompressed += trans->tr_chsize;
		} else {
			newlen = state->ct_max_block_size;
			rv = ct_uncompress(src, dst, len, &newlen);

			if (rv)
				CFATALX("failed to decompress block len %d",
				    len);
		}

		CNDBG(CT_LOG_TRANS, "compress block of %d to %lu, rv %d", len,
		    (unsigned long) newlen, rv);

		/* if compression failed for whatever reason use input data */
		if (rv == 0) {
			trans->tr_size[!slot] = newlen;
			trans->tr_dataslot = !slot;
		}

		if (compress)
			trans->tr_state = TR_S_COMPRESSED;
		else
			trans->tr_state = TR_S_EX_UNCOMPRESSED;
		ct_queue_transfer(state, trans);
		CT_LOCK(&state->ct_comp_lock);
	}
	CT_UNLOCK(&state->ct_comp_lock);
}

void
ct_compute_encrypt(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	uint8_t			*src, *dst;
	unsigned char		*key = NULL;
	uint8_t			*iv;
	size_t			ivlen;
	size_t			keysz = -1;
	ssize_t			newlen;
	int			slot;
	int			encr;
	int			len;

	CT_LOCK(&state->ct_crypt_lock);
	while (!TAILQ_EMPTY(&state->ct_crypt_queue))	{
		trans = TAILQ_FIRST(&state->ct_crypt_queue);
		TAILQ_REMOVE(&state->ct_crypt_queue, trans, tr_next);
		state->ct_crypt_qlen--;
		CT_UNLOCK(&state->ct_crypt_lock);

		switch(trans->tr_state) {
		case TR_S_EX_READ:
			/* decrypt */
			encr = 0;
			break;
		case TR_S_READ: /* uncompressed ctfile data */
		case TR_S_UNCOMPSHA_ED:
		case TR_S_COMPRESSED:
			encr = 1;
			break;
		default:
			CFATALX("unexpected state for encr %d",
			    trans->tr_state);
		}


		slot = trans->tr_dataslot;
		if (slot > 1) {
			CFATALX("transaction with special slot in encr: %d",
			    slot);
		}
		src = trans->tr_data[slot];
		len = trans->tr_size[slot];
		dst =  trans->tr_data[!slot];

		key = ct_crypto_key;
		keysz = sizeof ct_crypto_key;

		iv = trans->tr_iv;
		ivlen = sizeof trans->tr_iv;

		if (encr) {
			/* encr the chunk, if metadata, iv is alread valid */
			if ((trans->hdr.c_flags & C_HDR_F_METADATA) == 0) {
				if (ct_create_iv(ct_iv, sizeof(ct_iv), src,
				    len, iv, ivlen))
					CFATALX("can't create iv");
			}

			newlen = ct_encrypt(key, keysz, iv, ivlen, src,
			    len, dst, state->ct_alloc_block_size);
		} else {
			newlen = ct_decrypt(key, keysz, iv, ivlen,
			    src, len, dst, state->ct_alloc_block_size);
		}

		if (newlen < 0)
			CFATALX("failed to %scrypt files",
			    encr ? "en" : "de");

		CNDBG(CT_LOG_TRANS,
		    "%scrypt block of %d to %lu", encr ? "en" : "de",
		    len, (unsigned long) newlen);

		ct_stats->st_bytes_crypted += newlen;

		trans->tr_size[!slot] = newlen;
		trans->tr_dataslot = !slot;

		if (encr)
			trans->tr_state = TR_S_ENCRYPTED;
		else
			trans->tr_state = TR_S_EX_DECRYPTED;
		ct_queue_transfer(state, trans);
		CT_LOCK(&state->ct_crypt_lock);
	}
	CT_UNLOCK(&state->ct_crypt_lock);
}

void
ct_display_queues(struct ct_global_state *state)
{
	if (ct_verbose > 1) {
		CT_LOCK(&state->ct_sha_lock);
		CT_LOCK(&state->ct_comp_lock);
		CT_LOCK(&state->ct_crypt_lock);
		CT_LOCK(&state->ct_csha_lock);
		CT_LOCK(&state->ct_write_lock);
		CT_LOCK(&state->ct_queued_lock);
		CT_LOCK(&state->ct_complete_lock);
		fprintf(stderr, "Sha      queue len %d\n",
		    state->ct_sha_qlen);
		CT_UNLOCK(&state->ct_sha_lock);
		fprintf(stderr, "Comp     queue len %d\n",
		    state->ct_comp_qlen);
		CT_UNLOCK(&state->ct_comp_lock);
		fprintf(stderr, "Crypt    queue len %d\n",
		    state->ct_crypt_qlen);
		CT_UNLOCK(&state->ct_crypt_lock);
		fprintf(stderr, "Csha     queue len %d\n",
		    state->ct_csha_qlen);
		CT_UNLOCK(&state->ct_csha_lock);
		fprintf(stderr, "Write    queue len %d\n",
		    state->ct_write_qlen);
		CT_UNLOCK(&state->ct_write_lock);
		fprintf(stderr, "CRqueued queue len %d\n",
		    state->ct_queued_qlen);
		CT_UNLOCK(&state->ct_queued_lock);
		// XXX: Add locks for inflight queue throughout?
		fprintf(stderr, "Inflight queue len %d\n",
		    state->ct_inflight_rblen);
		fprintf(stderr, "Complete queue len %d\n",
		    state->ct_complete_rblen);
		CT_UNLOCK(&state->ct_complete_lock);
		fprintf(stderr, "Free     queue len %d\n",
		    state->ct_trans_free);
	}
	ct_dump_stats(state, stderr);
}
