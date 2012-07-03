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

#include <ct_crypto.h>
#include <ct_proto.h>
#include <ct_ctfile.h>
#include <cyphertite.h>
#include <ct_internal.h>


int	ct_reconnect_internal(struct ct_global_state *);

void ct_handle_exists_reply(struct ct_global_state *,  struct ct_trans *,
    struct ct_header *, void *);
void ct_handle_write_reply(struct ct_global_state *, struct ct_trans *,
    struct ct_header *, void *);
void ct_handle_read_reply(struct ct_global_state *, struct ct_trans *,
    struct ct_header *, void *);

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

struct ct_global_state *
ct_setup_state(struct ct_config *conf)
{
	struct ct_global_state *state;

	/* unless we have shared memory, init is simple */
	state = e_calloc(1, sizeof(*state));

	state->ct_config = conf;
	state->ct_stats = e_calloc(1, sizeof(*state->ct_stats));

	TAILQ_INIT(&state->ct_trans_free_head);
	state->ct_trans_id = 0;
	state->ct_packet_id = 0;
	state->ct_tr_tag = 0;
	state->ct_trans_free = 0;
	state->ct_trans_alloc = 0;
	state->ct_num_local_transactions = 0;
	 /* default block size, modified on server negotiation */
	state->ct_max_block_size = 256 * 1024;
	/* default max trans, modified by negotiation */
	state->ct_max_trans = conf->ct_max_trans;

	if (conf->ct_compress) {
		state->ct_compress_state =
		    ct_init_compression(conf->ct_compress);
		if (state->ct_compress_state == NULL)
			CFATALX("%d: %s", conf->ct_compress,
			    ct_strerror(CTE_SHRINK_INIT));
		state->ct_alloc_block_size =
		    ct_compress_bounds(state->ct_compress_state,
		    state->ct_max_block_size);
	} else {
		state->ct_compress_state = NULL;
		state->ct_alloc_block_size = state->ct_max_block_size;
	}

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
	ct_wakeup_sha(state->event_state);
	CT_UNLOCK(&state->ct_sha_lock);
}

struct ct_trans *
ct_dequeue_sha(struct ct_global_state *state)
{
	struct ct_trans *trans;

	CT_LOCK(&state->ct_sha_lock);
	if ((trans = TAILQ_FIRST(&state->ct_sha_queue)) != NULL) {
		TAILQ_REMOVE(&state->ct_sha_queue, trans, tr_next);
		state->ct_sha_qlen--;
	}
	CT_UNLOCK(&state->ct_sha_lock);

	return (trans);
}

void
ct_queue_compress(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_comp_lock);
	TAILQ_INSERT_TAIL(&state->ct_comp_queue, trans, tr_next);
	state->ct_comp_qlen++;
	ct_wakeup_compress(state->event_state);
	CT_UNLOCK(&state->ct_comp_lock);
}

struct ct_trans *
ct_dequeue_compress(struct ct_global_state *state)
{
	struct ct_trans	*trans;

	CT_LOCK(&state->ct_comp_lock);
	if ((trans = TAILQ_FIRST(&state->ct_comp_queue)) != NULL) {
		TAILQ_REMOVE(&state->ct_comp_queue, trans, tr_next);
		state->ct_comp_qlen--;
	}
	CT_UNLOCK(&state->ct_comp_lock);

	return (trans);
}

void
ct_queue_encrypt(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_crypt_lock);
	TAILQ_INSERT_TAIL(&state->ct_crypt_queue, trans, tr_next);
	state->ct_crypt_qlen++;
	ct_wakeup_encrypt(state->event_state);
	CT_UNLOCK(&state->ct_crypt_lock);
}

struct ct_trans *
ct_dequeue_encrypt(struct ct_global_state *state)
{
	struct ct_trans	*trans;

	CT_LOCK(&state->ct_crypt_lock);
	if ((trans = TAILQ_FIRST(&state->ct_crypt_queue)) != NULL) {
		TAILQ_REMOVE(&state->ct_crypt_queue, trans, tr_next);
		state->ct_crypt_qlen--;
	}
	CT_UNLOCK(&state->ct_crypt_lock);

	return (trans);
}

void
ct_queue_csha(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_csha_lock);
	TAILQ_INSERT_TAIL(&state->ct_csha_queue, trans, tr_next);
	state->ct_csha_qlen++;
	ct_wakeup_csha(state->event_state);
	CT_UNLOCK(&state->ct_csha_lock);
}

struct ct_trans *
ct_dequeue_csha(struct ct_global_state *state)
{
	struct ct_trans *trans;

	CT_LOCK(&state->ct_csha_lock);
	if ((trans = TAILQ_FIRST(&state->ct_csha_queue)) != NULL) {
		TAILQ_REMOVE(&state->ct_csha_queue, trans, tr_next);
		state->ct_csha_qlen--;
	}
	CT_UNLOCK(&state->ct_csha_lock);

	return (trans);
}

void
ct_queue_write(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_write_lock);
	TAILQ_INSERT_TAIL(&state->ct_write_queue, trans, tr_next);
	state->ct_write_qlen++;
	ct_wakeup_write(state->event_state);
	CT_UNLOCK(&state->ct_write_lock);
}

struct ct_trans *
ct_dequeue_write(struct ct_global_state *state)
{
	struct ct_trans	*trans;

	CT_LOCK(&state->ct_write_lock);
	if ((trans = TAILQ_FIRST(&state->ct_write_queue)) != NULL) {
		TAILQ_REMOVE(&state->ct_write_queue, trans, tr_next);
		state->ct_write_qlen--;
	}
	CT_UNLOCK(&state->ct_write_lock);

	return (trans);
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
ct_dequeue_queued(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_queued_lock);
	TAILQ_REMOVE(&state->ct_queued, trans, tr_next);
	state->ct_queued_qlen--;
	CT_UNLOCK(&state->ct_queued_lock);
}

void
ct_queue_complete(struct ct_global_state *state, struct ct_trans *trans)
{
	CT_LOCK(&state->ct_complete_lock);
	RB_INSERT(ct_trans_lookup, &state->ct_complete, trans);
	state->ct_complete_rblen++;
	ct_wakeup_complete(state->event_state);
	CT_UNLOCK(&state->ct_complete_lock);
}

struct ct_trans *
ct_dequeue_complete(struct ct_global_state *state)
{
	struct ct_trans	*trans;

	CT_LOCK(&state->ct_complete_lock);
	if ((trans = RB_MIN(ct_trans_lookup, &state->ct_complete)) != NULL &&
	    trans->tr_trans_id == state->ct_packet_id) {
		RB_REMOVE(ct_trans_lookup, &state->ct_complete, trans);
		state->ct_complete_rblen--;
		state->ct_packet_id++;
	} else if (trans != NULL && trans->tr_trans_id < state->ct_packet_id) {
		CABORTX("old transaction found in completion queue %" PRIu64
		    " %" PRIu64, trans->tr_trans_id, state->ct_packet_id);
	} else {
		trans = NULL;
	}
	CT_UNLOCK(&state->ct_complete_lock);

	return (trans);
}

void
ct_insert_inflight(struct ct_global_state *state, struct ct_trans *trans)
{
	RB_INSERT(ct_iotrans_lookup, &state->ct_inflight, trans);
	state->ct_inflight_rblen++;
}

struct ct_trans *
ct_dequeue_inflight(struct ct_global_state *state)
{
	struct ct_trans	*trans;

	if ((trans = RB_MAX(ct_iotrans_lookup, &state->ct_inflight)) != NULL) {
		RB_REMOVE(ct_iotrans_lookup, &state->ct_inflight,
		    trans);
		state->ct_inflight_rblen--;
	}

	return (trans);
}

struct ct_trans *
ct_lookup_inflight(struct ct_global_state *state, uint32_t tag)
{
	struct ct_trans		ltrans, *trans;

	ltrans.hdr.c_tag = tag;
	if ((trans = RB_FIND(ct_iotrans_lookup, &state->ct_inflight,
	    &ltrans)) != NULL) {
		RB_REMOVE(ct_iotrans_lookup, &state->ct_inflight,
		    trans);
		state->ct_inflight_rblen--;
	}

	return (trans);
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
		if (state->ct_config->ct_compress) {
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
		state->ct_stats->st_chunks_tot++;
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
	case TR_S_XML_CULL_SHA_SEND:
	case TR_S_XML_CULL_COMPLETE_SEND:
		ct_queue_write(state, trans);
		break;
	default:
		CABORTX("state %d, not handled in ct_queue_transfer()",
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
static struct ct_trans *
ct_trans_alloc_local(struct ct_global_state *state)
{

	struct ct_trans *trans;

	if (state->ct_num_local_transactions >= CT_MAX_LOCAL_TRANSACTIONS)
		return (NULL);
	state->ct_num_local_transactions++;

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
		if (state->ct_trans_alloc > state->ct_max_trans)
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
			CABORTX("too many transactions allocated");
	}

	return trans;
}

void
ct_trans_free(struct ct_global_state *state, struct ct_trans *trans)
{
	/* This should come from preallocated shared memory freelist */
	if (trans->tr_local) {
		/* just chuck local trans for now. */
		state->ct_num_local_transactions--;
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
		ct_wakeup_file(state->event_state);
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
	int			 ret;

	if ((ret = ct_ssl_connect(state)) != 0) {
		if ((ret = ct_assl_negotiate_poll(state)) != 0) {
			CFATALX("negotiate failed on reconnect: %s",
			    ct_strerror(ret));
		}

		if (state->ct_disconnected > 2)
			CINFO("Reconnected");
		state->ct_disconnected = 0;

		CT_LOCK(&state->ct_write_lock);
		TAILQ_FOREACH_SAFE(trans, &state->ct_write_queue, tr_next,
		    ttrans) {
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
					TAILQ_REMOVE(&state->ct_write_queue,
					    trans, tr_next);
					state->ct_write_qlen--;
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
				if ((ret = ct_xml_file_open_polled(state,
				    trans->tr_ctfile_name, MD_O_APPEND,
				    trans->tr_ctfile_chunkno)) != 0)
					CFATALX("can't reopen metadata file: %s",
					    ct_strerror(ret));
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
					CFATALX("can't reopen metadata file: %s",
					    ct_strerror(ret));
				break;
			}
		}
		CT_UNLOCK(&state->ct_write_lock);
	} else {
		CNDBG(CT_LOG_NET, "failed to reconnect to server: %s",
		    ct_strerror(ret));
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
	return (state->ct_disconnected > 0);
}

void
ct_reconnect(evutil_socket_t unused, short event, void *varg)
{
	struct ct_global_state *state = varg;

	if (ct_reconnect_internal(state) == 0) {
		state->ct_reconnect_timeout = CT_RECONNECT_DEFAULT_TIMEOUT;
		/* XXX - wakeup everyone */
		ct_wakeup_sha(state->event_state);
		ct_wakeup_compress(state->event_state);
		ct_wakeup_encrypt(state->event_state);
		ct_wakeup_csha(state->event_state);
		ct_wakeup_write(state->event_state);
		ct_wakeup_complete(state->event_state);
		ct_wakeup_file(state->event_state);
	} else {
		ct_set_reconnect_timeout(state->event_state,
		    state->ct_reconnect_timeout);
	}

}

void
ct_handle_disconnect(struct ct_global_state *state)
{
	struct ct_trans		*trans = NULL;
	int			 idle = 1;

	state->ct_disconnected = 1;
	ct_ssl_cleanup(state);

	while ((trans = ct_dequeue_inflight(state)) != NULL) {
		CNDBG(CT_LOG_NET,
		    "moving trans %" PRIu64 " back to queued",
		    trans->tr_trans_id);
		/* put on the head so write queue is still ordered. */
		ct_queue_write(state, trans);
		idle = 0;
	}
	if (idle) {
		state->ct_reconnect_pending = 1;
	} else {
		ct_set_reconnect_timeout(state->event_state,
		    state->ct_reconnect_timeout);
	}
}

void
ct_handle_msg(void *ctx, struct ct_header *hdr, void *vbody)
{
	struct ct_global_state	*state = ctx;
	struct ct_trans		*trans = NULL;

	if (hdr == NULL) {
		ct_handle_disconnect(state);
		return;
	}

	/* if a reply, lookup transaction */
	    /* update state */
	    /* requeue transaction */
	/* else */
	    /* handle request */

	if (hdr->c_opcode & 1) {
		CNDBG(CT_LOG_NET,
		    "handle message iotrans %u opcode %u status %u",
		    hdr->c_tag, hdr->c_opcode, hdr->c_status);
		if ((trans = ct_lookup_inflight(state, hdr->c_tag)) == NULL)
			CFATALX("%d: %s", hdr->c_tag,
			    ct_strerror(CTE_UNEXPECTED_TRANS));
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
		CFATALX("0x%x: %s", hdr->c_opcode,
		    ct_strerror(CTE_UNEXPECTED_OPCODE));
	}
}

int
ct_write_done(void *vctx, struct ct_header *hdr, void *vbody, int cnt)
{
	struct ct_global_state	*state = vctx;
	/* the header is first in the structure for this reason */
	struct ct_trans		*trans = (struct ct_trans *)hdr;

	if (hdr == NULL) {
		ct_handle_disconnect(state);
		return 1;
	}

	if (cnt != 0 && (hdr->c_opcode != C_HDR_O_WRITE ||
	    (hdr->c_flags & C_HDR_F_METADATA) == 0))
		CABORTX("not expecting vbody");

	CNDBG(CT_LOG_NET, "write done, trans %" PRIu64 " op %u",
	    trans->tr_trans_id, hdr->c_opcode);

	ct_dequeue_queued(state, trans);
	if (state->ct_disconnected) {
		/*
		 * this transaction is already in the inflight rb tree
		 * move back to to write_queue
		 */
		trans = (struct ct_trans *)hdr; /* cast to parent struct */
		CNDBG(CT_LOG_NET, "moving trans %" PRIu64" back to write queue",
		    trans->tr_trans_id);
		ct_queue_write(state, trans);
		return 0;
	}

	switch (hdr->c_opcode) {
	case C_HDR_O_EXISTS:
	case C_HDR_O_WRITE:
	case C_HDR_O_READ:
	case C_HDR_O_XML:
		ct_cleanup_packet(hdr, vbody);
		ct_insert_inflight(state, trans);
		break;
	default:
		/* Should not happen */
		CABORTX("unknown packet written for hdr opcode %u tag %u "
		    "trans %" PRIu64, hdr->c_opcode, hdr->c_tag,
		    trans->tr_trans_id);
	}
	return 0;
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

		/* XXX in this case should we fallback to alocation? */
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

	while ((trans = ct_dequeue_sha(state)) != NULL) {
		fnode = trans->tr_fl_node;

		switch (trans->tr_state) {
		case TR_S_READ:
			/* compute sha */
			break;
		case TR_S_WRITTEN:
		case TR_S_EXISTS:
			if (clog_mask_is_set(CT_LOG_SHA)) {
				ct_sha1_encode(trans->tr_sha, shat);
				CNDBG(CT_LOG_SHA,
				    "entering sha into db %" PRIu64 " %s",
				    trans->tr_trans_id, shat);
			}
			ctdb_insert_sha(state->ct_db_state, trans->tr_sha,
			    trans->tr_csha, trans->tr_iv);
			trans->tr_state = TR_S_WMD_READY;
			ct_queue_transfer(state, trans);
			continue;
		default:
			CABORTX("unexpected transaction state %d",
			    trans->tr_state);
		}
		state->ct_stats->st_chunks_tot++;
		slot = trans->tr_dataslot;
		CNDBG(CT_LOG_SHA,
		    "computing sha for trans %" PRIu64 " slot %d, size %d",
		    trans->tr_trans_id, slot, trans->tr_size[slot]);
		ct_sha1(trans->tr_data[slot], trans->tr_sha,
		    trans->tr_size[slot]);
		ct_sha1_add(trans->tr_data[slot], &fnode->fl_shactx,
		    trans->tr_size[slot]);

		state->ct_stats->st_bytes_sha += trans->tr_size[slot];

		if (clog_mask_is_set(CT_LOG_SHA)) {
			ct_sha1_encode(trans->tr_sha, shat);
			CNDBG(CT_LOG_SHA,
			    "block tr_id %" PRIu64 " sha %s sz %d",
			    trans->tr_trans_id, shat, trans->tr_size[slot]);
		}
		if (ctdb_lookup_sha(state->ct_db_state, trans->tr_sha,
			    trans->tr_csha, trans->tr_iv)) {
			state->ct_stats->st_bytes_exists += trans->tr_chsize;
			trans->tr_state = TR_S_WMD_READY;
		} else {
			trans->tr_state = TR_S_UNCOMPSHA_ED;
		}
		ct_queue_transfer(state, trans);
	}
}

void
ct_compute_csha(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	char			shat[SHA_DIGEST_STRING_LENGTH];
	int			slot;


	while ((trans = ct_dequeue_csha(state)) != NULL) {
		slot = trans->tr_dataslot;
		ct_sha1(trans->tr_data[slot], trans->tr_csha,
		    trans->tr_size[slot]);

		state->ct_stats->st_bytes_csha += trans->tr_size[slot];

		if (clog_mask_is_set(CT_LOG_SHA)) {
			ct_sha1_encode(trans->tr_sha, shat);
			CNDBG(CT_LOG_SHA, "block tr_id %" PRIu64 " sha %s",
			    trans->tr_trans_id, shat);
		}
		trans->tr_state = TR_S_COMPSHA_ED;
		ct_queue_transfer(state, trans);
	}
}

void
ct_process_completions(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans 	*trans;

	while ((trans = ct_dequeue_complete(state)) != NULL) {
		CNDBG(CT_LOG_TRANS,
		    "completing trans %" PRIu64 " pkt id: %" PRIu64"",
		    trans->tr_trans_id, state->ct_packet_id);
		if (trans->tr_complete(state, trans) != 0) {
			/* do we have more operations queued up? */
			if (ct_op_complete(state) != 0)
				ct_shutdown(state);
		}
		ct_trans_free(state, trans);

		/*
		 * XXX this is needed while the ctfile download protocol
		 * works as it does, we don't know the size of the file so
		 * we keep reading until we run out of chunks
		 */
		if (ct_get_file_state(state) != CT_S_FINISHED)
			ct_wakeup_file(state->event_state);
	}
}

void
ct_process_write(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_trans		*trans;
	struct ct_header	*hdr;
	void			*data;
	int			 nchunks;

	/* did we idle out? */
	if (state->ct_reconnect_pending) {
		if (ct_reconnect_internal(state) != 0)
			ct_set_reconnect_timeout(state->event_state,
			     state->ct_reconnect_timeout);
		state->ct_reconnect_pending = 0;
	}

	CNDBG(CT_LOG_NET, "wakeup write");
	while (state->ct_disconnected == 0 &&
	    (trans = ct_dequeue_write(state)) != NULL) {
		CNDBG(CT_LOG_NET, "wakeup write going");
		hdr = &trans->hdr;

		nchunks = 0;
		/* hdr->c_tag was set on transaction allocation */
		switch(trans->tr_state) {
		case TR_S_NEXISTS:
		case TR_S_COMPRESSED:
		case TR_S_ENCRYPTED: /* if dealing with metadata */
		case TR_S_READ: /* if dealing with ctfile non-comp/non-crypt */
			/* doesn't exist in backend, need to send chunk */
			if (hdr->c_flags & C_HDR_F_METADATA)
				ct_create_ctfile_write(hdr, &data, &nchunks,
				    trans->tr_data[(int)trans->tr_dataslot],
				    trans->tr_size[(int)trans->tr_dataslot],
				    trans->tr_ctfile_chunkno);
			else
				ct_create_write(hdr, &data,
				    trans->tr_data[(int)trans->tr_dataslot],
				    trans->tr_size[(int)trans->tr_dataslot]);
			state->ct_stats->st_bytes_sent +=
			    trans->tr_size[(int)trans->tr_dataslot];
			break;
		case TR_S_COMPSHA_ED:
			ct_create_exists(hdr, &data, trans->tr_csha,
			    sizeof(trans->tr_csha));
			break;
		case TR_S_UNCOMPSHA_ED:
			ct_create_exists(hdr, &data, trans->tr_sha,
			    sizeof(trans->tr_sha));
			break;
		case TR_S_EX_SHA:
			ct_create_read(hdr, &data, trans->tr_sha,
			    sizeof(trans->tr_sha));
			break;
		case TR_S_XML_OPEN:
		case TR_S_XML_CLOSING:
		case TR_S_XML_LIST:
		case TR_S_XML_DELETE:
		case TR_S_XML_CULL_SEND:
		case TR_S_XML_CULL_SHA_SEND:
		case TR_S_XML_CULL_COMPLETE_SEND:
			/* hdr populated previously */
			data = trans->tr_data[2];
			break;
		default:
			CABORTX("unexpected state in wakeup_write %d",
			    trans->tr_state);
		}

		CNDBG(CT_LOG_NET, "queuing write of op %u trans %" PRIu64
		    " iotrans %u tstate %d flags 0x%x",
		    hdr->c_opcode, trans->tr_trans_id, hdr->c_tag,
		    trans->tr_state, hdr->c_flags);

		/* move transaction to pending RB tree */
		ct_queue_queued(state, trans);

		if (nchunks > 0) {
			ct_assl_writev_op(state->ct_assl_ctx, hdr, data,
			    nchunks);
		} else {
			ct_assl_write_op(state->ct_assl_ctx, hdr, data);
		}
	}
}

void
ct_handle_exists_reply(struct ct_global_state *state, struct ct_trans *trans,
    struct ct_header *hdr, void *vbody)
{
	int exists, ret;

	CNDBG(CT_LOG_NET, "exists_reply %" PRIu64 " status %u",
	    trans->tr_trans_id, hdr->c_status);
	if ((ret = ct_parse_exists_reply(hdr, vbody, &exists)) != 0)
		CFATALX("invalid exists reply from server: %s",
		    ct_strerror(ret) );
	if (exists) {
		/* enter shas into local db */
		trans->tr_state = TR_S_EXISTS;
		state->ct_stats->st_bytes_exists += trans->tr_chsize;
	} else {
		trans->tr_state = TR_S_NEXISTS;
		trans->tr_fl_node->fl_comp_size +=
		    trans->tr_size[(int)trans->tr_dataslot];
	}
	ct_queue_transfer(state, trans);

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

	if (ct_parse_write_reply(hdr, vbody) != 0)
		CFATALX("chunk write failed: %s", ct_header_strerror(hdr));

	if (trans->hdr.c_flags & C_HDR_F_METADATA)
		trans->tr_state = TR_S_WMD_READY; /* XXX */
	else
		trans->tr_state = TR_S_WRITTEN;
	ct_queue_transfer(state, trans);
	ct_header_free(NULL, hdr);
}

void
ct_handle_read_reply(struct ct_global_state *state, struct ct_trans *trans,
    struct ct_header *hdr, void *vbody)
{
	char				 shat[SHA_DIGEST_STRING_LENGTH];
	int				 slot, ret;

	/* data was written to the 'alternate slot' so switch it */
	slot = trans->tr_dataslot = !(trans->tr_dataslot);

	if ((ret = ct_parse_read_reply(hdr, vbody)) == 0) {
		trans->tr_state = TR_S_EX_READ;
		if ((hdr->c_flags & C_HDR_F_METADATA) &&
		    (ret = ct_parse_read_ctfile_chunk_info(hdr, vbody,
			trans->tr_ctfile_chunkno)) != 0) 
				CFATALX("invalid ctfile read packet: %s",
				    ct_strerror(ret));
	} else {
		CNDBG(CT_LOG_NET, "c_flags on reply %x", hdr->c_flags);
		/* read failure for ctfiles just means eof */
		if (hdr->c_flags & C_HDR_F_METADATA) {
			ctfile_extract_handle_eof(state, trans);
			goto out;
		} else {
			/* any other read failure is bad */
			ct_sha1_encode(trans->tr_sha, shat);
			CFATALX("Data missing on server sha %s: %s",
			    shat, ct_strerror(ret));
		}
	} 

	if (clog_mask_is_set(CT_LOG_NET)) {
		ct_sha1_encode(trans->tr_sha, shat);
		CNDBG(CT_LOG_NET, "chunk received for %s len %u flags %u", shat,
		    hdr->c_size, hdr->c_flags);
	}
	trans->tr_size[slot] = trans->hdr.c_size = hdr->c_size;
	trans->hdr.c_flags = hdr->c_flags;
	state->ct_stats->st_bytes_read += trans->tr_size[slot];

out:

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


	while ((trans = ct_dequeue_compress(state)) != NULL) {
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
			ncompmode = state->ct_config->ct_compress;
			break;
		default:
			CABORTX("unexpected state for compress %d",
			    trans->tr_state);
		}

		if (state->ct_compress_state == NULL ||
		    ct_compress_type(state->ct_compress_state) != ncompmode) {
			/* initial or (change in the middle!) mode */
			if (state->ct_compress_state != NULL)
				ct_cleanup_compression(
				    state->ct_compress_state);
			if ((state->ct_compress_state =
			    ct_init_compression(ncompmode)) == NULL) {
				CFATALX("%d: %s", ncompmode,
				    ct_strerror(CTE_SHRINK_INIT));
			}
		}

		if (state->ct_compress_state == NULL)
			CABORTX("compression mode 0?");

		slot = trans->tr_dataslot;
		if (slot > 1) {
			CABORTX("transaction with special slot in compress: %d",
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
			rv = ct_compress(state->ct_compress_state, src, dst,
			    len, &newlen);
			if (newlen >= len) {
				CNDBG(CT_LOG_TRANS,
				    "use uncompressed buffer %d %lu", len,
				    (unsigned long) newlen);
				rv = 1; /* act like compression failed */
				newlen = len;
			}
			if (rv == 0)
				trans->hdr.c_flags |= ncompmode;
			state->ct_stats->st_bytes_compressed += newlen;
			state->ct_stats->st_bytes_uncompressed +=
			    trans->tr_chsize;
		} else {
			newlen = state->ct_max_block_size;
			rv = ct_uncompress(state->ct_compress_state, src, dst,
			    len, &newlen);
			if (rv)
				CFATALX("%s",
				    ct_strerror(CTE_DECOMPRESS_FAILED));
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
	}
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
	int			ret;

	while ((trans = ct_dequeue_encrypt(state)) != NULL) {
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
			CABORTX("unexpected state for encr %d",
			    trans->tr_state);
		}


		slot = trans->tr_dataslot;
		if (slot > 1) {
			CABORTX("transaction with special slot in encr: %d",
			    slot);
		}
		src = trans->tr_data[slot];
		len = trans->tr_size[slot];
		dst =  trans->tr_data[!slot];

		key = state->ct_crypto_key;
		keysz = sizeof(state->ct_crypto_key);

		iv = trans->tr_iv;
		ivlen = sizeof trans->tr_iv;

		if (encr) {
			/* encr the chunk. */
			if ((trans->hdr.c_flags & C_HDR_F_METADATA) == 0) {
				if ((ret = ct_create_iv(state->ct_iv,
				    sizeof(state->ct_iv), src, len, iv,
				    ivlen)) != 0)
					CFATALX("can't create iv: %s",
					    ct_strerror(ret));
			} else {
				if ((ret = ct_create_iv_ctfile(
				    trans->tr_ctfile_chunkno, iv, ivlen)) != 0)
					CFATALX("can't create iv for ctfile %d:"
					    "%s", trans->tr_ctfile_chunkno,
					    ct_strerror(ret));
			}

			newlen = ct_encrypt(key, keysz, iv, ivlen, src,
			    len, dst, state->ct_alloc_block_size);
		} else {
			/* iv was taken from ctfile or other information. */
			newlen = ct_decrypt(key, keysz, iv, ivlen,
			    src, len, dst, state->ct_alloc_block_size);
		}

		if (newlen < 0)
			CFATALX("%s", ct_strerror(encr ? CTE_ENCRYPT_FAILED :
			    CTE_DECRYPT_FAILED));

		CNDBG(CT_LOG_TRANS,
		    "%scrypt block of %d to %lu", encr ? "en" : "de",
		    len, (unsigned long) newlen);

		state->ct_stats->st_bytes_crypted += newlen;

		trans->tr_size[!slot] = newlen;
		trans->tr_dataslot = !slot;

		if (encr)
			trans->tr_state = TR_S_ENCRYPTED;
		else
			trans->tr_state = TR_S_EX_DECRYPTED;
		ct_queue_transfer(state, trans);
	}
}
