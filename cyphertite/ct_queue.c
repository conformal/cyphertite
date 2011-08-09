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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <clog.h>
#include <exude.h>

#include "ct.h"
#include "ct_crypto.h"

__attribute__((__unused__)) static const char *cvstag = "$cyphertite$";

void ct_handle_exists_reply(struct ct_trans *, struct ct_header *, void *);
void ct_handle_write_reply(struct ct_trans *, struct ct_header *, void *);
void ct_handle_read_reply(struct ct_trans *, struct ct_header *, void *);

void ct_write_md_special(struct ct_trans *);
void ct_write_md_eof(struct ct_trans *);
void ct_complete_normal(struct ct_trans *);

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
TAILQ_HEAD(,ct_trans)ct_trans_free_head =
    TAILQ_HEAD_INITIALIZER(ct_trans_free_head);;
int ct_numalloc = 0;
int ct_alloc_block_size;
int ct_cur_compress_mode = 0;
uint64_t	ct_packet_id = 0;

int ct_disconnected = 0;

int c_tr_tag = 0;
int c_trans_free = 0;

struct ct_global_state *ct_state = &ct_int_state;
struct ct_stat *ct_stats = &ct_int_stats;

void
ct_setup_state(void)
{
	/* unless we have shared memory, init is simple */
	ct_state = &ct_int_state;

	ct_stats = &ct_int_stats;

	ct_state->ct_file_state = CT_S_STARTING;
	ct_state->ct_comp_state = CT_S_WAITING_TRANS;
	ct_state->ct_crypt_state = CT_S_WAITING_TRANS;
	ct_state->ct_write_state = CT_S_WAITING_TRANS;

	TAILQ_INIT(&ct_state->ct_sha_queue);
	TAILQ_INIT(&ct_state->ct_comp_queue);
	TAILQ_INIT(&ct_state->ct_crypt_queue);
	TAILQ_INIT(&ct_state->ct_csha_queue);
	TAILQ_INIT(&ct_state->ct_write_queue);
	TAILQ_INIT(&ct_state->ct_queued);
	RB_INIT(&ct_state->ct_inflight);
	RB_INIT(&ct_state->ct_complete);
	TAILQ_INIT(&ct_state->ct_operations);

	ct_state->ct_sha_qlen = 0;
	ct_state->ct_comp_qlen = 0;
	ct_state->ct_crypt_qlen = 0;
	ct_state->ct_csha_qlen = 0;
	ct_state->ct_write_qlen = 0;
	ct_state->ct_inflight_rblen = 0;
	ct_state->ct_complete_rblen = 0;
}

void
ct_set_file_state(int newstate)
{
	ct_state->ct_file_state = newstate;
}

void
ct_queue_transfer(struct ct_trans *trans)
{
	CDBG("queuing transaction %" PRIu64 " %d",
	    trans->tr_trans_id, trans->tr_state);
	switch (trans->tr_state) {
	case TR_S_READ:
	case TR_S_WRITTEN: /* written goes back to this queue for local db */
	case TR_S_EXISTS:
		if (trans->hdr.c_flags & C_HDR_F_METADATA)
			goto skip_sha;
		ct_state->ct_sha_qlen++;
		TAILQ_INSERT_TAIL(&ct_state->ct_sha_queue, trans, tr_next);
		ct_wakeup_sha();
		break;
	case TR_S_UNCOMPSHA_ED:
skip_sha:	/* metadata skips shas */
		/* try to compress trans body, if compression enabled */
		if (ct_compress_enabled) {
			/* XXX - locks */
			ct_state->ct_comp_qlen++;
			TAILQ_INSERT_TAIL(&ct_state->ct_comp_queue, trans,
			  tr_next);

			if (ct_state->ct_comp_state != CT_S_RUNNING) {
				ct_wakeup_compress();
			}
			ct_wakeup_compress();
			break;
		}
		/* fallthru if compress not enabled */
	case TR_S_COMPRESSED:
		/* try to encrypt trans body, if compression enabled */
		if (ct_encrypt_enabled) {
			/* XXX - locks */
			ct_state->ct_crypt_qlen++;
			TAILQ_INSERT_TAIL(&ct_state->ct_crypt_queue, trans,
			  tr_next);

			ct_wakeup_encrypt();
			break;
		}
		/* fallthru if compress not enabled */
	case TR_S_COMPSHA_ED:
	case TR_S_NEXISTS:
		/* packet is compressed/crypted/SHAed as necessary, send */
		/* XXX - locks */
skip_csha:
		ct_state->ct_write_qlen++;
		TAILQ_INSERT_TAIL(&ct_state->ct_write_queue, trans, tr_next);

		ct_wakeup_write();
		break;
	case TR_S_ENCRYPTED:
		if (trans->hdr.c_flags & C_HDR_F_METADATA)
			goto skip_csha;
		/* after encrypting packet, create csha */
		/* XXX - locks */
		ct_state->ct_csha_qlen++;
		TAILQ_INSERT_TAIL(&ct_state->ct_csha_queue, trans, tr_next);
		ct_wakeup_csha();
		break;

	case TR_S_FILE_START:
	case TR_S_SPECIAL:
	case TR_S_WMD_READY:
		RB_INSERT(ct_trans_lookup, &ct_state->ct_complete, trans);
		ct_state->ct_complete_rblen++;

		ct_wakeup_complete();
		break;


	/* extract path */
	case TR_S_EX_SHA:
		ct_stats->st_chunks_tot++;
		ct_state->ct_write_qlen++;
		TAILQ_INSERT_TAIL(&ct_state->ct_write_queue, trans, tr_next);
		ct_wakeup_write();
		break;
	case TR_S_EX_READ:
		/* smash trans header with recieved header, flags, sz, op */
		if (trans->hdr.c_flags & C_HDR_F_ENCRYPTED) {
			ct_state->ct_crypt_qlen++;
			TAILQ_INSERT_TAIL(&ct_state->ct_crypt_queue, trans,
			    tr_next);
			ct_wakeup_encrypt();
			break;
		}
		/* FALLTHRU */
	case TR_S_EX_DECRYPTED:
		if (trans->hdr.c_flags & C_HDR_F_COMPRESSED_MASK) {
			ct_state->ct_comp_qlen++;
			TAILQ_INSERT_TAIL(&ct_state->ct_comp_queue, trans,
			    tr_next);
			ct_wakeup_compress();
			break;
		}
		/* FALLTHRU */
	case TR_S_EX_UNCOMPRESSED:
	case TR_S_EX_FILE_START:
	case TR_S_EX_SPECIAL:
	case TR_S_EX_FILE_END:
	case TR_S_DONE:
	case TR_S_XML_OPEN:
	case TR_S_XML_CLOSE:
	case TR_S_XML_CLOSING:
	case TR_S_XML_LIST:
	case TR_S_XML_DELETE:
		RB_INSERT(ct_trans_lookup, &ct_state->ct_complete, trans);
		ct_state->ct_complete_rblen++;

		ct_wakeup_complete();
		break;
	default:
		CFATALX("state %d, not handled in ct_queue_transfer()",
		    trans->tr_state);
	}
}

struct ct_trans *
ct_trans_alloc(void)
{
	struct ct_trans *trans;
	void *tr_data[2];
	uint16_t tag;

	/* This should come from preallocated shared memory */
	if (!TAILQ_EMPTY(&ct_trans_free_head)) {
		trans = TAILQ_FIRST(&ct_trans_free_head);
		TAILQ_REMOVE(&ct_trans_free_head, trans, tr_next);
		tr_data[0] = trans->tr_data[0];
		tr_data[1] = trans->tr_data[1];
		tag = trans->hdr.c_tag;
		bzero(trans, sizeof(*trans));
		trans->tr_data[0] = tr_data[0];
		trans->tr_data[1] = tr_data[1];
		trans->hdr.c_tag = tag;
		c_trans_free--;
	} else {
		if (ct_numalloc > ct_max_trans)
			return NULL;

		ct_numalloc++;

		if (ct_compress_enabled)
			ct_alloc_block_size = s_compress_bounds(
			    ct_max_block_size);
		else
			ct_alloc_block_size = ct_max_block_size;

		ct_alloc_block_size += ct_crypto_blocksz();

		trans = e_calloc(1, ct_alloc_block_size * 2 + sizeof(*trans));
		/* need to allocate body and compressed body */
		trans->tr_data[0] = (uint8_t *)trans + sizeof(*trans);
		trans->tr_data[1] = (uint8_t *)trans + sizeof(*trans)
		    + ct_alloc_block_size;

		trans->hdr.c_tag = c_tr_tag++;
		if (c_tr_tag >= 0x10000)
			CFATALX("too many transactions allocated");
	}

	return trans;
}

void
ct_trans_free(struct ct_trans *trans)
{
	/* This should come from preallocated shared memory freelist */
	TAILQ_INSERT_HEAD(&ct_trans_free_head, trans, tr_next);
	c_trans_free++;

	/* XXX - should this wait for a low threshold? */
	if (ct_state->ct_file_state == CT_S_WAITING_TRANS) {
		CDBG("send wakeup");
		ct_wakeup_file();
	}
}

void
ct_trans_cleanup(void)
{
	struct ct_trans *trans;
	int count = 0;

	CDBG("trans num free  %d", c_trans_free);
	/* free the transaction data block/or each element */
	while (!TAILQ_EMPTY(&ct_trans_free_head)) {
		trans = TAILQ_FIRST(&ct_trans_free_head);
		TAILQ_REMOVE(&ct_trans_free_head, trans, tr_next);
		e_free(&trans);
		count++;
	}
	CDBG("freed %d transactions", count);
}

void
ct_reconnect(int unused, short event, void *varg)
{
	struct ct_trans		*trans;

	ct_assl_ctx = ct_ssl_connect(1);
	if (ct_assl_ctx) {
		if (ct_assl_negotiate_poll(ct_assl_ctx)) {
			CFATALX("negotiate failed");
		}

		ct_disconnected = 0;
		CINFO("Reconnected");

		TAILQ_FOREACH(trans, &ct_state->ct_write_queue, tr_next) {
			if ((trans->hdr.c_flags & C_HDR_F_METADATA) == 0)
				continue;

			if (trans->hdr.c_opcode == C_HDR_O_XML) {
				/*
				 * Already an open first thing in the queue,
				 * don't worry.
				 */
				if (trans->tr_state == TR_S_XML_OPEN) {
					CDBG("found open in queue, ignoring");
					break;
				}
				/*
				 * Close without a read or write
				 * restart will have closed it for us, so
				 * just complete it and stop worrying
				 */
				if (trans->tr_state == TR_S_XML_CLOSING ||
				    trans->tr_state == TR_S_XML_CLOSE) {
					CDBG("found close in queue, completing");
					/* Don't try and close again */
					/* XXX should be S_DONE? */
					trans->tr_state = TR_S_XML_CLOSING;
					/* complete it and stop worrying */;
					TAILQ_REMOVE(&ct_state->ct_write_queue,
					    trans, tr_next);
					ct_state->ct_write_qlen--;
					RB_INSERT(ct_trans_lookup,
					    &ct_state->ct_complete, trans);
					ct_state->ct_complete_rblen++;
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
				CDBG("write in queue chunkno %d",
				    trans->tr_md_chunkno);
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
				if (ct_xml_file_open_polled(ct_assl_ctx,
				    trans->tr_md_name, MD_O_APPEND,
				    trans->tr_md_chunkno))
					CFATALX("can't reopen metadata file");
				break;
			} else if (trans->tr_state == TR_S_EX_SHA) {
				CDBG("read in queue chunkno %d",
				    trans->tr_md_chunkno);
				/*
				 * We had a read in progress. reinject
				 * the right open at chunkno
				 * For how this works see above.
				 */
				if (ct_xml_file_open_polled(ct_assl_ctx,
				    trans->tr_md_name, MD_O_READ,
				    trans->tr_md_chunkno))
					CFATALX("can't reopen metadata file");
				break;
			}
		}

		/* XXX - wakeup everyone */
		ct_wakeup_sha();
		ct_wakeup_compress();
		ct_wakeup_encrypt();
		ct_wakeup_csha();
		ct_wakeup_complete();
		ct_wakeup_write();
		ct_wakeup_complete();
		ct_wakeup_file();

	} else {
		ct_set_reconnect_timeout(ct_reconnect, NULL, 5);
	}
}

void
ct_handle_msg(void *ctx, struct ct_header *hdr, void *vbody)
{
	struct ct_trans		ltrans, *trans = NULL;
	int			lookup_body = 0;

	if (hdr == NULL) {
		/* backend disconnected -exit */
		CWARNX("Server disconnected, attempting to reconnect");

		ct_disconnected = 1;
		ct_assl_disconnect(ct_assl_ctx);
		while(!RB_EMPTY(&ct_state->ct_inflight)) {
			trans = RB_MAX(ct_iotrans_lookup,
			    &ct_state->ct_inflight);
			CDBG("moving trans %" PRIu64 " back to queued",
				trans->tr_trans_id);
			RB_REMOVE(ct_iotrans_lookup, &ct_state->ct_inflight,
			    trans);
			/* put on the head so write queue is still ordered. */
			TAILQ_INSERT_HEAD(&ct_state->ct_write_queue, trans,
			    tr_next);
			ct_state->ct_write_qlen++;
			ct_state->ct_inflight_rblen--;
		}

		ct_set_reconnect_timeout(ct_reconnect, NULL, 5);
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
		CDBG("handle message iotrans %u opcode %u status %u",
		    hdr->c_tag, hdr->c_opcode, hdr->c_status);
		trans = RB_FIND(ct_iotrans_lookup, &ct_state->ct_inflight,
		    &ltrans);

		if (trans == NULL)
			CFATALX("invalid io transaction reply(1)");

		RB_REMOVE(ct_iotrans_lookup, &ct_state->ct_inflight, trans);
		ct_state->ct_inflight_rblen--;
	}

	if (trans)
		CDBG("trans %" PRIu64 " found", trans->tr_trans_id);
	switch(hdr->c_opcode) {
	case C_HDR_O_EXISTS_REPLY:
		ct_handle_exists_reply(trans, hdr, vbody);
		break;
	case C_HDR_O_WRITE_REPLY:
		ct_handle_write_reply(trans, hdr, vbody);
		break;
	case C_HDR_O_READ_REPLY:
		ct_handle_read_reply(trans, hdr, vbody);
		break;
	case C_HDR_O_XML_REPLY:
		ct_handle_xml_reply(trans, hdr, vbody);
		break;
	default:
		CFATALX("unexpected message recieved 0x%x",
		    hdr->c_opcode);
	}
}

void
ct_write_done(void *vctx, struct ct_header *hdr, void *vbody, int cnt)
{
	/* the header is first in the structure for this reason */
	struct ct_trans *trans = (struct ct_trans *)hdr;

	if (cnt != 0 && (hdr->c_opcode != C_HDR_O_WRITE ||
	    (hdr->c_flags & C_HDR_F_METADATA) == 0))
		CFATALX("not expecting vbody");

	CDBG("write done, trans %" PRIu64 " op %u",
	    trans->tr_trans_id, hdr->c_opcode);

	if (ct_disconnected) {
		/*
		 * this transaction is already in the inflight rb tree
		 * move back to to write_queue
		 */
		trans = (struct ct_trans *)hdr; /* cast to parent struct */
		CDBG("moving trans %" PRIu64" back to write queue",
		    trans->tr_trans_id);
		TAILQ_REMOVE(&ct_state->ct_queued, trans, tr_next);
		ct_state->ct_queued_qlen--;
		ct_state->ct_write_qlen++;
		TAILQ_INSERT_TAIL(&ct_state->ct_write_queue, trans, tr_next);
		return;
	}

	switch (hdr->c_opcode) {
	case C_HDR_O_EXISTS:
	case C_HDR_O_WRITE:
	case C_HDR_O_READ:
	case C_HDR_O_XML:
		trans = (struct ct_trans *)hdr; /* cast to parent struct */
		TAILQ_REMOVE(&ct_state->ct_queued, trans, tr_next);
		RB_INSERT(ct_iotrans_lookup, &ct_state->ct_inflight, trans);
		ct_state->ct_queued_qlen--;
		ct_state->ct_inflight_rblen++;
		/* XXX no nice place to put this */
		if (hdr->c_opcode == C_HDR_O_WRITE &&
		    hdr->c_flags & C_HDR_F_METADATA &&
		    hdr->c_ex_status == 1) {
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
	uint8_t			*body;
	struct ct_trans		ltrans, *trans = NULL;
	int			slot;
	int			lookup_body = 0;

	/* if a reply, */
	   /* lookup transaction and return alternate data payload */
	/* else */
	   /* allocate buffer of hdr->c_size */
	CDBG("body alloc on iotrans %u", hdr->c_tag);

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
		trans = RB_FIND(ct_iotrans_lookup, &ct_state->ct_inflight,
		    &ltrans);

		if (trans == NULL)
			CFATALX("invalid io transaction reply(2)");

		slot = !(trans->tr_dataslot); /* alternate slot */
		body = trans->tr_data[slot];
	} else {
		body = e_calloc(1, hdr->c_size);
		CDBG("body allocated %p", body);
	}

	return body;
}

void
ct_body_free(void *vctx, void *body, struct ct_header *hdr)
{
	/* is this body one that was allocated or part of a reply? */

	/* if ct_header->c_opcode & 1 */
	if (hdr->c_opcode & 1) {
	    /* body is a transaction data, do not free */
	} else {
		e_free(&body);
	}
}

void
ct_compute_sha(void *vctx)
{
	struct ct_trans		*trans;
	struct fnode		*fnode;
	char			shat[SHA_DIGEST_STRING_LENGTH];
	int			slot;


	while (!TAILQ_EMPTY(&ct_state->ct_sha_queue)) {
		trans = TAILQ_FIRST(&ct_state->ct_sha_queue);
		TAILQ_REMOVE(&ct_state->ct_sha_queue, trans, tr_next);
		ct_state->ct_sha_qlen--;
		fnode = trans->tr_fl_node;

		switch (trans->tr_state) {
		case TR_S_READ:
			/* compute sha */
			break;
		case TR_S_WRITTEN:
		case TR_S_EXISTS:
			if (ct_debug) {
				ct_sha1_encode(trans->tr_sha, shat);
				CDBG("entering sha into db %" PRIu64 " %s",
				    trans->tr_trans_id, shat);
			}
			ctdb_insert(trans);
			trans->tr_state = TR_S_WMD_READY;
			ct_queue_transfer(trans);
			continue;
		default:
			CFATALX("unexpected transaction state %d",
			    trans->tr_state);
		}
		ct_stats->st_chunks_tot++;
		slot = trans->tr_dataslot;
		CDBG("computing sha for trans %" PRIu64 " slot %d, size %d",
			trans->tr_trans_id, slot, trans->tr_size[slot]);
		ct_sha1(trans->tr_data[slot], trans->tr_sha,
		    trans->tr_size[slot]);
		ct_sha1_add(trans->tr_data[slot], &fnode->fl_shactx,
		    trans->tr_size[slot]);

		ct_stats->st_bytes_sha += trans->tr_size[slot];

		if (ct_debug) {
			ct_sha1_encode(trans->tr_sha, shat);
			CDBG("block tr_id %" PRIu64 " sha %s sz %d",
			    trans->tr_trans_id, shat, trans->tr_size[slot]);
		}
		if (ctdb_exists(trans)) {
			ct_stats->st_bytes_exists += trans->tr_chsize;
			trans->tr_state = TR_S_WMD_READY;
		} else {
			trans->tr_state = TR_S_UNCOMPSHA_ED;
		}
		ct_queue_transfer(trans);
	}
}

void
ct_compute_csha(void *vctx)
{
	struct ct_trans		*trans;
	char			shat[SHA_DIGEST_STRING_LENGTH];
	int			slot;

	while (!TAILQ_EMPTY(&ct_state->ct_csha_queue)) {
		trans = TAILQ_FIRST(&ct_state->ct_csha_queue);
		TAILQ_REMOVE(&ct_state->ct_csha_queue, trans, tr_next);
		ct_state->ct_csha_qlen--;

		slot = trans->tr_dataslot;
		ct_sha1(trans->tr_data[slot], trans->tr_csha,
		    trans->tr_size[slot]);

		ct_stats->st_bytes_csha += trans->tr_size[slot];

		if (ct_debug) {
			ct_sha1_encode(trans->tr_sha, shat);
			CDBG("block tr_id %" PRIu64 " sha %s",
			    trans->tr_trans_id, shat);
		}
		trans->tr_state = TR_S_COMPSHA_ED;
		ct_queue_transfer(trans);
	}
}

void
ct_write_md_special(struct ct_trans *trans)
{
	struct fnode		*fnode = trans->tr_fl_node;
	char			link[PATH_MAX];
	char			*plink;
	int			type = fnode->fl_type;
	int			ret;

	if (C_ISDIR(type)) {
		if (ct_write_header(trans, fnode->fl_sname))
			CWARNX("header write failed");
		CDBG("record dir %s", fnode->fl_sname);
	} else if (C_ISCHR(type) || C_ISBLK(type)) {
		if (ct_write_header(trans, fnode->fl_sname))
			CWARNX("header write failed");
	} else if (C_ISFIFO(type)) {
		CWARNX("fifo not supported");
	} else if (C_ISLINK(type)) {
		if (fnode->fl_hardlink) {
			plink = fnode->fl_hlname;
		} else {
			ret = readlink(fnode->fl_fname, link, sizeof(link));
			if (ret == -1 || ret == sizeof(link)) {
				/* readlink failed, do not record */
				CWARNX("unable to read link for %s",
				    fnode->fl_sname);
				return;
			}
			link[ret] = '\0';
			plink = link;
		}
		if (fnode->fl_sname == NULL &&
		    plink == NULL) {
			CWARNX("%slink with no name or dest",
			    fnode->fl_hardlink ? "hard" : "sym");
			return;
		} else if (fnode->fl_sname == NULL) {
			CWARNX("%slink with no name",
			    fnode->fl_hardlink ? "hard" : "sym");
			return;
		} else if (plink == NULL) {
			CWARNX("%slink with no dest",
			    fnode->fl_hardlink ? "hard" : "sym");
			return;
		}
		CDBG("link %s %s", fnode->fl_sname, plink);
		if (ct_write_header(trans, fnode->fl_sname))
			CWARNX("header write failed");

		if (fnode->fl_hardlink) {
			fnode->fl_type = C_TY_REG; /* cheat */
		}

		if (ct_write_header(trans, plink))
			CWARNX("header write failed");

		fnode->fl_type = type; /* restore */

	} else if (C_ISSOCK(type)) {
		CWARNX("cannot archive a socket %s", fnode->fl_sname);
	} else {
		CWARNX("invalid type on %s %d", fnode->fl_sname,
		    type);
	}
}

void
ct_write_md_eof(struct ct_trans *trans)
{
	int			compression;
	struct fnode		*fnode;
	int			nrshas;

	fnode = trans->tr_fl_node;

	if ((ct_multilevel_allfiles == 0) &&
	    fnode->fl_skip_file)
		return;

	CDBG("trailer on trans %" PRIu64, trans->tr_trans_id);
	CDBG("should write trans for %s",
	    fnode->fl_sname);
	ct_write_trailer(trans);
	if (ct_verbose > 1) {

		if (fnode->fl_size == 0)
			compression = 0;
		else
			compression = 100 * (fnode->fl_size -
			    fnode->fl_comp_size) / fnode->fl_size;
		if (ct_verbose > 2) {
			nrshas = fnode->fl_size /
			    ct_max_block_size;
			if (fnode->fl_size % ct_max_block_size)
				nrshas++;

			printf(" shas %d", nrshas);
		}
		printf(" (%d%%)\n", compression);
	} else if (ct_verbose)
		printf("\n");
}

/* completion handler for states for non-metadata actions. */
void
ct_complete_normal(struct ct_trans *trans)
{
	int			slot;
	struct fnode		*fnode = trans->tr_fl_node;
	int			release_fnode = 0;

	switch (trans->tr_state) {
	case TR_S_DONE:
		ct_cleanup_md(); /* XXX */
		/* do we have more operations queued up? */
		if (ct_op_complete() == 0)
			return;
		if (ct_verbose_ratios)
			ct_dump_stats(stdout);
		ct_file_extract_fixup();
		ct_shutdown();
		break;
	case TR_S_SPECIAL:
		if (ct_verbose)
			printf("%s\n", fnode->fl_sname);
		ct_write_md_special(trans);
		release_fnode = 1;
		break;
	case TR_S_FILE_START:
		if ((ct_multilevel_allfiles == 0) &&
		    fnode->fl_skip_file) {
			release_fnode = 1;
			break;
		}

		if (ct_write_header(trans, fnode->fl_sname))
			CWARNX("header write failed");

		if (ct_verbose) {
			printf("%s", fnode->fl_sname);
			fflush(stdout);
		}

		if (trans->tr_eof == 1 || fnode->fl_skip_file) {
			ct_write_md_eof(trans);
			ct_stats->st_files_completed++;
		}
		break;
	case TR_S_WMD_READY:
		ct_stats->st_chunks_completed++;
		if (ct_encrypt_enabled) {
			ct_write_sha_crypto(trans);
		} else {
			ct_write_sha(trans);
		}
		if (trans->tr_eof == 1) {
			ct_write_md_eof(trans);
			release_fnode = 1;
		}
		break;
	case TR_S_EX_FILE_START:
		ct_sha1_setup(&trans->tr_fl_node->fl_shactx);
		ct_file_extract_open(trans->tr_fl_node);
		CDBG("should print");
		if (ct_verbose) {
			ct_pr_fmt_file(trans->tr_fl_node);
			printf("\n");
		}
		break;
	case TR_S_EX_FILE_END:
		ct_sha1_final(trans->tr_csha, &trans->tr_fl_node->fl_shactx);
		if (bcmp(trans->tr_csha, trans->tr_sha, sizeof(trans->tr_sha))
		    != 0)
			CWARNX("extract sha mismatch on %s",
			    trans->tr_fl_node->fl_sname);
		ct_stats->st_files_completed++;
		ct_file_extract_close(trans->tr_fl_node);
		break;
	case TR_S_EX_READ:
	case TR_S_EX_DECRYPTED:
	case TR_S_EX_UNCOMPRESSED:
		slot = trans->tr_dataslot;
		ct_sha1_add(trans->tr_data[slot], &trans->tr_fl_node->fl_shactx,
		    trans->tr_size[slot]);
		ct_stats->st_chunks_completed++;
		ct_file_extract_write(trans->tr_data[slot],
		    trans->tr_size[slot]);

		ct_stats->st_bytes_written += trans->tr_size[slot];
		break;
	case TR_S_EX_SPECIAL:
		ct_file_extract_special(trans->tr_fl_node);
		if (ct_verbose) {
			ct_pr_fmt_file(trans->tr_fl_node);
			printf("\n");
		}
		break;
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
	struct ct_trans *trans;

	trans = RB_MIN(ct_trans_lookup, &ct_state->ct_complete);
	if (trans)
		CDBG("completing trans %" PRIu64 " pkt id: %" PRIu64"",
		    trans->tr_trans_id, ct_packet_id);

	while (trans != NULL && trans->tr_trans_id == ct_packet_id) {
		RB_REMOVE(ct_trans_lookup, &ct_state->ct_complete, trans);
		ct_state->ct_complete_rblen--;

		CDBG("writing file trans %" PRIu64 " eof %d",
		    trans->tr_trans_id, trans->tr_eof);

		ct_packet_id++;

		if (trans->hdr.c_flags & C_HDR_F_METADATA) {
			ct_complete_metadata(trans);
		} else {
			ct_complete_normal(trans);
		}
		ct_trans_free(trans);

		/* XXX is this needed? */
		if (ct_state->ct_file_state != CT_S_FINISHED)
			ct_wakeup_file();


		trans = RB_MIN(ct_trans_lookup, &ct_state->ct_complete);
	}
	if (trans != NULL && trans->tr_trans_id < ct_packet_id) {
		CFATALX("old transaction found in completion queue %" PRIu64
		    " %" PRIu64, trans->tr_trans_id, ct_packet_id);
	}
}

void
ct_wakeup_write(void)
{
	struct ct_trans		*trans;
	struct ct_header	*hdr;
	void			*data;
	int			slot;

	CDBG("wakup write");
	while (ct_disconnected == 0 &&
	    !TAILQ_EMPTY(&ct_state->ct_write_queue)) {
		trans = TAILQ_FIRST(&ct_state->ct_write_queue);
		TAILQ_REMOVE(&ct_state->ct_write_queue, trans, tr_next);
		ct_state->ct_write_qlen--;

		CDBG("wakup write going");
		hdr = &trans->hdr;

		hdr->c_version = C_HDR_VERSION;

		/* this extra assignment here allows exists to be fallthru */
		data = trans->tr_sha;

		switch(trans->tr_state) {
		case TR_S_NEXISTS:
		case TR_S_COMPRESSED:
		case TR_S_ENCRYPTED: /* if dealing with metadata */
		case TR_S_READ: /* if dealing with md non-comp/non-crypt */
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
	#if 0
			if (verify)
				hdr->c_flags |= E_HDR_F_VERIFYDIGEST;
	#endif
			if (ct_encrypt_enabled) {
				hdr->c_flags |= C_HDR_F_ENCRYPTED;
			}
			break;
		case TR_S_EX_SHA:
			hdr->c_opcode = C_HDR_O_READ;
			hdr->c_size = sizeof(trans->tr_sha);
			data = trans->tr_sha;
			break;
		default:
			CFATALX("unexpected state in wakeup_write %d",
			    trans->tr_state);
		}
		/* hdr->c_tag - set once when trans was originally created */
		hdr->c_version = C_HDR_VERSION;

		CDBG("queuing write of op %u trans %" PRIu64
		    " iotrans %u tstate %d flags 0x%x",
		    hdr->c_opcode, trans->tr_trans_id, hdr->c_tag,
		    trans->tr_state, hdr->c_flags);

		/* move transaction to pending RB tree */
		TAILQ_INSERT_TAIL(&ct_state->ct_queued, trans, tr_next);
		ct_state->ct_queued_qlen++;

		/* XXX there really isn't a better place to do this */
		if (hdr->c_opcode == C_HDR_O_WRITE &&
		    (hdr->c_flags & C_HDR_F_METADATA) != 0 &&
		    hdr->c_ex_status == 1) {
			struct ct_metadata_footer	*cmf;
			struct ct_iovec			*iov;

			iov = e_calloc(2, sizeof(*iov));
			cmf = e_calloc(1, sizeof(*cmf));
			cmf->cmf_chunkno = trans->tr_md_chunkno;
			cmf->cmf_size = hdr->c_size;
			hdr->c_size += sizeof(*cmf);

			iov[0].iov_base = data;
			iov[0].iov_len = cmf->cmf_size;
			iov[1].iov_base = cmf;
			iov[1].iov_len = sizeof(*cmf);

			ct_assl_writev_op(ct_assl_ctx, hdr, iov, 2);
			continue;
		}

		ct_assl_write_op(ct_assl_ctx, hdr, data);
	}
}

void
ct_handle_exists_reply(struct ct_trans *trans, struct ct_header *hdr,
    void *vbody)
{
	int slot;

	CDBG("exists_reply %" PRIu64 " status %u",
	    trans->tr_trans_id, hdr->c_status);

	switch(hdr->c_status) {
	case C_HDR_S_FAIL:
		CFATALX("server connection failed");
	case C_HDR_S_EXISTS:
		/* enter shas into local db */
		trans->tr_state = TR_S_EXISTS;
		slot = trans->tr_dataslot;
		ct_stats->st_bytes_exists += trans->tr_chsize;
		ct_queue_transfer(trans);
		break;
	case C_HDR_S_DOESNTEXIST:
		trans->tr_state = TR_S_NEXISTS;
		slot = trans->tr_dataslot;
		trans->tr_fl_node->fl_comp_size += trans->tr_size[slot];
		ct_queue_transfer(trans);
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
ct_handle_write_reply(struct ct_trans *trans, struct ct_header *hdr,
    void *vbody)
{
	CDBG("handle_write_reply");
	CDBG("hdr op %u status %u size %u",
	    hdr->c_opcode, hdr->c_status, hdr->c_size);

	if (hdr->c_status == C_HDR_S_OK) {
		if (trans->hdr.c_flags & C_HDR_F_METADATA)
			trans->tr_state = TR_S_WMD_READY; /* XXX */
		else
			trans->tr_state = TR_S_WRITTEN;
		ct_queue_transfer(trans);
		ct_header_free(NULL, hdr);
	} else {
		CFATALX("chunk write failed");
	}
}

void
ct_handle_read_reply(struct ct_trans *trans, struct ct_header *hdr,
    void *vbody)
{
	struct ct_metadata_footer	*cmf;
	char				 shat[SHA_DIGEST_STRING_LENGTH];
	int				 slot;

	/* data was written to the 'alternate slot' so switch it */
	slot = trans->tr_dataslot = !(trans->tr_dataslot);
	if (hdr->c_status == C_HDR_S_OK) {
		trans->tr_state = TR_S_EX_READ;
		/* Check the chunk number for sanity */
		if (hdr->c_flags & C_HDR_F_METADATA &&
		    hdr->c_ex_status == 1) {
			CDBG("checking footer");
			cmf = (struct ct_metadata_footer *)
			    (trans->tr_data[slot] + hdr->c_size - sizeof(*cmf));

			if (cmf->cmf_size != hdr->c_size - sizeof(*cmf))
				CFATALX("invalid chunkfile footer");
			if (cmf->cmf_chunkno != trans->tr_md_chunkno)
				CFATALX("invalid chunkno %u %u",
				    cmf->cmf_chunkno, trans->tr_md_chunkno);
			CDBG("footer ok");
			hdr->c_size -= sizeof(*cmf);
		}
	} else {
		CDBG("c_flags on reply %x", hdr->c_flags);
		if (hdr->c_flags & C_HDR_F_METADATA) {
			/* FAIL on metadata read is 'eof' */
			if (ct_state->ct_file_state != CT_S_FINISHED) {
				ct_set_file_state(CT_S_FINISHED);
				trans->tr_state = TR_S_XML_CLOSE;
			} else {
				/*
				 * We had two ios in flight when we hit eof.
				 * We're already closing so just carry on
				 */
				trans->tr_state = TR_S_XML_CLOSING;
			}
		} else {
			ct_sha1_encode(trans->tr_sha, shat);
			CFATALX("Data missing on server return %u shat %s",
			    hdr->c_status, shat);
		}
	}

	if (ct_debug) {
		ct_sha1_encode(trans->tr_sha, shat);
		CDBG("chunk recieved for %s len %u flags %u", shat,
		    hdr->c_size, hdr->c_flags);
	}
	trans->tr_size[slot] = trans->hdr.c_size = hdr->c_size;
	trans->hdr.c_flags = hdr->c_flags;
	ct_stats->st_bytes_read += trans->tr_size[slot];

	ct_queue_transfer(trans);
	ct_header_free(NULL, hdr);
}

void
ct_compute_compress(void *vctx)
{
	struct ct_trans		*trans;
	uint8_t			*src, *dst;
	size_t			newlen;
	int			slot;
	int			compress;
	int			rv;
	int			len;
	int			ncompmode;

	/* #define LOW_PRI_COMPUTE */
	#ifdef LOW_PRI_COMPUTE
	if  (!TAILQ_EMPTY(&ct_state->ct_comp_queue))
	#else
	while (!TAILQ_EMPTY(&ct_state->ct_comp_queue))
	#endif
	{
		trans = TAILQ_FIRST(&ct_state->ct_comp_queue);
		TAILQ_REMOVE(&ct_state->ct_comp_queue, trans, tr_next);
		ct_state->ct_comp_qlen--;

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
				CDBG("use uncompressed buffer %d %zu", len,
				    newlen);
				rv = 1; /* act like compression failed */
			}
			if (rv == 0)
				trans->hdr.c_flags |= ncompmode;
			ct_stats->st_bytes_compressed += newlen;
			ct_stats->st_bytes_uncompressed += trans->tr_chsize;
		} else {
			newlen = ct_max_block_size;
			rv = ct_uncompress(src, dst, len, &newlen);

			if (rv)
				CFATALX("failed to decompress block len %d",
				    len);
		}

		CDBG("compress block of %d to %zu, rv %d", len, newlen, rv);

		/* if compression failed for whatever reason use input data */
		if (rv == 0) {
			trans->tr_size[!slot] = newlen;
			trans->tr_dataslot = !slot;
		}

		if (compress)
			trans->tr_state = TR_S_COMPRESSED;
		else
			trans->tr_state = TR_S_EX_UNCOMPRESSED;
		ct_queue_transfer(trans);
	}
	#ifdef LOW_PRI_COMPUTE
	if  (!TAILQ_EMPTY(&ct_state->ct_comp_queue)) {
		/*
		 * we are leaving something in the queue make certain
		 * it doesnt get lost by sending another wakeup
		 */
		ct_wakeup_compress();
	}
	#endif
}

void
ct_compute_encrypt(void *vctx)
{
	struct ct_trans		*trans;
	uint8_t			*src, *dst;
	unsigned char		*key = NULL;
	uint8_t			*iv;
	size_t			ivlen;
	size_t			keysz = -1;
	ssize_t			newlen;
	int			slot;
	int			encrypt;
	int			len;

	#ifdef LOW_PRI_COMPUTE
	if (!TAILQ_EMPTY(&ct_state->ct_crypt_queue))
	#else
	while (!TAILQ_EMPTY(&ct_state->ct_crypt_queue))
	#endif
	{
		trans = TAILQ_FIRST(&ct_state->ct_crypt_queue);
		TAILQ_REMOVE(&ct_state->ct_crypt_queue, trans, tr_next);
		ct_state->ct_crypt_qlen--;

		switch(trans->tr_state) {
		case TR_S_EX_READ:
			/* decrypt */
			encrypt = 0;
			break;
		case TR_S_READ: /* uncompressed md data */
		case TR_S_UNCOMPSHA_ED:
		case TR_S_COMPRESSED:
			encrypt = 1;
			break;
		default:
			CFATALX("unexpected state for encrypt %d",
			    trans->tr_state);
		}


		slot = trans->tr_dataslot;
		src = trans->tr_data[slot];
		len = trans->tr_size[slot];
		dst =  trans->tr_data[!slot];

		key = ct_crypto_key;
		keysz = sizeof ct_crypto_key;

		iv = trans->tr_iv;
		ivlen = sizeof trans->tr_iv;

		if (encrypt) {
			/* encrypt the chunk, if metadata, iv is alread valid */
			if ((trans->hdr.c_flags & C_HDR_F_METADATA) == 0) {
				if (ct_create_iv(ct_iv, sizeof(ct_iv), src,
				    len, iv, ivlen))
					CFATALX("can't create iv");
			}

			newlen = ct_encrypt(key, keysz, iv, ivlen, src,
			    len, dst, ct_alloc_block_size);
			/* XXX - which one ? */
			trans->hdr.c_flags |= C_HDR_F_ENCRYPTED;
		} else {
			newlen = ct_decrypt(key, keysz, iv, ivlen,
			    src, len, dst, ct_alloc_block_size);
		}

		if (newlen < 0)
			CFATALX("failed to %scrypt files",
			    encrypt ? "en" : "de");

		CDBG("%scrypt block of %d to %zu", encrypt ? "en" : "de",
		    len, newlen);

		ct_stats->st_bytes_crypted += newlen;

		trans->tr_size[!slot] = newlen;
		trans->tr_dataslot = !slot;

		if (encrypt)
			trans->tr_state = TR_S_ENCRYPTED;
		else
			trans->tr_state = TR_S_EX_DECRYPTED;
		ct_queue_transfer(trans);
	}
	#ifdef LOW_PRI_COMPUTE
	if (!TAILQ_EMPTY(&ct_state->ct_crypt_queue)) {
		/*
		 * we are leaving something in the queue make certain
		 * it doesnt get lost by sending another wakeup
		 */
		ct_wakeup_encrypt();
	}
	#endif
}

void
ct_display_queues(void)
{
	/* XXX - looks at queues without locks */

	if (ct_verbose > 1) {
		fprintf(stderr, "Sha      queue len %d\n",
		    ct_state->ct_sha_qlen);
		fprintf(stderr, "Comp     queue len %d\n",
		    ct_state->ct_comp_qlen);
		fprintf(stderr, "Crypt    queue len %d\n",
		    ct_state->ct_crypt_qlen);
		fprintf(stderr, "Csha     queue len %d\n",
		    ct_state->ct_csha_qlen);
		fprintf(stderr, "Write    queue len %d\n",
		    ct_state->ct_write_qlen);
		fprintf(stderr, "CRqueued queue len %d\n",
		    ct_state->ct_queued_qlen);
		fprintf(stderr, "Inflight queue len %d\n",
		    ct_state->ct_inflight_rblen);
		fprintf(stderr, "Complete queue len %d\n",
		    ct_state->ct_complete_rblen);
		fprintf(stderr, "Free     queue len %d\n", c_trans_free);
	}
	ct_dump_stats(stderr);
}
