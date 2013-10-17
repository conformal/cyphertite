/*
 * Copyright (c) 2010-2012 Conformal Systems LLC <info@conformal.com>
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

#include <sys/queue.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <event2/event.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>

#include <assl.h>
#include <clog.h>
#include <ctutil.h>

#include "ct_socket.h"

/* XXX */
void ct_wire_header(struct ct_header *h);
void ct_unwire_header(struct ct_header *h);

pid_t c_pid;

void
ct_event_assl_write(evutil_socket_t fd_notused, short events, void *arg)
{
	struct assl_context	*c;
	struct ct_assl_io_ctx	*ioctx = arg;
	struct ct_header	*hdr;
	uint8_t			*body;
	struct ct_io_queue	*iob;
	ssize_t			len;
	int			body_len;
	int			wlen;
	int			write_complete;
	int			s_errno;
	int			ctxgone;

send_another:
	write_complete = 0;

	c = ioctx->c;
	CT_LOCK(&ioctx->io_lock);
	iob = TAILQ_FIRST(&ioctx->io_o_q);
	hdr = iob->io_hdr;
	/* invalid to not have a header here */
	if (hdr == NULL) 
		CABORTX("NULL header");
	CT_UNLOCK(&ioctx->io_lock);
	body = NULL;

	CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" hdr op %d state %d, off %d "
	    "sz %d", (int64_t)c_pid, hdr->c_opcode, ioctx->io_o_state,
	    ioctx->io_o_off, hdr->c_size);

	switch (ioctx->io_o_state) {
	case 0: /* idle */
		/* start new IO */
		ioctx->io_o_off = 0 ;
		ioctx->io_o_state = 1;
		ioctx->io_o_written = 0;
		/* FALLTHRU */
		ct_wire_header(hdr);
	case 1: /* writing header */
		wlen = sizeof(*hdr) - ioctx->io_o_off;
		len = assl_write(c, (uint8_t *)hdr + ioctx->io_o_off, wlen);
		s_errno = errno;
		CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" wlen %d len %ld",
		    (int64_t)c_pid, wlen, (long) len);
		if (len == -1 || len == 0) {
			errno = s_errno;
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_wrcomplete_cb(ioctx->io_cb_arg,
				    NULL, NULL, 0);
			}
			return;
		}

		ioctx->io_write_count++;
		ioctx->io_write_bytes += len;

		ioctx->io_o_off += len;
		if (ioctx->io_o_off == sizeof(*hdr)) {
			ioctx->io_o_off = 0;
			ioctx->io_o_state = 2;
			/* only keep header wired in io_o_state == 1 */
			ct_unwire_header(hdr);
		} else {
			break;
		}

		/* fall thru */
	case 2: /* writing body */
	default:
		if (iob->iovcnt == 0) {
			body = iob->io_data;
			body_len = hdr->c_size;
		} else {
			int idx  = ioctx->io_o_state - 2;
			const struct ct_iovec *iov = iob->io_data;
			body = iov[idx].iov_base;
			body_len = iov[idx].iov_len;
		}
		wlen = body_len - ioctx->io_o_off;
		if (ioctx->io_max_transfer != 0 &&
		    wlen > ioctx->io_max_transfer)
			wlen = ioctx->io_max_transfer;

		if (wlen == 0) {
			len = 0;
			s_errno = 0;
		} else {
			len = assl_write(c, body + ioctx->io_o_off, wlen);
			s_errno = errno;
		}
		CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" wlen1 %d len %ld",
		    (int64_t)c_pid, wlen, (long) len);

		if (len == -1 || (len == 0 && wlen != 0)) {
			errno = s_errno;
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET, "socket disconnected");
				ioctx->io_wrcomplete_cb(ioctx->io_cb_arg,
				    NULL, NULL, 0);
			}
			return;
		}
		ioctx->io_write_count++;
		ioctx->io_write_bytes += len;

		ioctx->io_o_off += len;

		if (ioctx->io_o_off == body_len) {
			/* buffer complete, next buffer or packet */
			ioctx->io_o_written += ioctx->io_o_off;
			ioctx->io_o_off = 0;

			if ((iob->iovcnt == 0) ||
			    (iob->iovcnt == ioctx->io_o_state - 1)) {
				CNDBG(CTUTIL_LOG_SOCKET,
				    "pid %"PRId64" xmit completed %d",
				    (int64_t)c_pid, hdr->c_opcode);

				/* ready for next output packet */
				ioctx->io_o_state = 0;
				write_complete = 1;
			} else  {
				/* send next piece of iov */
				ioctx->io_o_state++;
			}
		}
		break;
		;
	}
	if (write_complete == 1) {
		if (hdr->c_size != ioctx->io_o_written)
			CFATALX("amount of data written does not match %d %d",
			    hdr->c_size, ioctx->io_o_written);

		CT_LOCK(&ioctx->io_lock);
		TAILQ_REMOVE(&ioctx->io_o_q, iob, io_next);
		CT_UNLOCK(&ioctx->io_lock);

		ctxgone = ioctx->io_wrcomplete_cb(ioctx->io_cb_arg, hdr,
		    iob->io_data, iob->iovcnt);

		ioctx->io_ioctx_free(iob);

		CT_LOCK(&ioctx->io_lock);
		if (!ctxgone && (TAILQ_EMPTY(&ioctx->io_o_q) ||
		    (ioctx->io_write_io_enabled == 0))) {
			event_del(ioctx->io_ev_wr);
		}
		CT_UNLOCK(&ioctx->io_lock);
	}
	if (ioctx->io_over_bw_check != NULL)
		ioctx->io_over_bw_check(ioctx->io_cb_arg, ioctx);
	if (write_complete && ioctx->io_disconnecting == 0 &&
	    ioctx->io_write_io_enabled != 0 && !TAILQ_EMPTY(&ioctx->io_o_q))
		goto send_another;
}

void
ct_event_assl_read(evutil_socket_t fd, short events, void *arg)
{
	struct assl_context	*c;
	struct ct_assl_io_ctx	*ioctx = arg;
	struct ct_header	*hdr;
	uint8_t			*body;
	ssize_t			len;
	int			rlen;
	int			s_errno;

	c = ioctx->c;
	hdr = ioctx->io_i_hdr;
	body = ioctx->io_i_data;

	CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" hdr state %d, off %d sz %d",
	    (int64_t)c_pid, ioctx->io_i_state, ioctx->io_i_off,
	    hdr != NULL ? hdr->c_size : -1);

again:
	switch (ioctx->io_i_state) {
	case 0: /* between packets */
		hdr = ioctx->io_header_alloc(ioctx->io_cb_arg);
		ioctx->io_i_hdr = hdr;
		ioctx->io_i_off = 0;
		ioctx->io_i_state = 1;

		/* fallthru */
	case 1: /* reading header */
		if (hdr == NULL)
			CABORTX("NULL header");
		rlen = sizeof(*hdr) - ioctx->io_i_off;
		len = assl_read(c, (uint8_t *)hdr + ioctx->io_i_off, rlen);

		if (len == -1 || len == 0) {
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_rd_cb(ioctx->io_cb_arg, NULL, NULL);
			}
			return;
		}
		ioctx->io_read_count++;
		ioctx->io_read_bytes += len;

		ioctx->io_i_off += len;
		if (ioctx->io_i_off == sizeof(*hdr)) {
			ioctx->io_i_off = 0;
			ioctx->io_i_state = 2;

			ct_unwire_header(hdr);

			if (hdr->c_size != 0)
				body = ioctx->io_body_alloc(ioctx->io_cb_arg,
				    hdr);
			else
				body = NULL;
			ioctx->io_i_data = body;
		} else {
			break;
		}

		/* fall thru */
	case 2: /* reading body */
		if (hdr == NULL)
			CABORTX("NULL header");
		rlen = hdr->c_size - ioctx->io_i_off;
		if (rlen == 0) {
			len = 0;
			s_errno = 0;
		} else {
			len = assl_read(c,  body + ioctx->io_i_off, rlen);
			s_errno = errno;
		}
		CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" op %d, body sz %d "
		    "read %ld, rlen %d off %d", (int64_t)c_pid, hdr->c_opcode,
		    hdr->c_size, (long) len, rlen, ioctx->io_i_off);

		if (len == -1 || (len == 0 && rlen != 0)) {
			errno = s_errno;
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_rd_cb(ioctx->io_cb_arg, NULL, NULL);
			}
			return;
		}

		ioctx->io_read_count++;
		ioctx->io_read_bytes += len;

		ioctx->io_i_off += len;

		if (ioctx->io_i_off == hdr->c_size) {
			/* packet complete */

			ioctx->io_i_state = 0;
			ioctx->io_i_hdr = NULL;
			ioctx->io_i_data = NULL;
			ioctx->io_i_off = 0;

			/*
			 * if this function was a function pointer in ioctx,
			 * this could be a pure library function.
			 */
			ioctx->io_rd_cb(ioctx->io_cb_arg, hdr, body);
		}

		break;
	default:
		CFATALX("invalid io state %d fd %"PRId64, ioctx->io_i_state,
		    (int64_t)fd);
	}
	if (ioctx->io_disconnecting == 0)
		goto again;
}

void
ct_event_io_write(evutil_socket_t fd, short events, void *arg)
{
	struct ct_io_ctx	*ioctx = arg;
	struct ct_header	*hdr;
	uint8_t			*body;
	struct ct_io_queue	*iob;
	ssize_t			len;
	int			body_len;
	int			wlen;
	int			write_complete;
	int			s_errno;
	int			ctxgone;

send_another:
	write_complete = 0;

	CT_LOCK(&ioctx->io_lock);
	iob = TAILQ_FIRST(&ioctx->io_o_q);
	CT_UNLOCK(&ioctx->io_lock);
	hdr = iob->io_hdr;
	/* invalid to not have a header here */
	if (hdr == NULL) 
		CABORTX("NULL header");
	body = NULL;

	CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" hdr op %d state %d, off %d "
	    "sz %d", (int64_t)c_pid, hdr->c_opcode, ioctx->io_o_state,
	    ioctx->io_o_off, hdr->c_size);

	switch (ioctx->io_o_state) {
	case 0: /* idle */
		/* start new IO */
		ioctx->io_o_off = 0 ;
		ioctx->io_o_state = 1;
		ioctx->io_o_written = 0;
		/* FALLTHRU */
	case 1: /* writing header */
		wlen = sizeof(*hdr) - ioctx->io_o_off;
		len = write(fd, (uint8_t *)hdr + ioctx->io_o_off, wlen);
		s_errno = errno;
		CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" wlen %d len %ld",
		    (int64_t)c_pid, wlen, (long) len);

		if (len == -1 || len == 0) {
			errno = s_errno;
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_wrcomplete_cb(ioctx->io_cb_arg,
				    NULL, NULL, 0);
			}
			return;
		}
		ioctx->io_write_count++;
		ioctx->io_write_bytes += len;

		ioctx->io_o_off += len;
		if (ioctx->io_o_off == sizeof(*hdr)) {
			ioctx->io_o_off = 0;
			ioctx->io_o_state = 2;
		} else {
			break;
		}

		/* fall thru */
	case 2: /* writing body */
	default:
write_next_iov:
		if (iob->iovcnt == 0) {
			body = iob->io_data;
			body_len = hdr->c_size;
		} else {
			int idx  = ioctx->io_o_state - 2;
			const struct ct_iovec *iov = iob->io_data;
			body = iov[idx].iov_base;
			body_len = iov[idx].iov_len;
		}
		CNDBG(CTUTIL_LOG_SOCKET, "writing body state %d sz %d count %d",
		    ioctx->io_o_state, body_len, iob->iovcnt);
		wlen = body_len - ioctx->io_o_off;
		if (wlen == 0) {
			len = 0;
			s_errno = 0;
		} else {
			len = write(fd, body + ioctx->io_o_off, wlen);
			s_errno = errno;
		}
		CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" wlen1 %d len %ld",
		    (int64_t)c_pid, wlen, (long) len);

		if (len == -1 || (len == 0 && wlen != 0)) {
			errno = s_errno;
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_wrcomplete_cb(ioctx->io_cb_arg,
				    NULL, NULL, 0);
			}
			return;
		}

		ioctx->io_write_count++;
		ioctx->io_write_bytes += len;

		ioctx->io_o_off += len;

		if (ioctx->io_o_off == body_len) {
			/* buffer complete, next buffer or packet */
			ioctx->io_o_written += ioctx->io_o_off;
			ioctx->io_o_off = 0;

			if ((iob->iovcnt == 0) ||
			    (iob->iovcnt == ioctx->io_o_state - 1)) {
				CNDBG(CTUTIL_LOG_SOCKET,
				    "pid %"PRId64" xmit completed %d",
				    (int64_t)c_pid, hdr->c_opcode);

				/* ready for next output packet */
				ioctx->io_o_state = 0;
				write_complete = 1;
			} else  {
				/* send next piece of iov */
				ioctx->io_o_state++;
				goto write_next_iov;
			}
		}
		break;
		;
	}
	if (write_complete == 1) {
		if (hdr->c_size != ioctx->io_o_written)
			CFATALX("amount of data written does not match %d %d",
			    hdr->c_size, ioctx->io_o_written);

		CT_LOCK(&ioctx->io_lock);
		TAILQ_REMOVE(&ioctx->io_o_q, iob, io_next);
		CT_UNLOCK(&ioctx->io_lock);

		ctxgone = ioctx->io_wrcomplete_cb(ioctx->io_cb_arg, hdr,
		    iob->io_data, iob->iovcnt);

		ioctx->io_ioctx_free(iob);

		CT_LOCK(&ioctx->io_lock);
		if (!ctxgone && TAILQ_EMPTY(&ioctx->io_o_q)) {
			event_del(ioctx->io_ev_wr);
		}
		CT_UNLOCK(&ioctx->io_lock);
	}
	if (write_complete && ioctx->io_disconnecting == 0 &&
	    ioctx->io_write_io_enabled != 0 && !TAILQ_EMPTY(&ioctx->io_o_q))
		goto send_another;
}

void
ct_event_io_read(evutil_socket_t fd, short events, void *arg)
{
	struct ct_io_ctx	*ioctx = arg;
	struct ct_header	*hdr;
	uint8_t			*body;
	ssize_t			len;
	int			rlen;
	int			s_errno;

	hdr = ioctx->io_i_hdr;
	body = ioctx->io_i_data;

	CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" hdr state %d, off %d sz %d",
	    (int64_t)c_pid, ioctx->io_i_state, ioctx->io_i_off,
	    hdr != NULL ? hdr->c_size : -1);

again:
	switch (ioctx->io_i_state) {
	case 0: /* between packets */
		hdr = ioctx->io_header_alloc(ioctx->io_cb_arg);
		ioctx->io_i_hdr = hdr;
		ioctx->io_i_off = 0;
		ioctx->io_i_state = 1;

		/* fallthru */
	case 1: /* reading header */
		if (hdr == NULL)
			CABORTX("NULL header");
		rlen = sizeof(*hdr) - ioctx->io_i_off;
		len = read(fd, (uint8_t *)hdr + ioctx->io_i_off, rlen);

		if (len == -1 || len == 0) {
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_rd_cb(ioctx->io_cb_arg, NULL, NULL);
			}
			return;
		}
		ioctx->io_read_count++;
		ioctx->io_read_bytes += len;

		ioctx->io_i_off += len;
		if (ioctx->io_i_off == sizeof(*hdr)) {
			ioctx->io_i_off = 0;
			ioctx->io_i_state = 2;

			if (hdr->c_size != 0)
				body = ioctx->io_body_alloc(ioctx->io_cb_arg,
				  hdr);
			else
				body = NULL;
			ioctx->io_i_data = body;
		} else {
			break;
		}

		/* fall thru */
	case 2: /* reading body */
		if (hdr == NULL)
			CABORTX("NULL header");
		rlen = hdr->c_size - ioctx->io_i_off;
		if (rlen == 0) {
			len = 0;
			s_errno = 0;
		} else {
			len = read(fd, body + ioctx->io_i_off, rlen);
			s_errno = errno;
		}
		CNDBG(CTUTIL_LOG_SOCKET, "pid %"PRId64" op %d, body sz %d "
		    "read %ld, rlen %d off %d", (int64_t)c_pid, hdr->c_opcode,
		    hdr->c_size, (long) len, rlen, ioctx->io_i_off);

		if (len == -1 || (len == 0 && rlen != 0)) {
			errno = s_errno;
			if (len == 0 || (errno != EINTR && errno != EAGAIN)) {
				/* lost socket */
				CNDBG(CTUTIL_LOG_SOCKET,
					"socket disconnected: %s",
					strerror(errno));
				ioctx->io_rd_cb(ioctx->io_cb_arg, NULL, NULL);
			}
			return;
		}

		ioctx->io_read_count++;
		ioctx->io_read_bytes += len;

		ioctx->io_i_off += len;

		if (ioctx->io_i_off == hdr->c_size) {
			/* packet complete */

			ioctx->io_i_state = 0;
			ioctx->io_i_hdr = NULL;
			ioctx->io_i_data = NULL;
			ioctx->io_i_off = 0;

			/*
			 * if this function was a function pointer in ioctx,
			 * this could be a pure library function.
			 */
			ioctx->io_rd_cb(ioctx->io_cb_arg, hdr, body);
		}

		break;
	default:
		CFATALX("invalid io state %d fd %"PRId64, ioctx->io_i_state,
		    (int64_t)fd);
	}
	if (ioctx->io_disconnecting == 0)
		goto again;
}

void
ct_assl_write_op(struct ct_assl_io_ctx *ioctx, struct ct_header *hdr,
    void *data)
{
	struct ct_io_queue	*iob;
	int			start_write = 0;


	iob = ioctx->io_ioctx_alloc();
	iob->io_hdr = hdr;
	iob->io_data = data;
	iob->iovcnt = 0;

	CT_LOCK(&ioctx->io_lock);
	if (TAILQ_EMPTY(&ioctx->io_o_q) && ioctx->io_write_io_enabled)
		start_write = 1;
	TAILQ_INSERT_TAIL(&ioctx->io_o_q, iob, io_next);
	CT_UNLOCK(&ioctx->io_lock);

	if (start_write) {
		event_add(ioctx->io_ev_wr, NULL);
	}
}

int
ct_assl_writev_op(struct ct_assl_io_ctx *ioctx, struct ct_header *hdr,
    struct ct_iovec *iov, int iovcnt)
{
	struct ct_io_queue	*iob;
	int			start_write = 0;
	int			i, sz;

	if (iovcnt == 0 || iovcnt > IOV_MAX)
		return 1;

	iob = ioctx->io_ioctx_alloc();
	iob->io_hdr = hdr;
	iob->io_data = iov;
	iob->iovcnt = iovcnt;
	sz = 0;
	for (i = 0; i < iovcnt; i++) {
		sz += iov[i].iov_len;
	}
	if (sz != hdr->c_size)
		CFATALX("invalid message length, len != sum iov[*].iov_len");

	CT_LOCK(&ioctx->io_lock);
	if (TAILQ_EMPTY(&ioctx->io_o_q) && ioctx->io_write_io_enabled)
		start_write = 1;

	TAILQ_INSERT_TAIL(&ioctx->io_o_q, iob, io_next);

	if (start_write) {
		event_add(ioctx->io_ev_wr, NULL);
	}
	CT_UNLOCK(&ioctx->io_lock);

	return 0;
}

void
ct_io_write_op(struct ct_io_ctx *ioctx, struct ct_header *hdr, void *data)
{
	struct ct_io_queue	*iob;
	int			start_write = 0;

	iob = ioctx->io_ioctx_alloc();
	iob->io_hdr = hdr;
	iob->io_data = data;
	iob->iovcnt = 0;

	CT_LOCK(&ioctx->io_lock);
	if (TAILQ_EMPTY(&ioctx->io_o_q) && ioctx->io_write_io_enabled)
		start_write = 1;

	TAILQ_INSERT_TAIL(&ioctx->io_o_q, iob, io_next);

	if (start_write) {
		event_add(ioctx->io_ev_wr, NULL);
	}
	CT_UNLOCK(&ioctx->io_lock);
}

int
ct_io_writev_op(struct ct_io_ctx *ioctx, struct ct_header *hdr,
    struct ct_iovec *iov, int iovcnt)
{
	struct ct_io_queue	*iob;
	int			start_write = 0;
	int			i, sz;

	if (iovcnt == 0 || iovcnt > IOV_MAX)
		return 1;

	CNDBG(CTUTIL_LOG_SOCKET, "scheduling iov cnt %d sz %d", iovcnt,
	    hdr->c_size);
	iob = ioctx->io_ioctx_alloc();
	iob->io_hdr = hdr;
	iob->io_data = iov;
	iob->iovcnt = iovcnt;
	sz = 0;
	for (i = 0; i < iovcnt; i++) {
		sz += iov[i].iov_len;
	}
	if (sz != hdr->c_size)
		CFATALX("invalid message length, len != sum iov[*].iov_len");

	CT_LOCK(&ioctx->io_lock);
	if (TAILQ_EMPTY(&ioctx->io_o_q) && ioctx->io_write_io_enabled)
		start_write = 1;
	TAILQ_INSERT_TAIL(&ioctx->io_o_q, iob, io_next);

	if (start_write) {
		event_add(ioctx->io_ev_wr, NULL);
	}
	CT_UNLOCK(&ioctx->io_lock);
	return 0;
}

/*
 * ct_io_connect_fd_pair
 * return value
 *  0 on success
 *  non-zero on failure, errno will show reason that event_add failed
 */
int
ct_io_connect_fd_pair(struct ct_io_ctx *ctx, int infd, int outfd,
    struct event_base *ev_base)
{
	ctx->io_i_fd    = infd;
	ctx->io_o_fd    = outfd;

	ctx->io_ev_rd = event_new(ev_base, infd, EV_READ|EV_PERSIST,
	    ct_event_io_read, ctx);
	if (ctx->io_ev_rd == NULL) {
		return (-1);
	}

	ctx->io_ev_wr = event_new(ev_base, outfd, EV_WRITE|EV_PERSIST,
	    ct_event_io_write, ctx);
	if (ctx->io_ev_wr == NULL) {
		event_free(ctx->io_ev_rd);
		ctx->io_ev_rd = NULL;
		return (-1);
	}

	return event_add(ctx->io_ev_rd, NULL);
}

/*
 * ct_io_disconnect
 *
 * Caller is assumed to free the context, as the ctx is likely
 * part of another structure that needs to be cleaned up and freed.
 * eg the structure containing the ct_io_ctx may be in an RB tree.
 */
void
ct_io_disconnect(struct ct_io_ctx *ioctx)
{
	/* XXX -check state? */
	struct ct_io_queue	*ioq;

	/* In case we are called from one of the callbacks, stop event loop */
	ioctx->io_disconnecting = 1;

	CNDBG(CTUTIL_LOG_SOCKET, "disconnecting");
	if (ioctx->io_ev_rd != NULL) {
		event_free(ioctx->io_ev_rd);
		ioctx->io_ev_rd = NULL;
	}
	if (ioctx->io_ev_wr != NULL) {
		event_free(ioctx->io_ev_wr);
		ioctx->io_ev_wr = NULL;
	}

	close(ioctx->io_i_fd);
	close(ioctx->io_o_fd);

	if (ioctx->io_i_data != NULL)
		ioctx->io_body_free(ioctx->io_cb_arg, ioctx->io_i_data,
		    ioctx->io_i_hdr);

	if (ioctx->io_i_hdr != NULL)
		ioctx->io_header_free(ioctx->io_cb_arg, ioctx->io_i_hdr);

	CT_LOCK(&ioctx->io_lock);
	while (!TAILQ_EMPTY(&ioctx->io_o_q)) {
		ioq = TAILQ_FIRST(&ioctx->io_o_q);
		TAILQ_REMOVE(&ioctx->io_o_q, ioq, io_next);

		CT_UNLOCK(&ioctx->io_lock);
		ioctx->io_wrcomplete_cb(ioctx->io_cb_arg,
		    ioq->io_hdr, ioq->io_data, ioq->iovcnt);

		ioctx->io_ioctx_free(ioq);
		CT_LOCK(&ioctx->io_lock);
	}
	CT_UNLOCK(&ioctx->io_lock);
}

int
ct_assl_connect(struct ct_assl_io_ctx *ctx, const char *host, const char *port,
   struct assl_connect_opts *aco, struct event_base *ev_base)
{
	int	rv;

	if ((rv = assl_connect_opts(ctx->c, host, port, aco)) != 0)
		return (rv);

	ctx->io_ev_rd = event_new(ev_base, assl_fd(ctx->c), EV_READ|EV_PERSIST,
	    ct_event_assl_read, ctx);
	if (ctx->io_ev_rd == NULL) {
		return (-1);
	}

	ctx->io_ev_wr = event_new(ev_base, assl_fd(ctx->c), EV_WRITE|EV_PERSIST,
	    ct_event_assl_write, ctx);
	if (ctx->io_ev_wr == NULL) {
		event_free(ctx->io_ev_rd);
		ctx->io_ev_rd = NULL;
		return (-1);
	}

	return event_add(ctx->io_ev_rd, NULL);
}

/*
 * ct_assl_disconnect
 *
 * Caller is assumed to free the context, as the ctx is likely
 * part of another structure that needs to be cleaned up and freed.
 * eg the structure containing the ct_io_ctx may be in an RB tree.
 */
void
ct_assl_disconnect(struct ct_assl_io_ctx *ioctx)
{
	/* XXX -check state? */
	struct ct_io_queue	*ioq;

	/* In case we are called from one of the callbacks, stop event loop */
	ioctx->io_disconnecting = 1;

	if (ioctx->io_ev_rd != NULL) {
		event_free(ioctx->io_ev_rd);
		ioctx->io_ev_rd = NULL;
	}
	if (ioctx->io_ev_wr != NULL) {
		event_free(ioctx->io_ev_wr);
		ioctx->io_ev_wr = NULL;
	}
	assl_close(ioctx->c);

	if (ioctx->io_i_data != NULL)
		ioctx->io_body_free(ioctx->io_cb_arg, ioctx->io_i_data,
		    ioctx->io_i_hdr);

	if (ioctx->io_i_hdr != NULL)
		ioctx->io_header_free(ioctx->io_cb_arg, ioctx->io_i_hdr);

	if (ioctx->io_o_state == 1) {
		/* closed while writing header,
		 * thus header is currently wired
		 */
		ioq = TAILQ_FIRST(&ioctx->io_o_q);
		if (ioq != NULL)
			ct_unwire_header(ioq->io_hdr);
	}

	CT_LOCK(&ioctx->io_lock);
	while (!TAILQ_EMPTY(&ioctx->io_o_q)) {
		ioq = TAILQ_FIRST(&ioctx->io_o_q);
		TAILQ_REMOVE(&ioctx->io_o_q, ioq, io_next);

		CT_UNLOCK(&ioctx->io_lock);
		ioctx->io_wrcomplete_cb(ioctx->io_cb_arg,
		    ioq->io_hdr, ioq->io_data, ioq->iovcnt);

		ioctx->io_ioctx_free(ioq);
		CT_LOCK(&ioctx->io_lock);
	}
	CT_UNLOCK(&ioctx->io_lock);
}

void
ct_assl_io_ctx_set_maxtrans(struct ct_assl_io_ctx *ctx, size_t newmax)
{
	CNDBG(CTUTIL_LOG_SOCKET, "setting max to %lu", (unsigned long) newmax);
	ctx->io_max_transfer = newmax;
}

void
ct_assl_io_ctx_set_over_bw_func(struct ct_assl_io_ctx *ctx,
    ct_assl_io_over_bw_check_func *func)
{
	ctx->io_over_bw_check = func;
}

void
ct_assl_io_ctx_init(struct ct_assl_io_ctx *ctx, struct assl_context *c,
    msgdeliver_ty *rd_cb, msgcomplete_ty *wrcomplete_cb, void *cb_arg,
    ct_header_alloc_func *io_header_alloc, ct_header_free_func *io_header_free,
    ct_body_alloc_func *io_body_alloc, ct_body_free_func *io_body_free,
    ct_ioctx_alloc_func *io_ioctx_alloc, ct_ioctx_free_func *io_ioctx_free)
{
	ctx->c = c;
	ctx->io_rd_cb = rd_cb;
	ctx->io_wrcomplete_cb = wrcomplete_cb;
	ctx->io_cb_arg = cb_arg;

	TAILQ_INIT(&ctx->io_o_q);
	CT_LOCK_INIT(&ctx->io_lock);
	ctx->io_i_hdr   = NULL;
	ctx->io_i_data  = NULL;
	ctx->io_i_state = ctx->io_o_state = 0;
	ctx->io_i_resid = ctx->io_o_resid = 0;
	ctx->io_i_off   = ctx->io_o_off   = 0;
	ctx->io_header_alloc = io_header_alloc;
	ctx->io_header_free = io_header_free;
	ctx->io_body_alloc = io_body_alloc;
	ctx->io_body_free = io_body_free;
	ctx->io_ioctx_alloc = io_ioctx_alloc;
	ctx->io_ioctx_free = io_ioctx_free;
	ctx->io_max_transfer = 0; /* 0 means no limit */

	ctx->io_write_io_enabled = 1;
}


void
ct_io_ctx_init(struct ct_io_ctx *ctx, msgdeliver_ty *rd_cb,
    msgcomplete_ty *wrcomplete_cb, void *cb_arg,
    ct_header_alloc_func *io_header_alloc, ct_header_free_func *io_header_free,
    ct_body_alloc_func *io_body_alloc, ct_body_free_func *io_body_free)
{
	ctx->io_rd_cb = rd_cb;
	ctx->io_wrcomplete_cb = wrcomplete_cb;
	ctx->io_cb_arg = cb_arg;

	TAILQ_INIT(&ctx->io_o_q);
	CT_LOCK_INIT(&ctx->io_lock);
	ctx->io_i_hdr   = NULL;
	ctx->io_i_data  = NULL;
	ctx->io_i_state = ctx->io_o_state = 0;
	ctx->io_i_resid = ctx->io_o_resid = 0;
	ctx->io_i_off   = ctx->io_o_off   = 0;
	ctx->io_header_alloc = io_header_alloc;
	ctx->io_header_free = io_header_free;
	ctx->io_body_alloc = io_body_alloc;
	ctx->io_body_free =io_body_free;

	ctx->io_write_io_enabled = 1;

	ctx->io_i_fd    = -1;
	ctx->io_o_fd    = -1;
}

void
ct_assl_io_block_writes(struct ct_assl_io_ctx *ctx)
{
	ctx->io_write_io_enabled = 0;
}

void
ct_assl_io_resume_writes(struct ct_assl_io_ctx *ctx)
{
	ctx->io_write_io_enabled = 1;
	if (!TAILQ_EMPTY(&ctx->io_o_q))
		event_add(ctx->io_ev_wr, NULL);
}

void
ct_io_block_writes(struct ct_io_ctx *ctx)
{
	ctx->io_write_io_enabled = 0;
}

void
ct_io_resume_writes(struct ct_io_ctx *ctx)
{
	ctx->io_write_io_enabled = 1;
	if (!TAILQ_EMPTY(&ctx->io_o_q))
		event_add(ctx->io_ev_wr, NULL);
}



size_t
ct_assl_io_write_poll(struct ct_assl_io_ctx *assl_io_ctx, void *vbuf,
    size_t len, int timeout)
{
	uint8_t			*buf;
	struct assl_context	*c;
	size_t			off;
	size_t			wlen;
	ssize_t			slen;

	c = assl_io_ctx->c;
	buf = vbuf;
	off = 0;
	wlen = len;

	while (wlen != 0) {
		slen = assl_write(c, buf + off, wlen);
		if (slen == -1) {
			usleep(100);
			continue;
		} else if (slen == 0) {
			return off;
		}

		off += slen;
		wlen -= slen;
	}
	return off;
}

size_t
ct_assl_io_read_poll(struct ct_assl_io_ctx *assl_io_ctx, void *vbuf, size_t len, int timeout)
{
	uint8_t			*buf;
	struct assl_context	*c;
	size_t			off;
	size_t			rlen;
	ssize_t			slen;

	c = assl_io_ctx->c;
	buf = vbuf;
	off = 0;
	rlen = len;

	while (rlen != 0) {
		slen = assl_read(c, buf + off, rlen);
		if (slen == -1) {
			usleep(100);
			continue;
		} else if (slen == 0) {
			return off;
		}

		off += slen;
		rlen -= slen;
	}
	return off;
}
