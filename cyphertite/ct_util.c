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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#ifndef NO_UTIL_H
#include <util.h>
#endif


#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>
#include <ctype.h>
#include <errno.h>

#include <clog.h>
#include <assl.h>
#include <exude.h>
#include <xmlsd.h>
#include <sqlite3.h>

#include "ct.h"
#include "ct_socket.h"
#include "ct_db.h"

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

/* assl pipe */
struct ct_assl_io_ctx	*ct_assl_ctx;
int			 ct_skip_xml_negotiate;

struct ct_io_queue	*ct_ioctx_alloc(void);
void			ct_ioctx_free(struct ct_io_queue *);
void			ct_print_scaled_stat(FILE *, const char *, int64_t,
			    int64_t, int);
int			ct_validate_xml_negotiate_xml(struct ct_global_state *,
			    struct ct_header *, char *);
char			*ct_getloginbyuid(uid_t);

struct ct_op *
ct_add_operation(struct ct_global_state *state, ct_op_cb *start,
    ct_op_cb *complete, void *args)
{
	struct ct_op	*op;

	op = e_calloc(1, sizeof(*op));
	op->op_start = start;
	op->op_complete = complete;
	op->op_args = args;

	TAILQ_INSERT_TAIL(&state->ct_operations, op, op_link);

	return (op);
}

struct ct_op *
ct_add_operation_after(struct ct_global_state *state, struct ct_op *after,
    ct_op_cb *start, ct_op_cb *complete, void *args)
{
	struct ct_op	*op;

	op = e_calloc(1, sizeof(*op));
	op->op_start = start;
	op->op_complete = complete;
	op->op_args = args;

	TAILQ_INSERT_AFTER(&state->ct_operations, after, op, op_link);

	return (op);
}

/* Do a complete ct operation from start to finish */
void
ct_do_operation(ct_op_cb *start, ct_op_cb *complete, void *args,
    int need_secrets, int only_metadata)
{
	struct ct_global_state	*state;
	int		 	 ret;

	ct_prompt_for_login_password();

	state = ct_init(1, need_secrets, only_metadata);
	ct_add_operation(state, start, complete, args);
	ct_wakeup_file();
	if ((ret = ct_event_dispatch()) != 0)
		CWARN("event_dispatch returned failure");
	ct_cleanup(state);
}

void
ct_nextop(void *vctx)
{
	struct ct_global_state	*state = vctx;
	struct ct_op		*op;

	op = TAILQ_FIRST(&state->ct_operations);
	if (op == NULL)
		CFATALX("no operation in queue");

	op->op_start(state, op);
}

int
ct_op_complete(struct ct_global_state *state)
{
	struct ct_op *op;

	op = TAILQ_FIRST(&state->ct_operations);
	if (op == NULL)
		CFATALX("no operation in queue");

	if (op->op_complete)
		op->op_complete(state, op);

	TAILQ_REMOVE(&state->ct_operations, op, op_link);
	e_free(&op);

	if (TAILQ_EMPTY(&state->ct_operations))
		return (1);

	/* set up for the next loop */
	ct_set_file_state(state, CT_S_STARTING);
	ct_wakeup_file();
	return (0);
}

void
ct_load_certs(struct assl_context *c)
{
	if (ct_cert == NULL)
		CFATALX("no cert provided in config");
	if (ct_ca_cert == NULL)
		CFATALX("no ca_cert provided in config");
	if (ct_key == NULL)
		CFATALX("no key provided in config");

	if (assl_load_file_certs(c, ct_ca_cert, ct_cert, ct_key))
		assl_fatalx("Failed to load certs. Ensure that "
		    "the ca_cert, cert and key are set to valid paths in %s",
		    ct_configfile);
}


struct ct_assl_io_ctx    *ct_ssl_ctx;

struct ct_assl_io_ctx *
ct_ssl_connect(struct ct_global_state *state, int nonfatal)
{
	struct assl_context *c;

	ct_ssl_ctx = e_calloc(1, sizeof (*ct_ssl_ctx));

	c = assl_alloc_context(ASSL_M_TLSV1_CLIENT, 0);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");

	ct_load_certs(c);

	ct_assl_io_ctx_init(ct_ssl_ctx, c, ct_handle_msg, ct_write_done,
	    state, ct_header_alloc, ct_header_free, ct_body_alloc,
	    ct_body_free, ct_ioctx_alloc, ct_ioctx_free);

	if (assl_event_connect(c, ct_host, ct_hostport,
		ASSL_F_NONBLOCK|ASSL_F_KEEPALIVE|ASSL_F_THROUGHPUT,
	    ct_evt_base, ct_event_assl_read, ct_event_assl_write, ct_ssl_ctx)) {
		if (nonfatal) {
			/* XXX */
			ct_assl_disconnect(ct_ssl_ctx);
			e_free(&ct_ssl_ctx);
		} else
			assl_fatalx("server connect failed");
	}
	if (ct_io_bw_limit && ct_ssl_ctx != NULL)
		ct_ssl_init_bw_lim(ct_ssl_ctx);

	return ct_ssl_ctx;
}

void
ct_ssl_cleanup(void)
{
	if (ct_ssl_ctx != NULL) {
		ct_assl_disconnect(ct_assl_ctx);
		e_free(&ct_ssl_ctx);
		ct_ssl_ctx = NULL;
	}
}

struct ct_io_queue *
ct_ioctx_alloc(void)
{
	struct ct_io_queue *ioq;
	ioq = e_calloc(1, sizeof(*ioq));
	return ioq;
}

void
ct_ioctx_free(struct ct_io_queue *ioq)
{
	e_free(&ioq);
}


struct ct_header *
ct_header_alloc(void *vctx)
{
	struct ct_header *hdr;
	hdr = e_calloc(1, sizeof(*hdr));
	return hdr;
}

void
ct_header_free(void *vctx, struct ct_header *hdr)
{
	e_free(&hdr);
}

#define ASSL_TIMEOUT 20
int
ct_assl_negotiate_poll(struct ct_global_state *state,
    struct ct_assl_io_ctx *asslctx)
{
	struct xmlsd_element		*xe;
	struct xmlsd_element_list	 xl;
	char				 b64_digest[128];
	uint8_t				 pwd_digest[SHA512_DIGEST_LENGTH];
	char				 *body;
	struct ct_header		 hdr;
	size_t				 orig_size;
	ssize_t				 sz;
	int				 rv = 1;
	int				 user_len, payload_sz;
	uint8_t				 buf[20];

	/* send server request */
	hdr.c_version = C_HDR_VERSION;
	hdr.c_opcode = C_HDR_O_NEG;
	hdr.c_tag = ct_max_trans;			/* XXX - fix */
	hdr.c_size = ct_max_block_size;			/* XXX - fix */
	hdr.c_size = 8;
	buf[0] = (ct_max_trans >>  0) & 0xff;
	buf[1] = (ct_max_trans >>  8) & 0xff;
	buf[2] = (ct_max_trans >> 16) & 0xff;
	buf[3] = (ct_max_trans >> 24) & 0xff;
	buf[4] = (ct_max_block_size >>  0) & 0xff;
	buf[5] = (ct_max_block_size >>  8) & 0xff;
	buf[6] = (ct_max_block_size >> 16) & 0xff;
	buf[7] = (ct_max_block_size >> 24) & 0xff;
	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(asslctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("could not write header");
		goto done;
	}
	if (ct_assl_io_write_poll(asslctx, buf, 8,  ASSL_TIMEOUT) != 8) {
		CWARNX("could not write body");
		goto done;
	}

	/* get server reply */
	sz = ct_assl_io_read_poll(asslctx, &hdr, sizeof hdr, ASSL_TIMEOUT);
	if (sz != sizeof hdr) {
		CWARNX("invalid header size %ld", (long) sz);
		goto done;
	}
	ct_unwire_header(&hdr);

	if (hdr.c_version == C_HDR_VERSION &&
	    hdr.c_opcode == C_HDR_O_NEG_REPLY) {
		if (hdr.c_size == 8) {
			if (ct_assl_io_read_poll(asslctx, buf, hdr.c_size,
			    ASSL_TIMEOUT) != hdr.c_size) {
				CWARNX("couldn't read neg parameters");
				goto done;
			}
			ct_max_trans = buf[0] | (buf[1] << 8) |
			    (buf[2] << 16) | (buf[3] << 24);
			ct_max_block_size = buf[4] | (buf[5] << 8) |
			    (buf[6] << 16) | (buf[7] << 24);
		} else {
			ct_max_trans =
			    MIN(hdr.c_tag, ct_max_trans);
			ct_max_block_size =
			    MIN(hdr.c_size, ct_max_block_size);
		}
	} else {
		CWARNX("invalid server reply");
		goto done;
	}

	CNDBG(CT_LOG_NET, "negotiated queue depth: %u max chunk size: %u",
	    ct_max_trans, ct_max_block_size);

	ct_sha512((uint8_t *)ct_password, pwd_digest, strlen(ct_password));
	if (ct_base64_encode(CT_B64_ENCODE, pwd_digest, sizeof pwd_digest,
	    (uint8_t *)b64_digest, sizeof b64_digest)) {
		CWARNX("can't base64 encode password");
		goto done;
	}

	user_len = strlen(ct_username);
	payload_sz = user_len + 1 + strlen(b64_digest) + 1;

	body = e_calloc(1, payload_sz);

	strlcpy(body, ct_username, payload_sz);
	strlcpy(body + user_len + 1, b64_digest,
	    payload_sz - user_len - 1);

	/* login in polled mode */
	bzero (&hdr, sizeof hdr);
	hdr.c_version = C_HDR_VERSION;
	hdr.c_opcode = C_HDR_O_LOGIN;
	hdr.c_tag = 1;
	hdr.c_size = payload_sz;
	hdr.c_flags = ct_compress_enabled;

	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(asslctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("could not write header");
		goto done;
	}
	if (ct_assl_io_write_poll(asslctx, body, payload_sz,  ASSL_TIMEOUT)
	    != payload_sz) {
		CWARNX("could not write body");
		goto done;
	}

	/* get server reply */
	sz = ct_assl_io_read_poll(asslctx, &hdr, sizeof hdr, ASSL_TIMEOUT);
	if (sz != sizeof hdr) {
		CWARNX("invalid header size %ld", (long) sz);
		goto done;
	}
	e_free(&body);
	ct_unwire_header(&hdr);

	if (hdr.c_version == C_HDR_VERSION &&
	    hdr.c_opcode == C_HDR_O_LOGIN_REPLY) {
		if (hdr.c_status != C_HDR_S_OK) {
			CFATALX("login failed: %s", ct_header_strerror(&hdr));
		}
	} else {
		CWARNX("login: invalid server reply");
		goto done;
	}

	if (ct_skip_xml_negotiate)
		goto out;

	/* XML negotiation */
	hdr.c_version = C_HDR_VERSION;
	hdr.c_opcode = C_HDR_O_XML;
	hdr.c_tag = 0;

	xe = xmlsd_create(&xl, "ct_negotiate");
	xe = xmlsd_add_element(&xl, xe, "clientdbgenid");
	xmlsd_set_attr_int32(xe, "value",
	    ctdb_get_genid(state->ct_db_state));

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &orig_size, 1);
	hdr.c_size = payload_sz = orig_size;

	ct_wire_header(&hdr);
	if (ct_assl_io_write_poll(ct_assl_ctx, &hdr, sizeof hdr, ASSL_TIMEOUT)
	    != sizeof hdr) {
		CWARNX("could not write header");
		goto done;
	}
	if (ct_assl_io_write_poll(ct_assl_ctx, body, payload_sz,  ASSL_TIMEOUT)
	    != payload_sz) {
		CWARNX("could not write body");
		goto done;
	}
	e_free(&body);

	/* get server reply */
	sz = ct_assl_io_read_poll(ct_assl_ctx, &hdr, sizeof hdr, ASSL_TIMEOUT);
	if (sz != sizeof hdr) {
		CWARNX("invalid header size %" PRId64, (int64_t)sz);
		goto done;
	}
	ct_unwire_header(&hdr);

	if (hdr.c_size == 0) {
		goto done;
	}
	/* get server reply body */
	body = e_calloc(1, hdr.c_size);
	sz = ct_assl_io_read_poll(ct_assl_ctx, body, hdr.c_size, ASSL_TIMEOUT);
	if (sz != hdr.c_size) {
		CWARNX("invalid xml body size %"PRId64" %d", (int64_t)sz,
		    hdr.c_size);
		goto done;
	}
	/* XXX check xml data */
	if (ct_validate_xml_negotiate_xml(state, &hdr, body)) {
		e_free(&body);
		goto done;
	}

	e_free(&body);

out:
	CNDBG(CT_LOG_NET, "login successful");
	rv = 0;
done:
	return (rv);
}
int
ct_validate_xml_negotiate_xml(struct ct_global_state *state,
    struct ct_header *hdr, char *xml_body)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element	*xe;
	char			*attrval;
	const char		*err;
	int			attrval_i = -1;
	int			r, rv = -1;

	TAILQ_INIT(&xl);

	r = xmlsd_parse_mem(xml_body, hdr->c_size - 1, &xl);
	if (r != XMLSD_ERR_SUCCES) {
		CNDBG(CT_LOG_NET, "xml reply '[%s]'", xml_body ? xml_body :
		    "<NULL>");
		CWARN("XML parse fail on XML negotiate");
		goto done;
	}

	/*
	 * XXX - do we want to validate the results?
	 * - other than validating it parses correctly, seems that
	 *   additional validation would just complicate future
	 *   client-server communication.
	 * - because of this assumption, any non-recognised
	 *   elements must be ignored.
	 */

	xe = TAILQ_FIRST(&xl);
	if (strcmp (xe->name, "ct_negotiate_reply") != 0) {
		CWARNX("Invalid xml reply type %s, [%s]", xe->name, xml_body);
		goto done;
	}

	TAILQ_FOREACH(xe, &xl, entry) {
		if (strcmp (xe->name, "clientdbgenid") == 0) {
			attrval = xmlsd_get_attr(xe, "value");
			err = NULL;
			attrval_i = strtonum(attrval, -1, INT_MAX, &err);
			if (err) {
				CWARNX("unable to parse clientdbgenid [%s]",
				    attrval);
				goto done;
			}
			CNDBG(CT_LOG_NET, "got cliendbgenid value %d",
			    attrval_i);
			break;
		}
	}

	if (attrval_i != -1 && attrval_i !=
	    ctdb_get_genid(state->ct_db_state)) {
		CNDBG(CT_LOG_DB, "need to recreate localdb");
		ctdb_reopendb(state->ct_db_state, attrval_i);
	}


	xmlsd_unwind(&xl);
	rv = 0;
done:
	return rv; /* success */
}

void
ct_shutdown_op(struct ct_global_state *state, struct ct_op *unused)
{
	ct_shutdown(state);
}

void
ct_shutdown(struct ct_global_state *state)
{
	ctdb_shutdown(state->ct_db_state);
	state->ct_db_state = NULL;
	ct_ssl_cleanup_bw_lim();
	ct_event_loopbreak();
}

void print_time_scaled(FILE *, char *s, struct timeval *t);
void
print_time_scaled(FILE *outfh, char *s, struct timeval *t)
{
	int			f = 3;
	double			te;
	char			*scale = "us";

	te = ((double)t->tv_sec * 1000000) + t->tv_usec;
	if (te > 1000) {
		te /= 1000;
		scale = "ms";
	}
	if (te > 1000) {
		te /= 1000;
		scale = "s";
	}

	fprintf(outfh, "%s%12.*f%-2s\n", s, f, te, scale);
}

void
ct_print_scaled_stat(FILE *outfh, const char *label, int64_t val,
    int64_t sec, int newline)
{
	char rslt[FMT_SCALED_STRSIZE];

	fprintf(outfh, "%s%12" PRId64, label, val);
	if (val == 0 || sec == 0) {
		if (newline)
			fprintf(outfh, "\n");
		return;
	}

	bzero(rslt, sizeof(rslt));
	rslt[0] = '?';

	fmt_scaled(val / sec, rslt);
	fprintf(outfh, "\t(%s/sec)%s", rslt, newline ? "\n": "");
}

void
ct_dump_stats(FILE *outfh)
{
	struct timeval time_end, scan_delta, time_delta;
	int64_t sec;
	int64_t val;
	char *sign;
	uint64_t sent, total;

	gettimeofday(&time_end, NULL);

	timersub(&time_end, &ct_stats->st_time_start, &time_delta);
	sec = (int64_t)time_delta.tv_sec;
	timersub(&ct_stats->st_time_scan_end, &ct_stats->st_time_start,
		    &scan_delta);

	if (ct_action == CT_A_ARCHIVE) {
		fprintf(outfh, "Files scanned\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_files_scanned);

		ct_print_scaled_stat(outfh, "Total bytes\t\t\t",
		    (int64_t)ct_stats->st_bytes_tot, sec, 1);
	}

	if (ct_action == CT_A_ARCHIVE &&
	    ct_stats->st_bytes_tot != ct_stats->st_bytes_read)
		ct_print_scaled_stat(outfh, "Bytes read\t\t\t",
		    (int64_t)ct_stats->st_bytes_read, sec, 1);

	if (ct_action == CT_A_EXTRACT)
		ct_print_scaled_stat(outfh, "Bytes written\t\t\t",
		    (int64_t)ct_stats->st_bytes_written, sec, 1);

	if (ct_action == CT_A_ARCHIVE) {
		ct_print_scaled_stat(outfh, "Bytes compressed\t\t",
		    (int64_t)ct_stats->st_bytes_compressed, sec, 0);
		fprintf(outfh, "\t(%" PRId64 "%%)\n",
		    (ct_stats->st_bytes_uncompressed == 0) ? (int64_t)0 :
		    (int64_t)(ct_stats->st_bytes_compressed * 100 /
		    ct_stats->st_bytes_uncompressed));

		fprintf(outfh,
		    "Bytes exists\t\t\t%12" PRIu64 "\t(%" PRId64 "%%)\n",
		    ct_stats->st_bytes_exists,
		    (ct_stats->st_bytes_exists == 0) ? (int64_t)0 :
		    (int64_t)(ct_stats->st_bytes_exists * 100 /
		    ct_stats->st_bytes_tot));

		fprintf(outfh, "Bytes sent\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_bytes_sent);

		sign = " ";
		if (ct_stats->st_bytes_tot != 0) {
			total = ct_stats->st_bytes_tot;
			sent = ct_stats->st_bytes_sent;

			if (sent <= total) {
				val = 100 * (total - sent) / total;
			} else {
				val = 100 * (sent - total) / sent;
				if (val != 0)
					sign = "-";
			}
		} else
			val = 0;
		fprintf(outfh, "Reduction ratio\t\t\t\t%s%" PRId64 "%%\n",
		    sign, val);
	}
	print_time_scaled(outfh, "Total Time\t\t\t    ",  &time_delta);

	if (ct_verbose > 2) {
		fprintf(outfh, "Total chunks\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_chunks_tot);
		fprintf(outfh, "Bytes crypted\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_bytes_crypted);

		fprintf(outfh, "Bytes sha\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_bytes_sha);
		fprintf(outfh, "Bytes crypt\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_bytes_crypt);
		fprintf(outfh, "Bytes csha\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_bytes_csha);
		fprintf(outfh, "Chunks completed\t\t%12" PRIu64 "\n",
		    ct_stats->st_chunks_completed);
		fprintf(outfh, "Files completed\t\t\t%12" PRIu64 "\n",
		    ct_stats->st_files_completed);

		if (ct_action == CT_A_ARCHIVE)
			print_time_scaled(outfh, "Scan Time\t\t\t    ",
			    &scan_delta);
		ct_display_assl_stats(outfh);
	}
}

void
ct_display_assl_stats(FILE *outfh)
{
	if (ct_assl_ctx == NULL)
		return;

	fprintf(outfh, "ssl bytes written %" PRIu64 "\n",
	    ct_assl_ctx->io_write_bytes);
	fprintf(outfh, "ssl writes        %" PRIu64 "\n",
	    ct_assl_ctx->io_write_count);
	fprintf(outfh, "avg write len     %" PRIu64 "\n",
	    ct_assl_ctx->io_write_count == 0 ?  (int64_t)0 :
	    ct_assl_ctx->io_write_bytes / ct_assl_ctx->io_write_count);
	fprintf(outfh, "ssl bytes read    %" PRIu64 "\n",
	    ct_assl_ctx->io_read_bytes);
	fprintf(outfh, "ssl reads         %" PRIu64 "\n",
	    ct_assl_ctx->io_read_count);
	fprintf(outfh, "avg read len      %" PRIu64 "\n",
	    ct_assl_ctx->io_read_count == 0 ?  (int64_t)0 :
	    ct_assl_ctx->io_read_bytes / ct_assl_ctx->io_read_count);
}

void
ct_pr_fmt_file(struct fnode *fnode)
{
	char *loginname;
	struct group *group;
	char *link_ty;
	char filemode[11];
	char uid[11];
	char gid[11];
	time_t ltime;
	char lctime[26];
	char *pchr;

	if (ct_verbose > 1) {
		switch(fnode->fl_type & C_TY_MASK) {
		case C_TY_DIR:
			filemode[0] = 'd'; break;
		case C_TY_CHR:
			filemode[0] = 'c'; break;
		case C_TY_BLK:
			filemode[0] = 'b'; break;
		case C_TY_REG:
			filemode[0] = '-'; break;
		case C_TY_FIFO:
			filemode[0] = 'f'; break;
		case C_TY_LINK:
			filemode[0] = 'l'; break;
		case C_TY_SOCK:
			filemode[0] = 's'; break;
		default:
			filemode[0] = '?';
		}
		filemode[1] = (fnode->fl_mode & 0400) ? 'r' : '-';
		filemode[2] = (fnode->fl_mode & 0100) ? 'w' : '-';
		filemode[3] = (fnode->fl_mode & 0200) ? 'x' : '-';
		filemode[4] = (fnode->fl_mode & 0040) ? 'r' : '-';
		filemode[5] = (fnode->fl_mode & 0020) ? 'w' : '-';
		filemode[6] = (fnode->fl_mode & 0010) ? 'x' : '-';
		filemode[7] = (fnode->fl_mode & 0004) ? 'r' : '-';
		filemode[8] = (fnode->fl_mode & 0002) ? 'w' : '-';
		filemode[9] = (fnode->fl_mode & 0001) ? 'x' : '-';
		filemode[10] = '\0';

		loginname = ct_getloginbyuid(fnode->fl_uid);
		if (loginname && (strlen(loginname) < sizeof(uid)))
			snprintf(uid, sizeof(uid), "%10s", loginname);
		else
			snprintf(uid, sizeof(uid), "%-10d", fnode->fl_uid);
		group = getgrgid(fnode->fl_gid);
		if (group && (strlen(group->gr_name) < sizeof(gid)))
			snprintf(gid, sizeof(gid), "%10s", group->gr_name);
		else
			snprintf(gid, sizeof(gid), "%-10d", fnode->fl_gid);
		ltime = fnode->fl_mtime;
		ctime_r(&ltime, lctime);
		pchr = strchr(lctime, '\n');
		if (pchr != NULL)
			*pchr = '\0'; /* stupid newline on ctime */

		printf("%s %s %s %s ", filemode, uid, gid, lctime);
	}
	printf("%s", fnode->fl_sname);

	if (ct_verbose > 1) {

		/* XXX - translate to guid name */
		if (C_ISLINK(fnode->fl_type))  {
			if (fnode->fl_hardlink)  {
				link_ty = "==";
			} else {
				link_ty = "->";
			}
			printf(" %s %s", link_ty, fnode->fl_hlname);
		} else if (C_ISREG(fnode->fl_type)) {
			if (ct_verbose > 1) {
			}
		}
	}
}

#include "ct_fb.h"
/*
 * 99% stolen from ct_pr_fmt_file, should amalgamate
 */
void
ct_fb_print_entry(char *name, struct ct_fb_key *key, int verbose)
{
	char *loginname;
	struct group *group;
	char *link_ty;
	char filemode[11];
	char uid[11];
	char gid[11];
	time_t ltime;
	char lctime[26];
	char *pchr;

	if (verbose > 1) {
		switch(key->cfb_type & C_TY_MASK) {
		case C_TY_DIR:
			filemode[0] = 'd'; break;
		case C_TY_CHR:
			filemode[0] = 'c'; break;
		case C_TY_BLK:
			filemode[0] = 'b'; break;
		case C_TY_REG:
			filemode[0] = '-'; break;
		case C_TY_FIFO:
			filemode[0] = 'f'; break;
		case C_TY_LINK:
			filemode[0] = 'l'; break;
		case C_TY_SOCK:
			filemode[0] = 's'; break;
		default:
			filemode[0] = '?';
		}
		filemode[1] = (key->cfb_mode & 0400) ? 'r' : '-';
		filemode[2] = (key->cfb_mode & 0100) ? 'w' : '-';
		filemode[3] = (key->cfb_mode & 0200) ? 'x' : '-';
		filemode[4] = (key->cfb_mode & 0040) ? 'r' : '-';
		filemode[5] = (key->cfb_mode & 0020) ? 'w' : '-';
		filemode[6] = (key->cfb_mode & 0010) ? 'x' : '-';
		filemode[7] = (key->cfb_mode & 0004) ? 'r' : '-';
		filemode[8] = (key->cfb_mode & 0002) ? 'w' : '-';
		filemode[9] = (key->cfb_mode & 0001) ? 'x' : '-';
		filemode[10] = '\0';

		loginname = ct_getloginbyuid(key->cfb_uid);
		if (loginname && (strlen(loginname) < sizeof(uid)))
			snprintf(uid, sizeof(uid), "%10s", loginname);
		else
			snprintf(uid, sizeof(uid), "%-10d", key->cfb_uid);
		group = getgrgid(key->cfb_gid);


		if (group && (strlen(group->gr_name) < sizeof(gid)))
			snprintf(gid, sizeof(gid), "%10s", group->gr_name);
		else
			snprintf(gid, sizeof(gid), "%-10d", key->cfb_gid);
		ltime = key->cfb_mtime;
		ctime_r(&ltime, lctime);
		pchr = strchr(lctime, '\n');
		if (pchr != NULL)
			*pchr = '\0'; /* stupid newline on ctime */

		printf("%s %s %s %s ", filemode, uid, gid, lctime);
	}
	printf("%s", name);

	if (verbose > 1) {

		/* XXX - translate to guid name */
		if (C_ISLINK(key->cfb_type))  {
			struct ct_fb_link *lnk = (struct ct_fb_link *)key;

			if (lnk->cfb_hardlink)  {
				link_ty = "==";
			} else {
				link_ty = "->";
			}
			printf(" %s %s", link_ty, lnk->cfb_linkname);
		} else if (C_ISREG(key->cfb_type)) {
			if (verbose > 1) {
			}
		}
	}
}

struct ct_login_cache {
	RB_ENTRY(ct_login_cache)	 lc_next;
	uid_t				 lc_uid;
	char				*lc_name;
};


int ct_cmp_logincache(struct ct_login_cache *, struct ct_login_cache *);

RB_HEAD(ct_login_cache_tree, ct_login_cache) ct_login_cache =
     RB_INITIALIZER(&login_cache);

#define MAX_LC_CACHE_SIZE 100
int ct_login_cache_size;

RB_PROTOTYPE(ct_login_cache_tree, ct_login_cache, lc_next, ct_cmp_logincache);
RB_GENERATE(ct_login_cache_tree, ct_login_cache, lc_next, ct_cmp_logincache);

void
ct_cleanup_login_cache(void)
{
	struct ct_login_cache *tmp;

	while ((tmp = RB_ROOT(&ct_login_cache)) != NULL) {
		RB_REMOVE(ct_login_cache_tree, &ct_login_cache, tmp);
		e_free(&tmp->lc_name);
		e_free(&tmp);
	}
	ct_login_cache_size  = 0;
}

char *
ct_getloginbyuid(uid_t uid)
{
	struct passwd *passwd;
	struct ct_login_cache *entry, search;

	search.lc_uid = uid;

	entry = RB_FIND(ct_login_cache_tree, &ct_login_cache, &search);

	if (entry != NULL) {
		return entry->lc_name;
	}

	/* if the cache gets too big, dump all entries and refill. */
	if (ct_login_cache_size > MAX_LC_CACHE_SIZE) {
		ct_cleanup_login_cache();
	}

	/* yes, this even caches negative entries */
	ct_login_cache_size++;

	entry = e_calloc(1, sizeof(*entry));
	entry->lc_uid = uid;

	passwd = getpwuid(uid);
	if (passwd)
		entry->lc_name = e_strdup(passwd->pw_name);
	else
		entry->lc_name = NULL; /* entry not found cache NULL */

	RB_INSERT(ct_login_cache_tree, &ct_login_cache, entry);

	return entry->lc_name;
}

int
ct_cmp_logincache(struct ct_login_cache *f1, struct ct_login_cache *f2)
{
	return ((f1->lc_uid < f2->lc_uid) ? -1 :
	    (f1->lc_uid == f2->lc_uid ? 0 : 1));
}

void
ct_prompt_for_login_password(void)
{
	char	answer[1024];

	if (ct_username == NULL) {
		if (ct_get_answer("Login username: ", NULL, NULL, NULL,
			answer, sizeof answer, 0)) {
			CFATALX("invalid username");
		} else if (!strlen(answer)) {
			CFATALX("username must not be empty");
		}
		ct_username = e_strdup(answer);
		bzero(answer, sizeof answer);
	}
	ct_normalize_username(ct_username);

	if (ct_password == NULL) {
		if (ct_get_answer("Login password: ", NULL, NULL, NULL,
			answer, sizeof answer, 1)) {
			CFATALX("invalid password");
		} else if (!strlen(answer)) {
			CFATALX("password must not be empty");
		}
		ct_password = e_strdup(answer);
		bzero(answer, sizeof answer);
	}

}

void
ct_normalize_username(char *username)
{
	/* Assume ASCII. */
	for (; *username != '\0'; username++)
		*username = tolower(*username);
}

void
ct_normalize_filelist(char **filelist)
{
	char	**fptr;

	fptr = filelist;
	while (*fptr != NULL) {
		*fptr = ct_normalize_path(*fptr);
		fptr++;
	}
}
