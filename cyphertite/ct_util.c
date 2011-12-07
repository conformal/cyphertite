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

#include <clog.h>
#include <assl.h>
#include <exude.h>

#include "ct.h"
#include "ct_socket.h"

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif


/* metadata file */
FILE	*ct_mdf;

/* assl pipe */
struct ct_assl_io_ctx	*ct_assl_ctx;

/* next transaction id */
int			ct_trans_id = 0;

struct ct_io_queue	*ct_ioctx_alloc(void);
void			ct_ioctx_free(struct ct_io_queue *);
void			ct_print_scaled_stat(FILE *, const char *, int64_t,
			    int64_t, int);



struct ct_op *
ct_add_operation(ct_op_cb *start, ct_op_cb *complete, char *localname,
    char *remotename, char **flist, char **exlist, char *basis, int matchmode,
    int action)
{
	struct ct_op	*op;

	op = e_calloc(1, sizeof(*op));
	op->op_start = start;
	op->op_complete = complete;
	op->op_local_fname = localname;
	op->op_remote_fname = remotename;
	op->op_filelist = flist;
	op->op_excludelist = exlist;
	op->op_basis = basis;
	op->op_matchmode = matchmode;
	op->op_action = action;

	TAILQ_INSERT_TAIL(&ct_state->ct_operations, op, op_link);

	return (op);
}

struct ct_op *
ct_add_operation_after(struct ct_op *after, ct_op_cb *start, ct_op_cb *complete,
    char *localname, char *remotename, char **flist, char **exlist, char *basis,
    int matchmode, int action)
{
	struct ct_op	*op;

	op = e_calloc(1, sizeof(*op));
	op->op_start = start;
	op->op_complete = complete;
	op->op_local_fname = localname;
	op->op_remote_fname = remotename;
	op->op_filelist = flist;
	op->op_excludelist = exlist;
	op->op_basis = basis;
	op->op_matchmode = matchmode;
	op->op_action = action;

	TAILQ_INSERT_AFTER(&ct_state->ct_operations, after, op, op_link);

	return (op);
}

void
ct_nextop(void *vctx)
{
	struct ct_op *op;

	op = TAILQ_FIRST(&ct_state->ct_operations);
	if (op == NULL)
		CFATALX("no operation in queue");

	op->op_start(op);
}

int
ct_op_complete(void)
{
	struct ct_op *op;

	op = TAILQ_FIRST(&ct_state->ct_operations);
	if (op == NULL)
		CFATALX("no operation in queue");

	if (op->op_complete)
		op->op_complete(op);

	TAILQ_REMOVE(&ct_state->ct_operations, op, op_link);
	e_free(&op);

	if (TAILQ_EMPTY(&ct_state->ct_operations))
		return (1);

	/* set up for the next loop */
	ct_set_file_state(CT_S_STARTING);
	ct_wakeup_file();
	return (0);
}

void
ct_load_certs(struct assl_context *c)
{
	if (assl_load_file_certs(c, ct_ca_cert, ct_cert, ct_key))
		assl_fatalx("assl_load_file_certs %s %s %s", ct_ca_cert,
		    ct_cert, ct_key);
}


struct ct_assl_io_ctx    *ct_ssl_ctx;

struct ct_assl_io_ctx *
ct_ssl_connect(int nonfatal)
{
	struct ct_assl_io_ctx    *ctx;
	struct assl_context *c;

	ctx = e_calloc(1, sizeof (*ctx));
	ct_ssl_ctx = ctx;

	c = assl_alloc_context(ASSL_M_TLSV1_CLIENT, 0);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");

	ct_load_certs(c);

	ct_assl_io_ctx_init(ctx, c, ct_handle_msg, ct_write_done,
	    ctx, ct_header_alloc, ct_header_free, ct_body_alloc,
	    ct_body_free, ct_ioctx_alloc, ct_ioctx_free);

	if (assl_event_connect(c, ct_host, ct_hostport,
		ASSL_F_NONBLOCK|ASSL_F_KEEPALIVE|ASSL_F_THROUGHPUT,
	    ct_event_assl_read, ct_event_assl_write, ctx)) {
		if (nonfatal) {
			/* XXX */
			ct_assl_disconnect(ctx);
			ctx = NULL;
		} else
			assl_fatalx("server connect failed");
	}
	if (ct_io_bw_limit && ctx != NULL)
		ct_ssl_init_bw_lim(ctx);

	return ctx;
}

void
ct_ssl_cleanup(void)
{
	ct_assl_disconnect(ct_assl_ctx);
	e_free(&ct_ssl_ctx);
}

void
ct_setup_write_md(const char *mfile, int infile, const char *basis, int lvl,
    char *cwd, char **filelist)
{
	ct_mdf = ct_metadata_create(mfile, infile, basis, lvl, cwd, filelist);
	if (ct_mdf == NULL)
		CFATAL("can't create %s", mfile);
}

void
ct_cleanup_md(void)
{
	if (ct_mdf != NULL) {
		ct_metadata_close(ct_mdf);
		ct_mdf = NULL;
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
ct_assl_negotiate_poll(struct ct_assl_io_ctx *asslctx)
{
	char			b64_digest[128];
	uint8_t			pwd_digest[SHA512_DIGEST_LENGTH];
	uint8_t			buf[20];
	uint8_t			*body;
	struct ct_header	hdr;
	int			rv = 1;
	int			user_len, payload_sz;
	ssize_t			sz;

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

	strlcpy((char *)body, ct_username, payload_sz);
	strlcpy((char *)body + user_len + 1, b64_digest,
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

	CNDBG(CT_LOG_NET, "login successful");
	rv = 0;
done:
	return (rv);
}

void
ct_shutdown_op(struct ct_op *unused)
{
	ct_shutdown();
}

void
ct_shutdown()
{
	ctdb_shutdown();
	event_loopbreak();
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
	struct passwd *passwd;
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

		passwd = getpwuid(fnode->fl_uid);
		if (passwd && (strlen(passwd->pw_name) < sizeof(uid)))
			snprintf(uid, sizeof(uid), "%10s", passwd->pw_name);
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
	struct passwd *passwd;
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

		passwd = getpwuid(key->cfb_uid);
		if (passwd && (strlen(passwd->pw_name) < sizeof(uid)))
			snprintf(uid, sizeof(uid), "%10s", passwd->pw_name);
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
