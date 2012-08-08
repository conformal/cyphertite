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

#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <errno.h>

#include <libgen.h>

#include <rpc/types.h>
#include <rpc/xdr.h>

#include <clog.h>
#include <exude.h>

#include <cyphertite.h>
#include <ct_ctfile.h>
#include <ct_internal.h>

#ifdef __linux__
#define xdr_u_int32_t	xdr_uint32_t
#define xdr_u_int64_t	xdr_uint64_t
#endif

bool_t          ct_xdr_dedup_sha(XDR *, uint8_t *);
bool_t		ct_xdr_dedup_sha_crypto(XDR *, uint8_t *, uint8_t *,
			uint8_t *);
bool_t          ct_xdr_header(XDR *, struct ctfile_header *, int);
bool_t          ct_xdr_trailer(XDR *, struct ctfile_trailer *);
bool_t          ct_xdr_stdin(XDR *, struct ctfile_stdin *);
int		ct_xdr_gheader(XDR *, struct ctfile_gheader *, int,
		    const char *);

static int	 ctfile_open(const char *, const char *,
		     FILE **, struct ctfile_gheader *, XDR *);
static int	 ctfile_open_f(FILE *, const char *,
		     struct ctfile_gheader *, XDR *);
static void	 ctfile_close(FILE *, XDR *);
static void	 ctfile_cleanup_gheader(struct ctfile_gheader *);

/*
 * XDR manipulation functions.
 */
bool_t
ct_xdr_dedup_sha(XDR *xdrs, uint8_t *sha)
{
	if (!xdr_opaque(xdrs, (caddr_t)sha, SHA_DIGEST_LENGTH))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_dedup_sha_crypto(XDR *xdrs, uint8_t *sha, uint8_t *csha, uint8_t *iv)
{
	if (!xdr_opaque(xdrs, (caddr_t)sha, SHA_DIGEST_LENGTH))
		return (FALSE);
	if (!xdr_opaque(xdrs, (caddr_t)csha, SHA_DIGEST_LENGTH))
		return (FALSE);
	if (!xdr_opaque(xdrs, (caddr_t)iv, CT_IV_LEN))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_header(XDR *xdrs, struct ctfile_header *objp, int version)
{
	if (!xdr_int(xdrs, &objp->cmh_beacon))
		return (FALSE);
	if (!xdr_u_int64_t(xdrs, &objp->cmh_nr_shas))
		return (FALSE);
	if (version >= CT_MD_V3) {
		if (!xdr_int64_t(xdrs, &objp->cmh_parent_dir))
			return (FALSE);
	} else {
		/* Old xdr versions are read-only */
		objp->cmh_parent_dir = -1;
	}
	if (!xdr_u_int32_t(xdrs, &objp->cmh_uid))
		return (FALSE);
	if (!xdr_u_int32_t(xdrs, &objp->cmh_gid))
		return (FALSE);
	if (!xdr_u_int32_t(xdrs, &objp->cmh_mode))
		return (FALSE);
	if (!xdr_int32_t(xdrs, &objp->cmh_rdev))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->cmh_atime))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->cmh_mtime))
		return (FALSE);
	if (!xdr_u_char(xdrs, &objp->cmh_type))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->cmh_filename, PATH_MAX))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_trailer(XDR *xdrs, struct ctfile_trailer *objp)
{
	if (!ct_xdr_dedup_sha(xdrs, objp->cmt_sha))
		return (FALSE);
	if (!xdr_u_int64_t(xdrs, &objp->cmt_orig_size))
		return (FALSE);
	if (!xdr_u_int64_t(xdrs, &objp->cmt_comp_size))
		return (FALSE);
	return (TRUE);
}

bool_t
ct_xdr_stdin(XDR *xdrs, struct ctfile_stdin *objp)
{
	if (!xdr_int(xdrs, &objp->cms_beacon))
		return (FALSE);
	/* XXX - crypt? */
	if (!ct_xdr_dedup_sha(xdrs, objp->cms_sha))
		return (FALSE);
	return (TRUE);
}

int
ct_xdr_gheader(XDR *xdrs, struct ctfile_gheader *objp,
    int direction, const char *ctfile_basedir)
{
	char	 *prevlvl = NULL;
	int	 i;

	if (!xdr_int(xdrs, &objp->cmg_beacon))
		return (CTE_XDR);
	if (!xdr_int(xdrs, &objp->cmg_version))
		return (CTE_XDR);
	if (!xdr_int(xdrs, &objp->cmg_chunk_size))
		return (CTE_XDR);
	if (!xdr_int64_t(xdrs, &objp->cmg_created))
		return (CTE_XDR);
	if (!xdr_int(xdrs, &objp->cmg_type))
		return (CTE_XDR);
	if (!xdr_int(xdrs, &objp->cmg_flags))
		return (CTE_XDR);
	if (direction  == XDR_ENCODE) {
		if (ctfile_basedir != NULL &&
		    objp->cmg_prevlvl_filename != NULL &&
		    objp->cmg_prevlvl_filename[0] != '\0') {
			/* XXX technically should just remove basedir if present */
			prevlvl = ct_basename(objp->cmg_prevlvl_filename);
		} else {
			prevlvl = e_strdup(objp->cmg_prevlvl_filename);
		}
		if (!xdr_string(xdrs, &prevlvl, PATH_MAX)) {
			e_free(&prevlvl);
			return (CTE_XDR);
		}
		e_free(&prevlvl);
	} else if (direction == XDR_DECODE) {
		if (!xdr_string(xdrs, &prevlvl, PATH_MAX))
			return (CTE_XDR);
		if (ctfile_basedir != NULL && prevlvl != NULL &&
		    prevlvl[0] != '\0') {
			if (asprintf(&objp->cmg_prevlvl_filename, "%s%s",
			    ctfile_basedir, prevlvl) == -1) {
				return (CTE_ERRNO);
			}
		} else {
			objp->cmg_prevlvl_filename = prevlvl;
		}
	}
	if (objp->cmg_version >= CT_MD_V2) {
		if (!xdr_int(xdrs, &objp->cmg_cur_lvl))
			return (CTE_XDR);
		if (!xdr_string(xdrs, &objp->cmg_cwd, PATH_MAX))
			return (CTE_XDR);
		if (!xdr_int(xdrs, &objp->cmg_num_paths))
			return (CTE_XDR);
		if (direction == XDR_DECODE) {
			if (objp->cmg_num_paths != 0)
				objp->cmg_paths = e_calloc(objp->cmg_num_paths,
				    sizeof(*objp->cmg_paths));
			else
				objp->cmg_paths = NULL;
		}
		for (i = 0; i < objp->cmg_num_paths; i++) {
			if (!xdr_string(xdrs, &objp->cmg_paths[i], PATH_MAX))
				return (CTE_XDR);
			if (direction == XDR_DECODE)
				objp->cmg_paths[i] =
				    ct_normalize_path(objp->cmg_paths[i]);
		}
	}
	return (0);
}

/*
 * General helper functions
 */
void
ctfile_close(FILE *file, XDR *xdr)
{
	xdr_destroy(xdr);
	fclose(file);
}

/*
 * Open filename as a ctfile, returning the xdr pointer and the global header.
 */
int
ctfile_open(const char *filename, const char *ctfile_basedir, FILE **f,
    struct ctfile_gheader *gh, XDR *xdr)
{
	if ((*f = fopen(filename, "rb")) == NULL)
		return (CTE_ERRNO);

	return (ctfile_open_f(*f, ctfile_basedir, gh, xdr));
}

/*
 * Open stream f as a ctfile, returning the xdr pointer and the global header.
 *
 * Upon failure the file will be *closed*.
 */
int
ctfile_open_f(FILE *f, const char *ctfile_basedir, struct ctfile_gheader *gh,
    XDR *xdr)
{
	int	ret;

	xdrstdio_create(xdr, f, XDR_DECODE);

	bzero(gh, sizeof *gh);

	if (ct_xdr_gheader(xdr, gh, XDR_DECODE, ctfile_basedir) != 0) {
		CNDBG(CT_LOG_CTFILE, "e_xdr_gheader failed");
		ret = CTE_CTFILE_CORRUPT;
		goto destroy;
	}

	/* don't bother with empty strings for prevlevel */
	if (gh->cmg_prevlvl_filename &&
	    gh->cmg_prevlvl_filename[0] == '\0') {
		free(gh->cmg_prevlvl_filename);
		gh->cmg_prevlvl_filename = NULL;
	}

	if (gh->cmg_beacon != CT_MD_BEACON) {
		CNDBG(CT_LOG_CTFILE, "%d is incorrect beacon value (%d exp)",
		    gh->cmg_beacon, CT_MD_BEACON);
		ret = CTE_CTFILE_CORRUPT;
		goto cleanup;
	}
	if (gh->cmg_version > CT_MD_VERSION) {
		CNDBG(CT_LOG_CTFILE, "%d is incorrect version value (%d exp)",
		    gh->cmg_beacon, CT_MD_VERSION);
		ret = CTE_CTFILE_CORRUPT;
		goto cleanup;
	}

	return (0);

cleanup:
	ctfile_cleanup_gheader(gh);
destroy:
	xdr_destroy(xdr);
	fclose(f);
	return (ret);
}

/*
 * Cleanup a global header that has been read from a file.
 * xdr strings are malloced and thus need cleaning up.
 */
void
ctfile_cleanup_gheader(struct ctfile_gheader *gh)
{
	int	 i;
	if (gh->cmg_prevlvl_filename) {
		free(gh->cmg_prevlvl_filename);
		gh->cmg_prevlvl_filename = NULL;
	}
	if (gh->cmg_cwd != NULL) {
		free(gh->cmg_cwd);
		gh->cmg_cwd = NULL;
	}
	if (gh->cmg_paths != NULL) {
		for (i = 0; i < gh->cmg_num_paths; i++)
			free(gh->cmg_paths[i]);

		e_free(&gh->cmg_paths);
	}
}


int
ct_basis_setup(int *nextlvlp, const char *basisbackup, char **filelist,
    int max_incrementals, time_t *prev_backup, const char *cwd)
{
	struct ctfile_parse_state	 xs_ctx;
	char				**fptr;
	time_t				 prev_backup_time = 0;
	int				 nextlvl, i, rooted = 1, ret, s_errno;

	if ((ret = ctfile_parse_init(&xs_ctx, basisbackup, NULL)))
		return (ret);

	if (max_incrementals == 0 ||
	    xs_ctx.xs_gh.cmg_cur_lvl < max_incrementals) {
		prev_backup_time = xs_ctx.xs_gh.cmg_created;
		CINFO("prev backup time %s %s", ctime(&prev_backup_time),
		    basisbackup);
		nextlvl = ++xs_ctx.xs_gh.cmg_cur_lvl;
	} else {
		nextlvl = 0;
	}

	/*
	 * if we have the list of dirs in this previous backup, check that
	 * our cwd matches and the list of dirs we care about are a strict
	 * superset of the previous backup
	 */
	if (xs_ctx.xs_gh.cmg_version >= CT_MD_V2) {
		for (i = 0, fptr = filelist; *fptr != NULL &&
		    i < xs_ctx.xs_gh.cmg_num_paths; fptr++, i++) {
			if (strcmp(xs_ctx.xs_gh.cmg_paths[i], *fptr) != 0)
				break;
			if (xs_ctx.xs_gh.cmg_paths[i][0] != '/')
				rooted = 0;
		}
		if (i < xs_ctx.xs_gh.cmg_num_paths || *fptr != NULL) {
				CWARNX(" list of directories in basis:");
				for (i = 0; i < xs_ctx.xs_gh.cmg_num_paths; i++)
					CWARNX("%s", xs_ctx.xs_gh.cmg_paths[i]);
				return (CTE_FILELIST_MISMATCH);
		}

		if (rooted == 0 && strcmp(cwd, xs_ctx.xs_gh.cmg_cwd) != 0) {
			CWARNX("previous cwd: %s", xs_ctx.xs_gh.cmg_cwd);
			return (CTE_CWD_MISMATCH);
		}
	}

	while ((ret = ctfile_parse(&xs_ctx)) != XS_RET_EOF) {
		if (ret == XS_RET_SHA)  {
			if (ctfile_parse_seek(&xs_ctx)) {
				s_errno = errno;
				ret = xs_ctx.xs_errno;
				ctfile_parse_close(&xs_ctx);
				errno = s_errno;
				return (ret);
			}
		} else if (ret == XS_RET_FAIL) {
			s_errno = errno;
			ret = xs_ctx.xs_errno;
			ctfile_parse_close(&xs_ctx);
			errno = s_errno;
			return (ret);
		}

	}
	ctfile_parse_close(&xs_ctx);

	if (nextlvl != 0 && prev_backup != NULL)
		*prev_backup = prev_backup_time;

	*nextlvlp = nextlvl;
	return (0);
}

char *
ctfile_get_previous(const char *path)
{
	FILE			*ctfile;
	char			*ret = NULL;
	XDR			 xdr;
	struct ctfile_gheader	 gh;

	if (ctfile_open(path, NULL, &ctfile, &gh, &xdr) == 0) {
		if (gh.cmg_prevlvl_filename)
			ret = e_strdup(gh.cmg_prevlvl_filename);

		ctfile_cleanup_gheader(&gh);
		ctfile_close(ctfile, &xdr);
	}

	return ret;
}

int
ctfile_parse_init_f(struct ctfile_parse_state *ctx, FILE *f,
    const char *ctfile_basedir)
{
	int ret;

	bzero (ctx, sizeof(*ctx));
	if ((ret = ctfile_open_f(f, ctfile_basedir,
	    &ctx->xs_gh, &ctx->xs_xdr)) != 0)
		return (ret);

	ctx->xs_f = f;
	ctx->xs_filename  = NULL;
	ctx->xs_dnum = 0;
	RB_INIT(&ctx->xs_dnum_head);

	ctx->xs_sha_sz = 0;
	ctx->xs_state = XS_STATE_FILE;
	ctx->xs_wasfile = 1;

	return (0);
}

int
ctfile_parse_init_at(struct ctfile_parse_state *ctx, const char *file,
    const char *ctfile_basedir, off_t offset)
{
	int	ret, s_errno;

	bzero (ctx, sizeof(*ctx));
	if ((ret = ctfile_open(file,  ctfile_basedir, &ctx->xs_f, &ctx->xs_gh,
	    &ctx->xs_xdr)) != 0)
		return (ret);

	ctx->xs_filename  = e_strdup(file);
	ctx->xs_dnum = 0;
	RB_INIT(&ctx->xs_dnum_head);

	if (offset != 0 && fseek(ctx->xs_f, offset, SEEK_SET) == -1) {
		s_errno = errno;
		ctfile_parse_close(ctx);
		errno = s_errno;
		return (CTE_ERRNO);
	}

	ctx->xs_sha_sz = 0;
	ctx->xs_state = XS_STATE_FILE;
	return 0;
}

static int
ctfile_parse_read_header(struct ctfile_parse_state *ctx,
    struct ctfile_header *hdr)
{
	bzero(hdr, sizeof *hdr);

	if (ct_xdr_header(&ctx->xs_xdr, hdr, ctx->xs_gh.cmg_version) == FALSE)
		return 1;

	CNDBG(CT_LOG_CTFILE,
	    "header beacon 0x%08x 0x%08x shas %" PRIu64 " name %s",
	    hdr->cmh_beacon, CT_HDR_BEACON, hdr->cmh_nr_shas,
	    hdr->cmh_filename);

	if (hdr->cmh_beacon != CT_HDR_BEACON && hdr->cmh_beacon != CT_HDR_EOF)
		return 1;

	return 0;
}

static int
ctfile_parse_read_trailer(struct ctfile_parse_state *ctx,
    struct ctfile_trailer *trl)
{
	bool_t ret;

	bzero (trl, sizeof *trl);

	ret = ct_xdr_trailer(&ctx->xs_xdr, trl);

	return (ret == FALSE);
}

int
ctfile_parse(struct ctfile_parse_state *ctx)
{
	off_t			pos0, pos1;
	int			ret;
	int			rv = XS_STATE_FAIL;

	pos0 = pos1 = 0;

	switch (ctx->xs_state) {
	case XS_STATE_FILE:
		/* actually between files, next expected object is hdr */
		ret = ctfile_parse_read_header(ctx, &ctx->xs_hdr);
		if (ret) {
			ctx->xs_errno = CTE_CTFILE_CORRUPT;
			goto fail;
		}

		if (ctx->xs_hdr.cmh_beacon == CT_HDR_EOF) {
			ctx->xs_state = XS_STATE_EOF;
			rv = XS_RET_EOF;
			break;
		}

		if (C_ISLINK(ctx->xs_hdr.cmh_type)) {
			ret = ctfile_parse_read_header(ctx, &ctx->xs_lnkhdr);
			if (ret) {
				ctx->xs_errno = CTE_CTFILE_CORRUPT;
				goto fail;
			}
		}
		if (C_ISREG(ctx->xs_hdr.cmh_type)) {
			ctx->xs_sha_cnt = ctx->xs_hdr.cmh_nr_shas;
			ctx->xs_state = XS_STATE_SHA;
		} else
			ctx->xs_state = XS_STATE_FILE;
		rv = XS_RET_FILE;
		break;
	case XS_STATE_SHA:
		/*
		 * in the middle of a file, expecting shas or trailer based
		 * based on sha cnt.
		 */
		 if (ctx->xs_sha_cnt > 0) {
			ctx->xs_sha_cnt--;
			/* XXX gh check? */
			if (ctx->xs_sha_sz == 0)
				pos0 = ftello(ctx->xs_f);

			if (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO) {
				ret = ct_xdr_dedup_sha_crypto(
				    &ctx->xs_xdr, ctx->xs_sha, ctx->xs_csha,
				    ctx->xs_iv);
			} else {
				ret = ct_xdr_dedup_sha(&ctx->xs_xdr,
				    ctx->xs_sha);
			}
			if (ret == FALSE) {
				ctx->xs_errno = CTE_CTFILE_CORRUPT;
				goto fail;
			}

			if (ctx->xs_sha_sz == 0) {
				pos1 = ftello(ctx->xs_f);
				ctx->xs_sha_sz = pos1 - pos0;
			}

			/*
			 * this stays in SHA state even if
			 * xs_sha_cnt == 0 so that it will read the trailer
			 */
			rv = XS_RET_SHA;
		 } else {
			ret = ctfile_parse_read_trailer(ctx, &ctx->xs_trl);
			if (ret) {
				ctx->xs_errno = CTE_CTFILE_CORRUPT;
				goto fail;
			}

			ctx->xs_state = XS_STATE_FILE;
			rv = XS_RET_FILE_END;
		 }

		break;
	case XS_STATE_EOF:
		/*
		 * fall thru to fail here, reading again after end of file
		 * is not allowed
		 */
	case XS_STATE_FAIL:
		ctx->xs_errno = CTE_CTFILE_CORRUPT;
		goto fail;

	}

	return rv;
fail:
	ctx->xs_state = XS_STATE_FAIL;
	return XS_RET_FAIL;
}

static inline int
ct_dnum_cmp(struct dnode *d1, struct dnode *d2)
{
	return (d1->d_num < d2->d_num ? -1 : d1->d_num > d2->d_num);
}
RB_PROTOTYPE_STATIC(d_num_tree, dnode, ds_rb, ct_dnum_cmp);
RB_GENERATE_STATIC(d_num_tree, dnode, d_rb_num, ct_dnum_cmp);

struct dnode *ctfile_parse_finddir(struct ctfile_parse_state *ctx, int num)
{
	struct dnode dsearch;

	dsearch.d_num = num;
	return RB_FIND(d_num_tree, &ctx->xs_dnum_head, &dsearch);
}

struct dnode *ctfile_parse_insertdir(struct ctfile_parse_state *ctx,
    struct dnode *dnode)
{
	dnode->d_num = ctx->xs_dnum++;
	return RB_INSERT(d_num_tree, &ctx->xs_dnum_head, dnode);
}

/*
 * If in SHA state, it is valid to tell the reader to seek to the end
 * of the shas and read the file trailer
 */
int
ctfile_parse_seek(struct ctfile_parse_state *ctx)
{
	off_t	pos0, pos1;

	if (ctx->xs_state != XS_STATE_SHA)
		CABORTX("%s called with invalid state: %d", __func__,
		    ctx->xs_state);
	if (ctx->xs_sha_cnt <= 0)
		return 0;

	if (ctx->xs_sha_sz == 0) {
		pos0 = ftello(ctx->xs_f);
		if (ctx->xs_gh.cmg_flags & CT_MD_CRYPTO) {
			if (ct_xdr_dedup_sha_crypto(&ctx->xs_xdr, ctx->xs_sha,
			    ctx->xs_csha, ctx->xs_iv) == FALSE) {
				ctx->xs_errno = CTE_CTFILE_CORRUPT;
				ctx->xs_state = XS_STATE_FAIL;
				return 1;
			}
		} else if (ct_xdr_dedup_sha(&ctx->xs_xdr,
		    ctx->xs_sha) == FALSE) {
			ctx->xs_errno = CTE_CTFILE_CORRUPT;
			ctx->xs_state = XS_STATE_FAIL;
			return 1;
		}

		pos1 = ftello(ctx->xs_f);
		ctx->xs_sha_sz = pos1 - pos0;
		ctx->xs_sha_cnt--;
	}
	if (fseek(ctx->xs_f, ctx->xs_sha_sz * ctx->xs_sha_cnt, SEEK_CUR) != 0) {
		ctx->xs_errno = CTE_ERRNO;
		ctx->xs_state = XS_STATE_FAIL;
		return 1;
	}
	ctx->xs_sha_cnt = 0;

	return 0;
}

off_t
ctfile_parse_tell(struct ctfile_parse_state *ctx)
{
	return (ftello(ctx->xs_f));
}

void
ctfile_parse_close(struct ctfile_parse_state *ctx)
{
	struct dnode *dnode;

	ctfile_cleanup_gheader(&ctx->xs_gh);
	if (ctx->xs_filename != NULL)
		e_free(&ctx->xs_filename);
	ctx->xs_dnum = 0;

	/*
	 * The directory number tree is provided as a convenience for looking
	 * up parents. Remove any entries from the tree, but do not free them
	 * the onus for that is on the caller.
	 */
	while ((dnode = RB_ROOT(&ctx->xs_dnum_head)) != NULL)
		RB_REMOVE(d_num_tree, &ctx->xs_dnum_head, dnode);

	if (ctx->xs_wasfile) {
		xdr_destroy(&ctx->xs_xdr);
	} else {
		ctfile_close(ctx->xs_f, &ctx->xs_xdr);
	}
}

struct ctfile_write_state {
	FILE		*cws_f;
	XDR		 cws_xdr;
	int		 cws_version;
	int		 cws_flags;
	int		 cws_block_size;
	int64_t		 cws_dirnum;
};
static int	ctfile_alloc_dirnum(struct ctfile_write_state *,
		    struct dnode *, struct dnode *);
static int	ctfile_write_header(struct ctfile_write_state *,
		    struct fnode *, char *, int);
static int	 ctfile_write_header_entry(struct ctfile_write_state *, char *,
		    int, uint64_t, uint32_t, uint32_t, int, dev_t, int64_t,
		    int64_t, struct dnode *, int);

/*
 * API for creating ctfiles.
 */
int
ctfile_write_init(struct ctfile_write_state **ctxp, const char *ctfile,
    const char *ctfile_basedir, int type, const char *basis, int lvl,
    char *cwd, char **filelist, int encrypted, int allfiles, int max_block_size)
{
	struct ctfile_write_state	*ctx;
	char				**fptr;
	struct ctfile_gheader		 gh;
	int				 ret, s_errno;

	ctx = e_calloc(1, sizeof(*ctx));

	/* always save to the current version */
	ctx->cws_version = CT_MD_VERSION;
	ctx->cws_dirnum = -1;

	if (lvl != 0 && basis == NULL)
		CABORTX("multilevel archive with no basis");

	/* open metadata file */
	if ((ctx->cws_f = fopen(ctfile, "wb")) == NULL) {
		ret = CTE_ERRNO;
		goto fail;
	}

	/* prepare header */
	bzero(&gh, sizeof gh);
	gh.cmg_beacon = CT_MD_BEACON;
	gh.cmg_version = CT_MD_VERSION;
	gh.cmg_chunk_size = ctx->cws_block_size = max_block_size;
	gh.cmg_created = time(NULL);
	gh.cmg_type = type;
	gh.cmg_flags = 0;
	if (encrypted)
		gh.cmg_flags |= CT_MD_CRYPTO;
	if (allfiles)
		gh.cmg_flags |= CT_MD_MLB_ALLFILES;
	gh.cmg_prevlvl_filename = basis ? (char *)basis : "";
	gh.cmg_cur_lvl = lvl;
	gh.cmg_cwd = cwd;

	ctx->cws_flags = gh.cmg_flags;

	fptr = filelist;
	while((*fptr++) != NULL)
		gh.cmg_num_paths++;
	gh.cmg_paths = filelist;

	/* write global header */
	xdrstdio_create(&ctx->cws_xdr, ctx->cws_f, XDR_ENCODE);
	if ((ret = ct_xdr_gheader(&ctx->cws_xdr, &gh, XDR_ENCODE,
	    ctfile_basedir)) != 0) {
		goto fail;
	}

	*ctxp = ctx;
	return (0);
fail:
	s_errno = errno;
	if (ctx) {
		if (ctx->cws_f)
			fclose(ctx->cws_f);
		e_free(&ctx);
	}
	*ctxp = NULL;
	errno = s_errno;
	return (ret);
}

/*
 * Allocate directory numbers for directory and its parents and write to
 * the ctfile
 */
int
ctfile_alloc_dirnum(struct ctfile_write_state *ctx, struct dnode *dnode,
    struct dnode *parentdir)
{
	int		 ret;

	if (dnode->d_num != -1)
		return (0);

	/* flag as allocate dirnum */
	dnode->d_num = -2;

	/* Recursively write all unwritten parents to the ctfile */
	if (parentdir && parentdir->d_num == -1) {
		if ((ret = ctfile_alloc_dirnum(ctx, parentdir,
		    parentdir->d_parent)) != 0)
			return (ret);
	}

	dnode->d_num = ++ctx->cws_dirnum;

	CNDBG(CT_LOG_CTFILE, "alloc_dirnum dir %"PRId64" %s", dnode->d_num,
	    dnode->d_name);
	return (ctfile_write_header_entry(ctx, dnode->d_name, C_TY_DIR,
	    0, dnode->d_uid, dnode->d_gid, dnode->d_mode, 0, dnode->d_atime,
	    dnode->d_mtime, dnode->d_parent, 1));
}

int
ctfile_write_header(struct ctfile_write_state *ctx, struct fnode *fnode,
    char *filename, int base)
{
	uint64_t nr_shas = 0;

	CNDBG(CT_LOG_CTFILE, "writing file header %s %s", fnode->fl_sname,
	    filename);

	if (C_ISDIR(fnode->fl_type)) {
		if (fnode->fl_curdir_dir->d_num == -2) {
			CABORTX("directory for allocation in write path");
		} else if (fnode->fl_curdir_dir->d_num != -1) {
			CABORTX("already allocated directory %" PRIu64
			    " in write path", fnode->fl_curdir_dir->d_num);
		}
		/* alloc_dirnum will write the node */
		return (ctfile_alloc_dirnum(ctx, fnode->fl_curdir_dir,
		    fnode->fl_parent_dir));
	} else if (fnode->fl_skip_file)
		nr_shas = -1LL;
	else if (C_ISREG(fnode->fl_type)) {
		nr_shas = fnode->fl_size / ctx->cws_block_size;
		if (fnode->fl_size % ctx->cws_block_size)
			nr_shas++;
	}

	return (ctfile_write_header_entry(ctx, filename, fnode->fl_type,
	    nr_shas, fnode->fl_uid, fnode->fl_gid, fnode->fl_mode,
	    fnode->fl_rdev, fnode->fl_atime, fnode->fl_mtime,
	    fnode->fl_parent_dir, base));
}

int
ctfile_write_header_entry(struct ctfile_write_state *ctx, char *filename,
    int type, uint64_t nr_shas, uint32_t uid, uint32_t gid, int mode,
    dev_t rdev, int64_t atime, int64_t mtime, struct dnode *parent_dir,
    int base)
{
	struct ctfile_header	hdr;

	bzero(&hdr, sizeof hdr);

	/* -3 for parent dir means this is the fake root, ignore it */
	if (parent_dir && parent_dir->d_num != -3) {
		if (parent_dir->d_num == -1) {
			ctfile_alloc_dirnum(ctx, parent_dir,
			    parent_dir->d_parent);
		}
		hdr.cmh_parent_dir = parent_dir->d_num;
	} else if (base && filename[0] == '/') {
		/* this is a rooted directory element */
		hdr.cmh_parent_dir = -2;
	} else {
		hdr.cmh_parent_dir = -1;
	}

	hdr.cmh_beacon = CT_HDR_BEACON;
	hdr.cmh_nr_shas = nr_shas;
	hdr.cmh_uid = uid;
	hdr.cmh_gid = gid;
	hdr.cmh_mode = mode;
	hdr.cmh_rdev = rdev;
	hdr.cmh_atime = atime;
	hdr.cmh_mtime = mtime;
	if (base)
		hdr.cmh_filename = basename(filename);
	else
		hdr.cmh_filename = filename;
	hdr.cmh_type = type;
	if (ct_xdr_header(&ctx->cws_xdr, &hdr, ctx->cws_version) == FALSE)
		return 1;

	return 0;
}

int
ctfile_write_special(struct ctfile_write_state *ctx, struct fnode *fnode)
{
	int type = fnode->fl_type;

	if (C_ISDIR(type)) {
		if (ctfile_write_header(ctx, fnode, fnode->fl_sname, 1)) {
			CNDBG(CT_LOG_CTFILE, "dir header write failed");
			return (1);
		}
		CNDBG(CT_LOG_CTFILE, "record dir %s", fnode->fl_sname);
	} else if (C_ISCHR(type) || C_ISBLK(type)) {
		if (ctfile_write_header(ctx, fnode, fnode->fl_sname, 1)) {
			CNDBG(CT_LOG_CTFILE, "special dev header write failed");
			return (1);
		}
	} else if (C_ISFIFO(type)) {
		CNDBG(CT_LOG_CTFILE, "fifo not supported (%s)",
		    fnode->fl_sname);
	} else if (C_ISLINK(type)) {
		if (fnode->fl_sname == NULL &&
		    fnode->fl_hlname == NULL) {
			CABORTX("%slink with no name or dest",
			    fnode->fl_hardlink ? "hard" : "sym");
		} else if (fnode->fl_sname == NULL) {
			CABORTX("%slink with no name",
			    fnode->fl_hardlink ? "hard" : "sym");
		} else if (fnode->fl_hlname == NULL) {
			CABORTX("%slink with no dest",
			    fnode->fl_hardlink ? "hard" : "sym");
		}
		CNDBG(CT_LOG_CTFILE, "mylink %s %s", fnode->fl_sname,
		    fnode->fl_hlname);
		if (ctfile_write_header(ctx, fnode, fnode->fl_sname, 1)) {
			CNDBG(CT_LOG_CTFILE, "link header write failed");
			return (1);
		}

		if (fnode->fl_hardlink) {
			fnode->fl_type = C_TY_REG; /* cheat */
		}

		if (ctfile_write_header(ctx, fnode, fnode->fl_hlname, 0)) {
			CNDBG(CT_LOG_CTFILE, "link header2 write failed");
			return (1);
		}

		fnode->fl_type = type; /* restore */

	} else if (C_ISSOCK(type)) {
		CNDBG(CT_LOG_CTFILE, "cannot archive a socket %s",
		    fnode->fl_sname);
	} else {
		CABORTX("invalid type on %s %d", fnode->fl_sname,
		    type);
	}

	return (0);
}

int
ctfile_write_file_start(struct ctfile_write_state *ctx, struct fnode *fnode)
{
	return (ctfile_write_header(ctx, fnode, fnode->fl_sname, 1));
}


int
ctfile_write_file_sha(struct ctfile_write_state *ctx, uint8_t *sha,
    uint8_t *csha, uint8_t *iv)
{
	bool_t	ret;

	CNDBG(CT_LOG_CTFILE, "writing sha %s", ctx->cws_flags & CT_MD_CRYPTO ?
	    "crypto" : "no crypto");
	if (ctx->cws_flags & CT_MD_CRYPTO) {
		ret = ct_xdr_dedup_sha_crypto(&ctx->cws_xdr, sha, csha, iv);
	} else {
		ret = ct_xdr_dedup_sha(&ctx->cws_xdr, sha);
	}

	return (ret == FALSE);
}

int
ctfile_write_file_pad(struct ctfile_write_state *ctx, struct fnode *fn)
{
	off_t		padlen = fn->fl_size - fn->fl_offset;
	uint8_t		sha[SHA_DIGEST_LENGTH];
	uint8_t		iv[CT_IV_LEN];
	int		ret = 0;

	bzero(sha, sizeof(sha));
	/*
	 * File got truncated during backup, pad up
	 * zero shas to the original size of the file.
	 */
	while (padlen > 0) {
		padlen -= ctx->cws_block_size;
		if ((ret = ctfile_write_file_sha(ctx, sha, sha, iv)) != 0)
			goto out;
	}
	fn->fl_size = fn->fl_offset;

out:
	return (ret);
}

int
ctfile_write_file_end(struct ctfile_write_state *ctx, struct fnode *fnode)
{
	struct ctfile_trailer	trl;
	bool_t			ret;

	if ((ctx->cws_flags & CT_MD_MLB_ALLFILES) == 0 && fnode->fl_skip_file)
		return (0);

	bzero (&trl, sizeof trl);

	CNDBG(CT_LOG_CTFILE, "multi %d",
	    !!(ctx->cws_flags & CT_MD_MLB_ALLFILES));
	CNDBG(CT_LOG_CTFILE, "writing file trailer %s", fnode->fl_sname);

	ct_sha1_final(trl.cmt_sha, &fnode->fl_shactx);
	trl.cmt_orig_size = fnode->fl_size;
	trl.cmt_comp_size = fnode->fl_comp_size;

	return (ct_xdr_trailer(&ctx->cws_xdr, &trl) == FALSE);

	return (ret == FALSE);
}

int
ctfile_write_close(struct ctfile_write_state *ctx)
{
	struct ctfile_header	hdr;
	char			fake[1];
	int			ret = 0;

	/* Write EOF header on close */
	bzero(&hdr, sizeof hdr);
	fake[0] = '\0';
	hdr.cmh_filename = fake;
	hdr.cmh_beacon = CT_HDR_EOF;
	if (ct_xdr_header(&ctx->cws_xdr, &hdr, ctx->cws_version) == FALSE)
		ret = 1;

	ctfile_close(ctx->cws_f, &ctx->cws_xdr);

	e_free(&ctx);

	return (ret);
}

/* Juke clean up any resources we have allocated */
void
ctfile_write_abort(struct ctfile_write_state *ctx)
{
	/* XXX consider unlinking? */
	ctfile_close(ctx->cws_f, &ctx->cws_xdr);

	e_free(&ctx);
}
