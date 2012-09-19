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
#ifndef CT_PROTO_H 
#define CT_PROTO_H 

#include <ctutil.h>
#include "ct_types.h"
#include "ct_db.h"

int	ct_create_neg(struct ct_header *, void **, int, int);
int	ct_parse_neg_reply(struct ct_header *, void *, int *, int *);
int	ct_create_login(struct ct_header *, void **, const char *, const char *);
int	ct_parse_login_reply(struct ct_header *, void *);
int	ct_create_xml_negotiate(struct ct_header *, void **, int32_t);
int	ct_parse_xml_negotiate_reply(struct ct_header *, void *,
	    struct ctdb_state *);
int	ct_create_exists(struct ct_header *, void **, uint8_t *, size_t);
int	ct_parse_exists_reply(struct ct_header *, void *, int *);
int	ct_create_write(struct ct_header *, void **, uint8_t *, size_t);
int	ct_create_ctfile_write(struct ct_header *, void **, int *, uint8_t *,
	     size_t, uint32_t);
int	ct_parse_write_reply(struct ct_header *, void *);
int	ct_create_read(struct ct_header *, void **, uint8_t *, size_t);
int	ct_parse_read_reply(struct ct_header *, void *);
int	ct_parse_read_ctfile_chunk_info(struct ct_header *, void *, uint32_t);

#define MD_O_READ	0
#define MD_O_WRITE	1
#define MD_O_APPEND	2
int	ct_create_xml_open(struct ct_header *, void **, const char *, int,
	    uint32_t);
int	ct_parse_xml_open_reply(struct ct_header *, void *, char **);
int	ct_create_xml_close(struct ct_header *, void **);
int	ct_parse_xml_close_reply(struct ct_header *, void *);
int	ct_create_xml_list(struct ct_header *, void **);
int	ct_parse_xml_list_reply(struct ct_header *, void *,
	    struct ctfile_list *);
int	ct_create_xml_delete(struct ct_header *, void **, const char *);
int	ct_parse_xml_delete_reply(struct ct_header *, void *, char **);
#define CT_CULL_PRECIOUS	0x1
int	ct_create_xml_cull_setup(struct ct_header *, void **, uint64_t, int);
int	ct_parse_xml_cull_setup_reply(struct ct_header *, void *);

/* XXX this really doesn't want to be here. */
RB_HEAD(ct_sha_lookup, sha_entry);
RB_PROTOTYPE(ct_sha_lookup, sha_entry, s_rb, ct_cmp_sha);
struct sha_entry {
	RB_ENTRY(sha_entry)      s_rb;
	uint8_t sha[SHA_DIGEST_LENGTH];
};

int	ct_create_xml_cull_shas(struct ct_header *hdr, void **vbody,
	    uint64_t cull_uuid, struct ct_sha_lookup *, int, int *);
int	ct_parse_xml_cull_shas_reply(struct ct_header *, void *);
#define CT_CULL_PROCESS		0x10
int	ct_create_xml_cull_complete(struct ct_header *, void **, uint64_t, int);
int	ct_parse_xml_cull_complete_reply(struct ct_header *, void *, int32_t *);

void	ct_cleanup_packet(struct ct_header *, void *);

#endif /* ! CT_PROTO_H */
