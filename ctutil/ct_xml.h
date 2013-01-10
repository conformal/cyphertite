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

/* XML transactions for Cyphertite MD. */

#define CT_MD_OPEN_CREATE_VERSION	"V3"
extern struct xmlsd_v_elem xe_ct_md_open_create[];

#define CT_MD_OPEN_READ_VERSION		"V3"
extern struct xmlsd_v_elem xe_ct_md_open_read[];

#define CT_MD_CLOSE_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_md_close[];

#define CT_MD_LIST_VERSION		"V3"
extern struct xmlsd_v_elem xe_ct_md_list[];

#define CT_MD_DELETE_VERSION		"V3"
extern struct xmlsd_v_elem xe_ct_md_delete[];

#define CT_CULL_SETUP_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_cull_setup[];

#define CT_CULL_SHA_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_cull_shas[];

#define CT_CULL_COMPLETE_VERSION	"V1"
extern struct xmlsd_v_elem xe_ct_cull_complete[];

#define CT_CULL_SETUP_REPLY_VERSION	"V1"
extern struct xmlsd_v_elem xe_ct_cull_setup_reply[];

#define CT_CULL_SHAS_REPLY_VERSION	"V1"
extern struct xmlsd_v_elem xe_ct_cull_shas_reply[];

#define CT_CULL_COMPLETE_REPLY_VERSION	"V1"
extern struct xmlsd_v_elem xe_ct_cull_complete_reply[];

#define CT_NEGOTIATE_VERSION		"V1"

#define CT_NEGOTIATE_REPLY_VERSION	"V1"
extern struct xmlsd_v_elem xe_ct_negotiate_reply[];

#define CT_CLIENTDB_NEWVER_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_clientdb_newver[];

#define CT_CLIENTDB_NEWVER_REPLY_VERSION	"V1"
extern struct xmlsd_v_elem xe_ct_clientdb_newver_reply[];

#define CT_ARCHIVE_CREATE_VERSION		"V1"
#define CT_ARCHIVE_CREATE_REPLY_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_archive_create_reply[];

#define CT_ARCHIVE_REPLACE_VERSION		"V1"
#define CT_ARCHIVE_REPLACE_REPLY_VERSION	"V1"

#define CT_ARCHIVE_REMOVE_VERSION		"V1"
#define CT_ARCHIVE_REMOVE_REPLY_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_archive_remove_reply[];

#define CT_ARCHIVE_LIST_VERSION			"V1"
#define CT_ARCHIVE_LIST_REPLY_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_archive_list_reply[];

#define CT_ARCHIVE_GET_VERSION			"V1"
#define CT_ARCHIVE_GET_REPLY_VERSION		"V1"
extern struct xmlsd_v_elem xe_ct_archive_get_reply[];
