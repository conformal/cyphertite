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

#include <xmlsd.h>
#include <ct_xml.h>


/* Cyphertite MD commands */

struct xmlsd_v_attr		ct_cmd_attr[] = {
	{ "version" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_md_file_attr[] = {
	{ "name" },
	{ "size" },
	{ "mtime" },
	{ "chunkno" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_cull_attr[] = {
	{ "type" },
	{ "uuid" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_sha_attr[] = {
	{ "sha" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_value_attr[] = {
	{ "value" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_reply_attr[] = {
	{ "version" },
	{ "xmlversion" },
	{ "success" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_clientdb_newver_attr[] = {
	{ "version" },
	{ "clientdbgenid" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_cull_reply_attr[] = {
	{ "version" },
	{ "success" },
	{ "clientdbgenid" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_archive_ctfile_attr[] = {
	{ "xmlversion" },
	{ "tag" },
	{ "timestamp" },
	{ "level" },
	{ "version" },
	{ "mtime" },
	{ "size" },
	{ "success" },
	{ NULL }
};

struct xmlsd_v_elem             xe_ct_md_open_create[] = {
	{ "ct_md_open_create","",		ct_cmd_attr },
	{ "file",	"file.ct_md_open_create", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_md_open_read[] = {
	{ "ct_md_open_read","",	ct_cmd_attr },
	{ "file",	"file.ct_md_open_read", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_md_close[] = {
	{ "ct_md_close","",	ct_cmd_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_md_list[] = {
	{ "ct_md_list",		"",		ct_cmd_attr },
	{ "file",		"file.ct_md_list", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_md_delete[] = {
	{ "ct_md_delete","",	ct_cmd_attr },
	{ "file",		"file.ct_md_delete", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_cull_setup[] = {
	{ "ct_cull_setup","",			ct_cmd_attr },
	{ "cull", "cull.ct_cull_setup",	xa_ct_cull_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_cull_setup_reply[] = {
	{ "ct_cull_setup_reply","",		xa_ct_reply_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_cull_shas[] = {
	{ "ct_cull_shas","",	ct_cmd_attr },
	{ "uuid", "uuid.ct_cull_shas",		xa_ct_value_attr },
	{ "sha", "sha.ct_cull_shas",		xa_ct_sha_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_cull_shas_reply[] = {
	{ "ct_cull_shas_reply","",		xa_ct_reply_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_cull_complete[] = {
	{ "ct_cull_complete","",		ct_cmd_attr },
	{ "cull", "cull.ct_cull_complete",	xa_ct_cull_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_cull_complete_reply[] = {
	{ "ct_cull_complete_reply","",		xa_ct_cull_reply_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem		xe_ct_negotiate_reply[] = {
	{ "ct_negotiate_reply","",		xa_ct_reply_attr },
	{ "clientdbgenid", "clientdbgenid.ct_negotiate_reply",
	    xa_ct_value_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem		xe_ct_clientdb_newver[] = {
	{ "ct_clientdb_newver","",		xa_ct_clientdb_newver_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem		xe_ct_clientdb_newver_reply[] = {
	{ "ct_clientdb_newver_reply","",		xa_ct_reply_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_attr		xa_ct_archive_reply_attr[] = {
	{ "xmlversion", XMLSD_V_ATTR_F_REQUIRED  },
	{ "success",  XMLSD_V_ATTR_F_REQUIRED },
	{ NULL }
};

struct xmlsd_v_elem		xe_ct_archive_create_reply[] = {
	{ "ct_archive_create_reply","",		xa_ct_archive_reply_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem		xe_ct_archive_remove_reply[] = {
	{ "ct_archive_remove_reply","",		xa_ct_archive_reply_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem		xe_ct_archive_list_reply[] = {
	{ "ct_archive_list_reply","",		xa_ct_reply_attr },
	{ "archive", "archive.ct_archive_list_reply",
	    xa_ct_archive_ctfile_attr },
	{ NULL,		NULL,			NULL}
};
struct xmlsd_v_elem		xe_ct_archive_get_reply[] = {
	{ "ct_archive_get_reply","",		xa_ct_archive_ctfile_attr },
	{ "chunk", "chunk.ct_archive_get_reply", xa_ct_sha_attr },
	{ NULL,		NULL,			NULL}
};
