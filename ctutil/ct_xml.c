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

#include <xmlsd.h>
#include <ct_xml.h>

/* Cyphertite MD commands */

struct xmlsd_v_attr		ct_cmd_attr[] = {
	{ "version" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_md_file_attr[] = {
	{ "name" },
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
	{ "file",	"file.ct_md_list",	xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_elem             xe_ct_md_delete[] = {
	{ "ct_md_delete","",	ct_cmd_attr },
	{ "file",		"file.ct_md_delete", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};
