/* $chunkfs$ */
/*
 * Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
 * All rights reserved.
 */

#include <xmlsd.h>
#include <ct_xml.h>

/* Cyphertite MD commands */
struct xmlsd_v_attr		xa_ct_md_file_attr[] = {
	{ "name" },
	{ NULL }
};

struct xmlsd_v_attr		xa_ct_md_open_create_attr[] = {
	{ "version" },
	{ "test" },
	{ NULL }
};

struct xmlsd_v_elem             xe_ct_md_open_create[] = {
	{ "ct_md_open_create","",		xa_ct_md_open_create_attr },
	{ "file",	"file.ct_md_open_create", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_attr		xa_ct_md_open_read_attr[] = {
	{ "version" },
	{ "test" },
	{ NULL }
};

struct xmlsd_v_elem             xe_ct_md_open_read[] = {
	{ "ct_md_open_read","",	xa_ct_md_open_read_attr },
	{ "file",	"file.ct_md_open_read", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_attr		xa_ct_md_close_attr[] = {
	{ "version" },
	{ "test" },
	{ NULL }
};

struct xmlsd_v_elem             xe_ct_md_close[] = {
	{ "ct_md_close","",	xa_ct_md_close_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_attr		xa_ct_md_list_attr[] = {
	{ "version" },
	{ "test" },
	{ NULL }
};

struct xmlsd_v_elem             xe_ct_md_list[] = {
	{ "ct_md_list",		"",		xa_ct_md_list_attr },
	{ "file",	"file.ct_md_list",	xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};

struct xmlsd_v_attr		xa_ct_md_delete_attr[] = {
	{ "version" },
	{ "test" },
	{ NULL }
};

struct xmlsd_v_elem             xe_ct_md_delete[] = {
	{ "ct_md_delete","",	xa_ct_md_delete_attr },
	{ "file",		"file.ct_md_delete", xa_ct_md_file_attr },
	{ NULL,		NULL,			NULL}
};
