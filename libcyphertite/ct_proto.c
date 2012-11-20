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

#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <assl.h>
#include <clog.h>
#include <curl/curl.h>
#include <exude.h>
#include <xmlsd.h>
#include <shrink.h>

#include <ctutil.h>
#include <ct_socket.h>
#include "ct_xml.h"
#include "ct_proto.h"
#include <cyphertite.h>
#include "ct_internal.h"

void	*ct_body_alloc_xml(size_t);

int c_hdr_login_reply_ex_errcodes[] = {
	CTE_INVALID_CREDENTIALS,
	CTE_ACCOUNT_DISABLED,
};

int c_hdr_write_reply_ex_errcodes[] = {
	CTE_OUT_OF_SPACE,
};

int
ct_errcode_from_status(struct ct_header *hdr)
{
	int	ret = CTE_OPERATION_FAILED;

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

	switch (hdr->c_opcode) {
	case C_HDR_O_LOGIN_REPLY:
		if (hdr->c_ex_status > nitems(c_hdr_login_reply_ex_errcodes))
			break;
		ret = c_hdr_login_reply_ex_errcodes[hdr->c_ex_status];
		break;
	case C_HDR_O_WRITE_REPLY:
		if (hdr->c_ex_status > nitems(c_hdr_write_reply_ex_errcodes))
			break;
		ret = c_hdr_write_reply_ex_errcodes[hdr->c_ex_status];
		break;
	default:
		break;

	}
#undef nitems

	return (ret);
}
/*
 * For use with xmlsd_generate for allocating xml bodies.
 * The body alloc is done directly instead of in another path so as to
 * decouple xml size from chunk size.
 */
void *
ct_body_alloc_xml(size_t sz)
{
	return (e_calloc(1, sz));
}

int
ct_create_neg(struct ct_header *hdr, void **vbody, int max_trans,
    int max_block_size)
{
	uint8_t		*body;

	/* send server request */
	bzero(hdr, sizeof(*hdr));
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_NEG;
	hdr->c_size = 8;

	body = e_calloc(8, sizeof(*body));
	body[0] = (max_trans >>  0) & 0xff;
	body[1] = (max_trans >>  8) & 0xff;
	body[2] = (max_trans >> 16) & 0xff;
	body[3] = (max_trans >> 24) & 0xff;
	body[4] = (max_block_size >>  0) & 0xff;
	body[5] = (max_block_size >>  8) & 0xff;
	body[6] = (max_block_size >> 16) & 0xff;
	body[7] = (max_block_size >> 24) & 0xff;

	*vbody = body;
	return (0);
}

int
ct_parse_neg_reply(struct ct_header *hdr, void *body, int *max_trans,
    int *max_block_size)
{
	uint8_t		*buf = body;

	if (hdr->c_version != C_HDR_VERSION)
		return (CTE_INVALID_REPLY_VERSION);
	if (hdr->c_opcode != C_HDR_O_NEG_REPLY)
		return (CTE_INVALID_REPLY_TYPE);
	if (hdr->c_size != 8)
		return (CTE_INVALID_REPLY_LEN);

	*max_trans = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	*max_block_size = buf[4] | (buf[5] << 8) | (buf[6] << 16) |
	    (buf[7] << 24);
	return (0);
}

int
ct_create_login(struct ct_header *hdr, void **vbody, const char *username,
    const char *passphrase)
{
	int				 user_len, payload_sz;
	char				 b64_digest[128];
	char				*body;
	uint8_t				 pwd_digest[SHA512_DIGEST_LENGTH];

	ct_sha512((uint8_t *)passphrase, pwd_digest, strlen(passphrase));
	if (ct_base64_encode(CT_B64_ENCODE, pwd_digest, sizeof pwd_digest,
	    (uint8_t *)b64_digest, sizeof b64_digest)) {
		return (CTE_CANT_BASE64);
	}

	user_len = strlen(username);
	payload_sz = user_len + 1 + strlen(b64_digest) + 1;

	body = e_calloc(1, payload_sz);

	strlcpy(body, username, payload_sz);
	strlcpy(body + user_len + 1, b64_digest,
	    payload_sz - user_len - 1);

	/* login in polled mode */
	bzero(hdr, sizeof hdr);
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_LOGIN;
	hdr->c_tag = 1;
	hdr->c_size = payload_sz;
	hdr->c_flags = 0; /* XXX used to be compress type, but unused. */

	*vbody = body;
	return (0);

}

int
ct_parse_login_reply(struct ct_header *hdr, void *body)
{
	if (hdr->c_version != C_HDR_VERSION)
		return (CTE_INVALID_REPLY_VERSION);
	if (hdr->c_opcode != C_HDR_O_LOGIN_REPLY)
		return (CTE_INVALID_REPLY_TYPE);
	if (hdr->c_status != C_HDR_S_OK)
		return (ct_errcode_from_status(hdr));
	if (hdr->c_size != 0)
		return (CTE_INVALID_REPLY_LEN);

	return (0);
}

#include <sys/utsname.h>
char *
ct_os_version(void)
{
	struct utsname	 u;
	char		*os_string;

	if (uname(&u) == -1)
		e_asprintf(&os_string, "INVALID");
	else
		e_asprintf(&os_string, "%s-%s-%s %s\n",
		    u.sysname, u.machine, u.release, u.version);
	return (os_string);
}

int
ct_create_xml_negotiate(struct ct_header *hdr, void **vbody,
    int32_t dbgenid)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*root, *xe;
	char				*body;
	char				*os_version = NULL;
	char				*verbuf = NULL;
	size_t				 orig_size;
	int				 ret = CTE_XMLSD_FAILURE;
#ifdef BUILDSTR
	static const char *vertag = CT_VERSION " " BUILDSTR;
#else
	static const char *vertag = CT_VERSION;
#endif
	static const char *opensslver = "version: " OPENSSL_VERSION_TEXT;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_tag = 0;

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((root = xmlsd_doc_add_elem(xl, NULL, "ct_negotiate")) == NULL)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, root, "clientdbgenid")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr_int32(xe, "value", dbgenid) != 0)
		goto out;
	/* Send library version. */
	if ((xe = xmlsd_doc_add_elem(xl, root, "libcyphertite_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", vertag) != 0)
		goto out;
	/*
	 * Add version for all libraries we care about so we can be warned
	 * about incompatibilities.
	 */
	if ((xe = xmlsd_doc_add_elem(xl, root, "assl_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", assl_verstring()) != 0)
		goto out;
#ifdef NEED_LIBCLENS
	if ((xe = xmlsd_doc_add_elem(xl, root, "clens_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", clens_verstring()) != 0)
		goto out;
#endif /* NEED_LIBCLENS */
	if ((xe = xmlsd_doc_add_elem(xl, root, "clog_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", clog_verstring()) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, root, "curl_version")) == NULL)
		goto out;
	e_asprintf(&verbuf, "version: %s", curl_version());
	if (xmlsd_elem_set_attr(xe, "value", verbuf) != 0)
		goto out;
	e_free(&verbuf);
	if ((xe = xmlsd_doc_add_elem(xl, root, "event_version")) == NULL)
		goto out;
	e_asprintf(&verbuf, "version: %s", event_get_version());
	if (xmlsd_elem_set_attr(xe, "value", event_get_version()) != 0)
		goto out;
	e_free(&verbuf);
	if ((xe = xmlsd_doc_add_elem(xl, root, "exude_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", exude_verstring()) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, root, "openssl_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", opensslver) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, root, "shrink_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", shrink_verstring()) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, root, "xmlsd_version")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "value", xmlsd_verstring()) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, root, "os_version")) == NULL)
		goto out;
	os_version = ct_os_version();
	if (xmlsd_elem_set_attr(xe, "value", os_version) != 0)
		goto out;

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &orig_size,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;
	ret = 0;
	hdr->c_size = orig_size;

	*vbody = body;
out:
	if (os_version)
		e_free(&os_version);
	if (verbuf)
		e_free(&verbuf);
	xmlsd_doc_free(xl);
	return (ret);

}

int
ct_parse_xml_negotiate_reply(struct ct_header *hdr, void *body,
    struct ctdb_state *ctdb)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe, *xc;
	char			*xml_body = body;
	const char		*err;
	int			attrval_i = -1;
	int			r, rv;

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((r = xmlsd_parse_mem(xml_body, hdr->c_size - 1,
	    xl)) != XMLSD_ERR_SUCCES) {
		CNDBG(CT_LOG_NET, "xml reply '[%s]'", xml_body ? xml_body :
		    "<NULL>");
		rv = CTE_XML_PARSE_FAIL;
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

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_negotiate_reply") != 0) {
		CNDBG(CT_LOG_XML, "invalid xml type %s",
		    xmlsd_elem_get_name(xe));
		rv = CTE_INVALID_XML_TYPE;
		goto done;
	}

	XMLSD_ELEM_FOREACH_CHILDREN(xc, xe) {
		if (strcmp(xmlsd_elem_get_name(xc), "clientdbgenid") == 0) {
			err = NULL;
			attrval_i = xmlsd_elem_get_attr_strtonum(xc, "value",
			    -1, INT_MAX, &err);
			if (err) {
				CNDBG(CT_LOG_XML,
				    "unable to parse clientdbgenid [%s]",
				    xmlsd_elem_get_attr(xe, "value"));
				rv = CTE_XML_PARSE_FAIL;
				goto done;
			}
			CNDBG(CT_LOG_NET, "got cliendbgenid value %d",
			    attrval_i);
			break;
		}
	}

	if (attrval_i != -1 && attrval_i !=
	    ctdb_get_genid(ctdb)) {
		ctdb_set_genid(ctdb, attrval_i);
	}


	rv = 0;
done:
	xmlsd_doc_free(xl);
	return rv; /* success */
}

int
ct_create_exists(struct ct_header *hdr, void **vbody, uint8_t *sha,
    size_t shasz)
{
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_EXISTS;
	hdr->c_size = shasz;
	/*
	 * Do not zero out flags, caller often is using this header
	 * to keep track whether data is currently encrypted etc.
	 */
	*vbody = sha;

	return (0);
}

int
ct_parse_exists_reply(struct ct_header *hdr, void *body, int *exists)
{
	if (hdr->c_version != C_HDR_VERSION)
		return (CTE_INVALID_REPLY_VERSION);
	if (hdr->c_opcode != C_HDR_O_EXISTS_REPLY)
		return (CTE_INVALID_REPLY_TYPE);

	switch (hdr->c_status) {
	case C_HDR_S_FAIL:
		return (CTE_OPERATION_FAILED); /* XXX better errno? */
	case C_HDR_S_EXISTS:
		*exists = 1;
		break;
	case C_HDR_S_DOESNTEXIST:
		*exists = 0;
		break;
	default:
		return (CTE_INVALID_REPLY_TYPE);
	}
	return (0);
}

int
ct_create_write(struct ct_header *hdr, void **vbody, uint8_t *data,
    size_t datasize)
{
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_WRITE;
	hdr->c_size = datasize;

	*vbody = data;
	return (0);
}

int
ct_create_ctfile_write(struct ct_header *hdr, void **vbody, int *nbody,
    uint8_t *data, size_t datasize, uint32_t chunkno)
{
	struct ct_metadata_footer	*cmf;
	struct ct_iovec			*iov;
	int				 rv;

	/* do normal write preparation */
	if ((rv = ct_create_write(hdr, vbody, data, datasize)) != 0)
		return (rv);

	iov = e_calloc(2, sizeof(*iov));
	cmf = e_calloc(1, sizeof(*cmf));
	cmf->cmf_chunkno = htonl(chunkno);
	cmf->cmf_size = htonl(hdr->c_size);

	iov[0].iov_base = data;
	iov[0].iov_len = hdr->c_size;
	iov[1].iov_base = cmf;
	iov[1].iov_len = sizeof(*cmf);

	hdr->c_size += sizeof(*cmf);
	*vbody = iov;
	*nbody = 2;

	return (0);
}


int
ct_parse_write_reply(struct ct_header *hdr, void *vbody)
{
	if (hdr->c_version != C_HDR_VERSION)
		return (CTE_INVALID_REPLY_VERSION);
	if (hdr->c_opcode != C_HDR_O_WRITE_REPLY)
		return (CTE_INVALID_REPLY_TYPE);
	if (hdr->c_status != C_HDR_S_OK)
		return (ct_errcode_from_status(hdr));
	return (0);
}

/*
 * Create a read packet for the sha ``sha''. Header flags and tag are set by
 * caller, the rest of the header will be overwritten.
 */
int
ct_create_read(struct ct_header *hdr, void **vbody, uint8_t *sha, size_t shasz)
{
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_READ;
	hdr->c_size = shasz;
	/* hdr->c_flags set by caller */

	*vbody = sha;
	return (0);
}

int
ct_parse_read_reply(struct ct_header *hdr, void *vbody)
{
	if (hdr->c_version != C_HDR_VERSION)
		return (CTE_INVALID_REPLY_VERSION);
	if (hdr->c_opcode != C_HDR_O_READ_REPLY)
		return (CTE_INVALID_REPLY_TYPE);
	if (hdr->c_status != C_HDR_S_OK)
		return (ct_errcode_from_status(hdr));
	return (0);
}

int
ct_parse_read_ctfile_chunk_info(struct ct_header *hdr, void *vbody,
    uint32_t expected_chunkno)
{
	struct ct_metadata_footer	*cmf;

	/* Not metadata? */
	if ((hdr->c_flags & C_HDR_F_METADATA) == 0) {
		/* invalid to call with a packet without metadata set. */
		CABORTX("not metadata packet");
	}
	/*
	 * The server will only send ctfileproto v1 (ex_status == 0) or
	 * v3 (ex_status == 2), v3 fixed a byteswapping issue in v2. v2
	 * will never be sent to a client that speaks other versions.
	 */
	if (hdr->c_ex_status != 0 && hdr->c_ex_status != 2)
		return (CTE_INVALID_CTFILE_PROTOCOL);
	if (hdr->c_ex_status == 2) {
			cmf = (struct ct_metadata_footer *)
			    ((uint8_t *)vbody + hdr->c_size - sizeof(*cmf));
			cmf->cmf_size = ntohl(cmf->cmf_size);
			cmf->cmf_chunkno = ntohl(cmf->cmf_chunkno);

			CNDBG(CT_LOG_CTFILE,
			    "size: a %" PRIu32 "d e %" PRIu32
			    "chunkno a %" PRIu32 "d e %" PRIu32, cmf->cmf_size,
			    (uint32_t)(hdr->c_size - sizeof(*cmf)),
			    cmf->cmf_chunkno, expected_chunkno);
			if (cmf->cmf_size != hdr->c_size - sizeof(*cmf))
				return (CTE_INVALID_CTFILE_FOOTER);
			if (cmf->cmf_chunkno != expected_chunkno)
				return (CTE_INVALID_CTFILE_CHUNKNO);
			hdr->c_size -= sizeof(*cmf);
	}

	return (0);
}

static struct xmlsd_v_elements ct_xml_open_cmds[] = {
	{ "ct_md_open_read", xe_ct_md_open_read },
	{ "ct_md_open_create", xe_ct_md_open_create },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_close_cmds[] = {
	{ "ct_md_close", xe_ct_md_close },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_list_cmds[] = {
	{ "ct_md_list", xe_ct_md_list },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_delete_cmds[] = {
	{ "ct_md_delete", xe_ct_md_delete },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_cull_setup_cmds[] = {
	{ "ct_cull_setup_reply", xe_ct_cull_setup_reply },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_cull_shas_cmds[] = {
	{ "ct_cull_shas_reply", xe_ct_cull_shas_reply },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_cull_complete_cmds[] = {
	{ "ct_cull_complete_reply", xe_ct_cull_complete_reply },
	{ NULL, NULL }
};

static struct xmlsd_v_elements ct_xml_unsolicited_cmds[] = {
	{ "ct_clientdb_newver", xe_ct_clientdb_newver },
	{ NULL, NULL }
};

int
ct_parse_xml_prepare(struct ct_header *hdr, void *vbody,
    struct xmlsd_v_elements *x_cmds, struct xmlsd_document **xl)
{
#if 0
	struct xmlsd_attribute	*xa;
	struct xmlsd_element	*xe;
#endif
	char			*body = vbody;
	int			 r;

	CNDBG(CT_LOG_XML, "xml [%s]", (char *)vbody);

	/* Dispose of last parsed command. */
	if ((xmlsd_doc_alloc(xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	r = xmlsd_parse_mem(body, hdr->c_size - 1, *xl);
	if (r) {
		CNDBG(CT_LOG_XML, "XML parse failed! (%d)", r);
		xmlsd_doc_free(*xl);
		return (CTE_XML_PARSE_FAIL);
	}

#if 0
	TAILQ_FOREACH(xe, xl, entry) {
		CNDBG(CT_LOG_XML, "%d %s = %s (parent = %s)",
		    xe->depth, xmsld_elem_get_name(xe), xe->value ? xe->value : "NOVAL",
		    xe->parent ? xe->parent->name : "NOPARENT");
		TAILQ_FOREACH(xa, &xe->attr_list, entry)
			CNDBG(CT_LOG_XML, "\t%s = %s", xa->name, xa->value);
	}
#endif

	if ((r = xmlsd_validate(*xl, x_cmds)) != 0) {
		CNDBG(CT_LOG_XML, "XML validate of '%s' failed! (%d)", body, r);
		xmlsd_doc_free(*xl);
		return (CTE_INVALID_XML_TYPE);
	}

	if (xmlsd_doc_is_empty(*xl)) {
		CNDBG(CT_LOG_XML, "parse command: No XML");
		xmlsd_doc_free(*xl);
		return (CTE_EMPTY_XML);
	}

	return (0);
}

/*
 * Create an xml open packet for file with mode at chunkno.
 * header is preallocated and passed in, body is allocated and returned.
 * hdr->c_tag is *not* set.
 */
int
ct_create_xml_open(struct ct_header *hdr, void **vbody, const char *file,
    int mode, uint32_t chunkno)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xe;
	char				*body = NULL;
	char			 	 b64[CT_MAX_MD_FILENAME];
	size_t			 	 sz;
	int				 rv = CTE_XMLSD_FAILURE;

	CNDBG(CT_LOG_XML, "settting up XML open for %s", file);
	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)file, strlen(file),
	    (uint8_t *)b64, sizeof(b64))) {
		CNDBG(CT_LOG_CTFILE, "can't base64 encode %s", file);
		return (CTE_CANT_BASE64);
	}

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if (mode == MD_O_WRITE || mode == MD_O_APPEND) {
		if ((xe = xmlsd_doc_add_elem(xl, NULL,
		    "ct_md_open_create")) == NULL)
			goto out;
		if (xmlsd_elem_set_attr(xe, "version",
		    CT_MD_OPEN_CREATE_VERSION) != 0)
			goto out;
	} else {	/* mode == MD_O_READ */
		if ((xe = xmlsd_doc_add_elem(xl, NULL,
		    "ct_md_open_read")) == NULL)
			goto out;
		if (xmlsd_elem_set_attr(xe, "version",
		    CT_MD_OPEN_READ_VERSION) != 0)
			goto out;
	}

	if ((xe = xmlsd_doc_add_elem(xl, xe, "file")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "name", b64) != 0)
		goto out;
	if (mode == MD_O_APPEND || chunkno) {
		if (xmlsd_elem_set_attr_uint32(xe, "chunkno", chunkno) != 0)
			goto out;
	}

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER))  == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	rv = 0;
out:
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_parse_xml_open_reply(struct ct_header *hdr, void *vbody, char **filename)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xe, *xc;
	int				 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody, ct_xml_open_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strncmp(xmlsd_elem_get_name(xe), "ct_md_open",
	    strlen("ct_md_open")) == 0) {
		XMLSD_ELEM_FOREACH_CHILDREN(xc, xe) {
			if (strcmp(xmlsd_elem_get_name(xc), "file") == 0) {
				*filename =
				    e_strdup(xmlsd_elem_get_attr(xc, "name"));
				if (*filename[0] == '\0')
					e_free(filename);
			}
		}
		rv = 0;
	} else {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_create_xml_close(struct ct_header *hdr, void **vbody)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xe;
	char				*body;
	size_t				 sz;
	int				 rv = CTE_XMLSD_FAILURE;

	CNDBG(CT_LOG_XML, "creating xml close packet");
	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((xe = xmlsd_doc_add_elem(xl, NULL, "ct_md_close")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "version", CT_MD_CLOSE_VERSION) != 0)
		goto out;
	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	rv = 0;
out:
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_parse_xml_close_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe;
	int			 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_close_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_md_close") == 0) {
		rv = 0;
	} else {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_create_xml_list(struct ct_header *hdr, void **vbody)
{
	struct xmlsd_document	 	*xl;
	struct xmlsd_element		*xe;
	char				*body;
	size_t				 sz;
	int				 rv = CTE_XMLSD_FAILURE;

	CNDBG(CT_LOG_XML, "creating xml list packet");

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((xe = xmlsd_doc_add_elem(xl, NULL, "ct_md_list")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "version", CT_MD_LIST_VERSION) != 0)
		goto out;

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	rv = 0;
out:
	xmlsd_doc_free(xl);
	return (rv);
}


int
ct_parse_xml_list_reply(struct ct_header *hdr, void *vbody,
    struct ctfile_list *head)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe, *xc;
	int			 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_list_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_md_list") == 0) {
		struct ctfile_list_file	*file;
		const char		*errstr, *tmp;

		XMLSD_ELEM_FOREACH_CHILDREN(xc, xe) {
			if (strcmp(xmlsd_elem_get_name(xc), "file") == 0) {
				file = e_malloc(sizeof(*file));
				tmp = xmlsd_elem_get_attr(xc, "name");
				if (tmp == NULL) {
					e_free(&file);
					continue;
				}

				if (ct_base64_encode(CT_B64_M_DECODE,
				    (uint8_t *)tmp, strlen(tmp),
				    (uint8_t *)file->mlf_name,
				    sizeof(file->mlf_name))) {
					    e_free(&file);
					    continue;
				}

				tmp = xmlsd_elem_get_attr(xc, "size");
				file->mlf_size = strtonum(tmp, 0, LLONG_MAX,
				    &errstr);
				if (errstr != NULL) {
					CNDBG(CT_LOG_XML,
					    "can't parse file size %s", errstr);
					e_free(&file);
					continue;
				}

				tmp = xmlsd_elem_get_attr(xc, "mtime");
				file->mlf_mtime = strtonum(tmp, 0, LLONG_MAX,
				    &errstr);
				if (errstr != NULL) {
					e_free(&file);
					CNDBG(CT_LOG_XML,
					    "can't parse file mtime %s",
					    errstr);
					e_free(&file);
					continue;
				}
				SIMPLEQ_INSERT_TAIL(head, file, mlf_link);
			}
		}
	} else  {
		rv = CTE_INVALID_XML_TYPE;
	}
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_create_xml_delete(struct ct_header *hdr, void **vbody, const char *name)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xe;
	char				*body;
	char				 b64[CT_MAX_MD_FILENAME * 2];
	size_t				 sz;
	int				 rv = CTE_XMLSD_FAILURE;

	CNDBG(CT_LOG_XML, "creating xml delete for %s", name);
	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)name, strlen(name),
	    (uint8_t *)b64, sizeof(b64))) {
		CNDBG(CT_LOG_CTFILE, "can't base64 encode %s", name);
		return (CTE_CANT_BASE64);
	}

	if (xmlsd_doc_alloc(&xl) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((xe = xmlsd_doc_add_elem(xl, NULL, "ct_md_delete")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "version", CT_MD_DELETE_VERSION) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, xe, "file")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "name", b64))
		goto out;

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	rv = 0;
out:
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_parse_xml_delete_reply(struct ct_header *hdr, void *vbody, char **filename)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe, *xc;
	char			 b64[CT_MAX_MD_FILENAME * 2];
	int			 rv;
	const char		*fname;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_delete_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_md_delete") == 0) {
		XMLSD_ELEM_FOREACH_CHILDREN(xc, xe) {
			if (strcmp(xmlsd_elem_get_name(xc), "file") == 0) {
				fname = xmlsd_elem_get_attr(xc, "name");
				if (fname[0] == '\0') {
					fname = NULL;
					continue;
				}
				if (ct_base64_encode(CT_B64_M_DECODE,
				    (uint8_t *)fname, strlen(fname),
				    (uint8_t *)b64, sizeof(b64))) {
					CNDBG(CT_LOG_XML,
					    "cant base64 decode %s",
					    *filename);
					return (CTE_CANT_BASE64);
				}
				*filename = e_strdup(b64);
			}
		}
		rv = 0;
	} else  {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_create_xml_cull_setup(struct ct_header *hdr, void **vbody,
    uint64_t cull_uuid, int mode)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xp, *xe;
	char				*body;
	char				*type;
	size_t				 sz;
	int				 rv = CTE_XMLSD_FAILURE;

	CNDBG(CT_LOG_XML, "creating xml cull setup");

	switch (mode) {
	case CT_CULL_PRECIOUS:
		type = "precious";
		break;
	default:
		CABORTX("invalid cull type %d", mode);
	};

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((xp = xmlsd_doc_add_elem(xl, NULL,
	    "ct_cull_setup")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xp, "version", CT_CULL_SETUP_VERSION) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, xp, "cull")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "type", type) != 0)
		goto out;
	if (xmlsd_elem_set_attr_uint64(xe, "uuid", cull_uuid) != 0)
		goto out;

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	rv = 0;

out:
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_parse_xml_cull_setup_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe;
	int			 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_cull_setup_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_cull_setup_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_setup_reply");
		rv = 0;
	} else  {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_create_xml_cull_shas(struct ct_header *hdr, void **vbody, uint64_t cull_uuid,
    struct ct_sha_lookup *head, int sha_per_packet, int *no_shas)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xe, *xp;
	struct sha_entry		*node;
	char				*body;
	char				shat[SHA_DIGEST_STRING_LENGTH];
	size_t				sz;
	int				shas_in_packet = 0;
	int				rv = CTE_XMLSD_FAILURE;

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((xp = xmlsd_doc_add_elem(xl, NULL,
	    "ct_cull_shas")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xp, "version", CT_CULL_SHA_VERSION) != 0)
		goto out;

	if ((xe = xmlsd_doc_add_elem(xl, xp, "uuid")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr_uint64(xe, "value", cull_uuid) != 0)
		goto out;

	while ((node = RB_ROOT(head)) != NULL &&
	    shas_in_packet < sha_per_packet) {
		if ((xe = xmlsd_doc_add_elem(xl, xp, "sha")) == NULL)
			goto out;
		ct_sha1_encode(node->sha, shat);
		//CNDBG(CT_LOG_SHA, "adding sha %s\n", shat);
		if (xmlsd_elem_set_attr(xe, "sha", shat) != 0)
			goto out;
		shas_in_packet++;

		RB_REMOVE(ct_sha_lookup, head, node);
		e_free(&node);
	}

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	if (no_shas)
		*no_shas = shas_in_packet;
	*vbody = body;
	rv = 0;
out:
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_parse_xml_cull_shas_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe;
	int			 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_cull_shas_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_cull_shas_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_shas_reply");
		rv = 0;
	} else  {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_create_xml_cull_complete(struct ct_header *hdr, void **vbody,
    uint64_t cull_uuid, int mode)
{
	struct xmlsd_document		*xl;
	struct xmlsd_element		*xp, *xe;
	char				*body;
	char				*type;
	size_t				 sz;
	int				 rv = CTE_XMLSD_FAILURE;

	CNDBG(CT_LOG_XML, "creating xml cull setup");

	switch (mode) {
	case CT_CULL_PROCESS:
		type = "process";
		break;
	default:
		CABORTX("invalid cull type %d", mode);
	};

	if ((xmlsd_doc_alloc(&xl)) != XMLSD_ERR_SUCCES)
		return (CTE_XMLSD_FAILURE);

	if ((xp = xmlsd_doc_add_elem(xl, NULL,
	    "ct_cull_complete")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xp, "version", CT_CULL_COMPLETE_VERSION) != 0)
		goto out;
	if ((xe = xmlsd_doc_add_elem(xl, xp, "cull")) == NULL)
		goto out;
	if (xmlsd_elem_set_attr(xe, "type", type) != 0)
		goto out;
	if (xmlsd_elem_set_attr_uint64(xe, "uuid", cull_uuid) != 0)
		goto out;

	if ((body = xmlsd_generate(xl, ct_body_alloc_xml, &sz,
	    XMLSD_GEN_ADD_HEADER)) == NULL)
		goto out;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	rv = 0;
out:
	xmlsd_doc_free(xl);
	return (rv);
}

int
ct_parse_xml_cull_complete_reply(struct ct_header *hdr, void *vbody,
    int32_t *newgenid)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe;
	const char		*errstr;
	int			 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_cull_complete_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_cull_complete_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_complete_reply");
		*newgenid = xmlsd_elem_get_attr_strtonum(xe, "clientdbgenid",
		    INT32_MIN, INT32_MAX, &errstr);
		if (errstr != NULL) {
			CNDBG(CT_LOG_XML, "failed to get clientdbgenid: %s",
			    errstr);
			*newgenid = -1;
		}
		rv = 0;
	} else  {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}

/*
 * Cleanup any resources that we allocated just for protocol reasons.
 * To be called after the data has been sent.
 * The header and the main body information (as passed into the api by the
 * caller) still belong to the caller.
 */
void
ct_cleanup_packet(struct ct_header *hdr, void *vbody)
{
	/* ctfile write footer api allocates extra data */
	if (hdr->c_opcode == C_HDR_O_WRITE &&
	    hdr->c_flags & C_HDR_F_METADATA) {
		/* free iovec and footer data */
		struct ct_iovec	*iov = vbody;

		e_free(&iov[1].iov_base);
		/* real body was in iov[0] and belongs to caller */
		e_free(&iov);
	}
}

#include <cyphertite.h>
/*
 * XXX proto.c functions generally don't know about global state
 */
int
ct_handle_unsolicited_xml(struct ct_header *hdr, void *vbody,
    struct ct_global_state *state)
{
	struct xmlsd_document	*xl;
	struct xmlsd_element	*xe;
	const char		*errstr;
	int32_t 		 newgenid;
	int			 rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_unsolicited_cmds, &xl)) != 0)
		return (rv);

	xe = xmlsd_doc_get_first_elem(xl);
	if (strcmp(xmlsd_elem_get_name(xe), "ct_clientdb_newver") == 0) {
		CNDBG(CT_LOG_XML, "ct_clientdb_newver");
		newgenid = xmlsd_elem_get_attr_strtonum(xe, "clientdbgenid",
		    INT32_MIN, INT32_MAX, &errstr);
		if (errstr != NULL) {
			CNDBG(CT_LOG_XML, "failed to get clientdbgenid: %s",
			    errstr);
			newgenid = -1;
		}

		CNDBG(CT_LOG_XML, "newgenid message with genid %d", newgenid);
		ctdb_set_genid(state->ct_db_state, newgenid);
		state->ct_cull_occurred = 1;
		ct_wakeup_file(state->event_state);

		rv = 0;
	} else  {
		rv = CTE_INVALID_XML_TYPE;
	}

	xmlsd_doc_free(xl);
	return (rv);
}
