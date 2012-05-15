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
#include <unistd.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <clog.h>
#include <exude.h>
#include <xmlsd.h>

#include <ctutil.h>
#include <ct_socket.h>
#include "ct_xml.h"
#include "ct_proto.h"

void	*ct_body_alloc_xml(size_t);

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
	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_NEG;
	hdr->c_tag = max_trans;		/* XXX - fix */
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
	
	if (hdr->c_version != C_HDR_VERSION ||
	    hdr->c_opcode != C_HDR_O_NEG_REPLY ||
	    hdr->c_size != 8) {
		return (1);
	}

	*max_trans = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	*max_block_size = buf[4] | (buf[5] << 8) | (buf[6] << 16) |
	    (buf[7] << 24);
	return (0);
}

int
ct_create_login(struct ct_header *hdr, void **vbody, const char *username, const
char *passphrase)
{
	int				 user_len, payload_sz;
	char				 b64_digest[128];
	char				*body;
	uint8_t				 pwd_digest[SHA512_DIGEST_LENGTH];

	ct_sha512((uint8_t *)passphrase, pwd_digest, strlen(passphrase));
	if (ct_base64_encode(CT_B64_ENCODE, pwd_digest, sizeof pwd_digest,
	    (uint8_t *)b64_digest, sizeof b64_digest)) {
		CWARNX("can't base64 encode password");
		return (1);
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
	if (hdr->c_version != C_HDR_VERSION) {
		CWARNX("invalid protocol version %d", hdr->c_version);
		return (1);
	}
	if (hdr->c_opcode != C_HDR_O_LOGIN_REPLY) {
		CWARNX("invalid opcode %d", hdr->c_opcode);
		return (1);
	}
	if (hdr->c_status != C_HDR_S_OK) {
		CWARNX("login failed: %s", ct_header_strerror(hdr));
		return (1);
	}
	if (hdr->c_size != 0) {
		CWARNX("invalid server reply");
		return (1);
	}

	return (0);
}

int
ct_create_xml_negotiate(struct ct_header *hdr, void **vbody,
    int32_t dbgenid)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	char				*body;
	size_t				 orig_size;

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_tag = 0;

	xe = xmlsd_create(&xl, "ct_negotiate");
	xe = xmlsd_add_element(&xl, xe, "clientdbgenid");
	xmlsd_set_attr_int32(xe, "value", dbgenid);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &orig_size, 1);
	hdr->c_size = orig_size;

	*vbody = body;
	return (0);

}

int
ct_parse_xml_negotiate_reply(struct ct_header *hdr, void *body,
    struct ctdb_state *ctdb)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element	*xe;
	char			*attrval;
	char			*xml_body = body;
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
	    ctdb_get_genid(ctdb)) {
		CINFO("need to recreate localdb");
		ctdb_reopendb(ctdb, attrval_i);
	}


	xmlsd_unwind(&xl);
	rv = 0;
done:
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
		return (1);
	if (hdr->c_opcode != C_HDR_O_EXISTS_REPLY)
		return (1);
	switch (hdr->c_status) {
	case C_HDR_S_FAIL:
		return (1);
	case C_HDR_S_EXISTS:
		*exists = 1;
		break;
	case C_HDR_S_DOESNTEXIST:
		*exists = 0;
		break;
	default:
		return (1);
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
		return (1);
	if (hdr->c_opcode != C_HDR_O_WRITE_REPLY)
		return (1);
	if (hdr->c_status != C_HDR_S_OK)
		return (1);
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
		return (1);
	if (hdr->c_opcode != C_HDR_O_READ_REPLY)
		return (1);
	if (hdr->c_status != C_HDR_S_OK)
		return (1);
	return (0);
}

int
ct_parse_read_ctfile_chunk_info(struct ct_header *hdr, void *vbody,
    uint32_t expected_chunkno)
{
	struct ct_metadata_footer	*cmf;

	/* Not metadata? */
	if ((hdr->c_flags & C_HDR_F_METADATA) == 0) {
		CWARNX("not metadata packet");
		return (1);
	}
	/*
	 * The server will only send ctfileproto v1 (ex_status == 0) or
	 * v3 (ex_status == 2), v3 fixed a byteswapping issue in v2. v2
	 * will never be sent to a client that speaks other versions.
	 */
	if (hdr->c_ex_status != 0 && hdr->c_ex_status != 2) {
	       CWARNX("invalid metadata prootcol (v%d)",
	           hdr->c_ex_status + 1);
		return (1);
	}
	if (hdr->c_ex_status == 2) {
			cmf = (struct ct_metadata_footer *)
			    ((uint8_t *)vbody + hdr->c_size - sizeof(*cmf));
			cmf->cmf_size = ntohl(cmf->cmf_size);
			cmf->cmf_chunkno = ntohl(cmf->cmf_chunkno);

			if (cmf->cmf_size != hdr->c_size - sizeof(*cmf))
				CFATALX("invalid chunkfile footer");
			if (cmf->cmf_chunkno != expected_chunkno)
				CFATALX("invalid chunkno %u %u",
				    cmf->cmf_chunkno, expected_chunkno);
			hdr->c_size -= sizeof(*cmf);
	}

	return (0);
}

/* XXX this needs a home now */
#ifdef CT_EXT_XML_CMDS
	CT_EXT_XML_CMDS
#endif

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

int
ct_parse_xml_prepare(struct ct_header *hdr, void *vbody,
    struct xmlsd_v_elements *x_cmds, struct xmlsd_element_list *xl)
{
	struct xmlsd_attribute	*xa;
	struct xmlsd_element	*xe;
	char			*body = vbody;
	int			 r;

	CNDBG(CT_LOG_XML, "xml [%s]", (char *)vbody);

	/* Dispose of last parsed command. */
	TAILQ_INIT(xl);

	r = xmlsd_parse_mem(body, hdr->c_size - 1, xl);
	if (r)
		CFATALX("XML parse failed! (%d)", r);

	TAILQ_FOREACH(xe, xl, entry) {
		CNDBG(CT_LOG_XML, "%d %s = %s (parent = %s)",
		    xe->depth, xe->name, xe->value ? xe->value : "NOVAL",
		    xe->parent ? xe->parent->name : "NOPARENT");
		TAILQ_FOREACH(xa, &xe->attr_list, entry)
			CNDBG(CT_LOG_XML, "\t%s = %s", xa->name, xa->value);
	}

	r = xmlsd_validate(xl, x_cmds);
	if (r)
		CFATALX("XML validate of '%s' failed! (%d)", body, r);

	if (TAILQ_EMPTY(xl))
		CFATALX("parse command: No XML");

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
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	char				*body = NULL;
	char			 	 b64[CT_MAX_MD_FILENAME];
	size_t			 	 sz;

	CNDBG(CT_LOG_XML, "settting up XML open for %s", file);
	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)file, strlen(file),
	    (uint8_t *)b64, sizeof(b64))) {
		CWARNX("can't base64 encode %s", file);
		return (1);
	}

	if (mode == MD_O_WRITE || mode == MD_O_APPEND) {
		xe = xmlsd_create(&xl, "ct_md_open_create");
		xmlsd_set_attr(xe, "version", CT_MD_OPEN_CREATE_VERSION);
	} else {	/* mode == MD_O_READ */
		xe = xmlsd_create(&xl, "ct_md_open_read");
		xmlsd_set_attr(xe, "version", CT_MD_OPEN_READ_VERSION);
	}

	xe = xmlsd_add_element(&xl, xe, "file");
	xmlsd_set_attr(xe, "name", b64);
	if (mode == MD_O_APPEND || chunkno)
		xmlsd_set_attr_uint32(xe, "chunkno", chunkno);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	return (0);
}

int
ct_parse_xml_open_reply(struct ct_header *hdr, void *vbody, char **filename)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	int			rv = 1;

	if ((rv = ct_parse_xml_prepare(hdr, vbody, ct_xml_open_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strncmp(xe->name, "ct_md_open", strlen("ct_md_open")) == 0) {
		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				*filename = e_strdup(xmlsd_get_attr(xe, "name"));
				if (*filename[0] == '\0')
					e_free(filename);
			}
		}
	} else {
		return (1);
		CABORTX("unexpected XML returned [%s]", (char *)vbody);
	}

	xmlsd_unwind(&xl);
	return (0);
}

int
ct_create_xml_close(struct ct_header *hdr, void **vbody)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	char				*body;
	size_t				 sz;

	CNDBG(CT_LOG_XML, "creating xml close packet");
	xe = xmlsd_create(&xl, "ct_md_close");
	xmlsd_set_attr(xe, "version", CT_MD_CLOSE_VERSION);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	return (0);
}

int
ct_parse_xml_close_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element *xe;
	int rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_close_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strcmp(xe->name, "ct_md_close") == 0) {
		rv = 0;
	}

	xmlsd_unwind(&xl);
	return (0);
}

int
ct_create_xml_list(struct ct_header *hdr, void **vbody)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	char				*body;
	size_t				 sz;

	CNDBG(CT_LOG_XML, "creating xml list packet");
	xe = xmlsd_create(&xl, "ct_md_list");
	xmlsd_set_attr(xe, "version", CT_MD_LIST_VERSION);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	return (0);
}


int
ct_parse_xml_list_reply(struct ct_header *hdr, void *vbody,
    struct ctfile_list *head)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element *xe;
	int rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_list_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strcmp(xe->name, "ct_md_list") == 0) {
		struct ctfile_list_file	*file;
		const char		*errstr;
		char			*tmp;

		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				file = e_malloc(sizeof(*file));
				tmp = xmlsd_get_attr(xe, "name");
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

				tmp = xmlsd_get_attr(xe, "size");
				file->mlf_size = strtonum(tmp, 0, LLONG_MAX,
				    &errstr);
				if (errstr != NULL)
					CFATAL("can't parse file size %s",
					    errstr);

				tmp = xmlsd_get_attr(xe, "mtime");
				file->mlf_mtime = strtonum(tmp, 0, LLONG_MAX,
				    &errstr);
				if (errstr != NULL)
					CFATAL("can't parse mtime: %s", errstr);
				SIMPLEQ_INSERT_TAIL(head, file, mlf_link);
			}
		}
	}
	xmlsd_unwind(&xl);
	return (0);
}

int
ct_create_xml_delete(struct ct_header *hdr, void **vbody, const char *name)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xe;
	char				*body;
	char				 b64[CT_MAX_MD_FILENAME * 2];
	size_t				 sz;

	CNDBG(CT_LOG_XML, "creating xml delete for %s", name);
	if (ct_base64_encode(CT_B64_M_ENCODE, (uint8_t *)name, strlen(name),
	    (uint8_t *)b64, sizeof(b64))) {
		CWARNX("cant base64 encode %s", name);
		return (1);
	}

	xe = xmlsd_create(&xl, "ct_md_delete");
	xmlsd_set_attr(xe, "version", CT_MD_DELETE_VERSION);
	xe = xmlsd_add_element(&xl, xe, "file");
	xmlsd_set_attr(xe, "name", b64);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	return (0);
}

int
ct_parse_xml_delete_reply(struct ct_header *hdr, void *vbody, char **filename)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element *xe;
	char b64[CT_MAX_MD_FILENAME * 2];
	int rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_delete_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strcmp(xe->name, "ct_md_delete") == 0) {
		TAILQ_FOREACH(xe, &xl, entry) {
			if (strcmp(xe->name, "file") == 0) {
				*filename = xmlsd_get_attr(xe, "name");
				if (*filename[0] == '\0') {
					*filename = NULL;
					continue;
				}
				if (ct_base64_encode(CT_B64_M_DECODE,
				    (uint8_t *)*filename, strlen(*filename),
				    (uint8_t *)b64, sizeof(b64))) {
					CFATALX("cant base64 encode %s",
					    *filename);
				}
				*filename = e_strdup(b64);
			}
		}
	}

	xmlsd_unwind(&xl);
	return (0);
}

int
ct_create_xml_cull_setup(struct ct_header *hdr, void **vbody,
    uint64_t cull_uuid, int mode)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xp, *xe;
	char				*body;
	char				*type;
	size_t				 sz;

	CNDBG(CT_LOG_XML, "creating xml cull setup");

	switch (mode) {
	case CT_CULL_PRECIOUS:
		type = "precious";
		break;
	default:
		CWARNX("invalid cull type %d", mode);
		return (1);
	};

	xp = xmlsd_create(&xl, "ct_cull_setup");
	xmlsd_set_attr(xp, "version", CT_CULL_SETUP_VERSION);
	xe = xmlsd_add_element(&xl, xp, "cull");
	xmlsd_set_attr(xe, "type", type);
	xmlsd_set_attr_uint64(xe, "uuid", cull_uuid);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	return (0);
}

int
ct_parse_xml_cull_setup_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element *xe;
	int rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_cull_setup_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strcmp(xe->name, "ct_cull_setup_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_setup_reply");
	}

	xmlsd_unwind(&xl);
	return (0);
}

int
ct_create_xml_cull_shas(struct ct_header *hdr, void **vbody, uint64_t cull_uuid,
 struct ct_sha_lookup *head, int sha_per_packet, int *no_shas)
{
	struct xmlsd_element_list	xl;
	struct xmlsd_element		*xe, *xp;
	struct sha_entry		*node;
	char				*body;
	char				shat[SHA_DIGEST_STRING_LENGTH];
	size_t				sz;
	int				shas_in_packet = 0;

	xp = xmlsd_create(&xl, "ct_cull_shas");
	xmlsd_set_attr(xp, "version", CT_CULL_SHA_VERSION);

	xe = xmlsd_add_element(&xl, xp, "uuid");
	xmlsd_set_attr_uint64(xe, "value", cull_uuid);

	while ((node = RB_ROOT(head)) != NULL &&
	    shas_in_packet < sha_per_packet) {
		xe = xmlsd_add_element(&xl, xp, "sha");
		ct_sha1_encode(node->sha, shat);
		//CNDBG(CT_LOG_SHA, "adding sha %s\n", shat);
		xmlsd_set_attr(xe, "sha", shat);
		shas_in_packet++;

		RB_REMOVE(ct_sha_lookup, head, node);
		e_free(&node);
	}

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	if (no_shas)
		*no_shas = shas_in_packet;
	*vbody = body;
	return (0);
}

int
ct_parse_xml_cull_shas_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element *xe;
	int rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_cull_shas_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strcmp(xe->name, "ct_cull_shas_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_shas_reply");
	}

	xmlsd_unwind(&xl);
	return (0);
}

int
ct_create_xml_cull_complete(struct ct_header *hdr, void **vbody,
    uint64_t cull_uuid, int mode)
{
	struct xmlsd_element_list	 xl;
	struct xmlsd_element		*xp, *xe;
	char				*body;
	char				*type;
	size_t				 sz;

	CNDBG(CT_LOG_XML, "creating xml cull setup");

	switch (mode) {
	case CT_CULL_PROCESS:
		type = "process";
		break;
	default:
		CWARNX("invalid cull type %d", mode);
		return (1);
	};

	xp = xmlsd_create(&xl, "ct_cull_complete");
	xmlsd_set_attr(xp, "version", CT_CULL_COMPLETE_VERSION);
	xe = xmlsd_add_element(&xl, xp, "cull");
	xmlsd_set_attr(xe, "type", type);
	xmlsd_set_attr_uint64(xe, "uuid", cull_uuid);

	body = xmlsd_generate(&xl, ct_body_alloc_xml, &sz, 1);
	xmlsd_unwind(&xl);

	hdr->c_version = C_HDR_VERSION;
	hdr->c_opcode = C_HDR_O_XML;
	hdr->c_flags = C_HDR_F_METADATA;
	hdr->c_size = sz;

	*vbody = body;
	return (0);
}

int
ct_parse_xml_cull_complete_reply(struct ct_header *hdr, void *vbody)
{
	struct xmlsd_element_list xl;
	struct xmlsd_element *xe;
	int rv;

	if ((rv = ct_parse_xml_prepare(hdr, vbody,
	    ct_xml_cull_complete_cmds, &xl)) != 0)
		return (rv);

	xe = TAILQ_FIRST(&xl);
	if (strcmp(xe->name, "ct_cull_complete_reply") == 0) {
		CNDBG(CT_LOG_XML, "cull_complete_reply");
	}

	xmlsd_unwind(&xl);
	return (0);
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
