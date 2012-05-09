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
#ifndef CT_INTERNAL_H
#define CT_INTERNAL_H
#include <ct_socket.h>

ct_header_alloc_func	ct_header_alloc;
ct_header_free_func	ct_header_free;
ct_body_alloc_func	ct_body_alloc;
ct_body_free_func	ct_body_free;

msgdeliver_ty		ct_handle_msg;
msgcomplete_ty		ct_write_done;

void			ct_handle_xml_reply(struct ct_global_state *,
			    struct ct_trans *trans,
			    struct ct_header *hdr, void *vbody);
void			ct_xml_file_open(struct ct_global_state *,
			    struct ct_trans *, const char *,
			    int, uint32_t);
int			ct_xml_file_open_polled(
			    struct ct_global_state *,
			    const char *, int, uint32_t);
void			ct_xml_file_close(struct ct_global_state *);

int			ct_basis_setup(const char *, char **, int,
			    time_t *, int);
void		 	ct_complete_metadata(struct ct_global_state *,
			    struct ct_trans *);

#endif /* ! CT_INTERNAL_H */
