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
int			ct_xml_file_open_polled(
			    struct ct_global_state *,
			    const char *, int, uint32_t);

int			ct_basis_setup(int *, const char *, char **, int,
			    time_t *, const char *);

typedef void (ct_func_cb)(void *);
int	ct_setup_wakeup_file(struct ct_event_state *, void *, ct_func_cb *);
int	ct_setup_wakeup_sha(struct ct_event_state *, void *, ct_func_cb *);
int	ct_setup_wakeup_compress(struct ct_event_state *, void *, ct_func_cb *);
int	ct_setup_wakeup_csha(struct ct_event_state *, void *, ct_func_cb *);
int	ct_setup_wakeup_encrypt(struct ct_event_state *, void *, ct_func_cb *);
int	ct_setup_wakeup_write(struct ct_event_state *, void *, ct_func_cb *);
int	ct_setup_wakeup_complete(struct ct_event_state *, void *, ct_func_cb *);
void	ct_set_reconnect_timeout(struct ct_event_state *, int);

void ctfile_extract_handle_eof(struct ct_global_state *, struct ct_trans *);

struct ct_trans *ct_fatal_alloc_trans(struct ct_global_state *);
void		 ct_fatal(struct ct_global_state *, const char *, int);

char		*ct_os_version(void);

#endif /* ! CT_INTERNAL_H */
