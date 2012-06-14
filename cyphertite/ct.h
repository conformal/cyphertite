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

#include <limits.h>

#include <sys/tree.h>
#include <sys/queue.h>

#include <openssl/sha.h>

#include <ctutil.h>
#include <ct_socket.h>
#include <ct_threads.h>
#include <ct_types.h>
#include <ct_crypto.h>
#include <ct_proto.h>
#include <ct_ctfile.h>
#include <ct_db.h>
#include <ct_match.h>
#include <ct_ctfile.h>


#include <event2/event.h>

#ifndef evutil_socket_t
#define evutil_socket_t int
#endif

/* versioning */
#define CT_STRINGIFY(x)		#x
#define CT_STR(x)		CT_STRINGIFY(x)

extern char		*__progname;
extern int		ct_skip_xml_negotiate;


/* what are we doing? */
extern int		ct_action;
#define CT_A_ARCHIVE	(1)
#define CT_A_LIST	(2)
#define CT_A_EXTRACT	(3)
#define CT_A_ERASE	(4)
#define CT_A_JUSTDL	(5)	/* fake option for ctfb */

uint64_t 	ct_get_debugmask(char *);
void		ct_info_sig(evutil_socket_t fd, short event, void *vctx);
