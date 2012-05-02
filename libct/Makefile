# cyphertite library code

.include "${.CURDIR}/../config/Makefile.common"
SYSTEM != uname -s
.if exists(${.CURDIR}/../config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/../config/Makefile.$(SYSTEM:L)"
.endif

.if ${.TARGETS:M*analyze*}
CC=clang
CFLAGS+=--analyze
.elif ${.TARGETS:M*clang*}
CC=clang
.endif

LIB=	ct
SRCS=	ct_match.c ct_proto.c ct_xdr.c ct_db.c ct_trees.c ct_crypto.c
SRCS+=	ct_aes_xts.c

SRCS=	ct_aes_xts.c ct_bw_lim.c ct_config.c ct_config_paths.c ct_crypto.c
SRCS+=	ct_ctfile_mode.c ct_ctfile_remote.c ct_ctfile_traverse.c ct_db.c
SRCS+=	ct_event.c ct_files.c ct_match.c ct_ops.c ct_proto.c
SRCS+=	ct_queue.c ct_trees.c ct_util.c ct_xdr.c
INCS=	ct_crypto.h ct_ctfile.h ct_db.h ct_ext.h ct_lib.h ct_match.h
INCS+=	ct_proto.h ct_types.h

NOPIC=	nopic

LOCALBASE?=/usr/local

INCFLAGS+= -I${.CURDIR}/../ctutil -I${LOCALBASE}/include -I${.CURDIR}
CFLAGS+= ${INCFLAGS} ${WARNFLAGS}

.include <bsd.lib.mk>
