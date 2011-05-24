# $cyphertite$

SYSTEM != uname -s
.if exists(${.CURDIR}/../config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/../config/Makefile.$(SYSTEM:L)"
.endif

LOCALBASE?=/usr/local
BINDIR?=${LOCALBASE}/bin
INCDIR?=${LOCALBASE}/include
.PATH: ${.CURDIR}/../ctutil

PROG= cyphertite
SRCS= ct_main.c ct_files.c ct_util.c ct_queue.c ct_event.c
SRCS+= ct_aes_xts.c ct_crypto.c ct_match.c ct_metadata.c
SRCS+= ct_db.c ct_xdr.c ct_xml.c
MAN= cyphertite.conf.5 cyphertite.8

.if exists(${.CURDIR}/../ctutil/obj)
LDADD+=	-L${.CURDIR}/../ctutil/obj
.else
LDADD+=	-L${.CURDIR}/../ctuil
.endif

COPT+= -O2
CFLAGS+= -Wall -Werror -ggdb3
LDADD+= -L${LOCALBASE}/lib
LDADD+=	-lassl -lclog -lcrypto -levent -lexpat -lexude -lshrink
LDADD+=	-lsqlite3 -lssl -lutil -lxmlsd -lctutil
CLEANFILES= cyphertite.conf.cat5 cyphertite.cat8

CFLAGS+= -I${.CURDIR}/../libshrink -I.

LINKS=${BINDIR}/cyphertite ${BINDIR}/ct
MLINKS=cyphertite.8 ct.8

.include <bsd.prog.mk>
