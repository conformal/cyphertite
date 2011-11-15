
SYSTEM != uname -s
.if exists(${.CURDIR}/../config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/../config/Makefile.$(SYSTEM:L)"
.endif

.if ${.TARGETS:M*analyze*}
CC=clang
CFLAGS+=--analzye
.elif ${.TARGETS:M*clang*}
CC=clang
.endif

LOCALBASE?=/usr/local
BINDIR?=${LOCALBASE}/bin
INCDIR?=${LOCALBASE}/include
.PATH: ${.CURDIR}/../ctutil

PROG= cyphertite
SRCS= ct_main.c ct_files.c ct_util.c ct_queue.c ct_event.c
SRCS+= ct_aes_xts.c ct_crypto.c ct_match.c ct_metadata.c
SRCS+= ct_db.c ct_xdr.c ct_xml.c ct_bw_lim.c ct_ctl.c ct_md_xdr.c
SRCS+= ct_config.c
MAN= cyphertite.1 cyphertite.conf.5

.if ${.CURDIR} == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../ctutil
.elif ${.CURDIR}/obj == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../ctutil/obj
.else
LDADD+= -L${.OBJDIR}/../ctutil
.endif

BUILDVERSION != sh "${.CURDIR}/../buildver.sh"

COPT+= -O2
CFLAGS+= -Wall -Werror -ggdb3
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DBUILDSTR=\"$(BUILDVERSION)\"
.endif

LDADD+= -L${LOCALBASE}/lib
LDADD+=	-lassl -lclog -lcrypto -levent -lexpat -lexude -lshrink
LDADD+=	-lsqlite3 -lssl -lutil -lxmlsd -lctutil
LDADD+= ${LDADDSSL}
CLEANFILES= cyphertite.cat1 cyphertite.conf.cat5

CFLAGS+= -I${.CURDIR}/../libshrink -I.

LINKS=${BINDIR}/cyphertite ${BINDIR}/ct
LINKS+=${BINDIR}/cyphertite ${BINDIR}/cyphertitectl
LINKS+=${BINDIR}/cyphertite ${BINDIR}/ctctl
MLINKS=cyphertite.1 ct.1

analyze: all
clang: all

.include <bsd.prog.mk>
