
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

LOCALBASE?=/usr/local
BINDIR?=${LOCALBASE}/bin
INCDIR?=${LOCALBASE}/include
.PATH: ${.CURDIR}/../ctutil

PROG= cyphertite
SRCS= ct_main.c ct_files.c ct_util.c ct_queue.c ct_event.c
SRCS+= ct_aes_xts.c ct_crypto.c ct_match.c ct_ctfile_mode.c
SRCS+= ct_db.c ct_xdr.c ct_xml.c ct_bw_lim.c ct_ctl.c ct_ops.c
SRCS+= ct_config.c ct_config_paths.c ct_ctfile_traverse.c
SRCS+= ct_fb.c ct_fb_ops.c ct_ctfile_remote.c $(CT_EXT_SRC)
MAN= cyphertitectl.1 cyphertite.1 cyphertite.conf.5 cyphertitefb.1

.if ${.CURDIR} == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../ctutil
.elif ${.CURDIR}/obj == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../ctutil/obj
.else
LDADD+= -L${.OBJDIR}/../ctutil
.endif

BUILDVERSION != sh "${.CURDIR}/../buildver.sh"

INCFLAGS+= -I${.CURDIR}/../ctutil -I${LOCALBASE}/include
CFLAGS+= ${INCFLAGS} ${WARNFLAGS}
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DBUILDSTR=\"$(BUILDVERSION)\"
.endif

LDADD+= -L${LOCALBASE}/lib
LDADD+=	-lassl -lclog -lcrypto -levent_core -lexpat -lexude -lshrink
LDADD+=	-lsqlite3 -lssl -lutil -lxmlsd -lctutil -ledit -lncurses -lcurl
LDADD+= ${LDADDSSL}
CLEANFILES= cyphertite.cat1 cyphertite.conf.cat5

CFLAGS+= -I${.CURDIR}/../libshrink -I${.CURDIR}

LINKS=${BINDIR}/cyphertite ${BINDIR}/ct
LINKS+=${BINDIR}/cyphertite ${BINDIR}/cyphertitectl
LINKS+=${BINDIR}/cyphertite ${BINDIR}/ctctl
LINKS+=${BINDIR}/cyphertite ${BINDIR}/cyphertitefb
LINKS+=${BINDIR}/cyphertite ${BINDIR}/ctfb
MLINKS=cyphertite.1 ct.1
MLINKS+=cyphertitefb.1 ctfb.1
MLINKS+=cyphertitectl.1 ctctl.1

analyze: all
clang: all

.include <bsd.prog.mk>
