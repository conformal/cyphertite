
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
SRCS= ct_main.c ct_ctl.c ct_fb.c ct_fb_ops.c $(CT_EXT_SRC)
MAN= cyphertitectl.1 cyphertite.1 cyphertite.conf.5 cyphertitefb.1

.if ${.CURDIR} == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../ctutil
DPADD+= ${.CURDIR}/../ctutil/libctutil.a
LDADD+= -L${.CURDIR}/../libct
DPADD+= ${.CURDIR}/../libct/libct.a
.elif ${.CURDIR}/obj == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../ctutil/obj
DPADD+= ${.CURDIR}/../ctutil/obj/libctutil.a
LDADD+= -L${.CURDIR}/../libct/obj
DPADD+= ${.CURDIR}/../libct/obj/libct.a
.else
LDADD+= -L${.OBJDIR}/../ctutil
DPADD+= ${.OBJDIR}/../ctutil/libctutil.a
LDADD+= -L${.OBJDIR}/../libct
DPADD+= ${.OBJDIR}/../libct/libct.a
.endif

BUILDVERSION != sh "${.CURDIR}/../buildver.sh"

INCFLAGS+= -I${.CURDIR}/../ctutil -I${LOCALBASE}/include
INCFLAGS+= -I${.CURDIR}/../libct
CFLAGS+= ${INCFLAGS} ${WARNFLAGS}
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DBUILDSTR=\"$(BUILDVERSION)\"
.endif

LDADD+= -L${LOCALBASE}/lib
LDADD+=	-lassl -lclog -lcrypto -levent_core -lexpat -lexude -lshrink
LDADD+=	-lsqlite3 -lssl -lutil -lxmlsd -ledit -lncurses -lcurl
LDADD+= ${LDADDSSL} -lct -lctutil
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
