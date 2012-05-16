
.include "${.CURDIR}/../../config/Makefile.common"
SYSTEM != uname -s
.if exists(${.CURDIR}/../../config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/../../config/Makefile.$(SYSTEM:L)"
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
.PATH: ${.CURDIR}/../../ctutil

PROG= remotelist
SRCS= remotelist.c
NOMAN= 

install:

.if ${.CURDIR} == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../../ctutil
LDADD+= -L${.CURDIR}/../../libct
.elif ${.CURDIR}/obj == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../../ctutil/obj
LDADD+= -L${.CURDIR}/../../libct/obj
.else
LDADD+= -L${.OBJDIR}/../../ctutil
LDADD+= -L${.OBJDIR}/../../libct
.endif

BUILDVERSION != sh "${.CURDIR}/../../buildver.sh"

INCFLAGS+= -I${.CURDIR}/../../ctutil -I${LOCALBASE}/include
INCFLAGS+= -I${.CURDIR}/../../libct
CFLAGS+= ${INCFLAGS} ${WARNFLAGS}
.if !${BUILDVERSION} == ""
CPPFLAGS+= -DBUILDSTR=\"$(BUILDVERSION)\"
.endif

LDADD+= -L${LOCALBASE}/lib
LDADD+=	-lassl -lclog -lcrypto -levent_core -lexpat -lexude -lshrink
LDADD+=	-lsqlite3 -lssl -lutil -lxmlsd -ledit -lncurses -lcurl
LDADD+= ${LDADDSSL} -lct -lctutil
CLEANFILES= cyphertite.cat1 cyphertite.conf.cat5

CFLAGS+= -I${.CURDIR}

analyze: all
clang: all

.include <bsd.prog.mk>
