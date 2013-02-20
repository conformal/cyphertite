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

PROG= test_ct_fts
SRCS= test_ct_fts.c
NOMAN=

install:

.if ${.CURDIR} == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../../ctutil
LDADD+= -L${.CURDIR}/../../libcyphertite
.elif ${.CURDIR}/obj == ${.OBJDIR}
LDADD+= -L${.CURDIR}/../../ctutil/obj
LDADD+= -L${.CURDIR}/../../libcyphertite/obj
.else
LDADD+= -L${.OBJDIR}/../../ctutil
LDADD+= -L${.OBJDIR}/../../libcyphertite
.endif

INCFLAGS+= -I${.CURDIR}/../../ctutil
INCFLAGS+= -I${.CURDIR}/../../libcyphertite
INCFLAGS+= -I${LOCALBASE}/include
CFLAGS+= ${INCFLAGS} ${WARNFLAGS}
CFLAGS+= -I${.CURDIR}

LDADD+= -L${LOCALBASE}/lib
LDADD+=	-lassl -lclog -lcrypto -levent_core -lexpat -lexude -lshrink
LDADD+=	-lsqlite3 -lssl -lutil -lxmlsd -ledit -lncurses -lcurl
LDADD+= ${LDADDSSL} -lcyphertite -lctutil ${LDADDLATE}

analyze: all
clang: all

TESTDIR=testdir

# XXX how to clean up ${TESTDIR}, is dir so CLEANFILES won't work
run-regress-${PROG}: ${PROG}
	${.CURDIR}/build_environment.sh ${TESTDIR} || exit 1
	./${PROG} ${TESTDIR} 2>&1 | tee testlog
	diff -u ${.CURDIR}/testlog.expected testlog
	rm -f ${TESTDIR}/twogig

.include <bsd.regress.mk>

