# $cyphertite$

SYSTEM != uname -s
.if exists(${.CURDIR}/../config/Makefile.$(SYSTEM:L))
.  include "${.CURDIR}/../config/Makefile.$(SYSTEM:L)"
.endif

LOCALBASE?=/usr/local
BINDIR?=${LOCALBASE}/bin
LIBDIR?=${LOCALBASE}/lib
INCDIR=${LOCALBASE}/include

#WANTLINT=
LIB= ctutil
SRCS= ctutil.c ct_socket.c ct_core.c ct_ssl.c ct_compress.c
HDRS= ctutil.h ct_socket.h ct_xml.h

CFLAGS+= -O2
CFLAGS+= -Wall -Werror
CFLAGS+= -ggdb3

afterinstall:
	@cd ${.CURDIR}; for i in ${HDRS}; do \
	cmp -s $$i ${INCDIR}/$$i || \
	${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) $$i ${DESTDIR}${INCDIR}/; \
	echo ${INSTALL} ${INSTALL_COPY} -m 444 -o $(BINOWN) -g $(BINGRP) $$i ${DESTDIR}${INCDIR}/; \
	done

uninstall:
	@for i in ${HDRS}; do \
	echo rm -f ${INCDIR}/$$i; \
	rm -f ${INCDIR}/$$i; \
	done

	@for i in ${_LIBS}; do \
	echo rm -f ${LIBDIR}/$$i; \
	rm -f ${LIBDIR}/$$i; \
	done

.include <bsd.lib.mk>
