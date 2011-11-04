LOCALBASE?=	/usr/local

#CC=clang
CFLAGS+= -Wshadow
CFLAGS+= -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare

CFLAGS+=	-I${.CURDIR}/../ctutil -I${LOCALBASE}/include
LDFLAGS+=	-L${.CURDIR}/../ctutil

INSTALL_STRIP=
