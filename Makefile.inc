LOCALBASE?=	/usr/local

#CC=clang
CFLAGS+= -Wshadow
CFLAGS+= -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -Wpointer-sign

CFLAGS+=	-I${.CURDIR}/../ctutil -I${LOCALBASE}/include
LDFLAGS+=	-L${.CURDIR}/../ctutil

INSTALL_STRIP=
