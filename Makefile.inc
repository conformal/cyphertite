LOCALBASE?=	/usr/local

#CC=clang
#CFLAGS+=	-Wshadow -Werror

CFLAGS+=	-I${.CURDIR}/../ctutil -I${LOCALBASE}/include
LDFLAGS+=	-L${.CURDIR}/../ctutil

INSTALL_STRIP=
