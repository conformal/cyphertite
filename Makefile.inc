# $cyphertite$

LOCALBASE?=	/usr/local

CFLAGS+=	-I${.CURDIR}/../ctutil -I${LOCALBASE}/include
LDFLAGS+=	-L${.CURDIR}/../ctutil

INSTALL_STRIP=
