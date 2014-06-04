# $OpenBSD: Makefile,v 1.6 2011/08/29 21:42:54 dhill Exp $

COMMENT =		tar-like secure remote deduplicating archiver

DISTNAME =		cyphertite-2.0.3
EPOCH=			1
CATEGORIES =		sysutils archivers security

HOMEPAGE =		https://www.cyphertite.com/
MAINTAINER=		Conformal Systems LLC <info@conformal.com>

# ISC
PERMIT_PACKAGE_CDROM=	Yes

WANTLIB =		assl>=5 c clog>=2 crypto curl edit event_core expat \
			exude>=3 ncurses shrink>=2 sqlite3 ssl util xmlsd>=3

MASTER_SITES =		http://opensource.conformal.com/snapshots/cyphertite/

.if exists(/usr/lib/libsqlite3.a)
SQLITE= 
.else
SQLITE= databases/sqlite3
.endif

LIB_DEPENDS =		archivers/libshrink>=0.4.0	\
			${SQLITE}			\
			devel/libclog>=0.5.0		\
			devel/libexude>=0.7.0		\
			devel/libevent2			\
			net/curl			\
			security/assl>=1.1.0		\
			textproc/libxmlsd>=0.9.0

NO_TEST =		Yes

.include <bsd.port.mk>
