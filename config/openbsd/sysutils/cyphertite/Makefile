# $OpenBSD: Makefile,v 1.6 2011/08/29 21:42:54 dhill Exp $

COMMENT =		tar-like secure remote deduplicating archiver

DISTNAME =		cyphertite-1.0.2
CATEGORIES =		sysutils archivers security

HOMEPAGE =		https://www.cyphertite.com/
MAINTAINER=		Conformal Systems LLC <info@conformal.com>

# ISC
PERMIT_PACKAGE_CDROM=	Yes
PERMIT_PACKAGE_FTP=	Yes
PERMIT_DISTFILES_CDROM= Yes
PERMIT_DISTFILES_FTP=	Yes

WANTLIB =		assl>=3 c clog>=2 crypto edit event expat exude>=3 \
			ncurses shrink>=2 sqlite3 ssl util xmlsd>=2

MASTER_SITES =		http://opensource.conformal.com/snapshots/cyphertite/

LIB_DEPENDS =		archivers/libshrink>=0.3.0	\
			databases/sqlite3		\
			devel/libclog>=0.4.0		\
			devel/libexude>=0.6.0		\
			security/assl>=0.12.0		\
			textproc/libxmlsd>=0.7.0

NO_REGRESS =		Yes

.include <bsd.port.mk>
