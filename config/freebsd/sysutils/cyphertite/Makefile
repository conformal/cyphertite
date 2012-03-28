# New ports collection makefile for:    cyphertite
# Date created:         March 5, 2012
# Whom:                 Dale Rahn <drahn@conformal.com>
#
# $FreeBSD$
#

PORTNAME=       cyphertite
PORTVERSION=    1.1.1
PORTREVISION?=	
CATEGORIES=     textproc
MASTER_SITES=   https://opensource.conformal.com/snapshots/cyphertite/ \
		LOCAL/bf

MAINTAINER=     drahn@conformal.com
COMMENT=        Tar-like secure remote deduplicating archiver

BUILD_DEPENDS=  ${LOCALBASE}/lib/libclens.a:${PORTSDIR}/devel/clens
LIB_DEPENDS+=	expat.6:${PORTSDIR}/textproc/expat2
LIB_DEPENDS+=	event-1.4.4:${PORTSDIR}/devel/libevent
LIB_DEPENDS+=	sqlite3.8:${PORTSDIR}/databases/sqlite3
LIB_DEPENDS+=	exude.3:${PORTSDIR}/devel/libevent
LIB_DEPENDS+=	xmlsd.2:${PORTSDIR}/textproc/libxmlsd
LIB_DEPENDS+=	shrink.2:${PORTSDIR}/archivers/libshrink
LIB_DEPENDS+=	clog.2:${PORTSDIR}/devel/libclog

LICENSE=        MIT
LICENSE_COMB=   single

.include <bsd.port.mk>
