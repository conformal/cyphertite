.include <bsd.own.mk>

SUBDIR= ctutil libcyphertite cyphertite examples

TAGS=	${.CURDIR}/tags
tags:
	FILES=`mktemp /tmp/cyphertite_tag_XXXXXXXXXX` || exit 1;\
	find ${.CURDIR} -type f -iname '*.[ch]' > $${FILES} &&\
	ctags -wd -f ${TAGS} `cat $${FILES}` &&\
	sort -o ${TAGS} ${TAGS} &&\
	rm -f $${FILES}

.include <bsd.subdir.mk>
