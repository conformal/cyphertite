#!/bin/sh
#
# Copyright (c) 2012 Conformal Systems LLC <info@conformal.com>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
#
# port specific config data
#

name=cyphertite
port=cyphertite
category=sysutils

# local override variables
# PACKAGE_DATA_DIR - defaults to ~/package_data if not specified
# PACKAGE_DEST_DIR - no default - no action taken if not specified
[ "${PACKAGE_DATA_DIR}" = "" ] && PACKAGE_DATA_DIR=~/package_data

# local derived variables 
NAME=$(echo $name | tr '[a-z]' '[A-Z]')
PORT=$(echo $port | tr '[a-z]' '[A-Z]')

mkdir -p ${PACKAGE_DATA_DIR}
[ $? -ne 0 ] && exit 4
rev_file=${PACKAGE_DATA_DIR}/${name}.rev
VERSION=$(cd ../.. && sh version.sh)

PORTVERSION=$(grep PORTVERSION ${category}/${port}/Makefile | sed -e 's/.*=[^0-9]*//g' -e 's/[ \t]*//g')

if [ -f ${rev_file} ]
then
    . ${rev_file} 
else
    version=-1.-1.-1
fi

if [ "${PORTVERSION}" != "${VERSION}" ]
then
	echo "VERSION does not match distfile ver: ${VERSION} ${PORTVERSION}"
	exit 8
fi

rm -f ${name}-${VERSION}.tar.gz
rm -f ${name}-${VERSION}

ln -s ../.. ${name}-${VERSION}
tar czf ${name}-${VERSION}.tar.gz ${name}-${VERSION}/*

ls -l  ${name}-${VERSION}.tar.gz

export DISTDIR=${PWD}
export PACKAGE_REPOSITORY=${PWD}

#bump rev 
if [ "${VERSION}" = "${version}" ]
then
    if [ "${revision}" == "" ]
    then
	revision=1
    else
	revision=$(expr ${revision} + 1)
    fi
    prevision=_${revision}
    export REVISION=${revision}
else
    unset REVISION
    prevision=""
fi

# SHARED_LIBS ?
SUDOENV="${SUDOENV} DISTDIR=${DISTDIR}"
SUDOENV="${SUDOENV} PORTREVISION=${REVISION}"

(cd ${category}/${port} && rm -f distinfo && touch distinfo && make makesum)
(cd ${category}/${port} && make)
(cd ${category}/${port} && ${SUDO} env ${SUDOENV} make deinstall)
(cd ${category}/${port} && ${SUDO} env ${SUDOENV} make install)
(cd ${category}/${port} && env ${SUDOENV} make package)
(cd ${category}/${port} && rm -f distinfo)

rm -rf ${category}/${port}/work

echo "version=${VERSION}" >${rev_file}
if [ "${revision}" != "" ]
then
    echo "revision=${revision}" >>${rev_file}
fi

for dest in ${PACKAGE_DEST_DIR}
do
	scp ${category}/${port}/${port}-${VERSION}${prevision}${epoch}.tbz ${dest}
done

${SUDO} chown -R ${USER} ${category}/${port}

rm -f ${name}-${VERSION}.tar.gz
rm -f ${name}-${VERSION}

rm -f ${name}-${VERSION}
