#!/bin/sh
#
# Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
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
# Get version from header.
#
HEADER=libct/ct_lib.h
SCRIPT=version.sh
if [ ! -f "$HEADER" ]; then
	echo "$SCRIPT: error: $HEADER does not exist" 1>&2
	exit 1
fi
PAT_PREFIX='^#define[[:space:]]+CT_VERSION_'
PAT_SUFFIX='[[:space:]]+[0-9]+$'
MAJOR=$(egrep "${PAT_PREFIX}MAJOR${PAT_SUFFIX}" $HEADER | awk '{print $3}')
MINOR=$(egrep "${PAT_PREFIX}MINOR${PAT_SUFFIX}" $HEADER | awk '{print $3}')
PATCH=$(egrep "${PAT_PREFIX}PATCH${PAT_SUFFIX}" $HEADER | awk '{print $3}')
if [ -z "$MAJOR" -o -z "$MINOR" -o -z "$PATCH" ]; then
	echo "$SCRIPT: error: unable to get version from $HEADER" 1>&2
	exit 1
fi
echo $MAJOR.$MINOR.$PATCH | tr -d '\n'
