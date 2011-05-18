#!/bin/sh
# $cyphertite$
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
# This script must be compatible with ksh, bash, and csh.  Take care when
# editing it.

report_err_header()
{
	echo "***********" 1>&2
	echo "** ERROR **" 1>&2
	echo "***********" 1>&2
}

report_err()
{
	report_err_header
	echo -e "$1" 1>&2
	exit 1
}

report_util_err()
{
	report_err_header
	echo "Unable to find '$1' utility.  Install the utility or" 1>&2
	echo "ensure the directory where it resides in the system PATH." 1>&2
	exit 1
}

check_root_perms()
{
	if [ "$(id -u)" != "0" ]; then
		ERRMSG="This script must be run as root.  Try sudo $0"
		report_err "$ERRMSG"
	fi
}

check_utils()
{
	# check for presence of utilities used by script
	UTILS_USED="gcc grep make uname install rm"
	for util in $UTILS_USED; do
		type $util >/dev/null 2>&1 || report_util_err "$util"
	done
}

check_external_libs()
{
	OS=$(uname)
	EXTERNAL_LIBS="ssl crypto expat z lzo2 lzma sqlite3 event"

	# standard lib dirs - override below if needed
	LIB_DIRS="/usr/lib /usr/local/lib"

	# linux flavor
	if [ "$OS" = "Linux" ]; then
		EXTRA_LIBS="bsd"
		LIB_EXTS="a so"
	# bsd flavor
	elif echo "$OS" | grep "BSD" >/dev/null 2>&1; then
		LIB_EXTS="a so.*"
	fi

	
	# allow extra libs depending on os
	[ -n "$EXTRA_LIBS" ] && EXTERNAL_LIBS="$EXTERNAL_LIBS $EXTRA_LIBS"

	# find missing libs
	MISSING_LIBS=""
	for lib in $EXTERNAL_LIBS; do
		LIB_FOUND=0
		for d in $LIB_DIRS; do
			for ext in $LIB_EXTS; do
				LIB_FILES="$d/lib$lib."$ext
				for f in $LIB_FILES; do
					if [ -e "$f" ]; then
						LIB_FOUND=1
					fi
				done
			done
		done
		if [ $LIB_FOUND -eq 0 ]; then
			MISSING_LIBS="$MISSING_LIBS * $lib\n "
		fi
	done
	if [ -n "$MISSING_LIBS" ]; then
		ERRMSG="Unable to find the following required external libraries:\n" 
		ERRMSG="$ERRMSG $MISSING_LIBS"
		report_err "$ERRMSG"
	fi
}

check_ssl_ecdsa()
{
	#TODO: Test ssl for ciphers
	echo "stub" >/dev/null 2>&1
}

ct_build_and_install()
{
	# build and install packages in dependency order
	CT_PKGS="clens clog assl xmlsd shrink exude cyphertite"
	for pkg in $CT_PKGS; do
		cd "$pkg"
		make obj || report_err "Unable to make obj directory for '$pkg'."
		make depend || report_err "Unable to make dependencies for '$pkg'."
		make || report_err "Make failed for '$pkg'."
		make install || report_err "Install failed for '$pkg'."
		cd ..	
	done
}

ct_setup_conf()
{
	# setup cyphertite conf skeleton
	CT_CONF_DIR=/etc/cyphertite
	CT_CONF_PRIV_DIR="$CT_CONF_DIR/private"
	CT_CONF_FILE="cyphertite.conf" 
	CT_SAMPLE_CONF_FILE="cyphertite/cyphertite/$CT_CONF_FILE"
	install -d -m 700 "$CT_CONF_PRIV_DIR/" || 
		report_err "Unable to create $CT_CONF_PRIV_DIR" 
	if [ ! -e "$CT_CONF_DIR/$CT_CONF_FILE" ]; then
		install -m 600 "$CT_SAMPLE_CONF_FILE" "$CT_CONF_DIR/" || 
			report_err "Unable to install $CT_CONF_FILE" 
	fi
}


# main execution starts here
check_root_perms
check_utils
check_external_libs
check_ssl_ecdsa
ct_build_and_install
ct_setup_conf

# TODO: Success message / instructions
