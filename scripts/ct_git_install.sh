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
# This is a convenience script to automatically update cyphertite and all of
# its Conformal dependencies from the official source repositories, build them,
# and install them in the correct order.
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
	UTILS_USED="gcc git grep make mkdir uname install rm tar"
	for util in $UTILS_USED; do
		type $util >/dev/null 2>&1 || report_util_err "$util"
	done


	#  choose which ftp tool to use - wget by default
	OS=$(uname)
	DOWNLOAD_TOOL="wget"
	if [ "$OS" = "OpenBSD" ]; then
		DOWNLOAD_TOOL="ftp"
	elif [ "$OS" = "FreeBSD" ]; then
		DOWNLOAD_TOOL="fetch"
	fi
	type $DOWNLOAD_TOOL >/dev/null 2>&1 || report_util_err "$DOWNLOAD_TOOL"
}

check_external_libs()
{
	EXTERNAL_LIBS="expat z lzo2 lzma sqlite3 event_core edit ncurses curl"

	# standard lib dirs - override below if needed
	LIB_DIRS="/usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64"

	# linux flavor
	if [ "$OS" = "Linux" ]; then
		EXTRA_LIBS="bsd"
		LIB_EXTS="a so"
	# bsd flavor
	elif echo "$OS" | grep "BSD" >/dev/null 2>&1; then
		EXTRA_LIBS="ssl crypto"
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

ct_download_url()
{
	# use the correct syntax depending on the native download tool
	DOWNLOAD_NAME=$1
	DOWNLOAD_URL=$2
	if [ "$DOWNLOAD_TOOL" = "wget" ]; then
		"$DOWNLOAD_TOOL" "$DOWNLOAD_URL"
	elif [ "$DOWNLOAD_TOOL" = "fetch" ]; then
		"$DOWNLOAD_TOOL" "$DOWNLOAD_URL"
	elif [ "$DOWNLOAD_TOOL" = "ftp" ]; then
		"$DOWNLOAD_TOOL" -o "$DOWNLOAD_NAME" "$DOWNLOAD_URL"
	fi
}

ct_get_source()
{
	# create directory to house all source if needed
	CT_SRC_DIR="ct_src"
	if [ ! -d "$CT_SRC_DIR" ]; then
		mkdir "$CT_SRC_DIR" || report_err "Unable to create '$CT_SRC_DIR'."
	fi
	cd "$CT_SRC_DIR"

	# download the openssl source tar if needed
	if ! openssl ciphers | grep ECDSA >/dev/null 2>&1; then
		OPENSSL_PKG="openssl-1.0.1c"
		OPENSSL_TGZ="$OPENSSL_PKG.tar.gz"
		OPENSSL_URL="https://www.cyphertite.com/snapshots/OpenSSL/$OPENSSL_TGZ"
		if [ ! -d "$OPENSSL_PKG" ]; then
			if [ ! -e "$OPENSSL_TGZ" ]; then
				echo "Getting source ==> $OPENSSL_PKG"
				ct_download_url "$OPENSSL_TGZ" "$OPENSSL_URL"
			fi
			tar -zxf "$OPENSSL_TGZ"
		fi
	fi

	# clone the source or update existing repo for ct and all of its
	# Conformal dependencies
	CT_PKGS="clens clog assl xmlsd shrink exude cyphertite"
	for pkg in $CT_PKGS; do
		if [ ! -d "$pkg" ]; then
			echo "Getting source ==> $pkg"
			git clone https://opensource.conformal.com/git/$pkg.git ||
			    report_err "Unable to get source for '$pkg'."
		else
			echo "Updating source ==> $pkg"
			cd "$pkg"
			git pull || report_err "Unable to update source for '$pkg'."
			echo "Cleaning ==> $pkg"
			make clean || report_err "Make clean failed for '$pkg'."
			cd ..
		fi
	done
}

ct_build_and_install()
{
	# build and install openssl source with ECDSA if base system package
	# doesn't have it.
	pkg="$OPENSSL_PKG"
	if ! openssl ciphers | grep ECDSA >/dev/null 2>&1; then
		echo "Building ==> $pkg"
		cd "$pkg"
		./config || report_err "config script failed for '$pkg'."
		make || report_err "Make failed for '$pkg'."
		echo "Installing ==> $pkg"
		make install || report_err "Install failed for '$pkg'."
		cd ..
	fi

	# build and install packages in dependency order
	CT_PKGS="clens clog assl xmlsd shrink exude cyphertite"
	for pkg in $CT_PKGS; do
		echo "Building ==> $pkg"
		cd "$pkg"
		make obj || report_err "Unable to make obj directory for '$pkg'."
		make depend || report_err "Unable to make dependencies for '$pkg'."
		make || report_err "Make failed for '$pkg'."
		echo "Installing ==> $pkg"
		make install || report_err "Install failed for '$pkg'."
		cd ..
	done
}


# main execution starts here
check_root_perms
check_utils
check_external_libs
ct_get_source
ct_build_and_install

