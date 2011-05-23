#!/bin/sh
# $cyphertite$
#
# 

# usage
if [ -z "$1" ]; then
	echo "usage: $0 <version>"
	exit 1
fi

VERSION=$1
CT_SNAPSHOTS_DIR="ct_snapshots"
CT_RELEASE_DIR="cyphertite-$VERSION"
CT_RELEASE_TARBALL="cyphertite-$VERSION.tar.gz"

# error reporting
function error {
	echo "$1"
	exit 1
}

# clean up previous runs
rm -rf ~/"$CT_SNAPSHOTS_DIR/$CT_RELEASE_DIR/"
rm -f ~/"$CT_SNAPSHOTS_DIR/$CT_RELEASE_TARBALL"

# make release directory and checkout source
mkdir -p ~/"$CT_SNAPSHOTS_DIR/$CT_RELEASE_DIR/"
cd ~/"$CT_SNAPSHOTS_DIR/$CT_RELEASE_DIR/"
CT_PKGS="clens clog cyphertite assl xmlsd shrink exude"
for pkg in $CT_PKGS; do
	cvs -d anoncvs@opensource.conformal.com:/anoncvs/$pkg co -PA $pkg || \
		error "failed to checkout $pkg source via cvs."
done

# get and patch openssl
OPENSSL_PKG="openssl-1.0.0d"
ftp "ftp://ftp.openssl.org/source/$OPENSSL_PKG.tar.gz"
tar zxf "$OPENSSL_PKG.tar.gz"
rm "$OPENSSL_PKG.tar.gz"
cd "$OPENSSL_PKG"
patch -p1 < ../ecdsa_no_const_time.patch
cd ..
mv "$OPENSSL_PKG" "$OPENSSL_PKG-with-ec-patch"

# release directory
mv cyphertite/scripts/ct_install.sh .
find . -depth -name CVS -exec rm -rf {} \;

# make tarball and cleanup
cd ~/"$CT_SNAPSHOTS_DIR" 
tar zcvf "$CT_RELEASE_TARBALL" "$CT_RELEASE_DIR"
rm -rf "$CT_RELEASE_DIR/"
echo "Tarball created at: ~/$CT_SNAPSHOTS_DIR/$CT_RELEASE_TARBALL" 
