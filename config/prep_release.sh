#!/bin/sh
#
# Prepares for a release:
#   - Bumps version according to specified level (major, minor, or patch)
#   - Updates all necessary headers and package control files with new version
#   - Performs some basic validation on specified release notes
#   - Updates package control files with release notes
#

PROJECT=cyphertite
PROJECT_UC=$(echo $PROJECT | tr '[:lower:]' '[:upper:]')
SCRIPT=$(basename $0)
HEADER=../${PROJECT}/ct.h
VER_PREFIX=CT
RPM_SPEC=${PROJECT}.spec
DEB_CHANGELOG=debian/changelog
PORT_CATEGORY=security
PORT_NAME=${PROJECT}
PORT_MAKEFILE=openbsd/${PORT_CATEGORY}/${PORT_NAME}/Makefile

# verify params
if [ $# -lt 2 ]; then
	echo "usage: $SCRIPT {major | minor | patch} release-notes-file"
	exit 1
fi

CUR_DIR=$(pwd)
cd "$(dirname $0)"

# verify header exists
if [ ! -f "$HEADER" ]; then
	echo "$SCRIPT: error: $HEADER does not exist" 1>&2
	exit 1
fi

RTYPE="$1"
RELEASE_NOTES="$2"
if [ $(echo $RELEASE_NOTES | cut -c1) != "/" ]; then
	RELEASE_NOTES="$CUR_DIR/$RELEASE_NOTES"
fi

# verify valid release type
if [ "$RTYPE" != "major" -a "$RTYPE" != "minor" -a "$RTYPE" != "patch" ]; then
	echo "$SCRIPT: error: release type must be major, minor, or patch"
	exit 1
fi

# verify release notes
if [ ! -e "$RELEASE_NOTES" ]; then
	echo "$SCRIPT: error: specified release notes file does not exist"
	exit 1
fi

if [ ! -s "$RELEASE_NOTES" ]; then
	echo "$SCRIPT: error: specified release notes file is empty"
	exit 1
fi

# verify release notes format
while IFS='' read line; do
	if [ -z "$line" ]; then
		echo "$SCRIPT: error: release notes must not have blank lines"
		exit 1
	fi
	if [ ${#line} -gt 74 ]; then
		echo -n "$SCRIPT: error: release notes must not contain lines "
		echo    "with more than 74 characters"
		exit 1
	fi
	if expr "$line" : ".*\.$" >/dev/null 2>&1 ; then
		echo -n "$SCRIPT: error: release notes must not contain lines "
		echo    "that end in a period"
		exit 1
	fi
	if ! expr "$line" : "\-" >/dev/null 2>&1; then
	if ! expr "$line" : "  " >/dev/null 2>&1; then
		echo -n "$SCRIPT: error: release notes must not contain lines "
		echo    "that do not begin with a dash and are not indented"
		exit 1
	fi
	fi
done <"$RELEASE_NOTES"

# verify git is available
if ! type git >/dev/null 2>&1; then
	echo -n "$SCRIPT: error: Unable to find 'git' in the system path."
	exit 1
fi

# verify the git repository is on the master brnanch
BRANCH=$(git branch | grep '\*' | cut -c3-)
if [ "$BRANCH" != "master" ]; then
	echo "$SCRIPT: error: git repository must be on the master branch."
	exit 1
fi

# verify there are no uncommitted modifications prior to release modifications
NUM_MODIFIED=$(git diff 2>/dev/null | wc -l | sed 's/^[ \t]*//')
NUM_STAGED=$(git diff --cached 2>/dev/null | wc -l | sed 's/^[ \t]*//')
if [ "$NUM_MODIFIED" != "0" -o "$NUM_STAGED" != "0" ]; then
	echo -n "$SCRIPT: error: the working directory contains uncommitted "
	echo    "modifications"
	exit 1
fi

# get version
PAT_PREFIX="(^#define[[:space:]]+${VER_PREFIX}_VERSION"
PAT_SUFFIX='[[:space:]]+)[0-9]+$'
PAT_STR_SUFFIX='[[:space:]]+)"[0-9]+\.[0-9]+\.[0-9]+"$'
MAJOR=$(egrep "${PAT_PREFIX}_MAJOR${PAT_SUFFIX}" $HEADER | awk '{print $3}')
MINOR=$(egrep "${PAT_PREFIX}_MINOR${PAT_SUFFIX}" $HEADER | awk '{print $3}')
PATCH=$(egrep "${PAT_PREFIX}_PATCH${PAT_SUFFIX}" $HEADER | awk '{print $3}')
if [ -z "$MAJOR" -o -z "$MINOR" -o -z "$PATCH" ]; then
	echo "$SCRIPT: error: unable to get version from $HEADER" 1>&2
	exit 1
fi

# bump version according to level
if [ "$RTYPE" = "major" ]; then
	MAJOR=$(expr $MAJOR + 1)
	MINOR=0
	PATCH=0
elif [ "$RTYPE" = "minor" ]; then
	MINOR=$(expr $MINOR + 1)
	PATCH=0
elif [ "$RTYPE" = "patch" ]; then
	PATCH=$(expr $PATCH + 1)
fi
PROJ_VER="$MAJOR.$MINOR.$PATCH"

# update header with new version
sed -E "
    s/${PAT_PREFIX}_MAJOR${PAT_SUFFIX}/\1${MAJOR}/;
    s/${PAT_PREFIX}_MINOR${PAT_SUFFIX}/\1${MINOR}/;
    s/${PAT_PREFIX}_PATCH${PAT_SUFFIX}/\1${PATCH}/;
    s/${PAT_PREFIX}${PAT_STR_SUFFIX}/\1\"$PROJ_VER\"/;
" <"$HEADER" >"${HEADER}.tmp"

# modify RPM spec with release notes and version information
DATE=$(date "+%a %b %d %Y")
AUTHOR=$(whoami)
awk -v D="$DATE" -v VER="$PROJ_VER" -v A="$AUTHOR" '
/%define version/ {
	print "%define version		"VER
	next
}
/%changelog/ {
	print $0
	print "* "D" - "A" "VER"-1"
	exit
}
{ print $0 }
' < "$RPM_SPEC" >"${RPM_SPEC}.tmp"
cat "$RELEASE_NOTES" >>"${RPM_SPEC}.tmp"
awk -v RD="$RPMDATE" -v VER="$PROJ_VER" -v A="$AUTHOR" '
/%changelog/ {
	after_cl=1
	next
}
after_cl == 1 { print $0 }
' <"$RPM_SPEC" >>"${RPM_SPEC}.tmp"

# modify deb changelog with release notes and version information
# RFC 2822 formatted date
DATE=$(date "+%a, %d %b %Y %H:%M:%S %z")
echo "$PROJECT (${PROJ_VER}-1) unstable; urgency=low
" >"${DEB_CHANGELOG}.tmp"
cat "$RELEASE_NOTES" | sed 's/^\-/*/; s/^/  /' >>"${DEB_CHANGELOG}.tmp"
echo "
 -- Conformal Systems <package-discuss@conformal.com>  $DATE
" >>"${DEB_CHANGELOG}.tmp"
cat "${DEB_CHANGELOG}" >>"${DEB_CHANGELOG}.tmp"

#modify OpenBSD package files with new release number
sed -E "
    s/(DISTNAME=[[:space:]]+${PROJECT}-)[0-9]+\.[0-9]+\.[0-9]+/\1${PROJ_VER}/;
" <"$PORT_MAKEFILE" >"${PORT_MAKEFILE}.tmp"

# Apply changes
mv "${HEADER}.tmp" "$HEADER"
mv "${RPM_SPEC}.tmp" "$RPM_SPEC"
mv "${DEB_CHANGELOG}.tmp" "$DEB_CHANGELOG"
mv "${PORT_MAKEFILE}.tmp" "$PORT_MAKEFILE"

echo "All files have been prepared for release."
echo "Use the following commands to review the changes for accuracy:"
echo "  git status"
echo "  git diff"
echo ""
echo "If everything is accurate, use the following commands to commit, tag,"
echo "and push the changes"
echo "  git commit -am \"Prepare for release ${PROJ_VER}.\""
echo -n "  git tag -a \"${PROJECT_UC}_${MAJOR}_${MINOR}_${PATCH}\" -m "
echo    "\"Release ${PROJ_VER}\""
echo "  git push --tags origin master"
