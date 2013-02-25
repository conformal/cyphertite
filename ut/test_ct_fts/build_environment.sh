#!/bin/sh

DIR=$1

mkdir -p ${DIR}

# make a sparse file of just over 2gig in size.
dd if=/dev/zero of=${DIR}/twogig bs=1048576 count=1 seek=2048

# deeper directory structure
mkdir -p ${DIR}/subdir/subdir2

# with some files
dd if=/dev/zero of=${DIR}/subdir/smaller bs=10485 count=1 seek=2048
dd if=/dev/zero of=${DIR}/subdir/subdir2/smaller2 bs=1 count=1 seek=2048

# symlink
#
