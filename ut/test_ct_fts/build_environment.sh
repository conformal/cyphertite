#!/bin/sh

DIR=$1

mkdir -p ${DIR}

# make a spare file of just over 2gig in size.
dd if=/dev/zero of=${DIR}/twogig bs=1048576 count=1 seek=2048

# symlink
#
