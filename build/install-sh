#!/bin/sh
# simple BSD-like install replacement
#
# Copyright (c) 1994 The Regents of the University of Michigan
#

MODE=0755
USAGE="usage: $0 [-c] [-m mode] file dir"

while [ $# != 0 ]; do
    case "$1" in
    -c)
	;;
    -m)
	MODE=$2
	shift
	;;
    -*)
	echo "$USAGE"
	exit 1
	;;
    *)
	break
	;;
    esac
    shift
done

if [ $# != 2 ]; then
    echo "$USAGE"
    exit 1
fi

FILE=$1
DIR=$2

cp $FILE $DIR
if [ -d $DIR ]; then
    chmod $MODE $DIR/`basename $FILE`
else
#
# DIR is really the destination file
#
    chmod $MODE $DIR
fi
