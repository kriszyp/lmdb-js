#!/bin/sh
# simple BSD-like uname replacement for those systems without it
#
# Copyright (c) 1995 The Regents of the University of Michigan
#


#
# if /bin/uname or /usr/bin/uname exists, just use it
# ...unless we are on SCO, where the provided uname is bad
#
if  [ ! -f /usr/bin/swconfig ]; then
    if [ -f /bin/uname ]; then
	exec /bin/uname $*
    fi

    if [ -f /usr/bin/uname ]; then
	exec /usr/bin/uname $*
    fi
fi


#
# flags to keep track of what to output
#
PRINT_SYSTEM=0
PRINT_VERSION=0
PRINT_RELEASE=0

#
# process arguments
#
USAGE="usage: $0 [-s] [-v] [-r]"

while [ $# != 0 ]; do
    case "$1" in
    -s)
	PRINT_SYSTEM=1
	;;
    -v)
	PRINT_VERSION=1
	;;
    -r)
	PRINT_RELEASE=1
	;;
    *)
	echo "$USAGE"
	exit 1
	;;
    esac
    shift
done


#
# print system name by default
#
if [ $PRINT_VERSION = "0" -a $PRINT_RELEASE = "0" ]; then
    PRINT_SYSTEM=1
fi


#
# default to unknown everything...
#
SYSTEM="Unknown-System"
VERSION="Unknown-Version"
RELEASE="Unknown-Release"

#
# check to see if we are on a machine that runs NextSTEP or SCO
#
if [ -r /NextApps ]; then
    SYSTEM="NeXTSTEP"
elif [ -f /usr/bin/swconfig ]; then
    SYSTEM="SCO"
fi


#
# output requested information
#
OUTPUT=0
if [ $PRINT_SYSTEM = "1" ]; then
    echo -n "$SYSTEM"
    OUTPUT=1
fi

if [ $PRINT_VERSION = "1" ]; then
    if [ $OUTPUT = "1" ]; then
	echo -n " $VERSION"
    else
	echo -n "$VERSION"
	OUTPUT=1
    fi
fi

if [ $PRINT_RELEASE = "1" ]; then
    if [ $OUTPUT = "1" ]; then
	echo -n " $RELEASE"
    else
	echo -n "$RELEASE"
	OUTPUT=1
    fi
fi

echo

exit 0
