#!/bin/sh

# @(#) acc.sh 1.1 93/06/18 22:29:42
#
# Script to emulate most of an ANSI C compiler with a traditional UNIX
# C compiler.

# INCDIR should be the directory with auxiliary include files from the
# unproto source distribution (stdarg.h, stdlib.h, stddef.h, and other
# stuff that is missing from your compilation environment). With Ultrix
# 4.[0-2] you need unproto's stdarg.h even though the system provides
# one.
#
INCDIR=.

# CPPDIR should be the directory with the unprototypeing cpp filter
# (preferably the version with the PIPE_THROUGH_CPP feature).
#
CPPDIR=.

# DEFINES: you will want to define volatile and const, and maybe even
# __STDC__.
#
DEFINES="-Dvolatile= -Dconst= -D__STDC__"

# Possible problem: INCDIR should be listed after the user-specified -I
# command-line options, not before them as we do here. This is a problem
# only if you attempt to redefine system libraries.
#
# Choose one of the commands below that is appropriate for your system.
#
exec cc -Qpath ${CPPDIR} -I${INCDIR} ${DEFINES} "$@"	# SunOS 4.x
exec cc -tp -h${CPPDIR} -B -I${INCDIR} ${DEFINES} "$@"	# Ultrix 4.2
exec cc -Yp,${CPPDIR} -I${INCDIR} ${DEFINES} "$@"	# M88 SysV.3
exec cc -B${CPPDIR}/ -tp -I${INCDIR} ${DEFINES} "$@"	# System V.2
