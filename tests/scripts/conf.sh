#! /bin/sh
# $OpenLDAP$
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2003 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.
if [ x"$MONITORDB" = x"yes" ] ; then
	MON=monitor
else
	MON=nomonitor
fi
if [ x"$BACKENDTYPE" = x"mod" ]; then
	MODULELOAD="moduleload	back_${BACKEND}.la"
fi
sed -e "s/@BACKEND@/${BACKEND}/"	\
	-e "s/@MODULELOAD@/${MODULELOAD}/" \
	-e "s/^#${BACKEND}#//"			\
	-e "s/^#${MON}#//"				\
	-e "s/@CACHETTL@/${CACHETTL}/"   \
	-e "s/@ENTRY_LIMIT@/${CACHE_ENTRY_LIMIT}/"   
