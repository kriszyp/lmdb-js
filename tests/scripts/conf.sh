#! /bin/sh
# $OpenLDAP$
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2004 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.
if [ x"$MONITORDB" = x"yes" -o x"$MONITORDB" = xmod ] ; then
	MON=monitor
	if [ $MONITORDB = mod ] ; then
		MONMOD=monitormod
	else
		MONMOD=nomod
	fi
else
	MON=nomonitor
fi
if [ x"$WITH_SASL" = x"yes" -a x"$USE_SASL" != x"no" ] ; then
	SASL="sasl"
	if [ x"$USE_SASL" = x"yes" ] ; then
		USE_SASL=DIGEST-MD5
	fi
else
	SASL="nosasl"
	SASL_MECH=
fi
sed -e "s/@BACKEND@/${BACKEND}/"			\
	-e "s/^#${BACKEND}#//"				\
	-e "s/^#${BACKENDTYPE}#//"			\
	-e "s/^#${AC_ldap}#//"				\
	-e "s/^#${AC_pcache}#//"			\
	-e "s/^#${AC_ppolicy}#//"			\
	-e "s/^#${AC_refint}#//"			\
	-e "s/^#${AC_unique}#//"			\
	-e "s/^#${MON}#//"				\
	-e "s/^#${MONMOD}#//"				\
	-e "s/^#${SASL}#//"				\
	-e "s/#SASL_MECH#/\"mech=${USE_SASL}\"/"	\
	-e "s/@CACHETTL@/${CACHETTL}/"			\
	-e "s/@ENTRY_LIMIT@/${CACHE_ENTRY_LIMIT}/"   
