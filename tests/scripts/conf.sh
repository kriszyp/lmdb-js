#! /bin/sh
# $OpenLDAP$
sed -e s/@BACKEND@/$BACKEND/ -e s/^#x$BACKENDx#//
