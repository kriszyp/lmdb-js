#! /bin/sh
# $OpenLDAP$

. scripts/defines.sh

echo "Cleaning up in $DBDIR..."

rm -f $DBDIR/[!C]*

echo "Running slapadd to build slapd database..."
$slapadd -f $CONF -l $LDIF
RC=$?
if test $RC != 0 ; then
	echo "slapadd failed!"
	exit $RC
fi
