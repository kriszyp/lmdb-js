#! /bin/sh

. scripts/defines.sh

echo "Cleaning up in $DBDIR..."

rm -f $DBDIR/[!C]*

echo "Running ldif2ldbm to build slapd database..."
$LDIF2LDBM -f $CONF -l $LDIF
RC=$?
if test $RC != 0 ; then
	echo "ldif2ldbm failed!"
	exit $RC
fi
