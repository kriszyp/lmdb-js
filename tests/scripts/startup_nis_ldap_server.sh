#! /bin/sh
# $OpenLDAP$

if [ $# -eq 0 ]; then
	SRCDIR="."
else
	SRCDIR=$1; shift
fi
if [ $# -eq 1 ]; then
	BDB2=$1; shift
fi

. $SRCDIR/scripts/defines.sh $SRCDIR $BDB2

# Sample NIS database in LDIF format
NIS_LDIF=$SRCDIR/data/nis_sample.ldif

# Sample configuration file for your LDAP server
if test "$BACKEND" = "bdb2" ; then
	NIS_CONF=$DATADIR/slapd-bdb2-nis-master.conf
else
	NIS_CONF=$DATADIR/slapd-nis-master.conf
fi

echo "Cleaning up in $DBDIR..."

rm -f $DBDIR/[!C]*

echo "Running slapadd to build slapd database..."
$LDIF2LDBM -f $NIS_CONF -l $NIS_LDIF
RC=$?
if [ $RC != 0 ]; then
	echo "slapadd failed!"
	exit $RC
fi

echo "Starting slapd on TCP/IP port $PORT..."
$SLAPD -f $NIS_CONF -p $PORT -d $LVL $TIMING > $MASTERLOG 2>&1 &
PID=$!

echo ">>>>> LDAP server with NIS schema is up! PID=$PID"


exit 0
