#!/bin/sh

SRCDIR="../../../.."
METADBDIR="./meta-db"
SLAPADD="$SRCDIR/servers/slapd/tools/slapadd -v"

#ADDCONF="./slapd-meta-plain.conf"
ADDCONF="./slapd-meta-rewrite.conf"
#ADDCONF="./slapd-ldap-rewrite.conf"

LDAPADDCONF="./slapd-ldap-raw.conf"
CONF="./slapd.conf"
LDAPCONF="./slapd-ldap.conf"
PORT=9876
#DEBUG=-1
DEBUG=0

rm -rf $METADBDIR
rm -f schema ucdata

sed "s/@PORT@/$PORT/" $ADDCONF > $CONF
sed "s/@PORT@/$PORT/" $LDAPADDCONF > $LDAPCONF

ln -s "$SRCDIR/servers/slapd/schema" .
ln -s "$SRCDIR/libraries/liblunicode" ucdata

for i in 1 2 3 ; do
	echo "Feeding directory $i"
	mkdir -p "$METADBDIR/$i"
	$SLAPADD -f $ADDCONF -n `expr $i + 1` -l meta-$i.ldif
done

echo ""
echo "After slapd started, try"
echo ""
echo "    ldapsearch -x -H ldap://:$PORT/ -b '' -s base namingContexts"
echo ""
echo "and browse the directory using the last base that appears;"
echo "you may also try to bind as administrator of each subdirectory"
echo "or as \"cn=Ando, ...\" with password \"ando\": notice what happens"
echo "to attrs \"sn\" and \"cn\" of some entries based on the ACLs ..."
echo ""

echo "Starting slapd on port $PORT"
$SRCDIR/servers/slapd/slapd -f $CONF -h "ldap://:$PORT/" -d $DEBUG
echo "Waiting 2 secs for everything to shut down ..."
sleep 2

#exit

rm -rf $METADBDIR
rm -f schema ucdata $CONF $LDAPCONF

