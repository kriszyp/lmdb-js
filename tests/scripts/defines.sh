#! /bin/sh
# $OpenLDAP$

DATADIR=$SRCDIR/data
PROGDIR=./progs
DBDIR=./test-db
REPLDIR=./test-repl

CONF=$DATADIR/slapd.conf
MCONF=$DATADIR/slapd-master.conf
PWCONF=$DATADIR/slapd-pw.conf
ACLCONF=$DATADIR/slapd-acl.conf
RCONF=$DATADIR/slapd-referrals.conf
MASTERCONF=$DATADIR/slapd-repl-master.conf
SLAVECONF=$DATADIR/slapd-repl-slave.conf
REFSLAVECONF=$DATADIR/slapd-ref-slave.conf
SUBMASTERCONF=$DATADIR/slapd-repl-submaster.conf
SUBSLAVECONF=$DATADIR/slapd-repl-subslave.conf
SCHEMACONF=$DATADIR/slapd-schema.conf
GLUECONF=$DATADIR/slapd-glue.conf

DBCONF=$DBDIR/slapd.conf
ADDCONF=$DBDIR/slapadd.conf
REPLCONF=$REPLDIR/slapd.conf

TOOLARGS="-x $LDAP_TOOLARGS"
TOOLPROTO="-P 3"

PASSWDCONF=$DATADIR/slapd-passwd.conf

CLIENTDIR=../clients/tools
#CLIENTDIR=/usr/local/bin

LDIFFILTER=$SRCDIR/scripts/acfilter.sh
SUBFILTER=$SRCDIR/scripts/subfilter.sh
UNDIFFFILTER=$SRCDIR/scripts/undiff.sh
CONFFILTER=$SRCDIR/scripts/conf.sh

SLAPADD="../servers/slapd/tools/slapadd $LDAP_VERBOSE"
SLAPCAT="../servers/slapd/tools/slapcat $LDAP_VERBOSE"
SLAPINDEX="../servers/slapd/tools/slapindex $LDAP_VERBOSE"

unset DIFF_OPTIONS
DIFF="diff -iu"
CMP="diff -i"
CMPOUT=/dev/null
SLAPD="../servers/slapd/slapd -s0"
SLURPD=../servers/slurpd/slurpd
LDAPPASSWD="$CLIENTDIR/ldappasswd $TOOLARGS"
LDAPSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $TOOLARGS -LLL"
LDAPRSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $TOOLARGS"
LDAPMODIFY="$CLIENTDIR/ldapmodify $TOOLPROTO $TOOLARGS"
LDAPADD="$CLIENTDIR/ldapadd $TOOLPROTO $TOOLARGS"
LDAPMODRDN="$CLIENTDIR/ldapmodrdn $TOOLPROTO $TOOLARGS"
LDAPWHOAMI="$CLIENTDIR/ldapwhoami $TOOLARGS"
SLAPDTESTER=$PROGDIR/slapd-tester
LVL=${SLAPD_DEBUG-261}
LOCALHOST=localhost
PORT=9009
SLAVEPORT=9010
MASTERURI="ldap://${LOCALHOST}:$PORT/"
SLAVEURI="ldap://${LOCALHOST}:$SLAVEPORT/"
LDIF=$DATADIR/test.ldif
LDIFGLUED=$DATADIR/test-glued.ldif
LDIFORDERED=$DATADIR/test-ordered.ldif
LDIFBASE=$DATADIR/test-base.ldif
LDIFPASSWD=$DATADIR/passwd.ldif
LDIFPASSWDOUT=$DATADIR/passwd-out.ldif
LDIFLANG=$DATADIR/test-lang.ldif
LDIFLANGOUT=$DATADIR/lang-out.ldif
LDIFREF=$DATADIR/referrals.ldif
MONITOR=""
REFDN="c=US"
BASEDN="o=University of Michigan,c=US"
MANAGERDN="cn=Manager,o=University of Michigan,c=US"
UPDATEDN="cn=Replica,o=University of Michigan,c=US"
PASSWD=secret
BABSDN="cn=Barbara Jensen,ou=Information Technology DivisioN,OU=People,o=University of Michigan,c=us"
BJORNSDN="cn=Bjorn Jensen,ou=Information Technology DivisioN,OU=People,o=University of Michigan,c=us"
JAJDN="cn=James A Jones 1,ou=Alumni Association,ou=People,o=University of Michigan,c=US"
MASTERLOG=$DBDIR/master.log
SLAVELOG=$DBDIR/slave.log
SLURPLOG=$DBDIR/slurp.log
SEARCHOUT=$DBDIR/ldapsearch.out
SEARCHFLT=$DBDIR/ldapsearch.flt
LDIFFLT=$DBDIR/ldif.flt
SUBFLT=$DBDIR/sub.flt
SUBFLT2=$DBDIR/sub2.flt
MASTEROUT=$DBDIR/master.out
SLAVEOUT=$DBDIR/slave.out
SUBMASTEROUT=$DBDIR/submaster.out
TESTOUT=$DBDIR/test.out
INITOUT=$DBDIR/init.out
REFERRALOUT=$DATADIR/referrals.out
SEARCHOUTMASTER=$DATADIR/search.out.master
SEARCHOUTX=$DATADIR/search.out.xsearch
MODIFYOUTMASTER=$DATADIR/modify.out.master
ADDDELOUTMASTER=$DATADIR/adddel.out.master
MODRDNOUTMASTER0=$DATADIR/modrdn.out.master.0
MODRDNOUTMASTER1=$DATADIR/modrdn.out.master.1
MODRDNOUTMASTER2=$DATADIR/modrdn.out.master.2
MODRDNOUTMASTER3=$DATADIR/modrdn.out.master.3
ACLOUTMASTER=$DATADIR/acl.out.master
REPLOUTMASTER=$DATADIR/repl.out.master
MODSRCHFILTERS=$DATADIR/modify.search.filters
# Just in case we linked the binaries dynamically
LD_LIBRARY_PATH=`pwd`/../libraries:${LD_LIBRARY_PATH} export LD_LIBRARY_PATH
