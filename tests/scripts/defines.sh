#! /bin/sh
# $OpenLDAP$

DATADIR=$SRCDIR/data
PROGDIR=./progs
DBDIR=./test-db
REPLDIR=./test-repl
R1REPLDIR=$REPLDIR/r1
R2REPLDIR=$REPLDIR/r2
P1REPLDIR=$REPLDIR/p1
P2REPLDIR=$REPLDIR/p2
P3REPLDIR=$REPLDIR/p3
CACHEDIR=./test-cache

CONF=$DATADIR/slapd.conf
MCONF=$DATADIR/slapd-master.conf
PWCONF=$DATADIR/slapd-pw.conf
ACLCONF=$DATADIR/slapd-acl.conf
RCONF=$DATADIR/slapd-referrals.conf
MASTERCONF=$DATADIR/slapd-repl-master.conf
SRMASTERCONF=$DATADIR/slapd-syncrepl-master.conf
SLAVECONF=$DATADIR/slapd-repl-slave.conf
PROXYCACHECONF=$DATADIR/slapd-proxycache.conf
CACHEMASTERCONF=$DATADIR/slapd-cache-master.conf
R1SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-refresh1.conf
R2SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-refresh2.conf
P1SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-persist1.conf
P2SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-persist2.conf
P3SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-persist3.conf
REFSLAVECONF=$DATADIR/slapd-ref-slave.conf
SUBMASTERCONF=$DATADIR/slapd-repl-submaster.conf
SUBSLAVECONF=$DATADIR/slapd-repl-subslave.conf
SCHEMACONF=$DATADIR/slapd-schema.conf
GLUECONF=$DATADIR/slapd-glue.conf

DBCONF=$DBDIR/slapd.conf
ADDCONF=$DBDIR/slapadd.conf
REPLCONF=$REPLDIR/slapd.conf
R1REPLCONF=$R1REPLDIR/slapd.conf
R2REPLCONF=$R2REPLDIR/slapd.conf
P1REPLCONF=$P1REPLDIR/slapd.conf
P2REPLCONF=$P2REPLDIR/slapd.conf
P3REPLCONF=$P3REPLDIR/slapd.conf
CACHECONF=$CACHEDIR/slapd.conf

TOOLARGS="-x $LDAP_TOOLARGS"
TOOLPROTO="-P 3"

PASSWDCONF=$DATADIR/slapd-passwd.conf

CLIENTDIR=../clients/tools
#CLIENTDIR=/usr/local/bin

LDIFFILTER=$SRCDIR/scripts/acfilter.sh
SUBFILTER=$SRCDIR/scripts/subfilter.sh
UNDIFFFILTER=$SRCDIR/scripts/undiff.sh
CONFFILTER=$SRCDIR/scripts/conf.sh
STRIPATTR=$SRCDIR/scripts/stripattr.sh

SLAPADD="../servers/slapd/tools/slapadd $LDAP_VERBOSE"
SLAPCAT="../servers/slapd/tools/slapcat $LDAP_VERBOSE"
SLAPINDEX="../servers/slapd/tools/slapindex $LDAP_VERBOSE"

unset DIFF_OPTIONS
DIFF="diff -iu"
CMP="diff -i"
BCMP="diff -iB"
CMPOUT=/dev/null
SLAPD="../servers/slapd/slapd -s0"
SLURPD=../servers/slurpd/slurpd
LDAPPASSWD="$CLIENTDIR/ldappasswd $TOOLARGS"
LDAPSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $TOOLARGS -LLL"
LDAPRSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $TOOLARGS"
LDAPMODIFY="$CLIENTDIR/ldapmodify $TOOLPROTO $TOOLARGS"
LDAPADD="$CLIENTDIR/ldapmodify -a $TOOLPROTO $TOOLARGS"
LDAPMODRDN="$CLIENTDIR/ldapmodrdn $TOOLPROTO $TOOLARGS"
LDAPWHOAMI="$CLIENTDIR/ldapwhoami $TOOLARGS"
SLAPDTESTER=$PROGDIR/slapd-tester
LVL=${SLAPD_DEBUG-261}
LOCALHOST=localhost
PORT=9009
SLAVEPORT=9010
R1SLAVEPORT=9011
R2SLAVEPORT=9012
P1SLAVEPORT=9013
P2SLAVEPORT=9014
P3SLAVEPORT=9015
MASTERURI="ldap://${LOCALHOST}:$PORT/"
SLAVEURI="ldap://${LOCALHOST}:$SLAVEPORT/"
R1SLAVEURI="ldap://${LOCALHOST}:$R1SLAVEPORT/"
R2SLAVEURI="ldap://${LOCALHOST}:$R2SLAVEPORT/"
P1SLAVEURI="ldap://${LOCALHOST}:$P1SLAVEPORT/"
P2SLAVEURI="ldap://${LOCALHOST}:$P2SLAVEPORT/"
P3SLAVEURI="ldap://${LOCALHOST}:$P3SLAVEPORT/"
LDIF=$DATADIR/test.ldif
LDIFGLUED=$DATADIR/test-glued.ldif
LDIFORDERED=$DATADIR/test-ordered.ldif
LDIFORDEREDCP=$DATADIR/test-ordered-cp.ldif
LDIFORDEREDNOCP=$DATADIR/test-ordered-nocp.ldif
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
R1SLAVELOG=$DBDIR/r1.log
R2SLAVELOG=$DBDIR/r2.log
P1SLAVELOG=$DBDIR/p1.log
P2SLAVELOG=$DBDIR/p2.log
P3SLAVELOG=$DBDIR/p3.log
SLURPLOG=$DBDIR/slurp.log
SEARCHOUT=$DBDIR/ldapsearch.out
SEARCHFLT=$DBDIR/ldapsearch.flt
LDIFFLT=$DBDIR/ldif.flt
R1LDIFFLT=$DBDIR/r1ldif.flt
R2LDIFFLT=$DBDIR/r2ldif.flt
P1LDIFFLT=$DBDIR/p1ldif.flt
P2LDIFFLT=$DBDIR/p2ldif.flt
P3LDIFFLT=$DBDIR/p3ldif.flt
SUBFLT0=$DBDIR/sub0.flt
SUBFLT1=$DBDIR/sub1.flt
SUBFLT2=$DBDIR/sub2.flt
MASTEROUT=$DBDIR/master.out
SLAVEOUT=$DBDIR/slave.out
R1SLAVEOUT=$DBDIR/r1.out
R2SLAVEOUT=$DBDIR/r2.out
P1SLAVEOUT=$DBDIR/p1.out
P2SLAVEOUT=$DBDIR/p2.out
P3SLAVEOUT=$DBDIR/p3.out
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
CERTIFICATETLS=$DATADIR/certificate.tls
CERTIFICATEOUT=$DATADIR/certificate.out
# Just in case we linked the binaries dynamically
LD_LIBRARY_PATH=`pwd`/../libraries:${LD_LIBRARY_PATH} export LD_LIBRARY_PATH
