if test $# -eq 0 ; then
	SRCDIR="."
else
	SRCDIR=$1; shift
fi
if test $# -eq 0 ; then
	BACKEND=ldbm
else
	BACKEND=$1; shift
fi

DATADIR=$SRCDIR/data
PROGDIR=$SRCDIR/progs

if test "$BACKEND" = "bdb2" ; then
	LDIF2LDBM=../servers/slapd/tools/ldif2ldbm-bdb2
	CONF=$DATADIR/slapd-bdb2-master.conf
	ACLCONF=$DATADIR/slapd-bdb2-acl.conf
	MASTERCONF=$DATADIR/slapd-bdb2-repl-master.conf
	SLAVECONF=$DATADIR/slapd-bdb2-repl-slave.conf
	TIMING="-t"
else
	LDIF2LDBM=../servers/slapd/tools/ldif2ldbm
	CONF=$DATADIR/slapd-master.conf
	ACLCONF=$DATADIR/slapd-acl.conf
	MASTERCONF=$DATADIR/slapd-repl-master.conf
	SLAVECONF=$DATADIR/slapd-repl-slave.conf
fi

SLAPD=../servers/slapd/slapd
SLURPD=../servers/slurpd/slurpd
LDAPSEARCH=../clients/tools/ldapsearch
LDAPMODIFY=../clients/tools/ldapmodify
LDAPADD=../clients/tools/ldapadd
LDAPMODRDN=../clients/tools/ldapmodrdn
SLAPDTESTER=$PROGDIR/slapd-tester
LVL=5
ADDR=127.0.0.1
PORT=9009
SLAVEPORT=9010
DBDIR=./test-db
REPLDIR=./test-repl
LDIF=$DATADIR/test.ldif
LDIFORDERED=$DATADIR/test-ordered.ldif
BASEDN="o=University of Michigan, c=US"
MANAGERDN="cn=Manager, o=University of Michigan, c=US"
PASSWD=secret
BABSDN="cn=Barbara Jensen, ou=Information Technology Division, ou=People, o=University of Michigan, c=US"
BJORNSDN="cn=Bjorn Jensen, ou=Information Technology Division, ou=People, o=University of Michigan, c=US"
JAJDN="cn=James A Jones 1, ou=Alumni Association, ou=People, o=University of Michigan, c=US"
MASTERLOG=$DBDIR/master.log
SLAVELOG=$DBDIR/slave.log
SLURPLOG=$DBDIR/slurp.log
SEARCHOUT=$DBDIR/ldapsearch.out
SEARCHFLT=$DBDIR/ldapsearch.flt
LDIFFLT=$DBDIR/ldif.flt
MASTEROUT=$DBDIR/master.out
SLAVEOUT=$DBDIR/slave.out
TESTOUT=$DBDIR/ldapsearch.out
SEARCHOUTMASTER=$DATADIR/search.out.master
MODIFYOUTMASTER=$DATADIR/modify.out.master
ADDDELOUTMASTER=$DATADIR/adddel.out.master
MODRDNOUTMASTER=$DATADIR/modrdn.out.master
ACLOUTMASTER=$DATADIR/acl.out.master
REPLOUTMASTER=$DATADIR/repl.out.master
MODSRCHFILTERS=$DATADIR/modify.search.filters
