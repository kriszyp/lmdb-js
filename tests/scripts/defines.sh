LDIF2LDBM=../servers/slapd/tools/ldif2ldbm
SLAPD=../servers/slapd/slapd
SLURPD=../servers/slurpd/slurpd
LDAPSEARCH=../clients/tools/ldapsearch
LDAPMODIFY=../clients/tools/ldapmodify
LDAPADD=../clients/tools/ldapadd
PORT=9009
SLAVEPORT=9010
DBDIR=./test-db
REPLDIR=./test-repl
CONF=./data/slapd-master.conf
ACLCONF=./data/slapd-acl.conf
MASTERCONF=./data/slapd-repl-master.conf
SLAVECONF=./data/slapd-repl-slave.conf
LDIF=./data/test.ldif
LDIFORDERED=./data/test-ordered.ldif
BASEDN="o=University of Michigan, c=US"
MANAGERDN="cn=Manager, o=University of Michigan, c=US"
PASSWD=secret
BABSDN="cn=Barbara Jensen, ou=Information Technology Division, ou=People, o=University of Michigan, c=US"
BJORNSDN="cn=Bjorn Jensen, ou=Information Technology Division, ou=People, o=University of Michigan, c=US"
JAJDN="cn=James A Jones 1, ou=Alumni Association, ou=People, o=University of Michigan, c=US"
MASTERLOG=$DBDIR/master.log
SLAVELOG=$DBDIR/slave.log
SEARCHOUT=$DBDIR/ldapsearch.out
MASTEROUT=$DBDIR/master.out
SLAVEOUT=$DBDIR/slave.out
TESTOUT=$DBDIR/ldapsearch.out
SEARCHOUTMASTER=./data/search.out.master
MODIFYOUTMASTER=./data/modify.out.master
ADDDELOUTMASTER=./data/adddel.out.master
MODRDNOUTMASTER=./data/modrdn.out.master
ACLOUTMASTER=./data/acl.out.master
REPLOUTMASTER=./data/repl.out.master
MODSRCHFILTERS=./data/modify.search.filters
