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

MONITORDB=${AC_monitor-no}
BACKLDAP=${AC_ldap-ldapno}
BACKRELAY=${AC_relay-relayno}
BACKSQL=${AC_sql-sqlno}
RDBMS=${SLAPD_USE_SQL-rdbmsno}
RDBMSWRITE=${SLAPD_USE_SQLWRITE-no}
PROXYCACHE=${AC_pcache-pcacheno}
PPOLICY=${AC_ppolicy-ppolicyno}
REFINT=${AC_refint-refintno}
UNIQUE=${AC_unique-uniqueno}
RWM=${AC_rwm-rwmno}
WITH_SASL=${AC_WITH_SASL-no}
USE_SASL=${SLAPD_USE_SASL-no}
WITHTLS=${AC_WITHTLS-yes}

DATADIR=./testdata
PROGDIR=./progs
TESTDIR=./testrun

DBDIR1A=$TESTDIR/db.1.a
DBDIR1B=$TESTDIR/db.1.b
DBDIR1C=$TESTDIR/db.1.c
DBDIR1=$DBDIR1A
DBDIR2=$TESTDIR/db.2.a
DBDIR3=$TESTDIR/db.3.a
DBDIR4=$TESTDIR/db.4.a
DBDIR5=$TESTDIR/db.5.a
DBDIR6=$TESTDIR/db.6.a

CONF=$DATADIR/slapd.conf
CONFTWO=$DATADIR/slapd2.conf
MCONF=$DATADIR/slapd-master.conf
PWCONF=$DATADIR/slapd-pw.conf
WHOAMICONF=$DATADIR/slapd-whoami.conf
ACLCONF=$DATADIR/slapd-acl.conf
RCONF=$DATADIR/slapd-referrals.conf
MASTERCONF=$DATADIR/slapd-repl-master.conf
SRMASTERCONF=$DATADIR/slapd-syncrepl-master.conf
SLAVECONF=$DATADIR/slapd-repl-slave.conf
PPOLICYCONF=$DATADIR/slapd-ppolicy.conf
PROXYCACHECONF=$DATADIR/slapd-proxycache.conf
CACHEMASTERCONF=$DATADIR/slapd-cache-master.conf
R1SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-refresh1.conf
R2SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-refresh2.conf
P1SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-persist1.conf
P2SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-persist2.conf
P3SRSLAVECONF=$DATADIR/slapd-syncrepl-slave-persist3.conf
REFSLAVECONF=$DATADIR/slapd-ref-slave.conf
SCHEMACONF=$DATADIR/slapd-schema.conf
GLUECONF=$DATADIR/slapd-glue.conf
REFINTCONF=$DATADIR/slapd-refint.conf
UNIQUECONF=$DATADIR/slapd-unique.conf
LIMITSCONF=$DATADIR/slapd-limits.conf
DNCONF=$DATADIR/slapd-dn.conf
EMPTYDNCONF=$DATADIR/slapd-emptydn.conf
IDASSERTCONF=$DATADIR/slapd-idassert.conf
LDAPGLUECONF1=$DATADIR/slapd-ldapglue.conf
LDAPGLUECONF2=$DATADIR/slapd-ldapgluepeople.conf
LDAPGLUECONF3=$DATADIR/slapd-ldapgluegroups.conf
RWMCONF=$DATADIR/slapd-relay.conf
SQLCONF=$DATADIR/slapd-sql.conf

CONF1=$TESTDIR/slapd.1.conf
CONF2=$TESTDIR/slapd.2.conf
CONF3=$TESTDIR/slapd.3.conf
CONF4=$TESTDIR/slapd.4.conf
CONF5=$TESTDIR/slapd.5.conf
CONF6=$TESTDIR/slapd.6.conf
ADDCONF=$TESTDIR/slapadd.conf

TOOLARGS="-x $LDAP_TOOLARGS"
TOOLPROTO="-P 3"

PASSWDCONF=$DATADIR/slapd-passwd.conf

CLIENTDIR=../clients/tools
#CLIENTDIR=/usr/local/bin

LDIFFILTER=$SRCDIR/scripts/acfilter.sh
CONFFILTER=$SRCDIR/scripts/conf.sh

SLAPADD="../servers/slapd/slapd -Ta $LDAP_VERBOSE"
SLAPCAT="../servers/slapd/slapd -Tc $LDAP_VERBOSE"
SLAPINDEX="../servers/slapd/slapd -Ti $LDAP_VERBOSE"

unset DIFF_OPTIONS
DIFF="diff -iu"
CMP="diff -i"
BCMP="diff -iB"
CMPOUT=/dev/null
SLAPD="../servers/slapd/slapd -s0"
SLURPD=../servers/slurpd/slurpd
LDAPPASSWD="$CLIENTDIR/ldappasswd $TOOLARGS"
LDAPSASLSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $LDAP_TOOLARGS -LLL"
LDAPSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $TOOLARGS -LLL"
LDAPRSEARCH="$CLIENTDIR/ldapsearch $TOOLPROTO $TOOLARGS"
LDAPMODIFY="$CLIENTDIR/ldapmodify $TOOLPROTO $TOOLARGS"
LDAPADD="$CLIENTDIR/ldapmodify -a $TOOLPROTO $TOOLARGS"
LDAPMODRDN="$CLIENTDIR/ldapmodrdn $TOOLPROTO $TOOLARGS"
LDAPWHOAMI="$CLIENTDIR/ldapwhoami $TOOLARGS"
LDAPCOMPARE="$CLIENTDIR/ldapcompare $TOOLARGS"
SLAPDTESTER=$PROGDIR/slapd-tester
LVL=${SLAPD_DEBUG-261}
LOCALHOST=localhost
BASEPORT=${SLAPD_BASEPORT-9010}
PORT1=`expr $BASEPORT + 1`
PORT2=`expr $BASEPORT + 2`
PORT3=`expr $BASEPORT + 3`
PORT4=`expr $BASEPORT + 4`
PORT5=`expr $BASEPORT + 5`
PORT6=`expr $BASEPORT + 6`
URI1="ldap://${LOCALHOST}:$PORT1/"
URI2="ldap://${LOCALHOST}:$PORT2/"
URI3="ldap://${LOCALHOST}:$PORT3/"
URI4="ldap://${LOCALHOST}:$PORT4/"
URI5="ldap://${LOCALHOST}:$PORT5/"
URI6="ldap://${LOCALHOST}:$PORT6/"
LDIF=$DATADIR/test.ldif
LDIFGLUED=$DATADIR/test-glued.ldif
LDIFORDERED=$DATADIR/test-ordered.ldif
LDIFORDEREDCP=$DATADIR/test-ordered-cp.ldif
LDIFORDEREDNOCP=$DATADIR/test-ordered-nocp.ldif
LDIFBASE=$DATADIR/test-base.ldif
LDIFPASSWD=$DATADIR/passwd.ldif
LDIFWHOAMI=$DATADIR/test-whoami.ldif
LDIFPASSWDOUT=$DATADIR/passwd-out.ldif
LDIFPPOLICY=$DATADIR/ppolicy.ldif
LDIFLANG=$DATADIR/test-lang.ldif
LDIFLANGOUT=$DATADIR/lang-out.ldif
LDIFREF=$DATADIR/referrals.ldif
LDIFREFINT=$DATADIR/test-refint.ldif
LDIFUNIQUE=$DATADIR/test-unique.ldif
LDIFLIMITS=$DATADIR/test-limits.ldif
LDIFDN=$DATADIR/test-dn.ldif
LDIFEMPTYDN1=$DATADIR/test-emptydn1.ldif
LDIFEMPTYDN2=$DATADIR/test-emptydn2.ldif
LDIFIDASSERT1=$DATADIR/test-idassert1.ldif
LDIFIDASSERT2=$DATADIR/test-idassert2.ldif
LDIFLDAPGLUE1=$DATADIR/test-ldapglue.ldif
LDIFLDAPGLUE2=$DATADIR/test-ldapgluepeople.ldif
LDIFLDAPGLUE3=$DATADIR/test-ldapgluegroups.ldif
MONITOR=""
REFDN="c=US"
BASEDN="dc=example,dc=com"
MANAGERDN="cn=Manager,dc=example,dc=com"
UPDATEDN="cn=Replica,dc=example,dc=com"
PASSWD=secret
BABSDN="cn=Barbara Jensen,ou=Information Technology DivisioN,OU=People,dc=example,dc=com"
BJORNSDN="cn=Bjorn Jensen,ou=Information Technology DivisioN,OU=People,dc=example,dc=com"
JAJDN="cn=James A Jones 1,ou=Alumni Association,ou=People,dc=example,dc=com"
REFINTDN="cn=Manager,o=refint"
UNIQUEDN="cn=Manager,o=unique"
EMPTYDNDN="cn=Manager,c=US"

LOG1=$TESTDIR/slapd.1.log
LOG2=$TESTDIR/slapd.2.log
LOG3=$TESTDIR/slapd.3.log
LOG4=$TESTDIR/slapd.4.log
LOG5=$TESTDIR/slapd.5.log
LOG6=$TESTDIR/slapd.6.log
SLAPADDLOG1=$TESTDIR/slapadd.1.log
SLURPLOG=$TESTDIR/slurp.log

SEARCHOUT=$TESTDIR/ldapsearch.out
SEARCHFLT=$TESTDIR/ldapsearch.flt
LDIFFLT=$TESTDIR/ldif.flt
TESTOUT=$TESTDIR/test.out
INITOUT=$TESTDIR/init.out

SERVER1OUT=$TESTDIR/server1.out
SERVER1FLT=$TESTDIR/server1.flt
SERVER2OUT=$TESTDIR/server2.out
SERVER2FLT=$TESTDIR/server2.flt
SERVER3OUT=$TESTDIR/server3.out
SERVER3FLT=$TESTDIR/server3.flt
SERVER4OUT=$TESTDIR/server4.out
SERVER4FLT=$TESTDIR/server4.flt
SERVER5OUT=$TESTDIR/server5.out
SERVER5FLT=$TESTDIR/server5.flt
SERVER6OUT=$TESTDIR/server6.out
SERVER6FLT=$TESTDIR/server6.flt

MASTEROUT=$SERVER1OUT
MASTERFLT=$SERVER1FLT
SLAVEOUT=$SERVER2OUT
SLAVEFLT=$SERVER2FLT

PROXYCACHEOUT=$DATADIR/proxycache.out
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
DNOUT=$DATADIR/dn.out
EMPTYDNOUT1=$DATADIR/emptydn.out.slapadd
EMPTYDNOUT2=$DATADIR/emptydn.out
IDASSERTOUT=$DATADIR/idassert.out
LDAPGLUEOUT=$DATADIR/ldapglue.out
LDAPGLUEANONYMOUSOUT=$DATADIR/ldapglueanonymous.out
RELAYOUT=$DATADIR/relay.out
SQLMASTER=$DATADIR/sqlmaster.out
SQLMODS=$DATADIR/sqlmods.out

# Just in case we linked the binaries dynamically
LD_LIBRARY_PATH=`pwd`/../libraries:${LD_LIBRARY_PATH} export LD_LIBRARY_PATH
