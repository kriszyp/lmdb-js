/* acconfig.h
   Descriptive text for the C preprocessor macros that
   the distributed Autoconf macros can define.

   Leave the following blank line there!!  Autoheader needs it.  */


/* define this if sys_errlist is not defined in stdio.h or errno.h */
#undef DECL_SYS_ERRLIST

/* define this you have crypt */
#undef HAVE_CRYPT

/* define this for connectionless LDAP support */
#undef LDAP_CONNECTIONLESS

/* define this to remove -lldap cache support */
#undef LDAP_NOCACHE

/* define this for phonetic support */
#undef LDAP_PHONETIC

/* define this for LDAP referrals support */
#undef LDAP_REFERRALS

/* define this to use SLAPD shell backend */
#undef SLAPD_SHELL

/* define this to use SLAPD passwd backend */
#undef SLAPD_PASSWD

/* define this to use SLAPD LDBM backend */
#undef SLAPD_LDBM

/* define this to use DBBTREE w/ LDBM backend */
#undef LDBM_USE_DBBTREE

/* define this to use DBHASH w/ LDBM backend */
#undef LDBM_USE_DBHASH

/* define this to use GDBM w/ LDBM backend */
#undef LDBM_USE_GDBM

/* define this to use NDBM w/ LDBM backend */
#undef LDBM_USE_NDBM


/* Leave that blank line there!!  Autoheader needs it. */
