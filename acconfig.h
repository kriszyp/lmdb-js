/* acconfig.h
  Copyright 1998 The OpenLDAP Foundation,  All Rights Reserved.
  COPYING RESTRICTIONS APPLY, See COPYRIGHT file

   Descriptive text for the C preprocessor macros that
   the distributed Autoconf macros can define.

   Leave the following blank line there!!  Autoheader needs it.  */



/* define this if needed to get reentrant functions */
#undef REENTRANT
#undef _REENTRANT

/* define this if needed to get threadsafe functions */
#undef THREADSAFE
#undef _THREADSAFE
#undef THREAD_SAFE
#undef _THREAD_SAFE

/* define this if cross compiling */
#undef CROSS_COMPILING

/* define this if toupper() requires tolower() check */
#undef C_UPPER_LOWER

/* define this to the number of arguments ctime_r() expects
#undef CTIME_R_NARGS

/* define this if sys_errlist is not defined in stdio.h or errno.h */
#undef DECL_SYS_ERRLIST

/* define this if TIOCGWINSZ is defined in sys/ioctl.h */
#undef GWINSZ_IN_SYS_IOCTL

/* define if you have berkeley db */
#undef HAVE_BERKELEY_DB

/* define if you have berkeley db2 */
#undef HAVE_BERKELEY_DB2

/* define if you have crypt */
#undef HAVE_CRYPT

/* define if you have DSAP */
#undef HAVE_DSAP

/* define if you have GDBM */
#undef HAVE_GDBM

/* define if you have ISODE */
#undef HAVE_ISODE

/* define if you have Kerberos */
#undef HAVE_KERBEROS

/* define if you have LinuxThreads */
#undef HAVE_LINUX_THREADS

/* define if you have Sun LWP (SunOS style) */
#undef HAVE_LWP

/* define if you have -lncurses */
#undef HAVE_NCURSES

/* define if you have NDBM */
#undef HAVE_NDBM

/* define if you have Mach CThreads */
#undef HAVE_MACH_CTHREADS

/* define if you have POSIX termios */
#undef HAVE_POSIX_TERMIOS

/* define if you have PP */
#undef HAVE_PP

/* define if you have POSIX Threads */
#undef HAVE_PTHREADS

/* define if your POSIX Threads implementation is circa Final Draft */
#undef HAVE_PTHREADS_FINAL

/* define if your POSIX Threads implementation is circa Draft 4 */
#undef HAVE_PTHREADS_D4

/* define if you have ptrdiff_t */
#undef HAVE_PTRDIFF_T

/* define if you have sched_yield() */
#ifdef __notdef__
/* see second sched_yield define */
#undef HAVE_SCHED_YIELD
#endif

/* define if you have setproctitle() */
#undef HAVE_SETPROCTITLE

/* define if you have -lwrap */
#undef HAVE_TCPD

/* define if you have -ltermcap */
#undef HAVE_TERMCAP

/* define if you have Sun LWP (Solaris style) */
#undef HAVE_THR

/* define if you have XTPP */
#undef HAVE_XTPP

/* define this if select() implicitly yields in thread environments */
#undef HAVE_YIELDING_SELECT

/* define this for connectionless LDAP support */
#undef LDAP_CONNECTIONLESS

/* define this to add debugging code */
#undef LDAP_DEBUG

/* define this for LDAP DNS support */
#undef LDAP_DNS

/* define this to remove -lldap cache support */
#undef LDAP_NOCACHE

/* define this for LDAP process title support */
#undef LDAP_PROCTITLE

/* define this for LDAP User Interface support */
#undef LDAP_LIBUI

/* define this to add syslog code */
#undef LDAP_SYSLOG

/* define this to use DB2 in native mode */
#undef LDBM_USE_DB2

/* define this to use DB2 in compat185 mode */
#undef LDBM_USE_DB2_COMPAT185

/* define this to use DBBTREE w/ LDBM backend */
#undef LDBM_USE_DBBTREE

/* define this to use DBHASH w/ LDBM backend */
#undef LDBM_USE_DBHASH

/* define this to use GDBM w/ LDBM backend */
#undef LDBM_USE_GDBM

/* define this to use NDBM w/ LDBM backend */
#undef LDBM_USE_NDBM

/* define this if you want no termcap support */
#undef NO_TERMCAP

/* define this if you want no thread support */
#undef NO_THREADS

/* define this for ACL Group support */
#undef SLAPD_ACLGROUPS

/* define this for ClearText password support */
#undef SLAPD_CLEARTEXT

/* define this for crypt(3) password support */
#undef SLAPD_CRYPT

/* define this to use SLAPD LDBM backend */
#undef SLAPD_LDBM

/* define this to use SLAPD passwd backend */
#undef SLAPD_PASSWD

/* define this for phonetic support */
#undef SLAPD_PHONETIC

/* define this for Reverse Lookup support */
#undef SLAPD_RLOOKUPS

/* define this to use SLAPD shell backend */
#undef SLAPD_SHELL

/* define this to be empty if your compiler doesn't support volatile */
#undef volatile

/* define this if sig_atomic_t isn't defined in signal.h */
#undef sig_atomic_t

/* These are defined in ldap_features.h */
/*
	LDAP_API_FEATURE_X_OPENLDAP_REENTRANT
	LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE
	LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
	LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
*/


/* Leave that blank line there!!  Autoheader needs it. */
