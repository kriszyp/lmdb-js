/* Generic unistd.h */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_UNISTD_H
#define _AC_UNISTD_H

#if HAVE_SYS_TYPES_H
#	include <sys/types.h>
#endif

#if HAVE_UNISTD_H
#	include <unistd.h>
#endif

/* crypt() may be defined in a separate include file */
#if HAVE_CRYPT_H
#	include <crypt.h>
#else
	extern char *crypt();
#endif

#ifndef HAVE_GETPASS
extern char* getpass LDAP_P((const char *getpass));
#endif

/* getopt() defines may be in separate include file */
#if HAVE_GETOPT_H
#	include <getopt.h>

#elif !defined(HAVE_GETOPT)
	/* no getopt, assume we need getopt-compat.h */
#	include <getopt-compat.h>

#else
	/* assume we need to declare these externs */
	extern char *optarg;
	extern int optind, opterr, optopt;
#endif

#ifndef HAVE_TEMPNAM
	extern char *tempnam(const char *tmpdir, const char *prefix);
#endif
#ifndef HAVE_MKTEMP
	extern char *mktemp(char *);
#endif

/* use _POSIX_VERSION for POSIX.1 code */

/* Setup file locking macros */
#if defined (HAVE_LOCKF) && defined (F_LOCK) && defined (F_ULOCK)
#	define ldap_lockf(x) lockf(fileno(x),F_LOCK, 0)
#	define ldap_unlockf(x) lockf(fileno(x),F_ULOCK, 0)
#elif defined (HAVE_FCNTL_H) && defined (F_WRLCK) && defined (F_UNLCK)
#	ifndef  NEED_FCNTL_LOCKING
#		define NEED_FCNTL_LOCKING
#	endif
#	include <lutil_lockf.h>
#	define ldap_lockf(x) lutil_ldap_lockf(x)
#	define ldap_unlockf(x) lutil_ldap_unlockf(x)
#elif defined (HAVE_FLOCK) && defined (LOCK_EX) && defined (LOCK_UN)
#	if HAVE_SYS_FILE_H
#		include <sys/file.h>
#	endif
#	define ldap_lockf(x) flock(fileno(x),LOCK_EX)
#	define ldap_unlockf(x) flock(fileno(x),LOCK_UN)
#else
#error no_suitable_locking_found
#endif

#endif /* _AC_UNISTD_H */
