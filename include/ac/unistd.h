/* Generic unistd.h */
/* $OpenLDAP$ */
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

#if HAVE_PROCESS_H
#	include <process.h>
#endif

/* note: callers of crypt(3) should include <ac/crypt.h> */

#ifndef HAVE_GETPASS
LIBLUTIL_F(char*)(getpass) LDAP_P((const char *getpass));
#else
LIBC_F(char*)(getpass)();
#endif

/* getopt() defines may be in separate include file */
#if HAVE_GETOPT_H
#	include <getopt.h>

#elif !defined(HAVE_GETOPT)
	/* no getopt, assume we need getopt-compat.h */
#	include <getopt-compat.h>

#else
	/* assume we need to declare these externs */
	LIBC_F (char *) optarg;
	LIBC_F (int) optind, opterr, optopt;
#endif

#ifndef HAVE_TEMPNAM
	LIBLUTIL_F(char *)(tempnam) LDAP_P(( const char *tmpdir,
					     const char *prefix));
#endif

/* use lutil file locking */
#define ldap_lockf(x)	lutil_lockf(x)
#define ldap_unlockf(x)	lutil_unlockf(x)
#include <lutil_lockf.h>

#endif /* _AC_UNISTD_H */
