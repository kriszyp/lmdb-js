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
/*
 * getopt(3) declarations
 */
#ifndef _GETOPT_COMPAT_H
#define _GETOPT_COMPAT_H

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

extern char *optarg;
extern int optind, opterr, optopt;

#ifdef __MINGW32__
#   undef LDAP_F_PRE
#   ifdef LIBLUTIL_DECL
#	define LDAP_F_PRE	extern __declspec(LIBLUTIL_DECL)
#   else
#	define LDAP_F_PRE	extern
#   endif
#endif

LDAP_F( int )
getopt LDAP_P((
	int,
	char * const [],
	const char *));

LDAP_END_DECL

#endif /* _GETOPT_COMPAT_H */
