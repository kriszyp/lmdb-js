/*
 * Copyright 1998-2002 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */

#ifndef _LDAP_PORTABLE_H
#define _LDAP_PORTABLE_H

/* end of preamble */

@TOP@

/* define this if needed to get reentrant functions */
#ifndef REENTRANT
#undef REENTRANT
#endif
#ifndef _REENTRANT
#undef _REENTRANT
#endif

/* define this if needed to get threadsafe functions */
#ifndef THREADSAFE
#undef THREADSAFE
#endif
#ifndef _THREADSAFE
#undef _THREADSAFE
#endif
#ifndef THREAD_SAFE
#undef THREAD_SAFE
#endif
#ifndef _THREAD_SAFE
#undef _THREAD_SAFE
#endif

#ifndef _SGI_MP_SOURCE
#undef _SGI_MP_SOURCE
#endif

/* define this if TIOCGWINSZ is defined in sys/ioctl.h */
#undef GWINSZ_IN_SYS_IOCTL

/* These are defined in ldap_features.h */
/*
	LDAP_API_FEATURE_X_OPENLDAP_REENTRANT
	LDAP_API_FEATURE_X_OPENLDAP_THREAD_SAFE
	LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
*/

/* These are defined in lber_types.h */
/*
	LBER_INT_T
	LBER_LEN_T
	LBER_SOCKET_T
	LBER_TAG_T
*/

/* define to character address type */
#undef caddr_t

/* define to signed size type */
#undef ssize_t


/* Leave that blank line there!!  Autoheader needs it. */

@BOTTOM@

/* begin of postamble */

#ifdef _WIN32
	/* don't suck in all of the win32 api */
#	define WIN32_LEAN_AND_MEAN 1
#endif

#ifndef LDAP_NEEDS_PROTOTYPES
/* force LDAP_P to always include prototypes */
#define LDAP_NEEDS_PROTOTYPES 1
#endif

#ifdef HAVE_STDDEF_H
#	include <stddef.h>
#endif

#if defined(LDAP_DEVEL) && !defined(LDAP_TEST)
#define LDAP_TEST
#endif
#if defined(LDAP_TEST) && !defined(LDAP_DEBUG)
#define LDAP_DEBUG
#endif

#include "ldap_cdefs.h"
#include "ldap_features.h"

#include "ac/assert.h"

#endif /* _LDAP_PORTABLE_H */
