/* Generic setproctitle.h */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_SETPROCTITLE_H
#define _AC_SETPROCTITLE_H

#ifdef LDAP_PROCTITLE

#if defined( HAVE_LIBUTIL_H )
#	include <libutil.h>
#else
	/* use lutil version */
	LDAP_LUTIL_F (void) (setproctitle) LDAP_P((const char *fmt, ...)) \
		LDAP_GCCATTR((format(printf, 1, 2)));
	LDAP_LUTIL_V (int) Argc;
	LDAP_LUTIL_V (char) **Argv;
#endif

#endif /* LDAP_PROCTITLE */
#endif /* _AC_SETPROCTITLE_H */
