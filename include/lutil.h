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

#ifndef _LUTIL_H
#define _LUTIL_H 1

#include <ldap_cdefs.h>
/*
 * Include file for LDAP utility routine
 */

LDAP_BEGIN_DECL

/* ISC Base64 Routines */
/* base64.c */

LDAP_F( int )
lutil_b64_ntop LDAP_P((
	unsigned char const *,
	size_t,
	char *,
	size_t));

LDAP_F( int )
lutil_b64_pton LDAP_P((
	char const *,
	unsigned char *,
	size_t));

/* detach.c */
LDAP_F( void )
lutil_detach LDAP_P((
	int debug,
	int do_close));

/* passwd.c */
LDAP_F( int )
lutil_passwd LDAP_P((
	const char *cred,
	const char *passwd,
	const char **methods ));

/* utils.c */
LDAP_F( char* )
lutil_progname LDAP_P((
	const char* name,
	int argc,
	char *argv[] ));


LDAP_END_DECL

#endif /* _LUTIL_H */
