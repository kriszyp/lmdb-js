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
#include <lber_types.h>

/*
 * Include file for LDAP utility routine
 */

LDAP_BEGIN_DECL

#ifdef __MINGW32__
#   undef LDAP_F_PRE
#   ifdef LIBLUTIL_DECL
#	define LDAP_F_PRE	extern __declspec(LIBLUTIL_DECL)
#   else
#	define LDAP_F_PRE	extern
#   endif
#endif

/* n octets encode into ceiling(n/3) * 4 bytes */
/* Avoid floating point math by through extra padding */

#define LUTIL_BASE64_ENCODE_LEN(n)	((n)/3 * 4 + 4)
#define LUTIL_BASE64_DECODE_LEN(n)	((n)/4 * 3)

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

/* entropy.c */
LDAP_F( int )
lutil_entropy LDAP_P((
	char *buf,
	int nbytes ));

/* passwd.c */
LDAP_F( int )
lutil_passwd LDAP_P((
	const char *cred,
	const char *passwd,
	const char **methods ));

extern const char* lutil_passwd_schemes[];

LDAP_F( int )
lutil_passwd_scheme LDAP_P((char *scheme));

/* utils.c */
LDAP_F( char* )
lutil_progname LDAP_P((
	const char* name,
	int argc,
	char *argv[] ));

/* sockpair.c */
LDAP_F( int )
lutil_pair( LBER_SOCKET_T sd[2] );

LDAP_END_DECL

#endif /* _LUTIL_H */
