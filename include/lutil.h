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

#ifndef _LUTIL_H
#define _LUTIL_H 1

#include <ldap_cdefs.h>
#include <lber_types.h>

/*
 * Include file for LDAP utility routine
 */

LDAP_BEGIN_DECL

/* n octets encode into ceiling(n/3) * 4 bytes */
/* Avoid floating point math by through extra padding */

#define LUTIL_BASE64_ENCODE_LEN(n)	((n)/3 * 4 + 4)
#define LUTIL_BASE64_DECODE_LEN(n)	((n)/4 * 3)

/* ISC Base64 Routines */
/* base64.c */

LDAP_LUTIL_F( int )
lutil_b64_ntop LDAP_P((
	unsigned char const *,
	size_t,
	char *,
	size_t));

LDAP_LUTIL_F( int )
lutil_b64_pton LDAP_P((
	char const *,
	unsigned char *,
	size_t));

/* detach.c */
LDAP_LUTIL_F( void )
lutil_detach LDAP_P((
	int debug,
	int do_close));

/* entropy.c */
LDAP_LUTIL_F( int )
lutil_entropy LDAP_P((
	char *buf,
	ber_len_t nbytes ));

/* passwd.c */
struct berval; /* avoid pulling in lber.h */

LDAP_LUTIL_F( int )
lutil_authpasswd LDAP_P((
	const struct berval *passwd,	/* stored password */
	const struct berval *cred,	/* user supplied value */
	const char **methods ));

LDAP_LUTIL_F( int )
lutil_authpasswd_hash LDAP_P((
	const struct berval *cred,
	struct berval **passwd,	/* password to store */
	struct berval **salt,	/* salt to store */
	const char *method ));

#if defined( SLAPD_SPASSWD ) && defined( HAVE_CYRUS_SASL )
	/* cheat to avoid pulling in <sasl.h> */
LDAP_LUTIL_F( struct sasl_conn * ) lutil_passwd_sasl_conn;
#endif

LDAP_LUTIL_F( int )
lutil_passwd LDAP_P((
	const struct berval *passwd,	/* stored password */
	const struct berval *cred,	/* user supplied value */
	const char **methods ));

LDAP_LUTIL_F( struct berval * )
lutil_passwd_generate LDAP_P(( ber_len_t ));

LDAP_LUTIL_F( struct berval * )
lutil_passwd_hash LDAP_P((
	const struct berval *passwd,
	const char *method ));

LDAP_LUTIL_F( int )
lutil_passwd_scheme LDAP_P((
	const char *scheme ));

/* utils.c */
LDAP_LUTIL_F( char* )
lutil_progname LDAP_P((
	const char* name,
	int argc,
	char *argv[] ));

/* sockpair.c */
LDAP_LUTIL_F( int )
lutil_pair( LBER_SOCKET_T sd[2] );

LDAP_END_DECL

#endif /* _LUTIL_H */
