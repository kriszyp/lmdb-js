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

/* This version is based on:
 *	$OpenBSD: sha1.h,v 1.8 1997/07/15 01:54:23 millert Exp $	*/

#ifndef _LUTIL_SHA1_H_
#define _LUTIL_SHA1_H_

#include <ldap_cdefs.h>
#include <ac/bytes.h>

LDAP_BEGIN_DECL

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 */

#ifndef LDAP_UINT32
#define LDAP_UINT32 1
typedef ac_uint4 uint32;
#endif

typedef struct {
    uint32 state[5];
    uint32 count[2];  
    unsigned char buffer[64];
} lutil_SHA1_CTX;
  
LDAP_F( void )
lutil_SHA1Transform
	LDAP_P((uint32 state[5], const unsigned char buffer[64]));

LDAP_F( void  )
lutil_SHA1Init
	LDAP_P((lutil_SHA1_CTX *context));

LDAP_F( void  )
lutil_SHA1Update
	LDAP_P((lutil_SHA1_CTX *context, const unsigned char *data, uint32 len));

LDAP_F( void  )
lutil_SHA1Final
	LDAP_P((unsigned char digest[20], lutil_SHA1_CTX *context));

LDAP_F( char * )
lutil_SHA1End
	LDAP_P((lutil_SHA1_CTX *, char *));

LDAP_F( char * )
lutil_SHA1File
	LDAP_P((char *, char *));

LDAP_F( char * )
lutil_SHA1Data
	LDAP_P((const unsigned char *, size_t, char *));

LDAP_END_DECL

#endif /* _LUTIL_SHA1_H_ */
