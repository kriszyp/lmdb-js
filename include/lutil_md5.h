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

/* See md5.c for explanation and copyright information.  */

#ifndef _LUTIL_MD5_H_
#define _LUTIL_MD5_H_

#include <lber_types.h>

LDAP_BEGIN_DECL

/* Unlike previous versions of this code, ber_int_t need not be exactly
   32 bits, merely 32 bits or more.  Choosing a data type which is 32
   bits instead of 64 is not important; speed is considerably more
   important.  ANSI guarantees that "unsigned long" will be big enough,
   and always using it seems to have few disadvantages.  */

struct lutil_MD5Context {
	ber_uint_t buf[4];
	ber_uint_t bits[2];
	unsigned char in[64];
};

LIBLUTIL_F( void )
lutil_MD5Init LDAP_P((
	struct lutil_MD5Context *context));

LIBLUTIL_F( void )
lutil_MD5Update LDAP_P((
	struct lutil_MD5Context *context,
	unsigned char const *buf,
	ber_len_t len));

LIBLUTIL_F( void )
lutil_MD5Final LDAP_P((
	unsigned char digest[16],
	struct lutil_MD5Context *context));

LIBLUTIL_F( void )
lutil_MD5Transform LDAP_P((
	ber_uint_t buf[4],
	const unsigned char in[64]));

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct lutil_MD5Context lutil_MD5_CTX;

LDAP_END_DECL

#endif /* _LUTIL_MD5_H_ */
