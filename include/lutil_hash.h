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

/* See hash.c for explanation and copyright information.  */

#ifndef _LUTIL_HASH_H_
#define _LUTIL_HASH_H_

#include <lber_types.h>

LDAP_BEGIN_DECL

#define LUTIL_HASH_BYTES 4

struct lutil_HASHContext {
	ber_uint_t hash;
};

LDAP_LUTIL_F( void )
lutil_HASHInit LDAP_P((
	struct lutil_HASHContext *context));

LDAP_LUTIL_F( void )
lutil_HASHUpdate LDAP_P((
	struct lutil_HASHContext *context,
	unsigned char const *buf,
	ber_len_t len));

LDAP_LUTIL_F( void )
lutil_HASHFinal LDAP_P((
	unsigned char digest[LUTIL_HASH_BYTES],
	struct lutil_HASHContext *context));

typedef struct lutil_HASHContext lutil_HASH_CTX;

LDAP_END_DECL

#endif /* _LUTIL_HASH_H_ */
