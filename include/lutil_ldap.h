/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _LUTIL_LDAP_H
#define _LUTIL_LDAP_H 1

#include <ldap_cdefs.h>
#include <lber_types.h>

/*
 * Include file for lutil LDAP routines
 */

LDAP_BEGIN_DECL

LDAP_LUTIL_F( void * )
lutil_sasl_defaults LDAP_P((
	LDAP *ld,
	char *mech,
	char *realm,
	char *authcid,
	char *passwd,
	char *authzid ));

LDAP_LUTIL_F( int )
lutil_sasl_interact LDAP_P((
	LDAP *ld, unsigned flags, void *defaults, void *p ));

LDAP_END_DECL

#endif /* _LUTIL_LDAP_H */
