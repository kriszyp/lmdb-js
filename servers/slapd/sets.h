/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#ifndef SLAP_SETS_H_
#define SLAP_SETS_H_

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

typedef struct slap_set_cookie {
	struct slap_op *op;
} SetCookie;

/* this routine needs to return the bervals instead of
 * plain strings, since syntax is not known.  It should
 * also return the syntax or some "comparison cookie"
 * that is used by set_filter.
 */
typedef BerVarray (SLAP_SET_GATHER)( SetCookie *cookie,
		struct berval *name, AttributeDescription *ad);

LDAP_SLAPD_F (int) slap_set_filter(
	SLAP_SET_GATHER gatherer,
	SetCookie *cookie, struct berval *filter,
	struct berval *user, struct berval *target, BerVarray *results);

LDAP_SLAPD_F (BerVarray) slap_set_join(SetCookie *cp,
	BerVarray lset, int op, BerVarray rset);
	
LDAP_END_DECL

#endif
