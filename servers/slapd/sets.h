/* $OpenLDAP$ */
/*
 * Copyright 2000-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef SLAP_SETS_H_
#define SLAP_SETS_H_

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/* this routine needs to return the bervals instead of
 * plain strings, since syntax is not known.  It should
 * also return the syntax or some "comparison cookie"
 * that is used by set_filter.
 */
typedef BerVarray (SLAP_SET_GATHER)(
	void *cookie, struct berval *name, struct berval *attr);

LDAP_SLAPD_F (long) slap_set_size(BerVarray set);
LDAP_SLAPD_F (void) slap_set_dispose(BerVarray set);

LDAP_SLAPD_F (int) slap_set_filter(
	SLAP_SET_GATHER gatherer,
	void *cookie, struct berval *filter,
	struct berval *user, struct berval *this, BerVarray *results);

LDAP_END_DECL

#endif
