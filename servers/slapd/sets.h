/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/* this routine needs to return the bervals instead of
 * plain strings, since syntax is not known.  It should
 * also return the syntax or some "comparison cookie"
 * that is used by set_filter.
 */
typedef BVarray (SET_GATHER) (void *cookie, char *name, struct berval *attr);

LDAP_SLAPD_F (long) set_size (BVarray set);
LDAP_SLAPD_F (void) set_dispose (BVarray set);

LDAP_SLAPD_F (int)
set_filter (SET_GATHER gatherer, void *cookie, struct berval *filter,
	    char *user, char *this, BVarray *results);

