/* overlays.c - Static overlay framework */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * Copyright 2003 by Howard Chu.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion in
 * OpenLDAP Software.
 */

#include "portable.h"

#include "slap.h"

#if SLAPD_OVER_CHAIN == SLAPD_MOD_STATIC
extern int chain_init();
#endif
#if SLAPD_OVER_DENYOP == SLAPD_MOD_STATIC
extern int denyop_init();
#endif
#if SLAPD_OVER_DYNGROUP == SLAPD_MOD_STATIC
extern int dyngroup_init();
#endif
#if SLAPD_OVER_LASTMOD == SLAPD_MOD_STATIC
extern int lastmod_init();
#endif
#if SLAPD_OVER_PPOLICY == SLAPD_MOD_STATIC
extern int ppolicy_init();
#endif
#if SLAPD_OVER_PROXYCACHE == SLAPD_MOD_STATIC
extern int pcache_init();
#endif
#if SLAPD_OVER_REFINT == SLAPD_MOD_STATIC
extern int refint_init();
#endif
#if SLAPD_OVER_RWM == SLAPD_MOD_STATIC
extern int rwm_init();
#endif
#if SLAPD_OVER_UNIQUE == SLAPD_MOD_STATIC
extern int unique_init();
#endif

static struct {
	char *name;
	int (*func)();
} funcs[] = {
#if SLAPD_OVER_CHAIN == SLAPD_MOD_STATIC
	{ "LDAP Chain Response", chain_init },
#endif
#if SLAPD_OVER_DENYOP == SLAPD_MOD_STATIC
	{ "Deny Operation", denyop_init },
#endif
#if SLAPD_OVER_DYNGROUP == SLAPD_MOD_STATIC
	{ "Dynamic Group", dyngroup_init },
#endif
#if SLAPD_OVER_LASTMOD == SLAPD_MOD_STATIC
	{ "Last Modification", lastmod_init },
#endif
#if SLAPD_OVER_PPOLICY == SLAPD_MOD_STATIC
	{ "Password Policy", ppolicy_init },
#endif
#if SLAPD_OVER_PROXYCACHE == SLAPD_MOD_STATIC
	{ "Proxy Cache", pcache_init },
#endif
#if SLAPD_OVER_REFINT == SLAPD_MOD_STATIC
	{ "Referential Integrity", refint_init },
#endif
#if SLAPD_OVER_RWM == SLAPD_MOD_STATIC
	{ "Rewrite/Remap", rwm_init },
#endif
#if SLAPD_OVER_UNIQUE == SLAPD_MOD_STATIC
	{ "Attribute Uniqueness", unique_init },
#endif
	{ NULL, NULL }
};

int
overlay_init(void)
{
	int i, rc = 0;

	for ( i=0; funcs[i].name; i++ ) {
		rc = funcs[i].func();
		if ( rc ) {
			Debug( LDAP_DEBUG_ANY,
		"%s overlay setup failed, err %d\n", funcs[i].name, rc, 0 );
			break;
		}
	}
	return rc;
}
