/* entry.c - ldbm backend entry_release routine */
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

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


int
ldbm_back_entry_release_rw(
	Operation *op,
	Entry   *e,
	int     rw
)
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;

	if ( slapMode == SLAP_SERVER_MODE ) {
		/* free entry and reader or writer lock */
		cache_return_entry_rw( &li->li_cache, e, rw ); 
		/* only do_add calls here with a write lock.
		 * get_entry doesn't obtain the giant lock, because its
		 * caller has already obtained it.
		 */
		if( rw ) {
			ldap_pvt_thread_rdwr_wunlock( &li->li_giant_rwlock );
		}
#if 0
		else {
			ldap_pvt_thread_rdwr_runlock( &li->li_giant_rwlock );
		}
#endif

	} else {
		entry_free( e );
	}

	return 0;
}

/* return LDAP_SUCCESS IFF we can retrieve the specified entry.
 */
int ldbm_back_entry_get(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **ent )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	Entry *e;
	int	rc;
	const char *at_name = at ? at->ad_cname.bv_val : "(null)";

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ARGS, 
		"ldbm_back_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 );
	LDAP_LOG( BACK_LDBM, ARGS, 
		"ldbm_back_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);
#else
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> ldbm_back_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);
#endif

	/* don't grab the giant lock - our caller has already gotten it. */

	/* can we find entry */
	e = dn2entry_rw( op->o_bd, ndn, NULL, rw );
	if (e == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_entry_get: cannot find entry (%s)\n", 
			ndn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"=> ldbm_back_entry_get: cannot find entry: \"%s\"\n",
				ndn->bv_val, 0, 0 ); 
#endif
		return LDAP_NO_SUCH_OBJECT; 
	}
	
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, DETAIL1, "ldbm_back_entry_get: found entry (%s)\n",
		ndn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ACL,
		"=> ldbm_back_entry_get: found entry: \"%s\"\n",
		ndn->bv_val, 0, 0 ); 
#endif

#ifdef BDB_ALIASES
	/* find attribute values */
	if( is_entry_alias( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_entry_get: entry (%s) is an alias\n", e->e_name.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_entry_get: entry is an alias\n", 0, 0, 0 );
#endif
		rc = LDAP_ALIAS_PROBLEM;
		goto return_results;
	}
#endif

	if( is_entry_referral( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_entry_get: entry (%s) is a referral.\n", e->e_name.bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_entry_get: entry is a referral\n", 0, 0, 0 );
#endif
		rc = LDAP_REFERRAL;
		goto return_results;
	}

	if ( oc && !is_entry_objectclass( e, oc, 0 )) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_entry_get: failed to find objectClass.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= ldbm_back_entry_get: failed to find objectClass\n",
			0, 0, 0 ); 
#endif
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

	rc = LDAP_SUCCESS;

return_results:
	if( rc != LDAP_SUCCESS ) {
		/* free entry */
		cache_return_entry_rw(&li->li_cache, e, rw);
	} else {
		*ent = e;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, "ldbm_back_entry_get: rc=%d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"ldbm_back_entry_get: rc=%d\n",
		rc, 0, 0 ); 
#endif
	return(rc);
}
