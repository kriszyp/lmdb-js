/* delete.c - ldbm backend delete routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_delete(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*dn,
    const char	*ndn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry	*matched;
	char	*pdn = NULL;
	Entry	*e, *p = NULL;
	int rootlock = 0;
	int	rc = -1;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_back_delete: %s\n", dn ));
#else
	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_delete: %s\n", dn, 0, 0);
#endif


	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, ndn, &matched )) == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_delete: no such object %s\n", dn ));
#else
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: no such object %s\n",
			dn, 0, 0);
#endif


		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return( -1 );
	}

    if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_delete: entry (%s) is a referral.\n",
			   e->e_dn ));
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );
#endif


		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		rc = 1;
		goto return_results;
	}


	if ( has_children( be, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "ldbm_back_delete: (%s) is a non-leaf node.\n", dn ));
#else
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: non leaf %s\n",
			dn, 0, 0);
#endif

		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
			NULL, "subtree delete not supported", NULL, NULL );
		goto return_results;
	}

	/* delete from parent's id2children entry */
	if( (pdn = dn_parent( be, e->e_ndn )) != NULL ) {
		if( (p = dn2entry_w( be, pdn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
				   "ldbm_back_delete: parent of (%s) does not exist\n", dn ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- ldbm_back_delete: parent does not exist\n",
				0, 0, 0);
#endif

			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "could not locate parent of entry", NULL, NULL );
			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
				   "ldbm_back_delete: no access to parent of (%s)\n", dn ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- ldbm_back_delete: no access to parent\n", 0,
				0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( be, op->o_ndn ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
				   "ldbm_back_delete: (%s) has no parent & not a root.\n",
				   dn ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- ldbm_back_delete: no parent & not root\n",
				0, 0, 0);
#endif

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto return_results;
		}

		ldap_pvt_thread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;
	}

	/* delete from dn2id mapping */
	if ( dn2id_delete( be, e->e_ndn, e->e_id ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "ldbm_back_delete: (%s) operations error\n", dn ));
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn, 0, 0);
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index delete failed", NULL, NULL );
		goto return_results;
	}

	/* delete from disk and cache */
	if ( id2entry_delete( be, e ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "ldbm_back_delete: (%s) operations error\n",
			   dn ));
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn, 0, 0);
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "entry delete failed", NULL, NULL );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	rc = 0;

return_results:;
	if ( pdn != NULL ) free(pdn);

	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	if ( rootlock ) {
		/* release root lock */
		ldap_pvt_thread_mutex_unlock(&li->li_root_mutex);
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );

	return rc;
}
