/* delete.c - ldbm backend delete routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
    struct berval	*dn,
    struct berval	*ndn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry	*matched;
	struct berval	pdn;
	Entry	*e, *p = NULL;
	int	rc = -1;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, "ldbm_back_delete: %s\n", dn->bv_val, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_delete: %s\n", dn->bv_val, 0, 0);
#endif

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, ndn, &matched )) == NULL ) {
		char *matched_dn = NULL;
		BerVarray refs;

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_delete: no such object %s\n", dn->bv_val, 0, 0 );
#else
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: no such object %s\n",
			dn->bv_val, 0, 0);
#endif

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );

		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( refs ) ber_bvarray_free( refs );
		free( matched_dn );

		return( -1 );
	}

	/* check entry for "entry" acl */
	if ( ! access_allowed( be, conn, op, e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_delete: no write access to entry of (%s)\n", 
			dn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<=- ldbm_back_delete: no write access to entry\n", 0,
			0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, "no write access to entry", NULL, NULL );

		rc = 1;
		goto return_results;
	}

    if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_delete: entry (%s) is a referral.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		if ( refs ) ber_bvarray_free( refs );

		rc = 1;
		goto return_results;
	}

	if ( has_children( be, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			   "ldbm_back_delete: (%s) is a non-leaf node.\n", dn->bv_val, 0,0);
#else
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: non leaf %s\n",
			dn->bv_val, 0, 0);
#endif

		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
			NULL, "subtree delete not supported", NULL, NULL );
		goto return_results;
	}

	/* delete from parent's id2children entry */
	if( !be_issuffix( be, &e->e_nname ) && (dnParent( &e->e_nname, &pdn ),
		pdn.bv_len) ) {
		if( (p = dn2entry_w( be, &pdn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_back_delete: parent of (%s) does not exist\n", dn, 0, 0 );
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
			children, NULL, ACL_WRITE, NULL ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_back_delete: no access to parent of (%s)\n", 
				dn->bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- ldbm_back_delete: no access to parent\n", 0,
				0, 0 );
#endif

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, "no write access to parent", NULL, NULL );
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( be, &op->o_ndn ) ) {
			if ( be_issuffix( be, (struct berval *)&slap_empty_bv ) || be_isupdate( be, &op->o_ndn ) ) {
				p = (Entry *)&slap_entry_root;
				
				rc = access_allowed( be, conn, op, p,
					children, NULL, ACL_WRITE, NULL );
				p = NULL;
								
				/* check parent for "children" acl */
				if ( ! rc ) {
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_delete: no access "
						"to parent of ("")\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- ldbm_back_delete: no "
						"access to parent\n", 0, 0, 0 );
#endif

					send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
						NULL, "no write access to parent", NULL, NULL );
					goto return_results;
				}

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR, 
					"ldbm_back_delete: (%s) has no "
					"parent & not a root.\n", dn, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"<=- ldbm_back_delete: no parent & "
					"not root\n", 0, 0, 0);
#endif

				send_ldap_result( conn, op, 
					LDAP_INSUFFICIENT_ACCESS,
					NULL, NULL, NULL, NULL );
				goto return_results;
			}
		}
	}

	/* delete from dn2id mapping */
	if ( dn2id_delete( be, &e->e_nname, e->e_id ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_delete: (%s) operations error\n", dn->bv_val, 0, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn->bv_val, 0, 0);
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index delete failed", NULL, NULL );
		goto return_results;
	}

	/* delete from disk and cache */
	if ( id2entry_delete( be, e ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_delete: (%s) operations error\n", dn->bv_val, 0, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn->bv_val, 0, 0);
#endif

		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "entry delete failed", NULL, NULL );
		goto return_results;
	}

	/* delete attribute indices */
	(void) index_entry_del( be, e, e->e_attrs );

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	rc = 0;

return_results:;
	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );

	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

	return rc;
}
