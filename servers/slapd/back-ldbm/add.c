/* add.c - ldap ldbm back-end add routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*pdn;
	Entry		*p = NULL;
	int			rootlock = 0;
	int			rc; 
	const char	*text = NULL;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *children = slap_schema.si_ad_children;
#else
	static const char *children = "children";
#endif


	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_add: %s\n", e->e_dn, 0, 0);

	/* nobody else can add until we lock our parent */
	ldap_pvt_thread_mutex_lock(&li->li_add_mutex);

	if ( ( dn2id( be, e->e_ndn ) ) != NOID ) {
		ldap_pvt_thread_mutex_unlock(&li->li_add_mutex);
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS,
			NULL, NULL, NULL, NULL );
		return( -1 );
	}

	rc = entry_schema_check( e, NULL, &text );

	if ( rc != LDAP_SUCCESS ) {
		ldap_pvt_thread_mutex_unlock(&li->li_add_mutex);

		Debug( LDAP_DEBUG_TRACE, "entry failed schema check: %s\n",
			text, 0, 0 );

		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		return( -1 );
	}

	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 * If the parent does not exist, only allow the "root" user to
	 * add the entry.
	 */

	pdn = dn_parent( be, e->e_ndn );

	if( pdn != NULL && *pdn != '\0' ) {
		Entry *matched = NULL;

		assert( *pdn != '\0' );

		/* get parent with writer lock */
		if ( (p = dn2entry_w( be, pdn, &matched )) == NULL ) {
			char *matched_dn;
			struct berval **refs;

			ldap_pvt_thread_mutex_unlock(&li->li_add_mutex);

			if ( matched != NULL ) {
				matched_dn = ch_strdup( matched->e_dn );
				refs = is_entry_referral( matched )
					? get_entry_referrals( be, conn, op, matched )
					: NULL;
				cache_return_entry_r( &li->li_cache, matched );

			} else {
				matched_dn = NULL;
				refs = default_referral;
			}

			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0 );

			send_ldap_result( conn, op, LDAP_REFERRAL,
			    matched_dn, NULL, refs, NULL );

			if( matched != NULL ) {
				ber_bvecfree( refs );
				free( matched_dn );
			}

			free( pdn );
			return -1;
		}

		/* don't need the add lock anymore */
		ldap_pvt_thread_mutex_unlock(&li->li_add_mutex);

		free(pdn);

		if ( ! access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE ) )
		{
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 

			Debug( LDAP_DEBUG_TRACE, "no write access to parent\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    NULL, "no write access to parent", NULL, NULL );


			return -1;
		}

		if ( is_entry_alias( p ) ) {
			/* parent is an alias, don't allow add */

			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p );

			Debug( LDAP_DEBUG_TRACE, "parent is alias\n", 0,
			    0, 0 );

			send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM,
			    NULL, "parent is an alias", NULL, NULL );

			return -1;
		}

		if ( is_entry_referral( p ) ) {
			/* parent is a referral, don't allow add */
			char *matched_dn = ch_strdup( p->e_dn );
			struct berval **refs = is_entry_referral( p )
				? get_entry_referrals( be, conn, op, p )
				: NULL;

			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p );

			Debug( LDAP_DEBUG_TRACE, "parent is referral\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_REFERRAL,
			    matched_dn, NULL, refs, NULL );

			ber_bvecfree( refs );
			free( matched_dn );
			return -1;
		}

	} else {
		if(pdn != NULL) {
			assert( *pdn == '\0' );
			free(pdn);
		}

		/* no parent, must be adding entry to root */
		if ( !be_isroot( be, op->o_ndn ) && !be_issuffix( be, "" ) ) {
			ldap_pvt_thread_mutex_unlock(&li->li_add_mutex);

			Debug( LDAP_DEBUG_TRACE, "%s add denied\n",
					pdn == NULL ? "suffix" : "entry at root",
					0, 0 );

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    NULL, NULL, NULL, NULL );

			return -1;
		}

		/*
		 * no parent, acquire the root write lock
		 * and release the add lock.
		 */
		ldap_pvt_thread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;
		ldap_pvt_thread_mutex_unlock(&li->li_add_mutex);
	}

	e->e_id = next_id( be );

	/*
	 * Try to add the entry to the cache, assign it a new dnid.
	 */
	rc = cache_add_entry_rw(&li->li_cache, e, CACHE_WRITE_LOCK);

	if ( rc != 0 ) {
		if( p != NULL) {
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
		}

		if ( rootlock ) {
			/* release root lock */
			ldap_pvt_thread_mutex_unlock(&li->li_root_mutex);
		}

		Debug( LDAP_DEBUG_ANY, "cache_add_entry_lock failed\n", 0, 0,
		    0 );

		send_ldap_result( conn, op,
			rc > 0 ? LDAP_ALREADY_EXISTS : LDAP_OTHER,
			NULL, rc > 0 ? NULL : "cache add failed", NULL, NULL );

		return( -1 );
	}

	rc = -1;

	/* attribute indexes */
	if ( index_entry_add( be, e, e->e_attrs ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "index_entry_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "index generation failed", NULL, NULL );

		goto return_results;
	}

	/* dn2id index */
	if ( dn2id_add( be, e->e_ndn, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "dn2id_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "DN index generation failed", NULL, NULL );

		goto return_results;
	}

	/* id2entry index */
	if ( id2entry_add( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "id2entry_add failed\n", 0,
		    0, 0 );
		(void) dn2id_delete( be, e->e_ndn, e->e_id );
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "entry store failed", NULL, NULL );

		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	rc = 0;

return_results:;
	if (p != NULL) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p ); 
	}

	if ( rootlock ) {
		/* release root lock */
		ldap_pvt_thread_mutex_unlock(&li->li_root_mutex);
	}

	if ( rc ) {
		/* free entry and writer lock */
		cache_return_entry_w( &li->li_cache, e );
	}

	return( rc );
}
