/* add.c - ldap bdb2 back-end add routine */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static DB_LOCK         lock;


static int
bdb2i_back_add_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*pdn;
	Entry		*p = NULL;
	int			rc; 
	struct timeval  time1;

	Debug(LDAP_DEBUG_ARGS, "==> bdb2i_back_add: %s\n", e->e_dn, 0, 0);

	if ( ( bdb2i_dn2id( be, e->e_ndn ) ) != NOID ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS,
			NULL, NULL, NULL, NULL );
		return( -1 );
	}

	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "entry failed schema check\n",
			0, 0, 0 );

		entry_free( e );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION,
			NULL, NULL, NULL, NULL );
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
		if ( (p = bdb2i_dn2entry_w( be, pdn, &matched )) == NULL ) {
			char *matched_dn;
			struct berval **refs;

			if( matched != NULL ) {
				matched_dn = ch_strdup( matched->e_dn );
				refs = is_entry_referral( matched )
					? get_entry_referrals( be, conn, op, matched )
					: NULL;

				bdb2i_cache_return_entry_w( &li->li_cache, matched ); 

			} else {
				matched_dn = NULL;
				refs = default_referral;
			}

			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0 );

			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			    matched_dn, NULL, NULL, NULL );

			if ( matched != NULL ) {
				ber_bvecfree( refs );
				free( matched_dn );
			}

			entry_free( e );
			free( pdn );
			return -1;
		}

		free(pdn);

		if ( ! access_allowed( be, conn, op, p,
			"children", NULL, ACL_WRITE ) )
		{
			/* free parent and writer lock */
			bdb2i_cache_return_entry_w( &li->li_cache, p ); 

			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    NULL, NULL, NULL, NULL );

			entry_free( e );
			return -1;
		}


		if ( is_entry_alias( p ) ) {
			/* parent is an alias, don't allow add */

			/* free parent and writer lock */
			bdb2i_cache_return_entry_w( &li->li_cache, p ); 

			Debug( LDAP_DEBUG_TRACE, "parent is alias\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_ALIAS_PROBLEM,
			    NULL, NULL, NULL, NULL );

			entry_free( e );
			return -1;
		}

		if ( is_entry_referral( p ) ) {
			/* parent is an referral, don't allow add */
			char *matched_dn = ch_strdup( matched->e_dn );
			struct berval **refs = is_entry_referral( matched )
					? get_entry_referrals( be, conn, op, matched )
					: NULL;

			/* free parent and writer lock */
			bdb2i_cache_return_entry_w( &li->li_cache, p ); 

			Debug( LDAP_DEBUG_TRACE, "parent is referral\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_REFERRAL,
			    matched_dn, NULL, refs, NULL );

			ber_bvecfree( refs );
			free( matched_dn );
			entry_free( e );
			return -1;
		}

	} else {
		if(pdn != NULL) {
			assert( *pdn == '\0' );
			free(pdn);
		}

		/* no parent, must be adding entry to root */
		if ( !be_isroot( be, op->o_ndn ) && !be_issuffix(be, "") ) {
			Debug( LDAP_DEBUG_TRACE, "%s add denied\n",
				pdn == NULL ? "suffix" : "entry at root",
				0, 0 );

			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    NULL, NULL, NULL, NULL );

			entry_free( e );
			return -1;
		}
	}

	e->e_id = bdb2i_next_id( be );

	/*
	 * Try to add the entry to the cache, assign it a new dnid.
	 */
	bdb2i_start_timing( be->bd_info, &time1 );

	rc = bdb2i_cache_add_entry_rw( &li->li_cache, e, CACHE_WRITE_LOCK );

	bdb2i_stop_timing( be->bd_info, time1, "ADD-CACHE", conn, op );

	if ( rc != 0 ) {
		if( p != NULL) {
			/* free parent and writer lock */
			bdb2i_cache_return_entry_w( &li->li_cache, p ); 
		}

		Debug( LDAP_DEBUG_ANY, "cache_add_entry_lock failed\n", 0, 0,
		    0 );

		/* free the entry */
		entry_free( e );

		send_ldap_result( conn, op,
			rc > 0 ? LDAP_ALREADY_EXISTS : LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );

		return( -1 );
	}

	rc = -1;

	/*
	 * Add the entry to the attribute indexes, then add it to
	 * the id2entry and dn2id index.
	 */

	bdb2i_start_timing( be->bd_info, &time1 );

	/* attribute indexes */
	if ( bdb2i_index_add_entry( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_index_add_entry failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );

		bdb2i_stop_timing( be->bd_info, time1, "ADD-INDEX", conn, op );

		goto return_results;
	}

	bdb2i_stop_timing( be->bd_info, time1, "ADD-INDEX", conn, op );

	bdb2i_start_timing( be->bd_info, &time1 );

	/* dn2id index */
	if ( bdb2i_dn2id_add( be, e->e_ndn, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_dn2id_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
 			NULL, NULL, NULL, NULL );

		bdb2i_stop_timing( be->bd_info, time1, "ADD-DN2ID", conn, op );

		goto return_results;
	}

	bdb2i_stop_timing( be->bd_info, time1, "ADD-DN2ID", conn, op );

	bdb2i_start_timing( be->bd_info, &time1 );

	/* id2entry index */
	if ( bdb2i_id2entry_add( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_id2entry_add failed\n", 0,
		    0, 0 );
		(void) bdb2i_dn2id_delete( be, e->e_ndn, e->e_id );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
 			NULL, NULL, NULL, NULL );

		bdb2i_stop_timing( be->bd_info, time1, "ADD-ID2ENTRY", conn, op );

		goto return_results;
	}

	bdb2i_stop_timing( be->bd_info, time1, "ADD-ID2ENTRY", conn, op );

	send_ldap_result( conn, op, LDAP_SUCCESS,
 			NULL, NULL, NULL, NULL );
	rc = 0;

return_results:;
	if (p != NULL) {
		/* free parent and writer lock */
		bdb2i_cache_return_entry_w( &li->li_cache, p ); 
	}

	if ( rc ) {
		/* free entry and writer lock */
		bdb2i_cache_return_entry_w( &li->li_cache, e );
	}

	return( rc );
}


int
bdb2_back_add(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldbminfo	*li  = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_w( &lock ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		return( -1 );
	}

	/*  check, if a new default attribute index will be created,
		in which case we have to open the index file BEFORE TP  */
	switch ( slapMode & SLAP_MODE ) {
		case SLAP_SERVER_MODE:
		case SLAP_TOOL_MODE:
			bdb2i_check_default_attr_index_add( li, e );
			break;
	}

	ret = bdb2i_back_add_internal( be, conn, op, e );

	/*  if the operation was successful, we will delay the unlock  */
	if ( ret )
		(void) bdb2i_leave_backend_w( lock );

	bdb2i_stop_timing( be->bd_info, time1, "ADD", conn, op );

	return( ret );
}


int
bdb2i_release_add_lock( void )
{
	(void) bdb2i_leave_backend_w( lock );
	return 0;
}


