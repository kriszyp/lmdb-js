/* add.c - ldap bdb2 back-end add routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

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

	Debug(LDAP_DEBUG_ARGS, "==> bdb2i_back_add: %s\n", e->e_dn, 0, 0);

	if ( ( bdb2i_dn2id( be, e->e_ndn ) ) != NOID ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, "", "" );
		return( -1 );
	}

	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "entry failed schema check\n",
			0, 0, 0 );

		entry_free( e );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION, "",
		    "" );
		return( -1 );
	}

	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 * If the parent does not exist, only allow the "root" user to
	 * add the entry.
	 */

	if ( (pdn = dn_parent( be, e->e_ndn )) != NULL ) {
		char *matched = NULL;

		/* get parent with writer lock */
		if ( (p = bdb2i_dn2entry_w( be, pdn, &matched )) == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			    matched, "" );

			if ( matched != NULL ) {
				free( matched );
			}

			entry_free( e );
			free( pdn );
			return -1;
		}

		free(pdn);

		if ( matched != NULL ) {
			free( matched );
		}

		if ( ! access_allowed( be, conn, op, p,
			"children", NULL, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    "", "" );

			/* free parent and writer lock */
			bdb2i_cache_return_entry_w( &li->li_cache, p ); 

			entry_free( e );
			return -1;
		}

	} else {
		/* no parent, must be adding entry to root */
		if ( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE, "no parent & not root\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    "", "" );

			entry_free( e );
			return -1;
		}
	}

	e->e_id = bdb2i_next_id( be );

	/*
	 * Try to add the entry to the cache, assign it a new dnid.
	 */
	rc = bdb2i_cache_add_entry_rw( &li->li_cache, e, CACHE_WRITE_LOCK );

	if ( rc != 0 ) {
		if( p != NULL) {
			/* free parent and writer lock */
			bdb2i_cache_return_entry_w( &li->li_cache, p ); 
		}

		Debug( LDAP_DEBUG_ANY, "cache_add_entry_lock failed\n", 0, 0,
		    0 );

		/* return the id */
		bdb2i_next_id_return( be, e->e_id );
                
		/* free the entry */
		entry_free( e );

		if(rc > 0) {
			send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, "", "" );
		} else {
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		}

		return( -1 );
	}

	rc = -1;

	/*
	 * add it to the id2children index for the parent
	 */

	if ( bdb2i_id2children_add( be, p, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_id2children_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );

		goto return_results;
	}

	/*
	 * Add the entry to the attribute indexes, then add it to
	 * the id2children index, dn2id index, and the id2entry index.
	 */

	/* attribute indexes */
	if ( bdb2i_index_add_entry( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_index_add_entry failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );

		goto return_results;
	}

	/* dn2id index */
	if ( bdb2i_dn2id_add( be, e->e_ndn, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_dn2id_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );

		goto return_results;
	}

	/* id2entry index */
	if ( bdb2i_id2entry_add( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb2i_id2entry_add failed\n", 0,
		    0, 0 );
		(void) bdb2i_dn2id_delete( be, e->e_ndn );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );

		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, "", "" );
	rc = 0;

return_results:;
	if (p != NULL) {
		/* free parent and writer lock */
		bdb2i_cache_return_entry_w( &li->li_cache, p ); 

	}

	/* free entry and writer lock */
	bdb2i_cache_return_entry_w( &li->li_cache, e ); 

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
	DB_LOCK         lock;
	struct ldbminfo	*li  = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_w( get_dbenv( be ), &lock ) != 0 ) {

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		return( -1 );

	}

	/*  check, if a new default attribute index will be created,
		in which case we have to open the index file BEFORE TP  */
	switch ( slapMode ) {
		case SLAP_SERVER_MODE:
		case SLAP_TIMEDSERVER_MODE:
		case SLAP_TOOL_MODE:
			bdb2i_check_default_attr_index_add( li, e );
			break;
	}

	ret = bdb2i_back_add_internal( be, conn, op, e );
	(void) bdb2i_leave_backend( get_dbenv( be ), lock );
	bdb2i_stop_timing( be->bd_info, time1, "ADD", conn, op );

	return( ret );
}


