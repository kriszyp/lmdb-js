/* add.c - ldap ldbm back-end add routine */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"

extern int	global_schemacheck;
extern char	*dn_parent();
extern char	*dn_normalize();
extern Entry	*dn2entry();

int
ldbm_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched;
	char		*dn = NULL, *pdn = NULL;
	Entry		*p;

	dn = dn_normalize( strdup( e->e_dn ) );
	matched = NULL;
	if ( (p = dn2entry( be, dn, &matched )) != NULL ) {
		cache_return_entry( &li->li_cache, p );
		entry_free( e );
		free( dn );
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, "", "" );
		return( -1 );
	}
	if ( matched != NULL ) {
		free( matched );
	}
	/* XXX race condition here til we cache_add_entry_lock below XXX */

	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "entry failed schema check\n", 0, 0,
		    0 );
		entry_free( e );
		free( dn );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION, "",
		    "" );
		return( -1 );
	}

	/*
	 * Try to add the entry to the cache, assign it a new dnid
	 * and mark it locked.  This should only fail if the entry
	 * already exists.
	 */

	e->e_id = next_id( be );
	if ( cache_add_entry_lock( &li->li_cache, e, ENTRY_STATE_CREATING )
	    != 0 ) {
		Debug( LDAP_DEBUG_ANY, "cache_add_entry_lock failed\n", 0, 0,
		    0 );
		next_id_return( be, e->e_id );
		entry_free( e );
		free( dn );
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, "", "" );
		return( -1 );
	}

	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 * If the parent does not exist, only allow the "root" user to
	 * add the entry.
	 */

	if ( (pdn = dn_parent( be, dn )) != NULL ) {
		/* no parent */
		matched = NULL;
		if ( (p = dn2entry( be, pdn, &matched )) == NULL ) {
			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			    matched, "" );
			if ( matched != NULL ) {
				free( matched );
			}
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n", 0,
			    0, 0 );
			goto error_return;
		}
		if ( matched != NULL ) {
			free( matched );
		}

		if ( ! access_allowed( be, conn, op, p, "children", NULL,
		    op->o_dn, ACL_WRITE ) ) {
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    "", "" );
			goto error_return;
		}
	} else {
		if ( ! be_isroot( be, op->o_dn ) ) {
			Debug( LDAP_DEBUG_TRACE, "no parent & not root\n", 0,
			    0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			    "", "" );
			goto error_return;
		}
		p = NULL;
	}

	/*
	 * add it to the id2children index for the parent
	 */

	if ( id2children_add( be, p, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "id2children_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "",
		    "" );
		goto error_return;
	}

	/*
	 * Add the entry to the attribute indexes, then add it to
	 * the id2children index, dn2id index, and the id2entry index.
	 */

	/* attribute indexes */
	if ( index_add_entry( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "index_add_entry failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto error_return;
	}

	/* dn2id index */
	if ( dn2id_add( be, dn, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "dn2id_add failed\n", 0,
		    0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto error_return;
	}

	/* id2entry index */
	if ( id2entry_add( be, e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "id2entry_add failed\n", 0,
		    0, 0 );
		(void) dn2id_delete( be, dn );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto error_return;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, "", "" );
	if ( dn != NULL )
		free( dn );
	if ( pdn != NULL )
		free( pdn );
	cache_set_state( &li->li_cache, e, 0 );
	cache_return_entry( &li->li_cache, e );
	return( 0 );

error_return:;
	if ( dn != NULL )
		free( dn );
	if ( pdn != NULL )
		free( pdn );
	next_id_return( be, e->e_id );
	cache_delete_entry( &li->li_cache, e );
	cache_return_entry( &li->li_cache, e );

	return( -1 );
}
