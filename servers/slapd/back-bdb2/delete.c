/* delete.c - bdb2 backend delete routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static int
bdb2i_back_delete_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char	*matched = NULL;
	char	*pdn = NULL;
	Entry	*e, *p = NULL;
	int rootlock = 0;
	int	rc = -1;

	Debug(LDAP_DEBUG_ARGS, "==> bdb2i_back_delete: %s\n", dn, 0, 0);

	/* get entry with writer lock */
	if ( (e = bdb2i_dn2entry_w( be, dn, &matched )) == NULL ) {
		Debug(LDAP_DEBUG_ARGS, "<=- bdb2i_back_delete: no such object %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	/* check for deleted */

	if ( bdb2i_has_children( be, e ) ) {
		Debug(LDAP_DEBUG_ARGS, "<=- bdb2i_back_delete: non leaf %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF, "",
		    "" );
		goto return_results;
	}

#ifdef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_WRITE ) )
	{
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: insufficient access %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS, "", "" );
		goto return_results;
	}
#endif

	/* delete from parent's id2children entry */
	if( (pdn = dn_parent( be, dn )) != NULL ) {
		if( (p = bdb2i_dn2entry_w( be, pdn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb2i_back_delete: parent does not exist\n", 0, 0, 0);
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				"", "");
			goto return_results;
		}

#ifndef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			"children", NULL, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb2i_back_delete: no access to parent\n", 0, 0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "" );
			goto return_results;
		}
#endif

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb2i_back_delete: no parent & not root\n", 0, 0, 0);
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "");
			goto return_results;
		}

		ldap_pvt_thread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;
	}

	if ( bdb2i_id2children_remove( be, p, e ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "","" );
		goto return_results;
	}

	/* delete from dn2id mapping */
	if ( bdb2i_dn2id_delete( be, e->e_dn ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto return_results;
	}

	/* delete from disk and cache */
	if ( bdb2i_id2entry_delete( be, e ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb2i_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, "", "" );
	rc = 0;

return_results:;
	if ( pdn != NULL ) free(pdn);

	if( p != NULL ) {
		/* free parent and writer lock */
		bdb2i_cache_return_entry_w( &li->li_cache, p );

	}

	if ( rootlock ) {
		/* release root lock */
		ldap_pvt_thread_mutex_unlock(&li->li_root_mutex);
	}

	/* free entry and writer lock */
	bdb2i_cache_return_entry_w( &li->li_cache, e );

	if ( matched != NULL ) free(matched);

	return rc;
}


int
bdb2_back_delete(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_w( get_dbenv( be ), &lock ) != 0 ) {

		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		return( -1 );

	}

	ret = bdb2i_back_delete_internal( be, conn, op, dn );
	(void) bdb2i_leave_backend( get_dbenv( be ), lock );
	bdb2i_stop_timing( be->bd_info, time1, "DEL", conn, op );

	return( ret );
}


