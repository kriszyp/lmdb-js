/* delete.c - ldbm backend delete routine */

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
    char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char	*matched = NULL;
	char	*pdn = NULL;
	Entry	*e, *p = NULL;
	int rootlock = 0;
	int	rc = -1;

	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_delete: %s\n", dn, 0, 0);

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: no such object %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	Debug (LDAP_DEBUG_TRACE,
		"rdwr_Xchk: readers_reading: %d writer_writing: %d\n",
		e->e_rdwr.readers_reading, e->e_rdwr.writer_writing, 0);

	/* check for deleted */

	if ( has_children( be, e ) ) {
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: non leaf %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF, "",
		    "" );
		goto return_results;
	}

#ifdef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
	if ( ! access_allowed( be, conn, op, e, "entry", NULL, op->o_dn,
	    ACL_WRITE ) ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: insufficient access %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS, "", "" );
		goto return_results;
	}
#endif

	Debug (LDAP_DEBUG_TRACE,
		"rdwr_Xchk: readers_reading: %d writer_writing: %d\n",
		e->e_rdwr.readers_reading, e->e_rdwr.writer_writing, 0);

	/* delete from parent's id2children entry */
	if( (pdn = dn_parent( be, dn )) != NULL ) {
		if( (p = dn2entry_w( be, pdn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				"", "");
			goto return_results;
		}

#ifndef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p, "children", NULL,
			op->o_dn, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "" );
			goto return_results;
		}
#endif

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( be, op->o_dn ) ) {
			Debug( LDAP_DEBUG_TRACE, "no parent & not root\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "");
			goto return_results;
		}

		pthread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;
	}

	if ( id2children_remove( be, p, e ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "","" );
		goto return_results;
	}

	/* delete from dn2id mapping */
	if ( dn2id_delete( be, e->e_dn ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			dn, 0, 0);
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto return_results;
	}

	/* delete from disk and cache */
	if ( id2entry_delete( be, e ) != 0 ) {
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
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
		cache_return_entry_w( &li->li_cache, p );
	}

	if ( rootlock ) {
		/* release root lock */
		pthread_mutex_unlock(&li->li_root_mutex);
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );

	if ( matched != NULL ) free(matched);

	return rc;
}
