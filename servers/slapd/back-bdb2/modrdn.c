/* modrdn.c - bdb2 backend modrdn routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static int
bdb2i_back_modrdn_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*newrdn,
    int		deleteoldrdn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched = NULL;
	char		*p_dn = NULL, *p_ndn = NULL;
	char		*new_dn = NULL, *new_ndn = NULL;
	char		sep[2];
	Entry		*e, *p = NULL;
	int			rc = -1;

	/* get entry with writer lock */
	if ( (e = bdb2i_dn2entry_w( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

#ifdef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
		/* check parent for "children" acl */
	if ( ! access_allowed( be, conn, op, e,
		"entry", NULL, ACL_WRITE ) )
	{
		Debug( LDAP_DEBUG_TRACE, "no access to entry\n", 0,
			0, 0 );
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			"", "" );
		goto return_results;
	}
#endif

	if ( (p_ndn = dn_parent( be, e->e_ndn )) != NULL ) {
		/* parent + rdn + separator(s) + null */
		if( (p = bdb2i_dn2entry_w( be, p_ndn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				"", "");
			goto return_results;
		}

#ifndef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
		/* check parent for "children" acl */
		if ( ! access_allowed( be, conn, op, p,
			"children", NULL, ACL_WRITE ) )
		{
			Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0,
				0, 0 );
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "" );
			goto return_results;
		}
#endif

		p_dn = dn_parent( be, e->e_dn );
		new_dn = (char *) ch_malloc( strlen( p_dn ) + strlen( newrdn )
		    + 3 );
		if ( dn_type( e->e_dn ) == DN_X500 ) {
			strcpy( new_dn, newrdn );
			strcat( new_dn, "," );
			strcat( new_dn, p_dn );
		} else {
			char *s;
			strcpy( new_dn, newrdn );
			s = strchr( newrdn, '\0' );
			s--;
			if ( *s != '.' && *s != '@' ) {
				if ( (s = strpbrk( dn, ".@" )) != NULL ) {
					sep[0] = *s;
					sep[1] = '\0';
					strcat( new_dn, sep );
				}
			}
			strcat( new_dn, p_dn );
		}

	} else {
		/* no parent, modrdn entry directly under root */
		if( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE, "no parent & not root\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "");
			goto return_results;
		}

		new_dn = ch_strdup( newrdn );
	}

	new_ndn = dn_normalize_case( ch_strdup( new_dn ) );

	if ( (bdb2i_dn2id ( be, new_ndn ) ) != NOID ) {
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, NULL, NULL );
		goto return_results;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto return_results;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* add new one */
	if ( bdb2i_dn2id_add( be, new_ndn, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto return_results;
	}

	/* delete old one */
	if ( bdb2i_dn2id_delete( be, e->e_ndn ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto return_results;
	}

	(void) bdb2i_cache_delete_entry( &li->li_cache, e );
	free( e->e_dn );
	free( e->e_ndn );
	e->e_dn = new_dn;
	e->e_ndn = new_ndn;
	(void) bdb2i_cache_update_entry( &li->li_cache, e );

	/*
	 * At some point here we need to update the attribute values in
	 * the entry itself that were effected by this RDN change
	 * (respecting the value of the deleteoldrdn parameter).
	 *
	 * Since the code to do this has not yet been written, treat this
	 * omission as a (documented) bug.
	 */

	/* id2entry index */
	if ( bdb2i_id2entry_add( be, e ) != 0 ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
	rc = 0;

return_results:
	if( new_dn != NULL ) free( new_dn );
	if( new_ndn != NULL ) free( new_ndn );
	if( p_dn != NULL ) free( p_dn );
	if( p_ndn != NULL ) free( p_ndn );

	if( matched != NULL ) free( matched );

	if( p != NULL ) {
		/* free parent and writer lock */
		bdb2i_cache_return_entry_w( &li->li_cache, p );

	}

	/* free entry and writer lock */
	bdb2i_cache_return_entry_w( &li->li_cache, e );
	return( rc );
}


int
bdb2_back_modrdn(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*newrdn,
    int		deleteoldrdn
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

	ret = bdb2i_back_modrdn_internal( be, conn, op, dn,
					newrdn, deleteoldrdn );

	(void) bdb2i_leave_backend( get_dbenv( be ), lock );
	bdb2i_stop_timing( be->bd_info, time1, "MODRDN", conn, op );

	return( ret );
}


