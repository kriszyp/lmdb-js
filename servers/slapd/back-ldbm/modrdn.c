/* modrdn.c - ldbm backend modrdn routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_modrdn(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*newrdn,
    int		deleteoldrdn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched = NULL;
	char		*pdn = NULL, *newdn = NULL;
	char		sep[2];
	Entry		*e, *p = NULL;
	int			rootlock = 0;
	int			rc = -1;

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

#ifdef SLAPD_CHILD_MODIFICATION_WITH_ENTRY_ACL
		/* check parent for "children" acl */
	if ( ! access_allowed( be, conn, op, e, "entry", NULL,
		op->o_dn, ACL_WRITE ) )
	{
		Debug( LDAP_DEBUG_TRACE, "no access to entry\n", 0,
			0, 0 );
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			"", "" );
		goto return_results;
	}
#endif

	if ( (pdn = dn_parent( be, dn )) != NULL ) {
		/* parent + rdn + separator(s) + null */
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

		newdn = (char *) ch_malloc( strlen( pdn ) + strlen( newrdn )
		    + 3 );
		if ( dn_type( dn ) == DN_X500 ) {
			strcpy( newdn, newrdn );
			strcat( newdn, ", " );
			strcat( newdn, pdn );
		} else {
			char *s;
			strcpy( newdn, newrdn );
			s = strchr( newrdn, '\0' );
			s--;
			if ( *s != '.' && *s != '@' ) {
				if ( (s = strpbrk( dn, ".@" )) != NULL ) {
					sep[0] = *s;
					sep[1] = '\0';
					strcat( newdn, sep );
				}
			}
			strcat( newdn, pdn );
		}
	} else {
		/* no parent, modrdn entry directly under root */
		if( ! be_isroot( be, op->o_dn ) ) {
			Debug( LDAP_DEBUG_TRACE, "no parent & not root\n",
				0, 0, 0);
			send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				"", "");
			goto return_results;
		}

		pthread_mutex_lock(&li->li_root_mutex);
		rootlock = 1;

		newdn = ch_strdup( newrdn );
	}

	(void) dn_normalize( newdn );

	if ( (dn2id ( be, newdn ) ) != NOID ) {
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, NULL, NULL );
		goto return_results;
	}

	/* check for abandon */
	pthread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		pthread_mutex_unlock( &op->o_abandonmutex );
		goto return_results;
	}
	pthread_mutex_unlock( &op->o_abandonmutex );

	/* add new one */
	if ( dn2id_add( be, newdn, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto return_results;
	}

	/* delete old one */
	if ( dn2id_delete( be, dn ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto return_results;
	}

	(void) cache_delete_entry( &li->li_cache, e );
	free( e->e_dn );
	e->e_dn = newdn;

	/* XXX
	 * At some point here we need to update the attribute values in
	 * the entry itself that were effected by this RDN change
	 * (respecting the value of the deleteoldrdn parameter).
	 *
	 * Since the code to do this has not yet been written, treat this
	 * omission as a (documented) bug.
	 */

	/* id2entry index */
	if ( id2entry_add( be, e ) != 0 ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", "" );
		goto return_results;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
	rc = 0;

return_results:
	if( newdn != NULL ) free( newdn );
	if( pdn != NULL ) free( pdn );
	if( matched != NULL ) free( matched );

	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	if ( rootlock ) {
		/* release root writer lock */
		pthread_mutex_unlock(&li->li_root_mutex);
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );
	return( rc );
}
