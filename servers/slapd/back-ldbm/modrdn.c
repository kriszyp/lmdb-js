/* modrdn.c - ldbm backend modrdn routine */

#include "portable.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

extern char	*dn_parent();

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
	char		*matched;
	char		*pdn, *newdn, *p;
	char		sep[2];
	Entry		*e;

	matched = NULL;

	/* get entry with writer lock */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched, "" );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	if ( (pdn = dn_parent( be, dn )) != NULL ) {
		/* parent + rdn + separator(s) + null */
		newdn = (char *) ch_malloc( strlen( pdn ) + strlen( newrdn )
		    + 3 );
		if ( dn_type( dn ) == DN_X500 ) {
			strcpy( newdn, newrdn );
			strcat( newdn, ", " );
			strcat( newdn, pdn );
		} else {
			strcpy( newdn, newrdn );
			p = strchr( newrdn, '\0' );
			p--;
			if ( *p != '.' && *p != '@' ) {
				if ( (p = strpbrk( dn, ".@" )) != NULL ) {
					sep[0] = *p;
					sep[1] = '\0';
					strcat( newdn, sep );
				}
			}
			strcat( newdn, pdn );
		}
	} else {
		newdn = strdup( newrdn );
	}
	(void) dn_normalize( newdn );

	/* get entry with writer lock */
	if ( (dn2id ( be, newdn ) ) != NOID ) {
		free( newdn );
		free( pdn );
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS, NULL, NULL );
		goto error_return;
	}

	/* check for abandon */
	pthread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		pthread_mutex_unlock( &op->o_abandonmutex );
		free( newdn );
		free( pdn );
		goto error_return;
	}
	pthread_mutex_unlock( &op->o_abandonmutex );

	/* add new one */
	if ( dn2id_add( be, newdn, e->e_id ) != 0 ) {
		free( newdn );
		free( pdn );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto error_return;
	}

	/* delete old one */
	if ( dn2id_delete( be, dn ) != 0 ) {
		free( newdn );
		free( pdn );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		goto error_return;
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
		goto error_return;
	}
	free( pdn );

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );
	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );

	return( 0 );

error_return:
	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );
	return( -1 );
}
