/* modify.c - ldbm backend modify routine */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"

extern int		global_schemacheck;
extern Entry		*dn2entry();
extern Attribute	*attr_find();

static int	add_values();
static int	delete_values();
static int	replace_values();

int
ldbm_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPMod	*mods
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*matched = NULL;
	Entry		*e;
	int		i, err, modtype;
	LDAPMod		*mod;

	if ( (e = dn2entry( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched,
		    NULL );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}
	/* lock entry */

	if ( (err = acl_check_mods( be, conn, op, e, mods )) != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, err, NULL, NULL );
		cache_return_entry( &li->li_cache, e );
		return( -1 );
	}

	for ( mod = mods; mod != NULL; mod = mod->mod_next ) {
		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
			err = add_values( e, mod, op->o_dn );
			break;

		case LDAP_MOD_DELETE:
			err = delete_values( e, mod, op->o_dn );
			break;

		case LDAP_MOD_REPLACE:
			err = replace_values( e, mod, op->o_dn );
			break;
		}

		if ( err != LDAP_SUCCESS ) {
			/* unlock entry, delete from cache */
			send_ldap_result( conn, op, err, NULL, NULL );
			cache_return_entry( &li->li_cache, e );
			return( -1 );
		}
	}

	/* check for abandon */
	pthread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		pthread_mutex_unlock( &op->o_abandonmutex );
		cache_return_entry( &li->li_cache, e );
		return( -1 );
	}
	pthread_mutex_unlock( &op->o_abandonmutex );

	/* check that the entry still obeys the schema */
	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION, NULL,
		    NULL );
		cache_return_entry( &li->li_cache, e );
		return( -1 );
	}

	/* modify indexes */
	if ( index_add_mods( be, mods, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		cache_return_entry( &li->li_cache, e );
		return( -1 );
	}

	/* check for abandon */
	pthread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		pthread_mutex_unlock( &op->o_abandonmutex );
		cache_return_entry( &li->li_cache, e );
		return( -1 );
	}
	pthread_mutex_unlock( &op->o_abandonmutex );

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		cache_return_entry( &li->li_cache, e );
		return( -1 );
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
	cache_return_entry( &li->li_cache, e );

	return( 0 );
}

static int
add_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	int		i;
	Attribute	*a;

	/* check if the values we're adding already exist */
	if ( (a = attr_find( e->e_attrs, mod->mod_type )) != NULL ) {
		for ( i = 0; mod->mod_bvalues[i] != NULL; i++ ) {
			if ( value_find( a->a_vals, mod->mod_bvalues[i],
			    a->a_syntax, 3 ) == 0 ) {
				return( LDAP_TYPE_OR_VALUE_EXISTS );
			}
		}
	}

	/* no - add them */
	if( attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 ) {
		return( LDAP_CONSTRAINT_VIOLATION );
	}

	return( LDAP_SUCCESS );
}

static int
delete_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	int		i, j, k, found;
	Attribute	*a;

	/* delete the entire attribute */
	if ( mod->mod_bvalues == NULL ) {
		Debug( LDAP_DEBUG_ARGS, "removing entire attribute %s\n",
		    mod->mod_type, 0, 0 );
		return( attr_delete( &e->e_attrs, mod->mod_type ) ?
		    LDAP_NO_SUCH_ATTRIBUTE : LDAP_SUCCESS );
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->mod_type )) == NULL ) {
		Debug( LDAP_DEBUG_ARGS, "could not find attribute %s\n",
		    mod->mod_type, 0, 0 );
		return( LDAP_NO_SUCH_ATTRIBUTE );
	}

	/* find each value to delete */
	for ( i = 0; mod->mod_bvalues[i] != NULL; i++ ) {
		found = 0;
		for ( j = 0; a->a_vals[j] != NULL; j++ ) {
			if ( value_cmp( mod->mod_bvalues[i], a->a_vals[j],
			    a->a_syntax, 3 ) != 0 ) {
				continue;
			}
			found = 1;

			/* found a matching value - delete it */
			ber_bvfree( a->a_vals[j] );
			for ( k = j + 1; a->a_vals[k] != NULL; k++ ) {
				a->a_vals[k - 1] = a->a_vals[k];
			}
			a->a_vals[k - 1] = NULL;
			break;
		}

		/* looked through them all w/o finding it */
		if ( ! found ) {
			Debug( LDAP_DEBUG_ARGS,
			    "could not find value for attr %s\n",
			    mod->mod_type, 0, 0 );
			return( LDAP_NO_SUCH_ATTRIBUTE );
		}
	}

	return( LDAP_SUCCESS );
}

static int
replace_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	(void) attr_delete( &e->e_attrs, mod->mod_type );

	if ( attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 ) {
		return( LDAP_CONSTRAINT_VIOLATION );
	}

	return( LDAP_SUCCESS );
}
