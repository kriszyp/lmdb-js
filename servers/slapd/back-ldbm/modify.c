/* modify.c - ldbm backend modify routine */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

static int	add_values(Entry *e, LDAPMod *mod, char *dn);
static int	delete_values(Entry *e, LDAPMod *mod, char *dn);
static int	replace_values(Entry *e, LDAPMod *mod, char *dn);

/* We need this function because of LDAP modrdn. If we do not 
 * add this there would be a bunch of code replication here 
 * and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 */ 

int ldbm_internal_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPMod	*mods,
    Entry	*e 
)
{
	int		i, err;
	LDAPMod		*mod;
	Attribute	*a;
	Attribute	*save_attrs;

	if ( (err = acl_check_mods( be, conn, op, e, mods )) != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, err, NULL, NULL );
		return -1;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( mod = mods; mod != NULL; mod = mod->mod_next ) {
		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
			err = add_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_DELETE:
			err = delete_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_REPLACE:
			err = replace_values( e, mod, op->o_ndn );
			break;

 		case LDAP_MOD_SOFTADD:
 			/* 
 			 * We need to add index if necessary.
 			 */
 			mod->mod_op = LDAP_MOD_ADD;
 			err = add_values( e, mod, op->o_ndn );
 			if ( err ==  LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
 			}
 			break;
		}

		if ( err != LDAP_SUCCESS ) {
			attrs_free( e->e_attrs );
			e->e_attrs = save_attrs;
			/* unlock entry, delete from cache */
			send_ldap_result( conn, op, err, NULL, NULL );
			return -1;
		}
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return -1;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* check that the entry still obeys the schema */
	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		Debug( LDAP_DEBUG_ANY, "entry failed schema check\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION, NULL, NULL );
		return -1;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return -1;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* remove old indices */
	for ( mod = mods; mod != NULL; mod = mod->mod_next ) {
		switch( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_REPLACE:
			/* Need to remove all values from indexes */
			a = save_attrs
				? attr_find( save_attrs, mod->mod_type )
				: NULL;

			if( a != NULL ) {
				(void) index_change_values( be,
					mod->mod_type,
					a->a_vals,
					e->e_id,
					__INDEX_DEL_OP);
			}
			break;

		case LDAP_MOD_DELETE:
			(void) index_change_values( be,
				mod->mod_type,
				mod->mod_bvalues,
				e->e_id,
				__INDEX_DEL_OP);
			break;
		}
	}

	attrs_free( save_attrs );

	/* add new indices */
	for ( mod = mods; mod != NULL; mod = mod->mod_next ) {
		switch( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
		case LDAP_MOD_REPLACE:
			(void) index_change_values( be,
				mod->mod_type,
				mod->mod_bvalues,
				e->e_id,
				__INDEX_ADD_OP);

			break;

		case LDAP_MOD_DELETE:
			/* Need to add all remaining values */
			a = e->e_attrs
				? attr_find( e->e_attrs, mod->mod_type )
				: NULL;

			if( a != NULL ) {
				(void) index_change_values( be,
					mod->mod_type,
					a->a_vals,
					e->e_id,
					__INDEX_ADD_OP);
			}
			break;
		}
	}

	return 0;
}


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
	char		*matched;
	Entry		*e;

	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);

	/* acquire and lock entry */
	if ( (e = dn2entry_w( be, dn, &matched )) == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT, matched,
		    NULL );
		if ( matched != NULL ) {
			free( matched );
		}
		return( -1 );
	}

	/* Modify the entry */
	if ( ldbm_internal_modify( be, conn, op, dn, mods, e ) != 0 ) {

		goto error_return;

	}

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		entry_free( e );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL, NULL );
		return -1;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
	cache_return_entry_w( &li->li_cache, e );
	return( 0 );

error_return:;
	cache_return_entry_w( &li->li_cache, e );
	return( -1 );
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

			/* delete the entire attribute, if no values remain */
			if ( a->a_vals[0] == NULL) {
				Debug( LDAP_DEBUG_ARGS,
					"removing entire attribute %s\n",
					mod->mod_type, 0, 0 );
				if ( attr_delete( &e->e_attrs, mod->mod_type ) ) {
					return LDAP_NO_SUCH_ATTRIBUTE;
				}
			}

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
