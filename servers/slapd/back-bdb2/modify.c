/* modify.c - bdb2 backend modify routine */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

int
bdb2i_back_modify_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPModList	*modlist,
    Entry	 *e
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	LDAPModList	*ml;
	int		err;

	Debug(LDAP_DEBUG_ARGS, "bdb2i_back_modify:\n", 0, 0, 0);

	if ( (err = acl_check_modlist( be, conn, op, e, modlist )) != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, err,
			NULL, NULL, NULL, NULL );
		goto error_return;
	}

	for ( ml = modlist; ml != NULL; ml = ml->ml_next ) {
		LDAPMod	*mod = &ml->ml_mod;

		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
			err = bdb2i_add_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_DELETE:
			err = bdb2i_delete_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_REPLACE:
			err = bdb2i_replace_values( e, mod, op->o_ndn );
			break;
		
		case LDAP_MOD_SOFTADD:
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
 			mod->mod_op = LDAP_MOD_ADD;
 			if ( (err = bdb2i_add_values( e, mod, op->o_ndn ))
 				==  LDAP_TYPE_OR_VALUE_EXISTS ) {
 
 				err = LDAP_SUCCESS;
 				mod->mod_op = LDAP_MOD_SOFTADD;
 
 			}
 			break;
		}

		if ( err != LDAP_SUCCESS ) {
			/* unlock entry, delete from cache */
			send_ldap_result( conn, op, err,
				NULL, NULL, NULL, NULL );
			goto error_return;
		}
	}

	/* check that the entry still obeys the schema */
	if ( global_schemacheck && oc_schema_check( e ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "entry failed schema check\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OBJECT_CLASS_VIOLATION,
			NULL, NULL, NULL, NULL );
		goto error_return;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto error_return;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* modify indexes */
	if ( bdb2i_index_add_mods( be, modlist, e->e_id ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto error_return;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		goto error_return;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* change the entry itself */
	if ( bdb2i_id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		goto error_return;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );
	return( 0 );

error_return:;
	return( -1 );
}


int
bdb2_back_modify(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPModList	*modlist
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret, manageDSAit;
	Entry		*matched;
	Entry		*e;

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
			bdb2i_check_default_attr_index_mod( li, modlist );
			break;
	}

	if ( (e = bdb2i_dn2entry_w( be, dn, &matched )) == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb2i_cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		ret = -1;
		goto done;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		bdb2i_cache_return_entry_w( &li->li_cache, e );

		ber_bvecfree( refs );

		ret = -1;
		goto done;
	}

	ret = bdb2i_back_modify_internal( be, conn, op, dn, modlist, e );
	bdb2i_cache_return_entry_w( &li->li_cache, e );

done:
	(void) bdb2i_leave_backend_w( lock );
	bdb2i_stop_timing( be->bd_info, time1, "MOD", conn, op );

	return( ret );
}


int
bdb2i_add_values(
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

int
bdb2i_delete_values(
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

int
bdb2i_replace_values(
    Entry	*e,
    LDAPMod	*mod,
    char	*dn
)
{
	(void) attr_delete( &e->e_attrs, mod->mod_type );

	if ( mod->mod_bvalues != NULL &&
		attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 )
	{
		return( LDAP_CONSTRAINT_VIOLATION );
	}

	return( LDAP_SUCCESS );
}
