/* modify.c - ldbm backend modify routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

static int add_values LDAP_P(( Entry *e, Modification *mod, char *dn ));
static int delete_values LDAP_P(( Entry *e, Modification *mod, char *dn ));
static int replace_values LDAP_P(( Entry *e, Modification *mod, char *dn ));

/* We need this function because of LDAP modrdn. If we do not 
 * add this there would be a bunch of code replication here 
 * and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 */ 

int ldbm_modify_internal(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    Modifications	*modlist,
    Entry	*e 
)
{
	int err;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;

	if ( !acl_check_modlist( be, conn, op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
		switch ( mod->sm_op )
#else
		switch ( mod->mod_op )
#endif
		{
		case LDAP_MOD_ADD:
			err = add_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_DELETE:
			err = delete_values( e, mod, op->o_ndn );
			break;

		case LDAP_MOD_REPLACE:
			err = replace_values( e, mod, op->o_ndn );
			break;

		case SLAP_MOD_SOFTADD:
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
#ifdef SLAPD_SCHEMA_NOT_COMPAT
 			mod->sm_op = LDAP_MOD_ADD;
#else
 			mod->mod_op = LDAP_MOD_ADD;
#endif
			err = add_values( e, mod, op->o_ndn );
 			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				mod->sm_op = SLAP_MOD_SOFTADD;
#else
				mod->mod_op = SLAP_MOD_SOFTADD;
#endif
 
 			}
 			break;
		}

		if ( err != LDAP_SUCCESS ) {
			attrs_free( e->e_attrs );
			e->e_attrs = save_attrs;
			/* unlock entry, delete from cache */
			return err; 
		}
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return SLAPD_ABANDON;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* check that the entry still obeys the schema */
	if ( schema_check_entry( e ) != 0 ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		Debug( LDAP_DEBUG_ANY, "entry failed schema check\n", 0, 0, 0 );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	/* check for abandon */
	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
	if ( op->o_abandon ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
		return SLAPD_ABANDON;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

	/* remove old indices */
	if( save_attrs != NULL ) {
		for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
			mod = &ml->sml_mod;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			if ( mod->sm_op == LDAP_MOD_REPLACE )
#else
			if ( mod->mod_op == LDAP_MOD_REPLACE )
#endif
			{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				/* not yet implemented */
#else
				/* Need to remove all values from indexes */
				Attribute *a = attr_find( save_attrs, mod->mod_type );

				if( a != NULL ) {
					(void) index_change_values( be,
						mod->mod_type,
						a->a_vals,
						e->e_id,
						SLAP_INDEX_DELETE_OP);
				}
#endif
			}
		}
		attrs_free( save_attrs );
	}

	/* modify indexes */
	if ( index_add_mods( be, modlist, e->e_id ) != 0 ) {
		/* our indices are likely hosed */
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}


int
ldbm_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn,
    Modifications	*modlist
)
{
	int rc;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*matched;
	Entry		*e;
	int		manageDSAit = get_manageDSAit( op );

	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);

	/* acquire and lock entry */
	if ( (e = dn2entry_w( be, ndn, &matched )) == NULL ) {
		char* matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return( -1 );
	}

    if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		goto error_return;
	}
	
	/* Modify the entry */
	rc = ldbm_modify_internal( be, conn, op, ndn, modlist, e );

	if( rc != LDAP_SUCCESS ) {
		if( rc != SLAPD_ABANDON ) {
			send_ldap_result( conn, op, rc,
		   		NULL, NULL, NULL, NULL );
		}

		goto error_return;
	}

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, NULL, NULL, NULL );
		goto error_return;
	}

	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, NULL, NULL, NULL );

	cache_return_entry_w( &li->li_cache, e );
	return( 0 );

error_return:;
	cache_return_entry_w( &li->li_cache, e );
	return( -1 );
}

static int
add_values(
    Entry	*e,
    Modification	*mod,
    char	*dn
)
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else
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
#endif

	return( LDAP_SUCCESS );
}

static int
delete_values(
    Entry	*e,
    Modification	*mod,
    char	*dn
)
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else
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
#endif

	return( LDAP_SUCCESS );
}

static int
replace_values(
    Entry	*e,
    Modification	*mod,
    char	*dn
)
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else
	(void) attr_delete( &e->e_attrs, mod->mod_type );

	if ( mod->mod_bvalues != NULL &&
		attr_merge( e, mod->mod_type, mod->mod_bvalues ) != 0 )
	{
		return( LDAP_CONSTRAINT_VIOLATION );
	}
#endif

	return( LDAP_SUCCESS );
}
