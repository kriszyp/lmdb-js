/* modify.c - ldbm backend modify routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
    const char	*dn,
    Modifications	*modlist,
    Entry	*e,
	const char **text 
)
{
	int rc, err;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;

	Debug(LDAP_DEBUG_TRACE, "ldbm_modify_internal:\n", 0, 0, 0);

	if ( !acl_check_modlist( be, conn, op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: add\n", 0, 0, 0);
			err = add_values( e, mod, op->o_ndn );

			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, text, 0);
				*text = "modify: add values failed";
			}
			break;

		case LDAP_MOD_DELETE:
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: delete\n", 0, 0, 0);
			err = delete_values( e, mod, op->o_ndn );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, text, 0);
				*text = "modify: delete values failed";
			}
			break;

		case LDAP_MOD_REPLACE:
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: replace\n", 0, 0, 0);
			err = replace_values( e, mod, op->o_ndn );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, text, 0);
				*text = "modify: replace values failed";
			}
			break;

		case SLAP_MOD_SOFTADD:
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: softadd\n", 0, 0, 0);
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
 			mod->sm_op = LDAP_MOD_ADD;
			err = add_values( e, mod, op->o_ndn );

 			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
 			}

			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, text, 0);
				*text = "modify: (soft)add values failed";
			}
 			break;

		default:
			Debug(LDAP_DEBUG_ANY, "ldbm_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
			*text = "Invalid modify operation";
			err = LDAP_OTHER;
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
				err, text, 0);
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
	rc = entry_schema_check( e, save_attrs, text );
	if ( rc != LDAP_SUCCESS ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		Debug( LDAP_DEBUG_ANY, "entry failed schema check: %s\n",
			*text, 0, 0 );
		return rc;
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

	/* run through the attributes removing old indices */
	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_REPLACE: {
			/* Need to remove all values from indexes */
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			/* not yet implemented */
#else
			Attribute *a = save_attrs
				? attr_find( save_attrs, mod->sm_desc )
				: NULL;

			if( a != NULL ) {
				(void) index_change_values( be,
					mod->mod_type,
					a->a_vals,
					e->e_id,
					SLAP_INDEX_DELETE_OP );
			}
#endif
			} break;

		case LDAP_MOD_DELETE:
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			/* not yet implemented */
#else
			/* remove deleted values */
			(void) index_change_values( be,
				mod->mod_type,
				mod->mod_bvalues,
				e->e_id,
				SLAP_INDEX_DELETE_OP );
#endif
			break;
		}
	}

	attrs_free( save_attrs );

	/* run through the attributes adding new indices */
	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_ADD:
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			/* not yet implemented */
#else
			(void) index_change_values( be,
				mod->mod_type,
				mod->mod_bvalues,
				e->e_id,
				SLAP_INDEX_ADD_OP );
#endif
			break;

		case LDAP_MOD_DELETE: {
			/* Need to add all remaining values */
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			/* not yet implemented */
#else
			Attribute *a = e->e_attrs
				? attr_find( e->e_attrs, mod->sm_desc )
				: NULL;

			if( a != NULL ) {
				(void) index_change_values( be,
					mod->mod_type,
					a->a_vals,
					e->e_id,
					SLAP_INDEX_ADD_OP );
			}
#endif
			} break;
		}
	}

	return LDAP_SUCCESS;
}


int
ldbm_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*dn,
    const char	*ndn,
    Modifications	*modlist
)
{
	int rc;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*matched;
	Entry		*e;
	int		manageDSAit = get_manageDSAit( op );
	const char *text = NULL;

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
	rc = ldbm_modify_internal( be, conn, op, ndn, modlist, e, &text );

	if( rc != LDAP_SUCCESS ) {
		if( rc != SLAPD_ABANDON ) {
			send_ldap_result( conn, op, rc,
		   		NULL, text, NULL, NULL );
		}

		goto error_return;
	}

	/* change the entry itself */
	if ( id2entry_add( be, e ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OTHER,
			NULL, "id2entry failure", NULL, NULL );
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
	int		i;
	Attribute	*a;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* char *desc = mod->sm_desc->ad_cname->bv_val; */
	MatchingRule *mr = mod->sm_desc->ad_type->sat_equality;

	if( mr == NULL ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

#else
	/* char *desc = mod->mod_type; */
#endif

	a = attr_find( e->e_attrs, mod->sm_desc );

	/* check if the values we're adding already exist */
	if ( a != NULL ) {
		for ( i = 0; mod->sm_bvalues[i] != NULL; i++ ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			int j;
			for ( j = 0; a->a_vals[j] != NULL; j++ ) {
				int match;
				const char *text = NULL;
				int rc = value_match( &match, mod->sm_desc, mr,
					mod->sm_bvalues[i], a->a_vals[j], &text );

				if( rc == LDAP_SUCCESS && match == 0 ) {
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}
#else
			if ( value_find( a->a_vals, mod->sm_bvalues[i],
			    a->a_syntax, 3 ) == 0 ) {
				return( LDAP_TYPE_OR_VALUE_EXISTS );
			}
#endif
		}
	}

	/* no - add them */
	if( attr_merge( e, mod->sm_desc, mod->sm_bvalues ) != 0 ) {
		/* this should return result return of attr_merge */
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}

static int
delete_values(
    Entry	*e,
    Modification	*mod,
    char	*dn
)
{
	int		i, j, k, found;
	Attribute	*a;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	char *desc = mod->sm_desc->ad_cname->bv_val;
	MatchingRule *mr = mod->sm_desc->ad_type->sat_equality;

	if( mr == NULL || !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}
#else
	char *desc = mod->mod_type;
#endif

	/* delete the entire attribute */
	if ( mod->sm_bvalues == NULL ) {
		Debug( LDAP_DEBUG_ARGS, "removing entire attribute %s\n",
		    desc, 0, 0 );
		return( attr_delete( &e->e_attrs, mod->sm_desc ) ?
		    LDAP_NO_SUCH_ATTRIBUTE : LDAP_SUCCESS );
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->sm_desc )) == NULL ) {
		Debug( LDAP_DEBUG_ARGS, "could not find attribute %s\n",
		    desc, 0, 0 );
		return( LDAP_NO_SUCH_ATTRIBUTE );
	}

	/* find each value to delete */
	for ( i = 0; mod->sm_bvalues[i] != NULL; i++ ) {
		found = 0;
		for ( j = 0; a->a_vals[j] != NULL; j++ ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			int match;
			const char *text = NULL;
			int rc = value_match( &match, mod->sm_desc,
				mr,
				mod->sm_bvalues[i], a->a_vals[j], &text );

			if( rc == LDAP_SUCCESS && match != 0 )
#else
			if ( value_cmp( mod->mod_bvalues[i], a->a_vals[j],
			    a->a_syntax, 3 ) != 0 )
#endif
			{
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
					desc, 0, 0 );
				if ( attr_delete( &e->e_attrs, mod->sm_desc ) ) {
					return LDAP_NO_SUCH_ATTRIBUTE;
				}
			}

			break;
		}

		/* looked through them all w/o finding it */
		if ( ! found ) {
			Debug( LDAP_DEBUG_ARGS,
			    "could not find value for attr %s\n",
			    desc, 0, 0 );
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	return LDAP_SUCCESS;
}

static int
replace_values(
    Entry	*e,
    Modification	*mod,
    char	*dn
)
{
	int rc = attr_delete( &e->e_attrs, mod->sm_desc );

	if( rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_ATTRIBUTE ) {
		return rc;
	}

	if ( mod->sm_bvalues != NULL &&
		attr_merge( e, mod->sm_desc, mod->sm_bvalues ) != 0 )
	{
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}
