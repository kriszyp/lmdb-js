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

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_modify_internal: %s\n", dn ));
#else
	Debug(LDAP_DEBUG_TRACE, "ldbm_modify_internal:\n", 0, 0, 0);
#endif


	if ( !acl_check_modlist( be, conn, op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_modify_internal: add\n" ));
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: add\n", 0, 0, 0);
#endif

			err = add_values( e, mod, op->o_ndn );

			if( err != LDAP_SUCCESS ) {
				*text = "modify: add values failed";
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_modify_internal: failed %d (%s)\n",
					   err, *text ));
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_DELETE:
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_modify_internal: delete\n" ));
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: delete\n", 0, 0, 0);
#endif

			err = delete_values( e, mod, op->o_ndn );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				*text = "modify: delete values failed";
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_modify_internal: failed %d (%s)\n", err, *text ));
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_REPLACE:
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_modify_internal:  replace\n" ));
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: replace\n", 0, 0, 0);
#endif

			err = replace_values( e, mod, op->o_ndn );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				*text = "modify: replace values failed";
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_modify_internal: failed %d (%s)\n", err, *text ));
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, *text, 0);
#endif

			}
			break;

		case SLAP_MOD_SOFTADD:
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				   "ldbm_modify_internal: softadd\n" ));
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: softadd\n", 0, 0, 0);
#endif

			/* Avoid problems in index_add_mods()
			 * We need to add index if necessary.
			 */
			mod->sm_op = LDAP_MOD_ADD;
			err = add_values( e, mod, op->o_ndn );

			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
				err = LDAP_SUCCESS;
			}

			if( err != LDAP_SUCCESS ) {
				*text = "modify: (soft)add values failed";
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
					   "ldbm_modify_internal: failed %d (%s)\n", err, *text ));
#else
				Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
					err, *text, 0);
#endif

			}
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
				   "ldbm_modify_internal: invalid op %d\n", mod->sm_op ));
#else
			Debug(LDAP_DEBUG_ANY, "ldbm_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
#endif

			err = LDAP_OTHER;
			*text = "Invalid modify operation";
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				   "ldbm_modify_internal: %d (%s)\n", err, *text ));
#else
			Debug(LDAP_DEBUG_ARGS, "ldbm_modify_internal: %d %s\n",
				err, *text, 0);
#endif

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
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "ldbm_modify_internal: entry failed schema check: %s\n",
			   *text ));
#else
		Debug( LDAP_DEBUG_ANY, "entry failed schema check: %s\n",
			*text, 0, 0 );
#endif

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

	/* delete indices for old attributes */
	index_entry_del( be, e, save_attrs);

	/* add indices for new attributes */
	index_entry_add( be, e, e->e_attrs);

	attrs_free( save_attrs );

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

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_back_modify: enter\n" ));
#else
	Debug(LDAP_DEBUG_ARGS, "ldbm_back_modify:\n", 0, 0, 0);
#endif


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

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldbm_back_modify: entry (%s) is referral\n", ndn ));
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );
#endif


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

	/* char *desc = mod->sm_desc->ad_cname->bv_val; */
	MatchingRule *mr = mod->sm_desc->ad_type->sat_equality;

	a = attr_find( e->e_attrs, mod->sm_desc );

	/* check if the values we're adding already exist */
	if ( a != NULL ) {
		if( mr == NULL || !mr->smr_match ) {
			/* do not allow add of additional attribute
				if no equality rule exists */
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		for ( i = 0; mod->sm_bvalues[i] != NULL; i++ ) {
			int rc;
			int j;
			const char *text = NULL;
			struct berval *asserted;

			rc = value_normalize( mod->sm_desc,
				SLAP_MR_EQUALITY,
				mod->sm_bvalues[i],
				&asserted,
				&text );

			if( rc != LDAP_SUCCESS ) return rc;

			for ( j = 0; a->a_vals[j] != NULL; j++ ) {
				int match;
				int rc = value_match( &match, mod->sm_desc, mr,
					SLAP_MR_MODIFY_MATCHING,
					a->a_vals[j], asserted, &text );

				if( rc == LDAP_SUCCESS && match == 0 ) {
					ber_bvfree( asserted );
					return LDAP_TYPE_OR_VALUE_EXISTS;
				}
			}

			ber_bvfree( asserted );
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
	char *desc = mod->sm_desc->ad_cname->bv_val;
	MatchingRule *mr = mod->sm_desc->ad_type->sat_equality;

	/* delete the entire attribute */
	if ( mod->sm_bvalues == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
			   "delete_values: removing entire attribute %s\n", desc ));
#else
		Debug( LDAP_DEBUG_ARGS, "removing entire attribute %s\n",
		    desc, 0, 0 );
#endif

		return( attr_delete( &e->e_attrs, mod->sm_desc ) ?
		    LDAP_NO_SUCH_ATTRIBUTE : LDAP_SUCCESS );
	}

	if( mr == NULL || !mr->smr_match ) {
		/* disallow specific attributes from being deleted if
			no equality rule */
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->sm_desc )) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "ldap_modify_delete: Could not find attribute %s\n", desc ));
#else
		Debug( LDAP_DEBUG_ARGS, "ldap_modify_delete: "
			"could not find attribute %s\n",
		    desc, 0, 0 );
#endif

		return( LDAP_NO_SUCH_ATTRIBUTE );
	}

	/* find each value to delete */
	for ( i = 0; mod->sm_bvalues[i] != NULL; i++ ) {
		int rc;
		const char *text = NULL;

		struct berval *asserted;

		rc = value_normalize( mod->sm_desc,
			SLAP_MR_EQUALITY,
			mod->sm_bvalues[i],
			&asserted,
			&text );

		if( rc != LDAP_SUCCESS ) return rc;

		found = 0;
		for ( j = 0; a->a_vals[j] != NULL; j++ ) {
			int match;
			int rc = value_match( &match, mod->sm_desc, mr,
				SLAP_MR_MODIFY_MATCHING,
				a->a_vals[j], asserted, &text );

			if( rc == LDAP_SUCCESS && match != 0 ) {
				continue;
			}

			/* found a matching value */
			found = 1;

			/* delete it */
			ber_bvfree( a->a_vals[j] );
			for ( k = j + 1; a->a_vals[k] != NULL; k++ ) {
				a->a_vals[k - 1] = a->a_vals[k];
			}
			a->a_vals[k - 1] = NULL;

			break;
		}

		ber_bvfree( asserted );

		/* looked through them all w/o finding it */
		if ( ! found ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_ARGS,
				   "delete_values: could not find value for attr %s\n", desc )); 
#else
			Debug( LDAP_DEBUG_ARGS,
			    "ldbm_modify_delete: could not find value for attr %s\n",
			    desc, 0, 0 );
#endif

			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	/* if no values remain, delete the entire attribute */
	if ( a->a_vals[0] == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
			   "delete_values: removing entire attribute %s\n", desc ));
#else
		Debug( LDAP_DEBUG_ARGS,
			"removing entire attribute %s\n",
			desc, 0, 0 );
#endif

		if ( attr_delete( &e->e_attrs, mod->sm_desc ) ) {
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
