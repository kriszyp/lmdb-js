/* modify.c - bdb backend modify routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/time.h>

#include "back-bdb.h"
#include "external.h"

static int add_values( Entry *e, Modification *mod, char *dn );
static int delete_values( Entry *e, Modification *mod, char *dn );
static int replace_values( Entry *e, Modification *mod, char *dn );

int bdb_modify_internal(
	BackendDB *be,
	Connection *conn,
	Operation *op,
	DB_TXN *tid,
	Modifications *modlist,
	Entry *e,
	const char **text )
{
	int rc, err;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;

	Debug( LDAP_DEBUG_TRACE, "bdb_modify_internal: 0x%08lx: %s\n",
		e->e_id, e->e_dn, 0);

	if ( !acl_check_modlist( be, conn, op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: add\n", 0, 0, 0);
			err = add_values( e, mod, op->o_ndn );

			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
				*text = "modify: add values failed";
			}
			break;

		case LDAP_MOD_DELETE:
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: delete\n", 0, 0, 0);
			err = delete_values( e, mod, op->o_ndn );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
				*text = "modify: delete values failed";
			}
			break;

		case LDAP_MOD_REPLACE:
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: replace\n", 0, 0, 0);
			err = replace_values( e, mod, op->o_ndn );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
				*text = "modify: replace values failed";
			}
			break;

		case SLAP_MOD_SOFTADD:
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: softadd\n", 0, 0, 0);
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
 			mod->sm_op = LDAP_MOD_ADD;
			err = add_values( e, mod, op->o_ndn );

 			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
 			}

			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
				*text = "modify: (soft)add values failed";
			}
 			break;

		default:
			Debug(LDAP_DEBUG_ANY, "bdb_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
			*text = "Invalid modify operation";
			err = LDAP_OTHER;
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
				err, *text, 0);
		}

		if ( err != LDAP_SUCCESS ) {
			attrs_free( e->e_attrs );
			e->e_attrs = save_attrs;
			/* unlock entry, delete from cache */
			return err; 
		}
	}

	/* check that the entry still obeys the schema */
	rc = entry_schema_check( e, save_attrs, text );
	if ( rc != LDAP_SUCCESS ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
		Debug( LDAP_DEBUG_ANY, "entry failed schema check: %s\n",
			*text, 0, 0 );
		return rc;
	}

#if 0
	/* delete indices for old attributes */
	rc = index_entry_del( be, tid, e, save_attrs);

	/* add indices for new attributes */
	rc = index_entry_add( be, tid, e, e->e_attrs);
#endif

	attrs_free( save_attrs );

	return rc;
}


int
bdb_modify(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	const char	*dn,
	const char	*ndn,
	Modifications	*modlist )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	Entry		*matched;
	Entry		*e;
	int		manageDSAit = get_manageDSAit( op );
	const char *text = NULL;
	DB_TXN	*ltid;
	struct bdb_op_info opinfo;

	Debug( LDAP_DEBUG_ARGS, "bdb_modify: %s\n", dn, 0, 0 );

	if (0) {
retry:	/* transaction retry */
		Debug(LDAP_DEBUG_TRACE,
			"bdb_modify: retrying...\n", 0, 0, 0);
		rc = txn_abort( ltid );
		ltid = NULL;
		op->o_private = NULL;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}
	}

	/* begin transaction */
	rc = txn_begin( bdb->bi_dbenv, NULL, &ltid, 0 );
	text = NULL;
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	/* get entry */
	rc = bdb_dn2entry( be, ltid, ndn, &e, &matched, 0 );

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: dn2entry failed (%d)\n",
			rc, 0, 0 );
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case DB_NOTFOUND:
			break;
		default:
			rc = LDAP_OTHER;
		}
		text = "internal error";
		goto return_results;
	}

	/* acquire and lock entry */
	if ( e == NULL ) {
		char* matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_entry_return( be, matched );
			matched = NULL;

		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return rc;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: entry is referral\n",
			0, 0, 0 );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		goto done;
	}
	
	/* Modify the entry */
	rc = bdb_modify_internal( be, conn, op, ltid, modlist, e, &text );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: modify failed (%d)\n",
			rc, 0, 0 );
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		goto return_results;
	}

	/* change the entry itself */
	rc = bdb_id2entry_update( be, ltid, e );
	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: id2entry update failed (%d)\n",
			rc, 0, 0 );
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		text = "entry update failed";
		goto return_results;
	}

	rc = txn_commit( ltid, 0 );
	ltid = NULL;
	op->o_private = NULL;

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_commit failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "commit failed";
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: updated id=%08x dn=\"%s\"\n",
			e->e_id, e->e_dn, 0 );
		rc = LDAP_SUCCESS;
		text = NULL;
	}

return_results:
	send_ldap_result( conn, op, rc,
		NULL, text, NULL, NULL );

done:
	if( ltid != NULL ) {
		txn_abort( ltid );
		op->o_private = NULL;
	}

	if( e != NULL ) {
		bdb_entry_return( be, e );
	}
	return rc;
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
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify_delete: removing entire attribute %s\n",
			desc, 0, 0 );
		return attr_delete( &e->e_attrs, mod->sm_desc )
			? LDAP_NO_SUCH_ATTRIBUTE : LDAP_SUCCESS;
	}

	if( mr == NULL || !mr->smr_match ) {
		/* disallow specific attributes from being deleted if
			no equality rule */
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	/* delete specific values - find the attribute first */
	if ( (a = attr_find( e->e_attrs, mod->sm_desc )) == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify_delete: could not find attribute %s\n",
			desc, 0, 0 );
		return LDAP_NO_SUCH_ATTRIBUTE;
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
			Debug( LDAP_DEBUG_TRACE,
				"bdb_modify_delete: could not find value for attr %s\n",
				desc, 0, 0 );
			return LDAP_NO_SUCH_ATTRIBUTE;
		}
	}

	/* if no values remain, delete the entire attribute */
	if ( a->a_vals[0] == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify_delete: removing entire attribute %s\n",
			desc, 0, 0 );
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
