/* index.c - routines for dealing with attribute indexes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb.h"
#include "lutil_hash.h"

static char presence_keyval[LUTIL_HASH_BYTES] = {0,0,0,1};
static struct berval presence_key = {LUTIL_HASH_BYTES, presence_keyval};

static slap_mask_t index_mask(
	Backend *be,
	AttributeDescription *desc,
	struct berval *atname )
{
	AttributeType *at;
	slap_mask_t mask = 0;

	bdb_attr_mask( be->be_private, desc, &mask );

	if( mask ) {
		*atname = desc->ad_cname;
		return mask;
	}

	/* If there is a tagging option, did we ever index the base
	 * type? If so, check for mask, otherwise it's not there.
	 */
	if( slap_ad_is_tagged( desc ) && desc != desc->ad_type->sat_ad ) {
		/* has tagging option */
		bdb_attr_mask( be->be_private, desc->ad_type->sat_ad, &mask );

		if ( mask && ( mask ^ SLAP_INDEX_NOTAGS ) ) {
			*atname = desc->ad_type->sat_cname;
			return mask;
		}
	}

	/* see if supertype defined mask for its subtypes */
	for( at = desc->ad_type; at != NULL ; at = at->sat_sup ) {
		/* If no AD, we've never indexed this type */
		if ( !at->sat_ad ) continue;

		bdb_attr_mask( be->be_private, at->sat_ad, &mask );

		if ( mask && ( mask ^ SLAP_INDEX_NOSUBTYPES ) ) {
			*atname = at->sat_cname;
			return mask;
		}
	}

	return 0;
}

int bdb_index_is_indexed(
	Backend *be,
	AttributeDescription *desc )
{
	slap_mask_t mask;
	struct berval prefix;

	mask = index_mask( be, desc, &prefix );

	if( mask == 0 ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	return LDAP_SUCCESS;
}

int bdb_index_param(
	Backend *be,
	AttributeDescription *desc,
	int ftype,
	DB **dbp,
	slap_mask_t *maskp,
	struct berval *prefixp )
{
	int rc;
	slap_mask_t mask;
	DB *db;

	mask = index_mask( be, desc, prefixp );

	if( mask == 0 ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	rc = bdb_db_cache( be, prefixp->bv_val, &db );

	if( rc != LDAP_SUCCESS ) {
		return rc;
	}

	switch( ftype ) {
	case LDAP_FILTER_PRESENT:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_PRESENT ) ) {
			*prefixp = presence_key;
			goto done;
		}
		break;

	case LDAP_FILTER_APPROX:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) ) {
			goto done;
		}
		/* fall thru */

	case LDAP_FILTER_EQUALITY:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_EQUALITY ) ) {
			goto done;
		}
		break;

	case LDAP_FILTER_SUBSTRINGS:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) ) {
			goto done;
		}
		break;

	default:
		return LDAP_OTHER;
	}

	return LDAP_INAPPROPRIATE_MATCHING;

done:
	*dbp = db;
	*maskp = mask;
	return LDAP_SUCCESS;
}

static int indexer(
	Operation *op,
	DB_TXN *txn,
	AttributeDescription *ad,
	struct berval *atname,
	BerVarray vals,
	ID id,
	int opid,
	slap_mask_t mask )
{
	int rc, i;
	const char *text;
	DB *db;
	struct berval *keys;
	void *mark;

	assert( mask );

	rc = bdb_db_cache( op->o_bd, atname->bv_val, &db );
	
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_index_read: Could not open DB %s\n",
			atname->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"bdb_index_read: Could not open DB %s\n",
			atname->bv_val, 0, 0 );
#endif
		return LDAP_OTHER;
	}

#if 0	/* No longer needed, our frees are in order so nothing accumulates */
	mark = sl_mark(op->o_tmpmemctx);
#endif

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_PRESENT ) ) {
		rc = bdb_key_change( op->o_bd, db, txn, &presence_key, id, opid );
		if( rc ) {
			goto done;
		}
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_EQUALITY ) ) {
		rc = ad->ad_type->sat_equality->smr_indexer(
			LDAP_FILTER_EQUALITY,
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_equality,
			atname, vals, &keys, op->o_tmpmemctx );

		if( rc == LDAP_SUCCESS && keys != NULL ) {
			for( i=0; keys[i].bv_val != NULL; i++ ) {
				rc = bdb_key_change( op->o_bd, db, txn, &keys[i], id, opid );
				if( rc ) {
					ber_bvarray_free_x( keys, op->o_tmpmemctx );
					goto done;
				}
			}
			ber_bvarray_free_x( keys, op->o_tmpmemctx );
		}
		rc = LDAP_SUCCESS;
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) ) {
		rc = ad->ad_type->sat_approx->smr_indexer(
			LDAP_FILTER_APPROX,
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_approx,
			atname, vals, &keys, op->o_tmpmemctx );

		if( rc == LDAP_SUCCESS && keys != NULL ) {
			for( i=0; keys[i].bv_val != NULL; i++ ) {
				rc = bdb_key_change( op->o_bd, db, txn, &keys[i], id, opid );
				if( rc ) {
					ber_bvarray_free_x( keys, op->o_tmpmemctx );
					goto done;
				}
			}
			ber_bvarray_free_x( keys, op->o_tmpmemctx );
		}

		rc = LDAP_SUCCESS;
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) ) {
		rc = ad->ad_type->sat_substr->smr_indexer(
			LDAP_FILTER_SUBSTRINGS,
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_substr,
			atname, vals, &keys, op->o_tmpmemctx );

		if( rc == LDAP_SUCCESS && keys != NULL ) {
			for( i=0; keys[i].bv_val != NULL; i++ ) {
				bdb_key_change( op->o_bd, db, txn, &keys[i], id, opid );
				if( rc ) {
					ber_bvarray_free_x( keys, op->o_tmpmemctx );
					goto done;
				}
			}
			ber_bvarray_free_x( keys, op->o_tmpmemctx );
		}

		rc = LDAP_SUCCESS;
	}

done:
#if 0
	sl_release( mark, op->o_tmpmemctx );
#endif
	return rc;
}

static int index_at_values(
	Operation *op,
	DB_TXN *txn,
	AttributeDescription *ad,
	AttributeType *type,
	struct berval *tags,
	BerVarray vals,
	ID id,
	int opid )
{
	int rc;
	slap_mask_t mask = 0;

	if( type->sat_sup ) {
		/* recurse */
		rc = index_at_values( op, txn, NULL,
			type->sat_sup, tags,
			vals, id, opid );

		if( rc ) return rc;
	}

	/* If this type has no AD, we've never used it before */
	if( type->sat_ad ) {
		bdb_attr_mask( op->o_bd->be_private, type->sat_ad, &mask );
		ad = type->sat_ad;
	}

	if( mask ) {
		rc = indexer( op, txn, ad, &type->sat_cname,
			vals, id, opid,
			mask );

		if( rc ) return rc;
	}

	if( tags->bv_len ) {
		AttributeDescription *desc;

		mask = 0;

		desc = ad_find_tags( type, tags );
		if( desc ) {
			bdb_attr_mask( op->o_bd->be_private, desc, &mask );
		}

		if( mask ) {
			rc = indexer( op, txn, desc, &desc->ad_cname,
				vals, id, opid,
				mask );

			if( rc ) {
				return rc;
			}
		}
	}

	return LDAP_SUCCESS;
}

int bdb_index_values(
	Operation *op,
	DB_TXN *txn,
	AttributeDescription *desc,
	BerVarray vals,
	ID id,
	int opid )
{
	int rc;

	rc = index_at_values( op, txn, desc,
		desc->ad_type, &desc->ad_tags,
		vals, id, opid );

	return rc;
}

int
bdb_index_entry(
	Operation *op,
	DB_TXN *txn,
	int opid,
	Entry	*e )
{
	int rc;
	Attribute *ap = e->e_attrs;

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "index_entry: %s (%s) %ld\n",
		opid == SLAP_INDEX_ADD_OP ? "add" : "del", e->e_dn, (long) e->e_id );
#else
	Debug( LDAP_DEBUG_TRACE, "=> index_entry_%s( %ld, \"%s\" )\n",
		opid == SLAP_INDEX_ADD_OP ? "add" : "del",
		(long) e->e_id, e->e_dn );
#endif

	/* add each attribute to the indexes */
	for ( ; ap != NULL; ap = ap->a_next ) {
		rc = bdb_index_values( op, txn, ap->a_desc,
			ap->a_nvals, e->e_id, opid );

		if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG( INDEX, ENTRY, 
				"index_entry: failure (%d)\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<= index_entry_%s( %ld, \"%s\" ) failure\n",
				opid == SLAP_INDEX_ADD_OP ? "add" : "del",
				(long) e->e_id, e->e_dn );
#endif
			return rc;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "index_entry: success\n", 0, 0, 0  );
#else
	Debug( LDAP_DEBUG_TRACE, "<= index_entry_%s( %ld, \"%s\" ) success\n",
		opid == SLAP_INDEX_ADD_OP ? "add" : "del",
		(long) e->e_id, e->e_dn );
#endif

	return LDAP_SUCCESS;
}
