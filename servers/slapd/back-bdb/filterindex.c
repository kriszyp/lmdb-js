/* filterindex.c - generate the list of candidate entries from a filter */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
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

#include "back-bdb.h"
#include "idl.h"

static int presence_candidates(
	Operation *op,
	AttributeDescription *desc,
	ID *ids );

static int equality_candidates(
	Operation *op,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp );
static int inequality_candidates(
	Operation *op,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp,
	int gtorlt );
static int approx_candidates(
	Operation *op,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp );
static int substring_candidates(
	Operation *op,
	SubstringsAssertion *sub,
	ID *ids,
	ID *tmp );

static int list_candidates(
	Operation *op,
	Filter *flist,
	int ftype,
	ID *ids,
	ID *tmp,
	ID *stack );

int
bdb_filter_candidates(
	Operation *op,
	Filter	*f,
	ID *ids,
	ID *tmp,
	ID *stack )
{
	int rc = 0;
	Debug( LDAP_DEBUG_FILTER, "=> bdb_filter_candidates\n", 0, 0, 0 );

	switch ( f->f_choice ) {
	case SLAPD_FILTER_COMPUTED:
		switch( f->f_result ) {
		case SLAPD_COMPARE_UNDEFINED:
		/* This technically is not the same as FALSE, but it
		 * certainly will produce no matches.
		 */
		/* FALL THRU */
		case LDAP_COMPARE_FALSE:
			BDB_IDL_ZERO( ids );
			break;
		case LDAP_COMPARE_TRUE: {
			struct bdb_info *bdb = (struct bdb_info *)op->o_bd->be_private;
			BDB_IDL_ALL( bdb, ids );
			} break;
		case LDAP_SUCCESS:
			/* this is a pre-computed scope, leave it alone */
			break;
		}
		break;
	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );
		rc = presence_candidates( op, f->f_desc, ids );
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
		rc = equality_candidates( op, f->f_ava, ids, tmp );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
		rc = approx_candidates( op, f->f_ava, ids, tmp );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		rc = substring_candidates( op, f->f_sub, ids, tmp );
		break;

	case LDAP_FILTER_GE:
		/* if no GE index, use pres */
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		if( f->f_ava->aa_desc->ad_type->sat_ordering &&
			( f->f_ava->aa_desc->ad_type->sat_ordering->smr_usage && SLAP_MR_ORDERED_INDEX ) )
			rc = inequality_candidates( op, f->f_ava, ids, tmp, LDAP_FILTER_GE );
		else
			rc = presence_candidates( op, f->f_ava->aa_desc, ids );
		break;

	case LDAP_FILTER_LE:
		/* if no LE index, use pres */
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		if( f->f_ava->aa_desc->ad_type->sat_ordering &&
			( f->f_ava->aa_desc->ad_type->sat_ordering->smr_usage && SLAP_MR_ORDERED_INDEX ) )
			rc = inequality_candidates( op, f->f_ava, ids, tmp, LDAP_FILTER_LE );
		else
			rc = presence_candidates( op, f->f_ava->aa_desc, ids );
		break;

	case LDAP_FILTER_NOT:
		/* no indexing to support NOT filters */
		Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );
		{ struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
		BDB_IDL_ALL( bdb, ids );
		}
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );
		rc = list_candidates( op, 
			f->f_and, LDAP_FILTER_AND, ids, tmp, stack );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );
		rc = list_candidates( op, 
			f->f_or, LDAP_FILTER_OR, ids, tmp, stack );
		break;

	default:
		Debug( LDAP_DEBUG_FILTER, "\tUNKNOWN %lu\n",
			(unsigned long) f->f_choice, 0, 0 );
		/* Must not return NULL, otherwise extended filters break */
		{ struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
		BDB_IDL_ALL( bdb, ids );
		}
	}

	Debug( LDAP_DEBUG_FILTER,
		"<= bdb_filter_candidates: id=%ld first=%ld last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST( ids ),
		(long) BDB_IDL_LAST( ids ) );

	return rc;
}

static int
list_candidates(
	Operation *op,
	Filter	*flist,
	int		ftype,
	ID *ids,
	ID *tmp,
	ID *save )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	int rc = 0;
	Filter	*f;

	Debug( LDAP_DEBUG_FILTER, "=> bdb_list_candidates 0x%x\n", ftype, 0, 0 );
	for ( f = flist; f != NULL; f = f->f_next ) {
		/* ignore precomputed scopes */
		if ( f->f_choice == SLAPD_FILTER_COMPUTED &&
		     f->f_result == LDAP_SUCCESS ) {
			continue;
		}
		BDB_IDL_ZERO( save );
		rc = bdb_filter_candidates( op, f, save, tmp,
			save+BDB_IDL_UM_SIZE );

		if ( rc != 0 ) {
			if ( ftype == LDAP_FILTER_AND ) {
				rc = 0;
				continue;
			}
			break;
		}

		
		if ( ftype == LDAP_FILTER_AND ) {
			if ( f == flist ) {
				BDB_IDL_CPY( ids, save );
			} else {
				bdb_idl_intersection( ids, save );
			}
			if( BDB_IDL_IS_ZERO( ids ) )
				break;
		} else {
			if ( f == flist ) {
				BDB_IDL_CPY( ids, save );
			} else {
				bdb_idl_union( ids, save );
			}
		}
	}

	if( rc == LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_FILTER,
			"<= bdb_list_candidates: id=%ld first=%ld last=%ld\n",
			(long) ids[0],
			(long) BDB_IDL_FIRST(ids),
			(long) BDB_IDL_LAST(ids) );

	} else {
		Debug( LDAP_DEBUG_FILTER,
			"<= bdb_list_candidates: undefined rc=%d\n",
			rc, 0, 0 );
	}

	return rc;
}

static int
presence_candidates(
	Operation *op,
	AttributeDescription *desc,
	ID *ids )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};

	Debug( LDAP_DEBUG_TRACE, "=> bdb_presence_candidates (%s)\n",
			desc->ad_cname.bv_val, 0, 0 );

	BDB_IDL_ALL( bdb, ids );

	if( desc == slap_schema.si_ad_objectClass ) {
		return 0;
	}

	rc = bdb_index_param( op->o_bd, desc, LDAP_FILTER_PRESENT,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: (%s) index_param "
			"returned=%d\n",
			desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if( db == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: (%s) not indexed\n",
			desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	if( prefix.bv_val == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: (%s) no prefix\n",
			desc->ad_cname.bv_val, 0, 0 );
		return -1;
	}

	rc = bdb_key_read( op->o_bd, db, NULL, &prefix, ids, NULL, 0 );

	if( rc == DB_NOTFOUND ) {
		BDB_IDL_ZERO( ids );
		rc = 0;
	} else if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presense_candidates: (%s) "
			"key read failed (%d)\n",
			desc->ad_cname.bv_val, rc, 0 );
		goto done;
	}

	Debug(LDAP_DEBUG_TRACE,
		"<= bdb_presence_candidates: id=%ld first=%ld last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );

done:
	return rc;
}

static int
equality_candidates(
	Operation *op,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_equality_candidates (%s)\n",
			ava->aa_desc->ad_cname.bv_val, 0, 0 );

	BDB_IDL_ALL( bdb, ids );

	rc = bdb_index_param( op->o_bd, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_equality_candidates: (%s) "
			"index_param failed (%d)\n",
			ava->aa_desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_equality_candidates: (%s) not indexed\n", 
			ava->aa_desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		return 0;
	}

	if( !mr->smr_filter ) {
		return 0;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		&prefix,
		&ava->aa_value,
		&keys, op->o_tmpmemctx );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_equality_candidates: (%s, %s) "
			"MR filter failed (%d)\n",
			prefix.bv_val, ava->aa_desc->ad_cname.bv_val, rc );
		return 0;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_equality_candidates: (%s) no keys\n",
			ava->aa_desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	for ( i= 0; keys[i].bv_val != NULL; i++ ) {
		rc = bdb_key_read( op->o_bd, db, NULL, &keys[i], tmp, NULL, 0 );

		if( rc == DB_NOTFOUND ) {
			BDB_IDL_ZERO( ids );
			rc = 0;
			break;
		} else if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_equality_candidates: (%s) "
				"key read failed (%d)\n",
				ava->aa_desc->ad_cname.bv_val, rc, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_equality_candidates: (%s) NULL\n", 
				ava->aa_desc->ad_cname.bv_val, 0, 0 );
			BDB_IDL_ZERO( ids );
			break;
		}

		if ( i == 0 ) {
			BDB_IDL_CPY( ids, tmp );
		} else {
			bdb_idl_intersection( ids, tmp );
		}

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
	}

	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	Debug( LDAP_DEBUG_TRACE,
		"<= bdb_equality_candidates: id=%ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );
	return( rc );
}


static int
approx_candidates(
	Operation *op,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_approx_candidates (%s)\n",
			ava->aa_desc->ad_cname.bv_val, 0, 0 );

	BDB_IDL_ALL( bdb, ids );

	rc = bdb_index_param( op->o_bd, ava->aa_desc, LDAP_FILTER_APPROX,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_approx_candidates: (%s) "
			"index_param failed (%d)\n",
			ava->aa_desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_approx_candidates: (%s) not indexed\n",
			ava->aa_desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	mr = ava->aa_desc->ad_type->sat_approx;
	if( !mr ) {
		/* no approx matching rule, try equality matching rule */
		mr = ava->aa_desc->ad_type->sat_equality;
	}

	if( !mr ) {
		return 0;
	}

	if( !mr->smr_filter ) {
		return 0;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_APPROX,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		&prefix,
		&ava->aa_value,
		&keys, op->o_tmpmemctx );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_approx_candidates: (%s, %s) "
			"MR filter failed (%d)\n",
			prefix.bv_val, ava->aa_desc->ad_cname.bv_val, rc );
		return 0;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_approx_candidates: (%s) no keys (%s)\n",
			prefix.bv_val, ava->aa_desc->ad_cname.bv_val, 0 );
		return 0;
	}

	for ( i= 0; keys[i].bv_val != NULL; i++ ) {
		rc = bdb_key_read( op->o_bd, db, NULL, &keys[i], tmp, NULL, 0 );

		if( rc == DB_NOTFOUND ) {
			BDB_IDL_ZERO( ids );
			rc = 0;
			break;
		} else if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_approx_candidates: (%s) "
				"key read failed (%d)\n",
				ava->aa_desc->ad_cname.bv_val, rc, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_approx_candidates: (%s) NULL\n",
				ava->aa_desc->ad_cname.bv_val, 0, 0 );
			BDB_IDL_ZERO( ids );
			break;
		}

		if ( i == 0 ) {
			BDB_IDL_CPY( ids, tmp );
		} else {
			bdb_idl_intersection( ids, tmp );
		}

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
	}

	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_approx_candidates %ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );
	return( rc );
}

static int
substring_candidates(
	Operation *op,
	SubstringsAssertion	*sub,
	ID *ids,
	ID *tmp )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_substring_candidates (%s)\n",
			sub->sa_desc->ad_cname.bv_val, 0, 0 );

	BDB_IDL_ALL( bdb, ids );

	rc = bdb_index_param( op->o_bd, sub->sa_desc, LDAP_FILTER_SUBSTRINGS,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_substring_candidates: (%s) "
			"index_param failed (%d)\n",
			sub->sa_desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_substring_candidates: (%s) not indexed\n",
			sub->sa_desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	mr = sub->sa_desc->ad_type->sat_substr;

	if( !mr ) {
		return 0;
	}

	if( !mr->smr_filter ) {
		return 0;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_SUBSTRINGS,
		mask,
		sub->sa_desc->ad_type->sat_syntax,
		mr,
		&prefix,
		sub,
		&keys, op->o_tmpmemctx );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_substring_candidates: (%s) "
			"MR filter failed (%d)\n",
			sub->sa_desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_substring_candidates: (0x%04lx) no keys (%s)\n",
			mask, sub->sa_desc->ad_cname.bv_val, 0 );
		return 0;
	}

	for ( i= 0; keys[i].bv_val != NULL; i++ ) {
		rc = bdb_key_read( op->o_bd, db, NULL, &keys[i], tmp, NULL, 0 );

		if( rc == DB_NOTFOUND ) {
			BDB_IDL_ZERO( ids );
			rc = 0;
			break;
		} else if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_substring_candidates: (%s) "
				"key read failed (%d)\n",
				sub->sa_desc->ad_cname.bv_val, rc, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_substring_candidates: (%s) NULL\n",
				sub->sa_desc->ad_cname.bv_val, 0, 0 );
			BDB_IDL_ZERO( ids );
			break;
		}

		if ( i == 0 ) {
			BDB_IDL_CPY( ids, tmp );
		} else {
			bdb_idl_intersection( ids, tmp );
		}

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
	}

	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_substring_candidates: %ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );
	return( rc );
}

static int
inequality_candidates(
	Operation *op,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp,
	int gtorlt )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;
	DBC * cursor = NULL;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_inequality_candidates (%s)\n",
			ava->aa_desc->ad_cname.bv_val, 0, 0 );

	BDB_IDL_ALL( bdb, ids );

	rc = bdb_index_param( op->o_bd, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_inequality_candidates: (%s) "
			"index_param failed (%d)\n",
			ava->aa_desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_inequality_candidates: (%s) not indexed\n", 
			ava->aa_desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		return 0;
	}

	if( !mr->smr_filter ) {
		return 0;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		&prefix,
		&ava->aa_value,
		&keys, op->o_tmpmemctx );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_inequality_candidates: (%s, %s) "
			"MR filter failed (%d)\n",
			prefix.bv_val, ava->aa_desc->ad_cname.bv_val, rc );
		return 0;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_inequality_candidates: (%s) no keys\n",
			ava->aa_desc->ad_cname.bv_val, 0, 0 );
		return 0;
	}

	BDB_IDL_ZERO( ids );
	while(1) {
		rc = bdb_key_read( op->o_bd, db, NULL, &keys[0], tmp, &cursor, gtorlt );

		if( rc == DB_NOTFOUND ) {
			rc = 0;
			break;
		} else if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
			       "<= bdb_inequality_candidates: (%s) "
			       "key read failed (%d)\n",
			       ava->aa_desc->ad_cname.bv_val, rc, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE,
			       "<= bdb_inequality_candidates: (%s) NULL\n", 
			       ava->aa_desc->ad_cname.bv_val, 0, 0 );
			break;
		}

		bdb_idl_union( ids, tmp );

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
		i++;
	}
	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	Debug( LDAP_DEBUG_TRACE,
		"<= bdb_inequality_candidates: id=%ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );
	return( rc );
}
