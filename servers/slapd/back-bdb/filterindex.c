/* filterindex.c - generate the list of candidate entries from a filter */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "idl.h"

#ifdef BDB_FILTER_INDICES

static int presence_candidates(
	Backend *be,
	AttributeDescription *desc,
	ID *ids );

static int equality_candidates(
	Backend *be,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp );
static int approx_candidates(
	Backend *be,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp );
static int substring_candidates(
	Backend *be,
	SubstringsAssertion *sub,
	ID *ids,
	ID *tmp );

static int list_candidates(
	Backend *be,
	Filter *flist,
	int ftype,
	ID *ids,
	ID *tmp );

int
bdb_filter_candidates(
	Backend	*be,
	Filter	*f,
	ID *ids,
	ID *tmp )
{
	int rc = -1;
	Debug( LDAP_DEBUG_FILTER, "=> bdb_filter_candidates\n", 0, 0, 0 );

	switch ( f->f_choice ) {
	case SLAPD_FILTER_DN_ONE:
		Debug( LDAP_DEBUG_FILTER, "\tDN ONE\n", 0, 0, 0 );
		rc = bdb_dn2idl( be, f->f_dn, DN_ONE_PREFIX, ids );
		break;

	case SLAPD_FILTER_DN_SUBTREE:
		Debug( LDAP_DEBUG_FILTER, "\tDN SUBTREE\n", 0, 0, 0 );
		rc = bdb_dn2idl( be, f->f_dn, DN_SUBTREE_PREFIX, ids );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );
		rc = presence_candidates( be, f->f_desc, ids );
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
		rc = equality_candidates( be, f->f_ava, ids, tmp );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
		rc = approx_candidates( be, f->f_ava, ids, tmp );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		rc = substring_candidates( be, f->f_sub, ids, tmp );
		break;

	case LDAP_FILTER_GE:
		/* no GE index, use pres */
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		rc = presence_candidates( be, f->f_desc, ids );
		break;

	case LDAP_FILTER_LE:
		/* no LE index, use pres */
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		rc = presence_candidates( be, f->f_desc, ids );
		break;

	case LDAP_FILTER_NOT:
		/* no indexing to support NOT filters */
		Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );
		rc = list_candidates( be, 
			f->f_and, LDAP_FILTER_AND, ids, tmp );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );
		rc = list_candidates( be, 
			f->f_or, LDAP_FILTER_OR, ids, tmp );
		break;

	default:
		Debug( LDAP_DEBUG_FILTER, "\tUNKNOWN %d\n",
			f->f_choice, 0, 0 );
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
	Backend	*be,
	Filter	*flist,
	int		ftype,
	ID *ids,
	ID *tmp )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc = 0;
	Filter	*f;

/* Systems that can't increase thread stack size will die with these
 * structures allocated on the stack. */
#if !defined(LDAP_PVT_THREAD_STACK_SIZE) || (LDAP_PVT_THREAD_STACK_SIZE == 0)
	ID *save = ch_malloc(BDB_IDL_UM_SIZEOF);
#else
	ID save[BDB_IDL_UM_SIZE];
#endif

	Debug( LDAP_DEBUG_FILTER, "=> bdb_list_candidates 0x%x\n", ftype, 0, 0 );

	if ( ftype == LDAP_FILTER_OR ) {
		BDB_IDL_ALL( bdb, save );
		BDB_IDL_ZERO( ids );
	} else {
		BDB_IDL_CPY( save, ids );
	}

	for ( f = flist; f != NULL; f = f->f_next ) {
		rc = bdb_filter_candidates( be, f, save, tmp );

		if ( rc != 0 ) {
			/* Error: treat as undefined */
			continue;
		}
		
		if ( ftype == LDAP_FILTER_AND ) {
			bdb_idl_intersection( ids, save );
			if( BDB_IDL_IS_ZERO( ids ) )
				break;
		} else {
			bdb_idl_union( ids, save );
			BDB_IDL_ALL( bdb, save );
		}
	}
#if !defined(LDAP_PVT_THREAD_STACK_SIZE) || (LDAP_PVT_THREAD_STACK_SIZE == 0)
	free(save);
#endif

	Debug( LDAP_DEBUG_FILTER,
		"<= bdb_list_candidates: id=%ld first=%ld last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );
	return 0;
}

static int
presence_candidates(
	Backend	*be,
	AttributeDescription *desc,
	ID *ids )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0};

	Debug( LDAP_DEBUG_TRACE, "=> bdb_presence_candidates\n", 0, 0, 0 );

	if( desc == slap_schema.si_ad_objectClass ) {
		BDB_IDL_ALL( bdb, ids );
		return 0;
	}

	rc = bdb_index_param( be, desc, LDAP_FILTER_PRESENT,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: index_param returned=%d\n",
			rc, 0, 0 );
		return 0;
	}

	if( db == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: not indexed\n",
			0, 0, 0 );
		return 0;
	}

	if( prefix.bv_val == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: no prefix\n",
			0, 0, 0 );
		return 0;
	}

	rc = bdb_key_read( be, db, NULL, &prefix, ids );

	if( rc == DB_NOTFOUND ) {
		rc = 0;

	} else if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presense_candidates: key read failed (%d)\n",
			rc, 0, 0 );
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
	Backend	*be,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp )
{
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0};
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_equality_candidates\n", 0, 0, 0 );

	rc = bdb_index_param( be, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_equality_candidates: index_param failed (%d)\n",
			rc, 0, 0 );
		return rc;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_equality_candidates: not indexed\n", 0, 0, 0 );
		return -1;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		return -1;
	}

	if( !mr->smr_filter ) {
		return -1;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		&prefix,
		ava->aa_value,
		&keys );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_equality_candidates: MR filter failed (%d)\n",
			rc, 0, 0 );
		return rc;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_equality_candidates: no keys\n",
			0, 0, 0 );
		return 0;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		rc = bdb_key_read( be, db, NULL, keys[i], tmp );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_equality_candidates key read failed (%d)\n",
				rc, 0, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_equality_candidates NULL\n",
				0, 0, 0 );
			BDB_IDL_ZERO( ids );
			break;
		}

		bdb_idl_intersection( ids, tmp );

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
	}

	ber_bvecfree( keys );

	Debug( LDAP_DEBUG_TRACE,
		"<= bdb_equality_candidates id=%ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );
	return( rc );
}


static int
approx_candidates(
	Backend	*be,
	AttributeAssertion *ava,
	ID *ids,
	ID *tmp )
{
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0};
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_approx_candidates\n", 0, 0, 0 );

	rc = bdb_index_param( be, ava->aa_desc, LDAP_FILTER_APPROX,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_approx_candidates: index_param failed (%d)\n",
			rc, 0, 0 );
		return rc;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_approx_candidates: not indexed\n", 0, 0, 0 );
		return -1;
	}

	mr = ava->aa_desc->ad_type->sat_approx;
	if( !mr ) {
		/* no approx matching rule, try equality matching rule */
		mr = ava->aa_desc->ad_type->sat_equality;
	}

	if( !mr ) {
		return -1;
	}

	if( !mr->smr_filter ) {
		return -1;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_APPROX,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		&prefix,
		ava->aa_value,
		&keys );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_approx_candidates: (%s) MR filter failed (%d)\n",
			prefix.bv_val, rc, 0 );
		return rc;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_approx_candidates: no keys (%s)\n",
			prefix.bv_val, 0, 0 );
		return 0;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		rc = bdb_key_read( be, db, NULL, keys[i], tmp );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "<= bdb_approx_candidates key read failed (%d)\n",
				rc, 0, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE, "<= bdb_approx_candidates NULL\n",
				0, 0, 0 );
			BDB_IDL_ZERO( ids );
			break;
		}

		bdb_idl_intersection( ids, tmp );

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
	}

	ber_bvecfree( keys );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_approx_candidates %ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );

	return( rc );
}

static int
substring_candidates(
	Backend	*be,
	SubstringsAssertion	*sub,
	ID *ids,
	ID *tmp )
{
	DB	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval prefix = {0};
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_substring_candidates\n", 0, 0, 0 );

	rc = bdb_index_param( be, sub->sa_desc, LDAP_FILTER_SUBSTRINGS,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_substring_candidates: index_param failed (%d)\n",
			rc, 0, 0 );
		return 0;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= bdb_substring_candidates not indexed\n",
			0, 0, 0 );
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
		&keys );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_substring_candidates: (%s) MR filter failed (%d)\n",
			sub->sa_desc->ad_cname.bv_val, rc, 0 );
		return 0;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_substring_candidates: (0x%04lx) no keys (%s)\n",
			mask, sub->sa_desc->ad_cname.bv_val, 0 );
		return 0;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		rc = bdb_key_read( be, db, NULL, keys[i], tmp );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "<= bdb_substring_candidates key read failed (%d)\n",
				rc, 0, 0 );
			break;
		}

		if( BDB_IDL_IS_ZERO( tmp ) ) {
			Debug( LDAP_DEBUG_TRACE, "<= bdb_substring_candidates NULL\n",
				0, 0, 0 );
			BDB_IDL_ZERO( ids );
			break;
		}

		bdb_idl_intersection( ids, tmp );

		if( BDB_IDL_IS_ZERO( ids ) )
			break;
	}

	ber_bvecfree( keys );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_substring_candidates %ld, first=%ld, last=%ld\n",
		(long) ids[0],
		(long) BDB_IDL_FIRST(ids),
		(long) BDB_IDL_LAST(ids) );

	return( 0 );
}

#endif
