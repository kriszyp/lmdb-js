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
	ID *range,
	AttributeDescription *desc,
	ID *ids );
static int equality_candidates(
	Backend *be,
	ID *range,
	AttributeAssertion *ava,
	ID *ids );
static int approx_candidates(
	Backend *be,
	ID *range,
	AttributeAssertion *ava,
	ID *ids );
static int substring_candidates(
	Backend *be,
	ID *range,
	SubstringsAssertion *sub,
	ID *ids );

static int list_candidates(
	Backend *be,
	ID *range,
	Filter *flist,
	int ftype,
	ID *ids );


int
bdb_filter_candidates(
	Backend	*be,
	ID *range,
	Filter	*f,
	ID *ids )
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
		rc = presence_candidates( be, range, f->f_desc, ids );
		break;

#if 0
	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
		rc = equality_candidates( be, range, f->f_ava, ids );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
		rc = approx_candidates( be, range, f->f_ava, ids );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		rc = substring_candidates( be, range, f->f_sub, ids );
		break;
#endif

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		rc = 0;
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		rc = 0;
		break;

	case LDAP_FILTER_NOT: {
			ID tmp[BDB_IDL_SIZE];

			Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );
			rc = bdb_filter_candidates( be, range, f->f_not, tmp );
			if( rc == 0 ) {
				rc = bdb_idl_notin( range, tmp, ids );
			}
		} break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );
		rc = list_candidates( be, range,
			f->f_and, LDAP_FILTER_AND, ids );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );
		rc = list_candidates( be, range,
			f->f_or, LDAP_FILTER_OR, ids );
		break;

	default:
		Debug( LDAP_DEBUG_FILTER, "\tUNKNOWN %d\n",
			f->f_choice, 0, 0 );
	}

	if( rc ) {
		BDB_IDL_CPY( ids, range );
	}

	Debug( LDAP_DEBUG_FILTER,
		"<= bdb_filter_candidates: id=%ld first=%ld last=%ld\n",
		ids[0], ids[1],
		BDB_IDL_IS_RANGE( ids ) ? ids[2] : ids[ids[0]] );

	return 0;
}

static int
list_candidates(
	Backend	*be,
	ID *range,
	Filter	*flist,
	int		ftype,
	ID *ids )
{
	int rc = 0;
	Filter	*f;

	Debug( LDAP_DEBUG_FILTER, "=> bdb_list_candidates 0x%x\n", ftype, 0, 0 );

	if( ftype == LDAP_FILTER_AND ) {
		BDB_IDL_CPY( ids, range );
	} else {
		BDB_IDL_ZERO( ids );
	}

	for ( f = flist; f != NULL; f = f->f_next ) {
		ID tmp[BDB_IDL_SIZE];
		ID result[BDB_IDL_SIZE];
		rc = bdb_filter_candidates( be, range, f, tmp );

		if ( rc != 0 ) {
			/* Error: treat as undefined */
			if( ftype == LDAP_FILTER_AND ) {
				continue;
			}
			BDB_IDL_CPY( ids, range );
			break;
		}


		if ( ftype == LDAP_FILTER_AND ) {
			bdb_idl_intersection( tmp, ids, result );
			if( BDB_IDL_IS_ZERO( result ) ) {
				BDB_IDL_ZERO( ids );
				break;
			}
		} else {
			bdb_idl_union( tmp, ids, result );
			if( BDB_IDL_IS_ALL( range, result ) ) {
				BDB_IDL_CPY( ids, range );
				break;
			}
		}

		BDB_IDL_CPY( ids, result );
	}

	Debug( LDAP_DEBUG_FILTER,
		"<= bdb_list_candidates: id=%ld first=%ld last=%ld\n",
		ids[0], BDB_IDL_FIRST(ids), BDB_IDL_LAST(ids) );
	return 0;
}

static int
presence_candidates(
	Backend	*be,
	ID *range,
	AttributeDescription *desc,
	ID *ids )
{
	DB *db;
	int rc;
	slap_mask_t mask;
	struct berval *prefix;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_presence_candidates\n", 0, 0, 0 );
	BDB_IDL_ZERO( ids );

	rc = bdb_index_param( be, desc, LDAP_FILTER_PRESENT,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presence_candidates: index_param returned=%d\n",
			rc, 0, 0 );
		return rc;
	}

	if( db == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presense_candidates: not indexed\n",
			0, 0, 0 );
		rc = -1;
		goto done;
	}

	if( prefix == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_presense_candidates: no prefix\n",
			0, 0, 0 );
		rc = -1;
		goto done;
	}

	rc = bdb_key_read( be, db, prefix, ids );

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
		ids[0], BDB_IDL_FIRST(ids), BDB_IDL_LAST(ids) );

done:
	ber_bvfree( prefix );
	return rc;
}

static int
equality_candidates(
	Backend	*be,
	ID *range,
	AttributeAssertion *ava,
	ID *ids )
{
	DB	*db;
	int i;
	int rc;
	char *dbname;
	slap_mask_t mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_equality_candidates\n", 0, 0, 0 );

	BDB_IDL_RANGE_CPY( range, ids );

	rc = bdb_index_param( be, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= equality_candidates: index_param failed (%d)\n",
			rc, 0, 0 );
		return 0;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		ber_bvfree( prefix );
		return 0;
	}

	if( !mr->smr_filter ) {
		ber_bvfree( prefix );
		return 0;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		ava->aa_value,
		&keys );

	ber_bvfree( prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_equality_candidates: (%s%s) MR filter failed (%d)\n",
			"", "", rc );
		return 0;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_equality_candidates: no keys (%s%s)\n",
			"", "", 0 );
		return 0;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		ID save[BDB_IDL_SIZE];
		ID tmp[BDB_IDL_SIZE];

		rc = bdb_key_read( be, db, keys[i], tmp );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_equality_candidates key read failed (%d)\n",
				rc, 0, 0 );
			break;
		}

		if( tmp == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_equality_candidates NULL\n",
				0, 0, 0 );
			break;
		}

		save = idl;
		idl = idl_intersection( be, idl, tmp );
		idl_free( save );
		idl_free( tmp );

		if( idl == NULL ) break;
	}

	ber_bvecfree( keys );

	Debug( LDAP_DEBUG_TRACE,
		"<= bdb_equality_candidates %ld\n",
		ids[0], BDB_IDL_FIRST(ids), BDB_IDL_LAST(ids) );
	return( idl );
}


static int
approx_candidates(
	Backend	*be,
	ID *range,
	AttributeAssertion *ava,
	ID *ids )
{
	ID_BLOCK *idl;
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_mask_t mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> approx_candidates\n", 0, 0, 0 );

	rc = bdb_index_param( be, ava->aa_desc, LDAP_FILTER_APPROX,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= approx_candidates: index_param failed (%d)\n",
			rc, 0, 0 );
		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_approx;
	if( !mr ) {
		/* no approx matching rule, try equality matching rule */
		mr = ava->aa_desc->ad_type->sat_equality;
	}

	if( !mr ) {
		ber_bvfree( prefix );
		return idl;
	}

	if( !mr->smr_filter ) {
		ber_bvfree( prefix );
		return idl;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_APPROX,
		mask,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		ava->aa_value,
		&keys );

	ber_bvfree( prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= approx_candidates: (%s%s) MR filter failed (%d)\n",
			dbname, LDBM_SUFFIX, rc );
		return idl;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= approx_candidates: no keys (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		return idl;
	}

	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= approx_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		return idl;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( be, db, keys[i], &tmp );

		if( rc != LDAP_SUCCESS ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= approx_candidates key read failed (%d)\n",
				rc, 0, 0 );
			break;
		}

		if( tmp == NULL ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= approx_candidates NULL\n",
				0, 0, 0 );
			break;
		}

		save = idl;
		idl = idl_intersection( be, idl, tmp );
		idl_free( save );

		if( idl == NULL ) break;
	}

	ber_bvecfree( keys );

	Debug( LDAP_DEBUG_TRACE, "<= approx_candidates %ld\n",
		ids[0], BDB_IDL_FIRST(ids), BDB_IDL_LAST(ids) );

	return( idl );
}

static int
substring_candidates(
	Backend	*be,
	ID *range,
	SubstringsAssertion	*sub,
	ID *ids )
{
	ID_BLOCK *idl;
	DBCache	*db;
	int i;
	int rc;
	slap_mask_t mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> substrings_candidates\n", 0, 0, 0 );

	idl = idl_allids( be );

	rc = bdb_index_param( be, sub->sa_desc, LDAP_FILTER_SUBSTRINGS,
		&db, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"<= substrings_candidates: index_param failed (%d)\n",
			rc, 0, 0 );
		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_ANY,
			"<= substrings_candidates: not indexed\n",
			0, 0, 0 );
		ber_bvfree( prefix );
		return idl;
	}

	mr = sub->sa_desc->ad_type->sat_substr;

	if( !mr ) {
		ber_bvfree( prefix );
		return idl;
	}

	if( !mr->smr_filter ) {
		ber_bvfree( prefix );
		return idl;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_SUBSTRINGS,
		mask,
		sub->sa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		sub,
		&keys );

	ber_bvfree( prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= substrings_candidates: (%s%s) MR filter failed (%d)\n",
			dbname, LDBM_SUFFIX, rc );
		return idl;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= substrings_candidates: (0x%04lx) no keys (%s%s)\n",
			mask, dbname, LDBM_SUFFIX );
		return idl;
	}

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_READER );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"<= substrings_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		return idl;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( be, db, keys[i], &tmp );

		if( rc != LDAP_SUCCESS ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= substrings_candidates key read failed (%d)\n",
				rc, 0, 0 );
			break;
		}

		if( tmp == NULL ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= substrings_candidates NULL\n",
				0, 0, 0 );
			break;
		}

		save = idl;
		idl = idl_intersection( be, idl, tmp );
		idl_free( save );

		if( idl == NULL ) break;
	}

	ber_bvecfree( keys );

	Debug( LDAP_DEBUG_TRACE, "<= substrings_candidates %ld\n",
		ids[0], BDB_IDL_FIRST(ids), BDB_IDL_LAST(ids) );

	return( idl );
}

#endif