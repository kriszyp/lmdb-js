/* filterindex.c - generate the list of candidate entries from a filter */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"

static ID_BLOCK	*presence_candidates(
	Operation *op,
	AttributeDescription *desc );
static ID_BLOCK	*equality_candidates(
	Operation *op, AttributeAssertion *ava );
static ID_BLOCK	*approx_candidates(
	Operation *op, AttributeAssertion *ava );
static ID_BLOCK	*substring_candidates(
	Operation *op,
	SubstringsAssertion *sub );
static ID_BLOCK	*list_candidates(
	Operation *op,
	Filter *flist,
	int ftype );

ID_BLOCK *
filter_candidates(
    Operation	*op,
    Filter	*f
)
{
	char *sub = "SUBTREE";
	ID_BLOCK	*result;

	Debug( LDAP_DEBUG_TRACE, "=> filter_candidates\n", 0, 0, 0 );


	result = NULL;
	switch ( f->f_choice ) {
	case SLAPD_FILTER_COMPUTED:
		switch( f->f_result ) {
		case SLAPD_COMPARE_UNDEFINED:
		/* This technically is not the same as FALSE, but it
		 * certainly will produce no matches.
		 */
		/* FALLTHRU */
		case LDAP_COMPARE_FALSE:
			result = NULL;
			break;
		case LDAP_COMPARE_TRUE:
			result = idl_allids( op->o_bd );
			break;
		}
		break;

	case SLAPD_FILTER_DN_ONE:
		Debug( LDAP_DEBUG_FILTER, "\tDN ONE\n", 0, 0, 0 );

		/* an error is treated as an empty list */
		if ( dn2idl( op->o_bd, f->f_dn, DN_ONE_PREFIX, &result ) != 0
				&& result != NULL ) {
			idl_free( result );
			result = NULL;
		}
		break;

#ifdef SLAPD_FILTER_DN_CHILDREN
	case SLAPD_FILTER_DN_CHILDREN:
		sub = "CHILDREN";
#endif
	case SLAPD_FILTER_DN_SUBTREE:
		Debug( LDAP_DEBUG_FILTER,
			"\tDN %s\n", sub, 0, 0 );

		/* an error is treated as an empty list */
		if ( dn2idl( op->o_bd, f->f_dn, DN_SUBTREE_PREFIX, &result ) != 0
				&& result != NULL ) {
			idl_free( result );
			result = NULL;
		}
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );

		result = presence_candidates( op, f->f_desc );
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );

		result = equality_candidates( op, f->f_ava );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );

		result = approx_candidates( op, f->f_ava );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );

		result = substring_candidates( op, f->f_sub );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );

		result = presence_candidates( op, f->f_ava->aa_desc );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );

		result = presence_candidates( op, f->f_ava->aa_desc );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );

		result = list_candidates( op, f->f_and, LDAP_FILTER_AND );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );

		result = list_candidates( op, f->f_or, LDAP_FILTER_OR );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );

		/*
		 * As candidates lists may contain entries which do
		 * not match the assertion, negation of the inner candidate
		 * list could result in matching entries be excluded from
		 * the returned candidate list.
		 */
		result = idl_allids( op->o_bd );
		break;
	default:
		Debug( LDAP_DEBUG_FILTER, "\tUNKNOWN\n", 0, 0, 0 );
		/* unknown filters must not return NULL, to allow
		 * extended filter processing to be done later.
		 */
		result = idl_allids( op->o_bd );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= filter_candidates %ld\n",
	    result ? ID_BLOCK_NIDS(result) : 0, 0, 0 );

	return( result );
}

static ID_BLOCK *
presence_candidates(
    Operation *op,
	AttributeDescription *desc
)
{
	ID_BLOCK	*idl;
	DBCache	*db;
	int rc;
	char *dbname;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};

	Debug( LDAP_DEBUG_TRACE, "=> presence_candidates\n", 0, 0, 0 );

	idl = idl_allids( op->o_bd );

	if( desc == slap_schema.si_ad_objectClass ) {
		return idl;
	}

	rc = index_param( op->o_bd, desc, LDAP_FILTER_PRESENT,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= presence_candidates: index_param returned=%d\n",
			rc, 0, 0 );

		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_TRACE,
		    "<= presense_candidates: not indexed\n",
			0, 0, 0 );

		return idl;
	}

	db = ldbm_cache_open( op->o_bd, dbname, LDBM_SUFFIX, LDBM_WRCREAT );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= presense_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );

		return idl;
	}

	if( prefix.bv_val != NULL ) {
		idl_free( idl );
		idl = NULL;

		rc = key_read( op->o_bd, db, &prefix, &idl );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= presense_candidates key read failed (%d)\n",
			    rc, 0, 0 );


		} else if( idl == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= presense_candidates NULL\n",
			    0, 0, 0 );

		}
	}

	ldbm_cache_close( op->o_bd, db );

	Debug( LDAP_DEBUG_TRACE, "<= presence_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );

	return( idl );
}

static ID_BLOCK *
equality_candidates(
    Operation *op,
	AttributeAssertion *ava
)
{
	ID_BLOCK	*idl;
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> equality_candidates\n", 0, 0, 0 );


	idl = idl_allids( op->o_bd );

	rc = index_param( op->o_bd, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= equality_candidates: index_param returned=%d\n",
			rc, 0, 0 );

		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_TRACE,
		    "<= equality_candidates: not indexed\n",
			0, 0, 0 );

		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		return idl;
	}

	if( !mr->smr_filter ) {
		return idl;
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
		    "<= equality_candidates: (%s%s) MR filter failed (%d)\n",
			dbname, LDBM_SUFFIX, rc );

		return idl;
	}

	if( keys == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= equality_candidates: no keys (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );

		return idl;
	}

	db = ldbm_cache_open( op->o_bd, dbname, LDBM_SUFFIX, LDBM_WRCREAT );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= equality_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );

		return idl;
	}

	for ( i= 0; keys[i].bv_val != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( op->o_bd, db, &keys[i], &tmp );

		if( rc != LDAP_SUCCESS ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE,
				"<= equality_candidates key read failed (%d)\n",
			    rc, 0, 0 );

			break;
		}

		if( tmp == NULL ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE,
				"<= equality_candidates NULL\n",
			    0, 0, 0 );

			break;
		}

		save = idl;
		idl = idl_intersection( op->o_bd, idl, tmp );
		idl_free( save );
		idl_free( tmp );

		if( idl == NULL ) break;
	}

	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	ldbm_cache_close( op->o_bd, db );


	Debug( LDAP_DEBUG_TRACE, "<= equality_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );

	return( idl );
}

static ID_BLOCK *
approx_candidates(
    Operation *op,
	AttributeAssertion *ava
)
{
	ID_BLOCK *idl;
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> approx_candidates\n", 0, 0, 0 );


	idl = idl_allids( op->o_bd );

	rc = index_param( op->o_bd, ava->aa_desc, LDAP_FILTER_APPROX,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= approx_candidates: index_param returned=%d\n",
			rc, 0, 0 );

		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_ANY,
		    "<= approx_candidates: not indexed\n",
			0, 0, 0 );

		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_approx;
	if( !mr ) {
		/* no approx matching rule, try equality matching rule */
		mr = ava->aa_desc->ad_type->sat_equality;
	}

	if( !mr ) {
		return idl;
	}

	if( !mr->smr_filter ) {
		return idl;
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

	db = ldbm_cache_open( op->o_bd, dbname, LDBM_SUFFIX, LDBM_WRCREAT );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= approx_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );

		return idl;
	}

	for ( i= 0; keys[i].bv_val != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( op->o_bd, db, &keys[i], &tmp );

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
		idl = idl_intersection( op->o_bd, idl, tmp );
		idl_free( save );
		idl_free( tmp );

		if( idl == NULL ) break;
	}

	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	ldbm_cache_close( op->o_bd, db );

	Debug( LDAP_DEBUG_TRACE, "<= approx_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );

	return( idl );
}

static ID_BLOCK *
list_candidates(
    Operation *op,
    Filter	*flist,
    int		ftype
)
{
	ID_BLOCK	*idl, *tmp, *tmp2;
	Filter	*f;

	Debug( LDAP_DEBUG_TRACE, "=> list_candidates 0x%x\n", ftype, 0, 0 );


	idl = NULL;
	for ( f = flist; f != NULL; f = f->f_next ) {
		if ( (tmp = filter_candidates( op, f )) == NULL &&
		    ftype == LDAP_FILTER_AND ) {
			Debug( LDAP_DEBUG_TRACE,
			       "<= list_candidates NULL\n", 0, 0, 0 );

			idl_free( idl );
			return( NULL );
		}

		tmp2 = idl;
		if ( idl == NULL ) {
			idl = tmp;
		} else if ( ftype == LDAP_FILTER_AND ) {
			idl = idl_intersection( op->o_bd, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		} else {
			idl = idl_union( op->o_bd, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= list_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );

	return( idl );
}

static ID_BLOCK *
substring_candidates(
    Operation *op,
    SubstringsAssertion	*sub
)
{
	ID_BLOCK *idl;
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_mask_t mask;
	struct berval prefix = {0, NULL};
	struct berval *keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> substrings_candidates\n", 0, 0, 0 );


	idl = idl_allids( op->o_bd );

	rc = index_param( op->o_bd, sub->sa_desc, LDAP_FILTER_SUBSTRINGS,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= substrings_candidates: index_param returned=%d\n",
			rc, 0, 0 );

		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		Debug( LDAP_DEBUG_ANY,
		    "<= substrings_candidates: not indexed\n",
			0, 0, 0 );

		return idl;
	}

	mr = sub->sa_desc->ad_type->sat_substr;

	if( !mr ) {
		return idl;
	}

	if( !mr->smr_filter ) {
		return idl;
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

	db = ldbm_cache_open( op->o_bd, dbname, LDBM_SUFFIX, LDBM_WRCREAT );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= substrings_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );

		return idl;
	}

	for ( i= 0; keys[i].bv_val != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( op->o_bd, db, &keys[i], &tmp );

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
		idl = idl_intersection( op->o_bd, idl, tmp );
		idl_free( save );
		idl_free( tmp );

		if( idl == NULL ) break;
	}

	ber_bvarray_free_x( keys, op->o_tmpmemctx );

	ldbm_cache_close( op->o_bd, db );

	Debug( LDAP_DEBUG_TRACE, "<= substrings_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );

	return( idl );
}
