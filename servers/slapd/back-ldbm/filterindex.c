/* filterindex.c - generate the list of candidate entries from a filter */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"

static ID_BLOCK	*presence_candidates(
	Backend *be,
	AttributeDescription *desc );
static ID_BLOCK	*equality_candidates(
	Backend *be, AttributeAssertion *ava );
static ID_BLOCK	*approx_candidates(
	Backend *be, AttributeAssertion *ava );
static ID_BLOCK	*substring_candidates(
	Backend *be,
	Filter *f );
static ID_BLOCK	*list_candidates(
	Backend *be,
	Filter *flist,
	int ftype );

ID_BLOCK *
filter_candidates(
    Backend	*be,
    Filter	*f
)
{
	ID_BLOCK	*result, *tmp1, *tmp2;

	Debug( LDAP_DEBUG_TRACE, "=> filter_candidates\n", 0, 0, 0 );

	result = NULL;
	switch ( f->f_choice ) {
	case SLAPD_FILTER_DN_ONE:
		Debug( LDAP_DEBUG_FILTER, "\tDN ONE\n", 0, 0, 0 );
		result = dn2idl( be, f->f_dn, DN_ONE_PREFIX );
		break;

	case SLAPD_FILTER_DN_SUBTREE:
		Debug( LDAP_DEBUG_FILTER, "\tDN SUBTREE\n", 0, 0, 0 );
		result = dn2idl( be, f->f_dn, DN_SUBTREE_PREFIX );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );
		result = presence_candidates( be, f->f_desc );
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
		result = equality_candidates( be, f->f_ava );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
		result = approx_candidates( be, f->f_ava );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		result = substring_candidates( be, f );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		result = idl_allids( be );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		result = idl_allids( be );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );
		result = list_candidates( be, f->f_and, LDAP_FILTER_AND );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );
		result = list_candidates( be, f->f_or, LDAP_FILTER_OR );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );
		tmp1 = idl_allids( be );
		tmp2 = filter_candidates( be, f->f_not );
		result = idl_notin( be, tmp1, tmp2 );
		idl_free( tmp2 );
		idl_free( tmp1 );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= filter_candidates %ld\n",
	    result ? ID_BLOCK_NIDS(result) : 0, 0, 0 );
	return( result );
}

static ID_BLOCK *
presence_candidates(
    Backend	*be,
	AttributeDescription *desc
)
{
	ID_BLOCK	*idl;
	DBCache	*db;
	int rc;
	char *dbname;
	slap_index mask;
	struct berval *prefix;

	Debug( LDAP_DEBUG_TRACE, "=> presence_candidates\n", 0, 0, 0 );

	idl = idl_allids( be );

	rc = index_param( be, desc, LDAP_FILTER_PRESENT,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		ber_bvfree( prefix );
		return idl;
	}

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_READER );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= presense_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		ber_bvfree( prefix );
		return idl;
	}

	if( prefix != NULL ) {
		idl_free( idl );
		idl = NULL;

		rc = key_read( be, db, prefix, &idl );

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

	ldbm_cache_close( be, db );
	ber_bvfree( prefix );

	Debug( LDAP_DEBUG_TRACE, "<= presence_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
equality_candidates(
    Backend	*be,
	AttributeAssertion *ava
)
{
	ID_BLOCK	*idl;
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_index mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> equality_candidates\n", 0, 0, 0 );

	idl = idl_allids( be );

	rc = index_param( be, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		ber_bvfree( prefix );
		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		ber_bvfree( prefix );
		/* return LDAP_INAPPROPRIATE_MATCHING; */
		return idl;
	}

	if( !mr->smr_filter ) {
		ber_bvfree( prefix );
		return idl;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		ava->aa_value,
		&keys );

	ber_bvfree( prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_READER );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= equality_candidates db open failed (%s%s)\n",
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
		idl = idl_intersection( be, idl, tmp );
		idl_free( save );
		idl_free( tmp );

		if( idl == NULL ) break;
	}

	ber_bvecfree( keys );

	ldbm_cache_close( be, db );


	Debug( LDAP_DEBUG_TRACE, "<= equality_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
approx_candidates(
    Backend	*be,
	AttributeAssertion *ava
)
{
	ID_BLOCK *idl;
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_index mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;

	Debug( LDAP_DEBUG_TRACE, "=> approx_candidates\n", 0, 0, 0 );

	idl = idl_allids( be );

	rc = index_param( be, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		ber_bvfree( prefix );
		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_approx;
	if( mr == NULL ) {
		/* no approx matching rule, try equality matching rule */
		mr = ava->aa_desc->ad_type->sat_equality;
	}

	if( !mr ) {
		ber_bvfree( prefix );
		/* return LDAP_INAPPROPRIATE_MATCHING; */
		return idl;
	}

	if( !mr->smr_filter ) {
		ber_bvfree( prefix );
		return idl;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		ava->aa_value,
		&keys );

	ber_bvfree( prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_READER );
	
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

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= approx_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
list_candidates(
    Backend	*be,
    Filter	*flist,
    int		ftype
)
{
	ID_BLOCK	*idl, *tmp, *tmp2;
	Filter	*f;

	Debug( LDAP_DEBUG_TRACE, "=> list_candidates 0x%x\n", ftype, 0, 0 );

	idl = NULL;
	for ( f = flist; f != NULL; f = f->f_next ) {
		if ( (tmp = filter_candidates( be, f )) == NULL &&
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
			idl = idl_intersection( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		} else {
			idl = idl_union( be, idl, tmp );
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
    Backend	*be,
    Filter	*f
)
{
	ID_BLOCK *idl;

	Debug( LDAP_DEBUG_TRACE, "=> substring_candidates\n", 0, 0, 0 );

	idl = idl_allids( be );
	Debug( LDAP_DEBUG_TRACE, "<= substring_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

