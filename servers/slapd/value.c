/* value.c - routines for dealing with values */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <sys/stat.h>

#include "slap.h"

int
value_add( 
    struct berval	***vals,
    struct berval	**addvals
)
{
	int	n, nn, i, j;

	for ( nn = 0; addvals != NULL && addvals[nn] != NULL; nn++ )
		;	/* NULL */

	if ( *vals == NULL ) {
		*vals = (struct berval **) ch_malloc( (nn + 1)
		    * sizeof(struct berval *) );
		n = 0;
	} else {
		for ( n = 0; (*vals)[n] != NULL; n++ )
			;	/* NULL */
		*vals = (struct berval **) ch_realloc( (char *) *vals,
		    (n + nn + 1) * sizeof(struct berval *) );
	}

	for ( i = 0, j = 0; i < nn; i++ ) {
		if ( addvals[i]->bv_len > 0 ) {
			(*vals)[n + j] = ber_bvdup( addvals[i] );
			if( (*vals)[n + j++] == NULL ) break;
		}
	}
	(*vals)[n + j] = NULL;

	return LDAP_SUCCESS;
}


int
value_normalize(
	AttributeDescription *ad,
	unsigned usage,
	struct berval *in,
	struct berval **out,
	const char **text )
{
	int rc;
	MatchingRule *mr;

	switch( usage & SLAP_MR_TYPE_MASK ) {
	case SLAP_MR_NONE:
	case SLAP_MR_EQUALITY:
		mr = ad->ad_type->sat_equality;
		break;
	case SLAP_MR_ORDERING:
		mr = ad->ad_type->sat_ordering;
		break;
	case SLAP_MR_SUBSTR:
		mr = ad->ad_type->sat_substr;
		break;
	case SLAP_MR_EXT:
	default:
		assert( 0 );
		*text = "internal error";
		return LDAP_OTHER;
	}

	if( mr == NULL ) {
		*text = "inappropriate matching request";
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	/* we only support equality matching of binary attributes */
	if( slap_ad_is_binary( ad ) && usage != SLAP_MR_EQUALITY ) {
		*text = "inappropriate binary matching";
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	if( mr->smr_normalize ) {
		rc = (mr->smr_normalize)( usage,
			ad->ad_type->sat_syntax,
			mr, in, out );

		if( rc != LDAP_SUCCESS ) {
			*text = "unable to normalize value";
			return LDAP_INVALID_SYNTAX;
		}

	} else if ( mr->smr_syntax->ssyn_normalize ) {
		rc = (mr->smr_syntax->ssyn_normalize)(
			ad->ad_type->sat_syntax,
			in, out );

		if( rc != LDAP_SUCCESS ) {
			*text = "unable to normalize value";
			return LDAP_INVALID_SYNTAX;
		}

	} else {
		*out = ber_bvdup( in );
	}

	return LDAP_SUCCESS;
}


int
value_match(
	int *match,
	AttributeDescription *ad,
	MatchingRule *mr,
	unsigned flags,
	struct berval *v1, /* stored value */
	void *v2, /* assertion */
	const char ** text )
{
	int rc;
	struct berval *nv1 = NULL;

	if( !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	if( ad->ad_type->sat_syntax->ssyn_normalize ) {
		rc = ad->ad_type->sat_syntax->ssyn_normalize(
			ad->ad_type->sat_syntax, v1, &nv1 );

		if( rc != LDAP_SUCCESS ) {
			return LDAP_INAPPROPRIATE_MATCHING;
		}
	}

	rc = (mr->smr_match)( match, flags,
		ad->ad_type->sat_syntax,
		mr,
		nv1 != NULL ? nv1 : v1,
		v2 );
	
	ber_bvfree( nv1 );
	return rc;
}


int value_find(
	AttributeDescription *ad,
	struct berval **vals,
	struct berval *val )
{
	int	i;
	int rc;
	struct berval *nval = NULL;
	MatchingRule *mr = ad->ad_type->sat_equality;

	if( mr == NULL || !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	if( mr->smr_syntax->ssyn_normalize ) {
		rc = mr->smr_syntax->ssyn_normalize(
			mr->smr_syntax, val, &nval );

		if( rc != LDAP_SUCCESS ) {
			return LDAP_INAPPROPRIATE_MATCHING;
		}
	}

	for ( i = 0; vals[i] != NULL; i++ ) {
		int match;
		const char *text;

		rc = value_match( &match, ad, mr, 0,
			vals[i], nval == NULL ? val : nval, &text );

		if( rc == LDAP_SUCCESS && match == 0 ) {
			return LDAP_SUCCESS;
		}
	}

	return LDAP_NO_SUCH_ATTRIBUTE;
}
