/* value.c - routines for dealing with values */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
    BerVarray *vals,
    BerVarray addvals
)
{
	int	n, nn;
	BerVarray v2;

	for ( nn = 0; addvals != NULL && addvals[nn].bv_val != NULL; nn++ )
		;	/* NULL */

	if ( *vals == NULL ) {
		*vals = (BerVarray) SLAP_MALLOC( (nn + 1)
		    * sizeof(struct berval) );
		if( *vals == NULL ) {
#ifdef NEW_LOGGING
			 LDAP_LOG( OPERATION, ERR,
		      "value_add: SLAP_MALLOC failed.\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_TRACE,
		      "value_add: SLAP_MALLOC failed.\n", 0, 0, 0 );
#endif
			return LBER_ERROR_MEMORY;
		}
		n = 0;
	} else {
		for ( n = 0; (*vals)[n].bv_val != NULL; n++ ) {
			;	/* Empty */
		}
		*vals = (BerVarray) SLAP_REALLOC( (char *) *vals,
		    (n + nn + 1) * sizeof(struct berval) );
		if( *vals == NULL ) {
#ifdef NEW_LOGGING
			 LDAP_LOG( OPERATION, ERR,
		      "value_add: SLAP_MALLOC failed.\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_TRACE,
		      "value_add: SLAP_MALLOC failed.\n", 0, 0, 0 );
#endif
			return LBER_ERROR_MEMORY;
		}
	}

	v2 = *vals + n;
	for ( ; addvals->bv_val; v2++, addvals++ ) {
		ber_dupbv(v2, addvals);
		if (v2->bv_val == NULL) break;
	}
	v2->bv_val = NULL;
	v2->bv_len = 0;

	return LDAP_SUCCESS;
}

int
value_add_one( 
    BerVarray *vals,
    struct berval *addval
)
{
	int	n;
	BerVarray v2;

	if ( *vals == NULL ) {
		*vals = (BerVarray) SLAP_MALLOC( 2 * sizeof(struct berval) );
		if( *vals == NULL ) {
#ifdef NEW_LOGGING
			 LDAP_LOG( OPERATION, ERR,
		      "value_add_one: SLAP_MALLOC failed.\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_TRACE,
		      "value_add_one: SLAP_MALLOC failed.\n", 0, 0, 0 );
#endif
			return LBER_ERROR_MEMORY;
		}
		n = 0;
	} else {
		for ( n = 0; (*vals)[n].bv_val != NULL; n++ ) {
			;	/* Empty */
		}
		*vals = (BerVarray) SLAP_REALLOC( (char *) *vals,
		    (n + 2) * sizeof(struct berval) );
		if( *vals == NULL ) {
#ifdef NEW_LOGGING
			 LDAP_LOG( OPERATION, ERR,
		      "value_add_one: SLAP_MALLOC failed.\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_TRACE,
		      "value_add_one: SLAP_MALLOC failed.\n", 0, 0, 0 );
#endif
			return LBER_ERROR_MEMORY;
		}
	}

	v2 = *vals + n;
	ber_dupbv(v2, addval);

	v2++;
	v2->bv_val = NULL;
	v2->bv_len = 0;

	return LDAP_SUCCESS;
}

int
value_validate(
	MatchingRule *mr,
	struct berval *in,
	const char **text )
{
	int rc;

	if( mr == NULL ) {
		*text = "inappropriate matching request";
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	if( mr->smr_syntax == NULL ) {
		*text = "no assertion syntax";
		return LDAP_INVALID_SYNTAX;
	}

	if( ! mr->smr_syntax->ssyn_validate ) {
		*text = "no syntax validator";
		return LDAP_INVALID_SYNTAX;
	}

	rc = (mr->smr_syntax->ssyn_validate)( mr->smr_syntax, in );

	if( rc != LDAP_SUCCESS ) {
		*text = "value is invalid";
		return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

int
value_normalize(
	AttributeDescription *ad,
	unsigned usage,
	struct berval *in,
	struct berval *out,
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
	/* This is suspect, flexible certificate matching will hit this */
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
		ber_dupbv( out, in );
	}

	return LDAP_SUCCESS;
}

int
value_validate_normalize(
	AttributeDescription *ad,
	unsigned usage,
	struct berval *in,
	struct berval *out,
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

	if( mr->smr_syntax == NULL ) {
		*text = "no assertion syntax";
		return LDAP_INVALID_SYNTAX;
	}

	if( ! mr->smr_syntax->ssyn_validate ) {
		*text = "no syntax validator";
		return LDAP_INVALID_SYNTAX;
	}

	rc = (mr->smr_syntax->ssyn_validate)( mr->smr_syntax, in );

	if( rc != LDAP_SUCCESS ) {
		*text = "value is invalid";
		return LDAP_INVALID_SYNTAX;
	}

	/* we only support equality matching of binary attributes */
	/* This is suspect, flexible certificate matching will hit this */
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
		ber_dupbv( out, in );
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
	struct berval nv1 = { 0, NULL };
	struct berval nv2 = { 0, NULL };

	assert( mr != NULL );

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

	if ( SLAP_IS_MR_VALUE_SYNTAX_NONCONVERTED_MATCH( flags ) &&
		mr->smr_convert )
	{
		rc = (mr->smr_convert)( v2, &nv2 );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		/* let smr_match know we've converted the value */
		flags |= SLAP_MR_VALUE_SYNTAX_CONVERTED_MATCH;
	}

	rc = (mr->smr_match)( match, flags,
		ad->ad_type->sat_syntax,
		mr,
		nv1.bv_val != NULL ? &nv1 : v1,
		nv2.bv_val != NULL ? &nv2 : v2 );
	
	if (nv1.bv_val ) free( nv1.bv_val );
	if (nv2.bv_val ) free( nv2.bv_val );
	return rc;
}


int value_find_ex(
	AttributeDescription *ad,
	unsigned flags,
	BerVarray vals,
	struct berval *val )
{
	int	i;
	int rc;
	struct berval nval = { 0, NULL };
	MatchingRule *mr = ad->ad_type->sat_equality;

	if( mr == NULL || !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	/* Take care of this here or ssyn_normalize later will hurt */
	if ( SLAP_IS_MR_VALUE_SYNTAX_NONCONVERTED_MATCH( flags )
		&& mr->smr_convert )
	{
		rc = (mr->smr_convert)( val, &nval );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		/* let value_match know we've done the version */
		flags |= SLAP_MR_VALUE_SYNTAX_CONVERTED_MATCH;
	}

	if( !(flags & SLAP_MR_VALUE_NORMALIZED_MATCH) &&
		mr->smr_syntax->ssyn_normalize ) {
		struct berval nval_tmp = { 0, NULL };

		rc = mr->smr_syntax->ssyn_normalize(
			mr->smr_syntax,
			nval.bv_val == NULL ? val : &nval, &nval_tmp );

		free(nval.bv_val);
		nval = nval_tmp;
		if( rc != LDAP_SUCCESS ) {
			free(nval.bv_val);
			return LDAP_INAPPROPRIATE_MATCHING;
		}
	}

	for ( i = 0; vals[i].bv_val != NULL; i++ ) {
		int match;
		const char *text;

		rc = value_match( &match, ad, mr, flags,
			&vals[i], nval.bv_val == NULL ? val : &nval, &text );

		if( rc == LDAP_SUCCESS && match == 0 ) {
			free( nval.bv_val );
			return LDAP_SUCCESS;
		}
	}

	free( nval.bv_val );
	return LDAP_NO_SUCH_ATTRIBUTE;
}
