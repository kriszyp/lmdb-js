/* value.c - routines for dealing with values */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
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
    BerVarray addvals )
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
    struct berval *addval )
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

int asserted_value_validate_normalize( 
	AttributeDescription *ad,
	MatchingRule *mr,
	unsigned usage,
	struct berval *in,
	struct berval *out,
	const char ** text,
	void *ctx )
{
	int rc;
	struct berval pval;
	pval.bv_val = NULL;

	/* we expect the value to be in the assertion syntax */
	assert( !SLAP_MR_IS_VALUE_OF_ATTRIBUTE_SYNTAX(usage) );

	if( mr == NULL ) {
		*text = "inappropriate matching request";
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	if( !mr->smr_match ) {
		*text = "requested matching rule not supported";
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	if( mr->smr_syntax->ssyn_pretty ) {
		rc = (mr->smr_syntax->ssyn_pretty)( mr->smr_syntax, in, &pval, ctx );
		in = &pval;

	} else {
		rc = (mr->smr_syntax->ssyn_validate)( mr->smr_syntax, in );
	}

	if( rc != LDAP_SUCCESS ) {
		*text = "value does not conform to assertion syntax";
		return LDAP_INVALID_SYNTAX;
	}

	if( mr->smr_normalize ) {
		rc = (mr->smr_normalize)(
			usage|SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
			ad ? ad->ad_type->sat_syntax : NULL,
			mr, in, out, ctx );

		if( pval.bv_val ) ber_memfree_x( pval.bv_val, ctx );

		if( rc != LDAP_SUCCESS ) {
			*text = "unable to normalize value for matching";
			return LDAP_INVALID_SYNTAX;
		}

	} else if ( pval.bv_val != NULL ) {
		*out = pval;

	} else {
		ber_dupbv_x( out, in, ctx );
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

	assert( mr != NULL );

	if( !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	rc = (mr->smr_match)( match, flags,
		ad->ad_type->sat_syntax, mr, v1, v2 );
	
	return rc;
}

int value_find_ex(
	AttributeDescription *ad,
	unsigned flags,
	BerVarray vals,
	struct berval *val,
	void *ctx )
{
	int	i;
	int rc;
	struct berval nval = BER_BVNULL;
	MatchingRule *mr = ad->ad_type->sat_equality;

	if( mr == NULL || !mr->smr_match ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	assert(SLAP_IS_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH( flags ));

	if( !SLAP_IS_MR_ASSERTED_VALUE_NORMALIZED_MATCH( flags ) &&
		mr->smr_normalize )
	{
		rc = (mr->smr_normalize)(
			flags & (SLAP_MR_TYPE_MASK|SLAP_MR_SUBTYPE_MASK|SLAP_MR_VALUE_OF_SYNTAX),
			ad ? ad->ad_type->sat_syntax : NULL,
			mr, val, &nval, ctx );

		if( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	for ( i = 0; vals[i].bv_val != NULL; i++ ) {
		int match;
		const char *text;

		rc = value_match( &match, ad, mr, flags,
			&vals[i], nval.bv_val == NULL ? val : &nval, &text );

		if( rc == LDAP_SUCCESS && match == 0 ) {
			slap_sl_free( nval.bv_val, ctx );
			return rc;
		}
	}

	slap_sl_free( nval.bv_val, ctx );
	return LDAP_NO_SUCH_ATTRIBUTE;
}
