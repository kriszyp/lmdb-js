/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* mra.c - routines for dealing with extensible matching rule assertions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"


void
mra_free(
    MatchingRuleAssertion *mra,
    int	freeit
)
{
	ad_free( mra->ma_desc, 1 );
	ch_free( (char *) mra->ma_rule );
	ber_bvfree( mra->ma_value );
	if ( freeit ) {
		ch_free( (char *) mra );
	}
}

int
get_mra(
    BerElement	*ber,
    MatchingRuleAssertion	**mra,
	const char **text
)
{
	int rc, tag;
	struct berval type, value, *nvalue;
	MatchingRuleAssertion *ma;

	ma = ch_malloc( sizeof( MatchingRuleAssertion ) );
	ma->ma_rule = NULL;
	ma->ma_desc = NULL;
	ma->ma_dnattrs = 0;
	ma->ma_value = NULL;

	rc = ber_scanf( ber, "{t", &tag );

	if( rc == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
		*text = "Error parsing matching rule assertion";
		return SLAPD_DISCONNECT;
	}

	if ( tag == LDAP_FILTER_EXT_OID ) {
		rc = ber_scanf( ber, "a", &ma->ma_rule );
		if ( rc == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf for mr\n", 0, 0, 0 );
			*text = "Error parsing matching rule in matching rule assertion";
			return SLAPD_DISCONNECT;
		}

		rc = ber_scanf( ber, "t", &tag );

		if( rc == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
			*text = "Error parsing matching rule assertion";
			return SLAPD_DISCONNECT;
		}
	}

	if ( tag == LDAP_FILTER_EXT_TYPE ) {
		rc = ber_scanf( ber, "o", &type );
		if ( rc == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf for ad\n", 0, 0, 0 );
			*text = "Error parsing attribute description in matching rule assertion";
			return SLAPD_DISCONNECT;
		}

		rc = slap_bv2ad( &type, &ma->ma_desc, text );
		ch_free( type.bv_val );

		if( rc != LDAP_SUCCESS ) {
			ch_free( value.bv_val );
			mra_free( ma, 1 );
			return rc;
		}

		rc = ber_scanf( ber, "t", &tag );

		if( rc == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
			*text = "Error parsing matching rule assertion";
			return SLAPD_DISCONNECT;
		}
	}

	rc = ber_scanf( ber, "o", &value );

	if( rc == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
		*text = "Error decoding value in matching rule assertion";
		return SLAPD_DISCONNECT;
	}

	/*
	 * OK, if no matching rule, normalize for equality, otherwise
	 * normalize for the matching rule.
	 */
	rc = value_normalize( ma->ma_desc, SLAP_MR_EQUALITY, &value, &nvalue, text );
	ch_free( value.bv_val );

	if( rc != LDAP_SUCCESS ) {
		ad_free( ma->ma_desc, 1 );
		ch_free( ma );
		return rc;
	}

	ma->ma_value = nvalue;
	*mra = ma;

	return LDAP_SUCCESS;
}

