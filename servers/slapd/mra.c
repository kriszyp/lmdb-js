/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
	ch_free( mra->ma_rule_text.bv_val );
	ch_free( mra->ma_value.bv_val );
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
	ber_len_t length;
	struct berval type, value;
	MatchingRuleAssertion *ma;

	ma = ch_malloc( sizeof( MatchingRuleAssertion ) );
	ma->ma_rule = NULL;
	ma->ma_rule_text.bv_val = NULL;
	ma->ma_rule_text.bv_len = 0;
	ma->ma_desc = NULL;
	ma->ma_dnattrs = 0;
	ma->ma_value.bv_val = NULL;

	rc = ber_scanf( ber, "{t", &tag );

	if( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
			   "get_mra: ber_scanf (\"{t\") failure\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
#endif

		*text = "Error parsing matching rule assertion";
		mra_free( ma, 1 );
		return SLAPD_DISCONNECT;
	}

	if ( tag == LDAP_FILTER_EXT_OID ) {
		rc = ber_scanf( ber, "o", &ma->ma_rule_text );
		if ( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
				   "get_mra: ber_scanf(\"o\") failure.\n" ));
#else
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf for mr\n", 0, 0, 0 );
#endif

			*text = "Error parsing matching rule in matching rule assertion";
			mra_free( ma, 1 );
			return SLAPD_DISCONNECT;
		}
		ma->ma_rule = mr_bvfind( &ma->ma_rule_text );

		rc = ber_scanf( ber, "t", &tag );

		if( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
				   "get_mra: ber_scanf (\"t\") failure\n" ));
#else
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
#endif

			*text = "Error parsing matching rule assertion";
			mra_free( ma, 1 );
			return SLAPD_DISCONNECT;
		}
	}

	if ( tag == LDAP_FILTER_EXT_TYPE ) {
		rc = ber_scanf( ber, "m", &type );
		if ( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
				   "get_mra: ber_scanf (\"o\") failure.\n" ));
#else
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf for ad\n", 0, 0, 0 );
#endif

			*text = "Error parsing attribute description in matching rule assertion";
			return SLAPD_DISCONNECT;
		}

		rc = slap_bv2ad( &type, &ma->ma_desc, text );

		if( rc != LDAP_SUCCESS ) {
			mra_free( ma, 1 );
			return rc;
		}

		rc = ber_scanf( ber, "t", &tag );

		if( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
				   "get_mra: ber_scanf (\"t\") failure.\n" ));
#else
			Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
#endif

			*text = "Error parsing matching rule assertion";
			mra_free( ma, 1 );
			return SLAPD_DISCONNECT;
		}
	}

	if ( tag != LDAP_FILTER_EXT_VALUE ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
			   "get_mra: ber_scanf missing value\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf missing value\n", 0, 0, 0 );
#endif

		*text = "Missing value in matching rule assertion";
		mra_free( ma, 1 );
		return SLAPD_DISCONNECT;
	}

	rc = ber_scanf( ber, "m", &value );

	if( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
			   "get_mra: ber_scanf (\"o\") failure.\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
#endif

		*text = "Error decoding value in matching rule assertion";
		mra_free( ma, 1 );
		return SLAPD_DISCONNECT;
	}

	/*
	 * OK, if no matching rule, normalize for equality, otherwise
	 * normalize for the matching rule.
	 */
	rc = value_normalize( ma->ma_desc, SLAP_MR_EQUALITY, &value, &ma->ma_value, text );

	if( rc != LDAP_SUCCESS ) {
		mra_free( ma, 1 );
		return rc;
	}

	tag = ber_peek_tag( ber, &length );

	if ( tag == LDAP_FILTER_EXT_DNATTRS ) {
		rc = ber_scanf( ber, "b}", &ma->ma_dnattrs );
	} else {
		rc = ber_scanf( ber, "}" );
		ma->ma_dnattrs = 0;
	}

	if( rc == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
			   "get_mra: ber_scanf failure\n"));
#else
		Debug( LDAP_DEBUG_ANY, "  get_mra ber_scanf\n", 0, 0, 0 );
#endif

		*text = "Error decoding dnattrs matching rule assertion";
		mra_free( ma, 1 );
		return SLAPD_DISCONNECT;
	}

	*mra = ma;

	return LDAP_SUCCESS;
}

