/* schema_init.c - init builtin schema */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"

static int
octetStringValidate(
	Syntax *syntax,
	struct berval *in )
{
	/* any value allowed */
	return 0;
}

static int
UTF8StringValidate(
	Syntax *syntax,
	struct berval *in )
{
	ber_len_t count;
	int len;
	unsigned char *u = in->bv_val;

	for( count = in->bv_len; count > 0; count+=len, u+=len ) {
		/* get the length indicated by the first byte */
		len = LDAP_UTF8_CHARLEN( u );

		/* should not be zero */
		if( len == 0 ) return -1;

		/* make sure len corresponds with the offset
			to the next character */
		if( LDAP_UTF8_OFFSET( u ) != len ) return -1;
	}

	if( count != 0 ) return -1;

	return 0;
}

static int
UTF8StringNormalize(
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *newval;
	char *p, *q, *s;

	newval = ch_malloc( sizeof( struct berval ) );

	p = val->bv_val;

	/* Ignore initial whitespace */
	while ( ldap_utf8_isspace( p ) ) {
		LDAP_UTF8_INCR( p );
	}

	if( *p ) {
		ch_free( newval );
		return 1;
	}

	newval->bv_val = ch_strdup( p );
	p = q = newval->bv_val;
	s = NULL;

	while ( *p ) {
		int len;

		if ( ldap_utf8_isspace( p ) ) {
			len = LDAP_UTF8_COPY(q,p);
			s=q;
			p+=len;
			q+=len;

			/* Ignore the extra whitespace */
			while ( ldap_utf8_isspace( p ) ) {
				LDAP_UTF8_INCR( p );
			}
		} else {
			len = LDAP_UTF8_COPY(q,p);
			s=NULL;
			p+=len;
			q+=len;
		}
	}

	assert( *newval->bv_val );
	assert( newval->bv_val < p );
	assert( p <= q );

	/* cannot start with a space */
	assert( !ldap_utf8_isspace(newval->bv_val) );

	/*
	 * If the string ended in space, backup the pointer one
	 * position.  One is enough because the above loop collapsed
	 * all whitespace to a single space.
	 */

	if ( s != NULL ) {
		q = s;
	}

	/* cannot end with a space */
	assert( !ldap_utf8_isspace( LDAP_UTF8_PREV(q) ) );

	/* null terminate */
	*q = '\0';

	newval->bv_len = q - newval->bv_val;
	normalized = &newval;

	return 0;
}

static int
IA5StringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	for(i=0; i < val->bv_len; i++) {
		if( !isascii(val->bv_val[i]) ) return -1;
	}

	return 0;
}

static int
IA5StringConvert(
	Syntax *syntax,
	struct berval *in,
	struct berval **out )
{
	ber_len_t i;
	struct berval *bv = ch_malloc( sizeof(struct berval) );
	bv->bv_len = (in->bv_len+1) * sizeof( ldap_unicode_t );
	bv->bv_val = ch_malloc( bv->bv_len );

	for(i=0; i < in->bv_len; i++ ) {
		/*
		 * IA5StringValidate should have been called to ensure
		 * input is limited to IA5.
		 */
		bv->bv_val[i] = in->bv_val[i];
	}

	*out = bv;
	return 0;
}

static int
IA5StringNormalize(
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *newval;
	char *p, *q;

	newval = ch_malloc( sizeof( struct berval ) );

	p = val->bv_val;

	/* Ignore initial whitespace */
	while ( isspace( *p++ ) ) {
		/* EMPTY */  ;
	}

	if( *p ) {
		ch_free( newval );
		return 1;
	}

	newval->bv_val = ch_strdup( p );
	p = q = newval->bv_val;

	while ( *p ) {
		if ( isspace( *p ) ) {
			*q++ = *p++;

			/* Ignore the extra whitespace */
			while ( isspace( *p++ ) ) {
				/* EMPTY */  ;
			}
		} else {
			*q++ = *p++;
		}
	}

	assert( *newval->bv_val );
	assert( newval->bv_val < p );
	assert( p <= q );

	/* cannot start with a space */
	assert( !isspace(*newval->bv_val) );

	/*
	 * If the string ended in space, backup the pointer one
	 * position.  One is enough because the above loop collapsed
	 * all whitespace to a single space.
	 */

	if ( isspace( q[-1] ) ) {
		--q;
	}

	/* cannot end with a space */
	assert( !isspace( q[-1] ) );

	/* null terminate */
	*q = '\0';

	newval->bv_len = q - newval->bv_val;
	normalized = &newval;

	return 0;
}

static int
caseExactIA5Match(
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	struct berval *assertedValue )
{
	return strcmp( value->bv_val, assertedValue->bv_val );
}

static int
caseIgnoreIA5Match(
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	struct berval *assertedValue )
{
	return strcasecmp( value->bv_val, assertedValue->bv_val );
}

struct syntax_defs_rec {
	char *sd_desc;
	slap_syntax_validate_func *sd_validate;
	slap_syntax_transform_func *sd_ber2str;
	slap_syntax_transform_func *sd_str2ber;
};

struct syntax_defs_rec syntax_defs[] = {
	{"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'AttributeTypeDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'BitString' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.9 DESC 'CertificateList' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.10 DESC 'CertificatePair' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'DeliveryMethod' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'DirectoryString' )",
		UTF8StringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.16 DESC 'DITContentRuleDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.17 DESC 'DITStructureRuleDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.21 DESC 'EnhancedGuide' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'FacsimileTelephoneNumber' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'GeneralizedTime' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5String' )",
		IA5StringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'MatchingRuleDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.31 DESC 'MatchingRuleUseDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.32 DESC 'MailPreference' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'NameAndOptionalUID' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'NameFormDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'NumericString' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'ObjectClassDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'OtherMailbox' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'OctetString' )",
		octetStringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'PostalAddress' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.42 DESC 'ProtocolInformation' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'PresentationAddress' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'PrintableString' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'SupportedAlgorithm' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'TelephoneNumber' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'TeletexTerminalIdentifier' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'TelexNumber' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTCTime' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAPSyntaxDescription' )",
		NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'SubstringAssertion' )",
		NULL, NULL, NULL},

	{NULL, NULL, NULL}
};

struct mrule_defs_rec {
	char *mrd_desc;
	slap_mr_convert_func *mrd_convert;
	slap_mr_normalize_func *mrd_normalize;
	slap_mr_match_func *mrd_match;
};

/*
 * Other matching rules in X.520 that we do not use:
 *
 * 2.5.13.9		numericStringOrderingMatch
 * 2.5.13.12	caseIgnoreListSubstringsMatch
 * 2.5.13.13	booleanMatch
 * 2.5.13.15	integerOrderingMatch
 * 2.5.13.18	octetStringOrderingMatch
 * 2.5.13.19	octetStringSubstringsMatch
 * 2.5.13.25	uTCTimeMatch
 * 2.5.13.26	uTCTimeOrderingMatch
 * 2.5.13.31	directoryStringFirstComponentMatch
 * 2.5.13.32	wordMatch
 * 2.5.13.33	keywordMatch
 * 2.5.13.34	certificateExactMatch
 * 2.5.13.35	certificateMatch
 * 2.5.13.36	certificatePairExactMatch
 * 2.5.13.37	certificatePairMatch
 * 2.5.13.38	certificateListExactMatch
 * 2.5.13.39	certificateListMatch
 * 2.5.13.40	algorithmIdentifierMatch
 * 2.5.13.41	storedPrefixMatch
 * 2.5.13.42	attributeCertificateMatch
 * 2.5.13.43	readerAndKeyIDMatch
 * 2.5.13.44	attributeIntegrityMatch
 */

/* recycled matching functions */
#define caseIgnoreMatch caseIgnoreIA5Match
#define caseExactMatch caseExactIA5Match

/* unimplemented matching functions */
#define objectIdentifierMatch NULL
#define distinguishedNameMatch NULL
#define caseIgnoreOrderingMatch NULL
#define caseIgnoreSubstringsMatch NULL
#define caseExactOrderingMatch NULL
#define caseExactSubstringsMatch NULL
#define numericStringMatch NULL
#define numericStringSubstringsMatch NULL
#define caseIgnoreListMatch NULL
#define integerMatch NULL
#define bitStringMatch NULL
#define octetStringMatch NULL
#define telephoneNumberMatch NULL
#define telephoneNumberSubstringsMatch NULL
#define presentationAddressMatch NULL
#define uniqueMemberMatch NULL
#define protocolInformationMatch NULL
#define generalizedTimeMatch NULL
#define generalizedTimeOrderingMatch NULL
#define integerFirstComponentMatch NULL
#define objectIdentifierFirstComponentMatch NULL
#define caseIgnoreIA5SubstringsMatch NULL

struct mrule_defs_rec mrule_defs[] = {
	{"( 2.5.13.0 NAME 'objectIdentifierMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		NULL, NULL, objectIdentifierMatch},

	{"( 2.5.13.1 NAME 'distinguishedNameMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, NULL, distinguishedNameMatch},

	{"( 2.5.13.2 NAME 'caseIgnoreMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, UTF8StringNormalize, caseIgnoreMatch},

	{"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, UTF8StringNormalize, caseIgnoreOrderingMatch},

	{"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		NULL, UTF8StringNormalize, caseIgnoreSubstringsMatch},

	/* Next three are not in the RFC's, but are needed for compatibility */
	{"( 2.5.13.5 NAME 'caseExactMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, UTF8StringNormalize, caseExactMatch},

	{"( 2.5.13.6 NAME 'caseExactOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, UTF8StringNormalize, caseExactOrderingMatch},

	{"( 2.5.13.7 NAME 'caseExactSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		NULL, UTF8StringNormalize, caseExactSubstringsMatch},

	{"( 2.5.13.8 NAME 'numericStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		NULL, NULL, numericStringMatch},

	{"( 2.5.13.10 NAME 'numericStringSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		NULL, NULL, numericStringSubstringsMatch},

	{"( 2.5.13.11 NAME 'caseIgnoreListMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
		NULL, NULL, caseIgnoreListMatch},

	{"( 2.5.13.14 NAME 'integerMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		NULL, NULL, integerMatch},

	{"( 2.5.13.16 NAME 'bitStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )",
		NULL, NULL, bitStringMatch},

	{"( 2.5.13.17 NAME 'octetStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		NULL, NULL, octetStringMatch},

	{"( 2.5.13.20 NAME 'telephoneNumberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
		NULL, NULL, telephoneNumberMatch},

	{"( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		NULL, NULL, telephoneNumberSubstringsMatch},

	{"( 2.5.13.22 NAME 'presentationAddressMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 )",
		NULL, NULL, presentationAddressMatch},

	{"( 2.5.13.23 NAME 'uniqueMemberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
		NULL, NULL, uniqueMemberMatch},

	{"( 2.5.13.24 NAME 'protocolInformationMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )",
		NULL, NULL, protocolInformationMatch},

	{"( 2.5.13.27 NAME 'generalizedTimeMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		NULL, NULL, generalizedTimeMatch},

	{"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		NULL, NULL, generalizedTimeOrderingMatch},

	{"( 2.5.13.29 NAME 'integerFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		NULL, NULL, integerFirstComponentMatch},

	{"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		NULL, NULL, objectIdentifierFirstComponentMatch},

	{"( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		NULL, IA5StringNormalize, caseExactIA5Match},

	{"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		NULL, IA5StringNormalize, caseIgnoreIA5Match},

	{"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		NULL, IA5StringNormalize, caseIgnoreIA5SubstringsMatch},

	{NULL, NULL, NULL, NULL}
};

int
schema_init( void )
{
	int		res;
	int		i;
	static int	schema_init_done = 0;

	/* We are called from read_config that is recursive */
	if ( schema_init_done )
		return( 0 );

	for ( i=0; syntax_defs[i].sd_desc != NULL; i++ ) {
		res = register_syntax( syntax_defs[i].sd_desc,
		    syntax_defs[i].sd_validate,
		    syntax_defs[i].sd_ber2str,
			syntax_defs[i].sd_str2ber );

		if ( res ) {
			fprintf( stderr, "schema_init: Error registering syntax %s\n",
				 syntax_defs[i].sd_desc );
			exit( EXIT_FAILURE );
		}
	}

	for ( i=0; mrule_defs[i].mrd_desc != NULL; i++ ) {
		res = register_matching_rule(
			mrule_defs[i].mrd_desc,
			mrule_defs[i].mrd_convert,
			mrule_defs[i].mrd_normalize,
		    mrule_defs[i].mrd_match );

		if ( res ) {
			fprintf( stderr,
				"schema_init: Error registering matching rule %s\n",
				 mrule_defs[i].mrd_desc );
			exit( EXIT_FAILURE );
		}
	}
	schema_init_done = 1;
	return( 0 );
}
