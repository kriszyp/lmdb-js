/* schema_init.c - init builtin schema */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
	unsigned use,
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
	unsigned use,
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
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	return strcmp( value->bv_val,
		((struct berval *) assertedValue)->bv_val );
}

static int
caseIgnoreIA5Match(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	return strcasecmp( value->bv_val,
		((struct berval *) assertedValue)->bv_val );
}

struct syntax_defs_rec {
	char *sd_desc;
	int sd_flags;
	slap_syntax_validate_func *sd_validate;
	slap_syntax_transform_func *sd_ber2str;
	slap_syntax_transform_func *sd_str2ber;
};

struct syntax_defs_rec syntax_defs[] = {
	{"( 1.3.6.1.4.1.1466.115.121.1.1 DESC 'ACI Item' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.2 DESC 'Access Point' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.9 DESC 'Certificate List' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.10 DESC 'Certificate Pair' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.13 DESC 'Data Quality' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'Delivery Method' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
		0, UTF8StringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.16 DESC 'DIT Content Rule Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.17 DESC 'DIT Structure Rule Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.19 DESC 'DSA Quality' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.20 DESC 'DSE Type' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.21 DESC 'Enhanced Guide' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'Facsimile Telephone Number' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.23 DESC 'Fax' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
		0, IA5StringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.29 DESC 'Master And Shadow Access Points' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.31 DESC 'Matching Rule Use Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.32 DESC 'Mail Preference' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.33 DESC 'MHS OR Address' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )",
		0, octetStringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.42 DESC 'Protocol Information' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'Presentation Address' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'Supported Algorithm' )",
		SLAP_SYNTAX_BINARY, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTC Time' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.55 DESC 'Modify Rights' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.56 DESC 'LDAP Schema Definition' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.57 DESC 'LDAP Schema Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )",
		0, NULL, NULL, NULL},

	/* OpenLDAP Experimental Syntaxes */
	{"( " SLAPD_OID_ACI_SYNTAX " DESC 'OpenLDAP Experimental ACI' )",
		0, NULL, NULL, NULL},

	{NULL, 0, NULL, NULL, NULL}
};

struct mrule_defs_rec {
	char *						mrd_desc;
	unsigned					mrd_usage;
	slap_mr_convert_func *		mrd_convert;
	slap_mr_normalize_func *	mrd_normalize;
	slap_mr_match_func *		mrd_match;
	slap_mr_indexer_func *		mrd_indexer;
	slap_mr_filter_func *		mrd_filter;
};

/*
 * Other matching rules in X.520 that we do not use:
 *
 * 2.5.13.9		numericStringOrderingMatch
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
#define caseIgnoreListSubstringsMatch NULL
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
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, objectIdentifierMatch, NULL, NULL},

	{"( 2.5.13.1 NAME 'distinguishedNameMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, distinguishedNameMatch, NULL, NULL},

	{"( 2.5.13.2 NAME 'caseIgnoreMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, UTF8StringNormalize, caseIgnoreMatch, NULL, NULL},

	{"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING,
		NULL, UTF8StringNormalize, caseIgnoreOrderingMatch, NULL, NULL},

	{"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, UTF8StringNormalize, caseIgnoreSubstringsMatch, NULL, NULL},

	/* Next three are not in the RFC's, but are needed for compatibility */
	{"( 2.5.13.5 NAME 'caseExactMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, UTF8StringNormalize, caseExactMatch, NULL, NULL},

	{"( 2.5.13.6 NAME 'caseExactOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING,
		NULL, UTF8StringNormalize, caseExactOrderingMatch, NULL, NULL},

	{"( 2.5.13.7 NAME 'caseExactSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, UTF8StringNormalize, caseExactSubstringsMatch, NULL, NULL},

	{"( 2.5.13.8 NAME 'numericStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, numericStringMatch, NULL, NULL},

	{"( 2.5.13.10 NAME 'numericStringSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL, numericStringSubstringsMatch, NULL, NULL},

	{"( 2.5.13.11 NAME 'caseIgnoreListMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreListMatch, NULL, NULL},

	{"( 2.5.13.12 NAME 'caseIgnoreListSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreListSubstringsMatch, NULL, NULL},

	{"( 2.5.13.14 NAME 'integerMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_NONE | SLAP_MR_EXT,
		NULL, NULL, integerMatch, NULL, NULL},

	{"( 2.5.13.16 NAME 'bitStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )",
		SLAP_MR_NONE | SLAP_MR_EXT,
		NULL, NULL, bitStringMatch, NULL, NULL},

	{"( 2.5.13.17 NAME 'octetStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, octetStringMatch, NULL, NULL},

	{"( 2.5.13.20 NAME 'telephoneNumberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, telephoneNumberMatch, NULL, NULL},

	{"( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL, telephoneNumberSubstringsMatch, NULL, NULL},

	{"( 2.5.13.22 NAME 'presentationAddressMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 )",
		SLAP_MR_NONE | SLAP_MR_EXT,
		NULL, NULL, presentationAddressMatch, NULL, NULL},

	{"( 2.5.13.23 NAME 'uniqueMemberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
		SLAP_MR_NONE | SLAP_MR_EXT,
		NULL, NULL, uniqueMemberMatch, NULL, NULL},

	{"( 2.5.13.24 NAME 'protocolInformationMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )",
		SLAP_MR_NONE | SLAP_MR_EXT,
		NULL, NULL, protocolInformationMatch, NULL, NULL},

	{"( 2.5.13.27 NAME 'generalizedTimeMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, generalizedTimeMatch, NULL, NULL},

	{"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		SLAP_MR_ORDERING,
		NULL, NULL, generalizedTimeOrderingMatch, NULL, NULL},

	{"( 2.5.13.29 NAME 'integerFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, integerFirstComponentMatch, NULL, NULL},

	{"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, objectIdentifierFirstComponentMatch, NULL, NULL},

	{"( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, IA5StringNormalize, caseExactIA5Match, NULL, NULL},

	{"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, IA5StringNormalize, caseIgnoreIA5Match, NULL, NULL},

	{"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_SUBSTR,
		NULL, IA5StringNormalize, caseIgnoreIA5SubstringsMatch, NULL, NULL},

	{NULL, SLAP_MR_NONE, NULL, NULL, NULL}
};

static int schema_init_done = 0;

int
schema_init( void )
{
	int		res;
	int		i;

	/* we should only be called once (from main) */
	assert( schema_init_done == 0 );

	for ( i=0; syntax_defs[i].sd_desc != NULL; i++ ) {
		res = register_syntax( syntax_defs[i].sd_desc,
		    syntax_defs[i].sd_flags,
		    syntax_defs[i].sd_validate,
		    syntax_defs[i].sd_ber2str,
			syntax_defs[i].sd_str2ber );

		if ( res ) {
			fprintf( stderr, "schema_init: Error registering syntax %s\n",
				 syntax_defs[i].sd_desc );
			return -1;
		}
	}

	for ( i=0; mrule_defs[i].mrd_desc != NULL; i++ ) {
		if( mrule_defs[i].mrd_usage == SLAP_MR_NONE ) {
			fprintf( stderr,
				"schema_init: Ingoring unusable matching rule %s\n",
				 mrule_defs[i].mrd_desc );
			continue;
		}

		res = register_matching_rule(
			mrule_defs[i].mrd_desc,
			mrule_defs[i].mrd_usage,
			mrule_defs[i].mrd_convert,
			mrule_defs[i].mrd_normalize,
		    mrule_defs[i].mrd_match,
			mrule_defs[i].mrd_indexer,
			mrule_defs[i].mrd_filter );

		if ( res ) {
			fprintf( stderr,
				"schema_init: Error registering matching rule %s\n",
				 mrule_defs[i].mrd_desc );
			return -1;
		}
	}
	schema_init_done = 1;
	return( 0 );
}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
struct slap_internal_schema slap_schema;

struct slap_schema_ad_map {
	char *ssm_type;
	size_t ssm_offset;
} ad_map[]  = {
	{ "objectClass",
		offsetof(struct slap_internal_schema, si_ad_objectClass) },

	{ "creatorsName",
		offsetof(struct slap_internal_schema, si_ad_creatorsName) },
	{ "createTimestamp",
		offsetof(struct slap_internal_schema, si_ad_createTimestamp) },
	{ "modifiersName",
		offsetof(struct slap_internal_schema, si_ad_modifiersName) },
	{ "modifyTimestamp",
		offsetof(struct slap_internal_schema, si_ad_modifyTimestamp) },

	{ "subschemaSubentry",
		offsetof(struct slap_internal_schema, si_ad_subschemaSubentry) },

	{ "namingContexts",
		offsetof(struct slap_internal_schema, si_ad_namingContexts) },
	{ "supportedControl",
		offsetof(struct slap_internal_schema, si_ad_supportedControl) },
	{ "supportedExtension",
		offsetof(struct slap_internal_schema, si_ad_supportedExtension) },
	{ "supportedLDAPVersion",
		offsetof(struct slap_internal_schema, si_ad_supportedLDAPVersion) },
	{ "supportedSASLMechanisms",
		offsetof(struct slap_internal_schema, si_ad_supportedSASLMechanisms) },

	{ "attributeTypes",
		offsetof(struct slap_internal_schema, si_ad_attributeTypes) },
	{ "ldapSyntaxes",
		offsetof(struct slap_internal_schema, si_ad_ldapSyntaxes) },
	{ "matchingRules",
		offsetof(struct slap_internal_schema, si_ad_matchingRules) },
	{ "objectClasses",
		offsetof(struct slap_internal_schema, si_ad_objectClasses) },

	{ "ref",
		offsetof(struct slap_internal_schema, si_ad_ref) },

	{ "entry",
		offsetof(struct slap_internal_schema, si_ad_entry) },
	{ "children",
		offsetof(struct slap_internal_schema, si_ad_children) },
	{ NULL, 0 }
};

#endif

int
schema_prep( void )
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	int i;
	char *text;
#endif
	/* we should only be called once after schema_init() was called */
	assert( schema_init_done == 1 );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	for( i=0; ad_map[i].ssm_type; i++ ) {
		int rc;

		AttributeDescription ** adp = (AttributeDescription **)
			&(((char *) &slap_schema)[ad_map[i].ssm_offset]);

		*adp = NULL;

		rc = slap_str2ad( ad_map[i].ssm_type, adp, &text );

		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr,
				"No attribute \"%s\" defined in schema\n",
				ad_map[i].ssm_type );
			return rc;
		}
	}
#endif

	++schema_init_done;
	return 0;
}
