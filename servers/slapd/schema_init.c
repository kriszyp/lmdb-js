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
#include "lutil_md5.h"

/* recycled validatation routines */
#define berValidate						blobValidate

/* unimplemented validators */
#define bitStringValidate				NULL
#define booleanValidate					NULL

/* recycled normalization routines */
#define faxNumberNormalize				numericStringNormalize
#define phoneNumberNormalize			numericStringNormalize
#define telexNumberNormalize			numericStringNormalize
#define integerNormalize				numericStringNormalize

/* unimplemented normalizers */
#define bitStringNormalize				NULL
#define booleanNormalize				NULL

/* unimplemented pretters */
#define booleanPretty					NULL
#define dnPretty						NULL
#define integerPretty					NULL

/* recycled matching routines */
#define caseIgnoreMatch					caseIgnoreIA5Match
#define caseIgnoreOrderingMatch			caseIgnoreMatch
#define caseIgnoreSubstringsMatch		caseIgnoreIA5SubstringsMatch

#define caseExactMatch					caseExactIA5Match
#define caseExactOrderingMatch			caseExactMatch
#define caseExactSubstringsMatch		caseExactIA5SubstringsMatch

#define numericStringMatch				caseIgnoreMatch
#define objectIdentifierMatch			numericStringMatch
#define integerMatch					numericStringMatch
#define telephoneNumberMatch			numericStringMatch
#define telephoneNumberSubstringsMatch	caseIgnoreIA5SubstringsMatch
#define generalizedTimeMatch			numericStringMatch
#define generalizedTimeOrderingMatch	numericStringMatch

/* unimplemented matching routines */
#define caseIgnoreListMatch				NULL
#define caseIgnoreListSubstringsMatch	NULL
#define bitStringMatch					NULL
#define presentationAddressMatch		NULL
#define uniqueMemberMatch				NULL
#define protocolInformationMatch		NULL
#define integerFirstComponentMatch		NULL

#define OpenLDAPaciMatch				NULL
#define authPasswordMatch				NULL

/* unimplied indexer/filter routines */
#define caseIgnoreIA5SubstringsIndexer	NULL
#define caseIgnoreIA5SubstringsFilter	NULL

/* recycled indexing/filtering routines */
#define caseIgnoreIndexer				caseIgnoreIA5Indexer
#define caseIgnoreFilter				caseIgnoreIA5Filter
#define caseExactIndexer				caseExactIA5Indexer
#define caseExactFilter					caseExactIA5Filter
#define dnIndexer						caseIgnoreIndexer
#define dnFilter						caseIgnoreFilter

#define caseIgnoreSubstringsIndexer		caseIgnoreIA5SubstringsIndexer
#define caseIgnoreSubstringsFilter		caseIgnoreIA5SubstringsFilter
#define caseExactSubstringsIndexer		caseExactIA5SubstringsIndexer
#define caseExactSubstringsFilter		caseExactIA5SubstringsFilter
#define caseExactIA5SubstringsFilter	caseIgnoreIA5SubstringsFilter
#define caseExactIA5SubstringsIndexer	caseIgnoreIA5SubstringsIndexer


static int
octetStringMatch(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = value->bv_len - ((struct berval *) assertedValue)->bv_len;

	if( match == 0 ) {
		match = memcmp( value->bv_val,
			((struct berval *) assertedValue)->bv_val,
			value->bv_len );
	}

	*matchp = match;
	return LDAP_SUCCESS;
}

/* Index generation function */
int octetStringIndexer(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];
	struct berval digest;
	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		lutil_MD5Init( &MD5context );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			lutil_MD5Update( &MD5context,
				prefix->bv_val, prefix->bv_len );
		}
		lutil_MD5Update( &MD5context,
			syntax->ssyn_oid, slen );
		lutil_MD5Update( &MD5context,
			mr->smr_oid, mlen );
		lutil_MD5Update( &MD5context,
			values[i]->bv_val, values[i]->bv_len );
		lutil_MD5Final( MD5digest, &MD5context );

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;

	*keysp = keys;

	return LDAP_SUCCESS;
}

/* Index generation function */
int octetStringFilter(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[LUTIL_MD5_BYTES];
	struct berval *value = (struct berval *) assertValue;
	struct berval digest;
	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

	lutil_MD5Init( &MD5context );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		lutil_MD5Update( &MD5context,
			prefix->bv_val, prefix->bv_len );
	}
	lutil_MD5Update( &MD5context,
		syntax->ssyn_oid, slen );
	lutil_MD5Update( &MD5context,
		mr->smr_oid, mlen );
	lutil_MD5Update( &MD5context,
		value->bv_val, value->bv_len );
	lutil_MD5Final( MD5digest, &MD5context );

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	*keysp = keys;

	return LDAP_SUCCESS;
}

static int
dnValidate(
	Syntax *syntax,
	struct berval *in )
{
	int rc;
	char *dn;

	if( in->bv_len == 0 ) return LDAP_SUCCESS;

	dn = ch_strdup( in->bv_val );

	rc = dn_validate( dn ) == NULL
		? LDAP_INVALID_SYNTAX : LDAP_SUCCESS;

	ch_free( dn );
	return rc;
}

static int
dnNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *out = ber_bvdup( val );

	if( out->bv_len != 0 ) {
		char *dn;
#ifdef USE_DN_NORMALIZE
		dn = dn_normalize( out->bv_val );
#else
		dn = dn_validate( out->bv_val );
#endif

		if( dn == NULL ) {
			ber_bvfree( out );
			return LDAP_INVALID_SYNTAX;
		}

		out->bv_val = dn;
		out->bv_len = strlen( dn );
	}

	*normalized = out;
	return LDAP_SUCCESS;
}

static int
dnMatch(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match;
	struct berval *asserted = (struct berval *) assertedValue;
	
	match = value->bv_len - asserted->bv_len;

	if( match == 0 ) {
#ifdef USE_DN_NORMALIZE
		match = strcmp( value->bv_val, asserted->bv_val );
#else
		match = strcasecmp( value->bv_val, asserted->bv_val );
#endif
	}

	Debug( LDAP_DEBUG_ARGS, "dnMatch %d\n\t\"%s\"\n\t\"%s\"\n",
	    match, value->bv_val, asserted->bv_val );

	*matchp = match;
	return LDAP_SUCCESS;
}

static int
inValidate(
	Syntax *syntax,
	struct berval *in )
{
	/* any value allowed */
	return LDAP_OTHER;
}

static int
blobValidate(
	Syntax *syntax,
	struct berval *in )
{
	/* any value allowed */
	return LDAP_SUCCESS;
}

static int
UTF8StringValidate(
	Syntax *syntax,
	struct berval *in )
{
	ber_len_t count;
	int len;
	unsigned char *u = in->bv_val;

	if( !in->bv_len ) return LDAP_INVALID_SYNTAX;

	for( count = in->bv_len; count > 0; count-=len, u+=len ) {
		/* get the length indicated by the first byte */
		len = LDAP_UTF8_CHARLEN( u );

		/* should not be zero */
		if( len == 0 ) return LDAP_INVALID_SYNTAX;

		/* make sure len corresponds with the offset
			to the next character */
		if( LDAP_UTF8_OFFSET( u ) != len ) return LDAP_INVALID_SYNTAX;
	}

	if( count != 0 ) return LDAP_INVALID_SYNTAX;

	return LDAP_SUCCESS;
}

static int
UTF8StringNormalize(
	Syntax *syntax,
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

	if( *p == '\0' ) {
		ch_free( newval );
		return LDAP_INVALID_SYNTAX;
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
	assert( p >= q );

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
	*normalized = newval;

	return LDAP_SUCCESS;
}

static int
oidValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( val->bv_len == 0 ) return 0;

	if( OID_LEADCHAR(val->bv_val[0]) ) {
		int dot = 0;
		for(i=1; i < val->bv_len; i++) {
			if( OID_SEPARATOR( val->bv_val[i] ) ) {
				if( dot++ ) return 1;
			} else if ( OID_CHAR( val->bv_val[i] ) ) {
				dot = 0;
			} else {
				return LDAP_INVALID_SYNTAX;
			}
		}

		return !dot ? LDAP_SUCCESS : LDAP_INVALID_SYNTAX;

	} else if( DESC_LEADCHAR(val->bv_val[0]) ) {
		for(i=1; i < val->bv_len; i++) {
			if( !DESC_CHAR(val->bv_val[i] ) ) {
				return LDAP_INVALID_SYNTAX;
			}
		}

		return LDAP_SUCCESS;
	}
	
	return LDAP_INVALID_SYNTAX;
}

static int
integerValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( !val->bv_len ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < val->bv_len; i++) {
		if( !ASCII_DIGIT(val->bv_val[i]) ) return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
printableStringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( !val->bv_len ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < val->bv_len; i++) {
		if( !isprint(val->bv_val[i]) ) return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
IA5StringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( !val->bv_len ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < val->bv_len; i++) {
		if( !isascii(val->bv_val[i]) ) return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
IA5StringConvert(
	Syntax *syntax,
	struct berval *in,
	struct berval **out )
{
	ldap_unicode_t *u;
	ber_len_t i, len = in->bv_len;
	struct berval *bv = ch_malloc( sizeof(struct berval) );

	bv->bv_len = len * sizeof( ldap_unicode_t );
	bv->bv_val = (char *) u = ch_malloc( bv->bv_len + sizeof(ldap_unicode_t) );

	for(i=0; i < len; i++ ) {
		/*
		 * IA5StringValidate should have been called to ensure
		 * input is limited to IA5.
		 */
		u[i] = in->bv_val[i];
	}
	u[i] = 0;

	*out = bv;
	return LDAP_SUCCESS;
}

static int
IA5StringNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *newval;
	char *p, *q;

	newval = ch_malloc( sizeof( struct berval ) );

	p = val->bv_val;

	/* Ignore initial whitespace */
	while ( ASCII_SPACE( *p ) ) {
		p++;
	}

	if( *p != '\0' ) {
		ch_free( newval );
		return LDAP_INVALID_SYNTAX;
	}

	newval->bv_val = ch_strdup( p );
	p = q = newval->bv_val;

	while ( *p ) {
		if ( ASCII_SPACE( *p ) ) {
			*q++ = *p++;

			/* Ignore the extra whitespace */
			while ( ASCII_SPACE( *p ) ) {
				p++;
			}
		} else {
			*q++ = *p++;
		}
	}

	assert( *newval->bv_val );
	assert( newval->bv_val < p );
	assert( p <= q );

	/* cannot start with a space */
	assert( !ASCII_SPACE(*newval->bv_val) );

	/*
	 * If the string ended in space, backup the pointer one
	 * position.  One is enough because the above loop collapsed
	 * all whitespace to a single space.
	 */

	if ( ASCII_SPACE( q[-1] ) ) {
		--q;
	}

	/* cannot end with a space */
	assert( !ASCII_SPACE( q[-1] ) );

	/* null terminate */
	*q = '\0';

	newval->bv_len = q - newval->bv_val;
	*normalized = newval;

	return LDAP_SUCCESS;
}

static int
caseExactIA5Match(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = value->bv_len - ((struct berval *) assertedValue)->bv_len;

	if( match == 0 ) {
		match = strncmp( value->bv_val,
			((struct berval *) assertedValue)->bv_val,
			value->bv_len );
	}

	*matchp = match;
	return LDAP_SUCCESS;
}

static int
caseExactIA5SubstringsMatch(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = 0;
	SubstringsAssertion *sub = assertedValue;
	struct berval left = *value;
	int i;
	ber_len_t inlen=0;

	/* Add up asserted input length */
	if( sub->sa_initial ) {
		inlen += sub->sa_initial->bv_len;
	}
	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i] != NULL; i++) {
			inlen += sub->sa_any[i]->bv_len;
		}
	}
	if( sub->sa_final ) {
		inlen += sub->sa_final->bv_len;
	}

	if( sub->sa_initial ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncmp( sub->sa_initial->bv_val, left.bv_val,
			sub->sa_initial->bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_val += sub->sa_initial->bv_len;
		left.bv_len -= sub->sa_initial->bv_len;
		inlen -= sub->sa_initial->bv_len;
	}

	if( sub->sa_final ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncmp( sub->sa_final->bv_val,
			&left.bv_val[left.bv_len - sub->sa_final->bv_len],
			sub->sa_final->bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_len -= sub->sa_final->bv_len;
		inlen -= sub->sa_final->bv_len;
	}

	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i]; i++) {
			ber_len_t idx;
			char *p;

retry:
			if( inlen > left.bv_len ) {
				/* not enough length */
				match = 1;
				goto done;
			}

			if( sub->sa_any[i]->bv_len == 0 ) {
				continue;
			}

			p = strchr( left.bv_val, *sub->sa_any[i]->bv_val );

			if( p == NULL ) {
				match = 1;
				goto done;
			}

			idx = p - left.bv_val;
			assert( idx < left.bv_len );

			if( idx >= left.bv_len ) {
				/* this shouldn't happen */
				return LDAP_OTHER;
			}

			left.bv_val = p;
			left.bv_len -= idx;

			if( sub->sa_any[i]->bv_len > left.bv_len ) {
				/* not enough left */
				match = 1;
				goto done;
			}

			match = strncmp( left.bv_val,
				sub->sa_any[i]->bv_val,
				sub->sa_any[i]->bv_len );

			if( match != 0 ) {
				left.bv_val++;
				left.bv_len--;
				goto retry;
			}

			left.bv_val += sub->sa_any[i]->bv_len;
			left.bv_len -= sub->sa_any[i]->bv_len;
			inlen -= sub->sa_any[i]->bv_len;
		}
	}

done:
	*matchp = match;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseExactIA5Indexer(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];
	struct berval digest;
	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		struct berval *value = values[i];

		lutil_MD5Init( &MD5context );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			lutil_MD5Update( &MD5context,
				prefix->bv_val, prefix->bv_len );
		}
		lutil_MD5Update( &MD5context,
			syntax->ssyn_oid, slen );
		lutil_MD5Update( &MD5context,
			mr->smr_oid, mlen );
		lutil_MD5Update( &MD5context,
			value->bv_val, value->bv_len );
		lutil_MD5Final( MD5digest, &MD5context );

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseExactIA5Filter(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[LUTIL_MD5_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	value = (struct berval *) assertValue;

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

	lutil_MD5Init( &MD5context );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		lutil_MD5Update( &MD5context,
			prefix->bv_val, prefix->bv_len );
	}
	lutil_MD5Update( &MD5context,
		syntax->ssyn_oid, slen );
	lutil_MD5Update( &MD5context,
		mr->smr_oid, mlen );
	lutil_MD5Update( &MD5context,
		value->bv_val, value->bv_len );
	lutil_MD5Final( MD5digest, &MD5context );

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	*keysp = keys;
	return LDAP_SUCCESS;
}

static int
caseIgnoreIA5Match(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = value->bv_len - ((struct berval *) assertedValue)->bv_len;

	if( match == 0 ) {
		match = strncasecmp( value->bv_val,
			((struct berval *) assertedValue)->bv_val,
			value->bv_len );
	}

	*matchp = match;
	return LDAP_SUCCESS;
}

static char *strcasechr( const char *str, int c )
{
	char *lower = strchr( str, TOLOWER(c) );
	char *upper = strchr( str, TOUPPER(c) );

	if( lower && upper ) {
		return lower < upper ? lower : upper;
	} else if ( lower ) {
		return lower;
	} else {
		return upper;
	}
}

static int
caseIgnoreIA5SubstringsMatch(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = 0;
	SubstringsAssertion *sub = assertedValue;
	struct berval left = *value;
	int i;
	ber_len_t inlen=0;

	/* Add up asserted input length */
	if( sub->sa_initial ) {
		inlen += sub->sa_initial->bv_len;
	}
	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i] != NULL; i++) {
			inlen += sub->sa_any[i]->bv_len;
		}
	}
	if( sub->sa_final ) {
		inlen += sub->sa_final->bv_len;
	}

	if( sub->sa_initial ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncasecmp( sub->sa_initial->bv_val, left.bv_val,
			sub->sa_initial->bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_val += sub->sa_initial->bv_len;
		left.bv_len -= sub->sa_initial->bv_len;
		inlen -= sub->sa_initial->bv_len;
	}

	if( sub->sa_final ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncasecmp( sub->sa_final->bv_val,
			&left.bv_val[left.bv_len - sub->sa_final->bv_len],
			sub->sa_final->bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_len -= sub->sa_final->bv_len;
		inlen -= sub->sa_final->bv_len;
	}

	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i]; i++) {
			ber_len_t idx;
			char *p;

retry:
			if( inlen > left.bv_len ) {
				/* not enough length */
				match = 1;
				goto done;
			}

			if( sub->sa_any[i]->bv_len == 0 ) {
				continue;
			}

			p = strcasechr( left.bv_val, *sub->sa_any[i]->bv_val );

			if( p == NULL ) {
				match = 1;
				goto done;
			}

			idx = p - left.bv_val;
			assert( idx < left.bv_len );

			if( idx >= left.bv_len ) {
				/* this shouldn't happen */
				return LDAP_OTHER;
			}

			left.bv_val = p;
			left.bv_len -= idx;

			if( sub->sa_any[i]->bv_len > left.bv_len ) {
				/* not enough left */
				match = 1;
				goto done;
			}

			match = strncasecmp( left.bv_val,
				sub->sa_any[i]->bv_val,
				sub->sa_any[i]->bv_len );

			if( match != 0 ) {
				left.bv_val++;
				left.bv_len--;

				goto retry;
			}

			left.bv_val += sub->sa_any[i]->bv_len;
			left.bv_len -= sub->sa_any[i]->bv_len;
			inlen -= sub->sa_any[i]->bv_len;
		}
	}

done:
	*matchp = match;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseIgnoreIA5Indexer(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];
	struct berval digest;
	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		struct berval *value = ber_bvdup( values[i] );
		ldap_pvt_str2upper( value->bv_val );

		lutil_MD5Init( &MD5context );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			lutil_MD5Update( &MD5context,
				prefix->bv_val, prefix->bv_len );
		}
		lutil_MD5Update( &MD5context,
			syntax->ssyn_oid, slen );
		lutil_MD5Update( &MD5context,
			mr->smr_oid, mlen );
		lutil_MD5Update( &MD5context,
			value->bv_val, value->bv_len );
		lutil_MD5Final( MD5digest, &MD5context );

		ber_bvfree( value );

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseIgnoreIA5Filter(
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[LUTIL_MD5_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	value = ber_bvdup( (struct berval *) assertValue );
	ldap_pvt_str2upper( value->bv_val );

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

	lutil_MD5Init( &MD5context );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		lutil_MD5Update( &MD5context,
			prefix->bv_val, prefix->bv_len );
	}
	lutil_MD5Update( &MD5context,
		syntax->ssyn_oid, slen );
	lutil_MD5Update( &MD5context,
		mr->smr_oid, mlen );
	lutil_MD5Update( &MD5context,
		value->bv_val, value->bv_len );
	lutil_MD5Final( MD5digest, &MD5context );

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	ber_bvfree( value );

	*keysp = keys;
	return LDAP_SUCCESS;
}

static int
numericStringNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	/* similiar to IA5StringNormalize except removes all spaces */
	struct berval *newval;
	char *p, *q;

	newval = ch_malloc( sizeof( struct berval ) );

	p = val->bv_val;

	/* Ignore initial whitespace */
	while ( ASCII_SPACE( *p ) ) {
		p++;
	}

	if( *p != '\0' ) {
		ch_free( newval );
		return LDAP_INVALID_SYNTAX;
	}

	newval->bv_val = ch_strdup( p );
	p = q = newval->bv_val;

	while ( *p ) {
		if ( ASCII_SPACE( *p ) ) {
			/* Ignore whitespace */
			p++;
		} else {
			*q++ = *p++;
		}
	}

	assert( *newval->bv_val );
	assert( newval->bv_val < p );
	assert( p <= q );

	/* cannot start with a space */
	assert( !ASCII_SPACE(*newval->bv_val) );

	/* cannot end with a space */
	assert( !ASCII_SPACE( q[-1] ) );

	/* null terminate */
	*q = '\0';

	newval->bv_len = q - newval->bv_val;
	*normalized = newval;

	return LDAP_SUCCESS;
}

static int
objectIdentifierFirstComponentMatch(
	int *matchp,
	unsigned use,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int rc = LDAP_SUCCESS;
	int match;
	struct berval *asserted = (struct berval *) assertedValue;
	ber_len_t i;
	struct berval oid;

	if( value->bv_len == 0 || value->bv_val[0] != '(' /*')'*/ ) {
		return LDAP_INVALID_SYNTAX;
	}

	/* trim leading white space */
	for( i=1; ASCII_SPACE(value->bv_val[i]) && i < value->bv_len; i++ ) {
		/* empty */
	}

	/* grab next word */
	oid.bv_val = &value->bv_val[i];
	oid.bv_len = value->bv_len - i;
	for( i=1; ASCII_SPACE(value->bv_val[i]) && i < oid.bv_len; i++ ) {
		/* empty */
	}
	oid.bv_len = i;

	/* insert attributeTypes, objectclass check here */
	if( OID_LEADCHAR(asserted->bv_val[0]) ) {
		rc = objectIdentifierMatch( &match, use, syntax, mr, &oid, asserted );

	} else {
		char *stored = ch_malloc( oid.bv_len + 1 );
		memcpy( stored, oid.bv_val, oid.bv_len );
		stored[oid.bv_len] = '\0';

		if ( !strcmp( syntax->ssyn_oid, SLAP_SYNTAX_MATCHINGRULES_OID ) ) {
			MatchingRule *asserted_mr = mr_find( asserted->bv_val );
			MatchingRule *stored_mr = mr_find( stored );

			if( asserted_mr == NULL ) {
				rc = SLAPD_COMPARE_UNDEFINED;
			} else {
				match = asserted_mr != stored_mr;
			}

		} else if ( !strcmp( syntax->ssyn_oid,
			SLAP_SYNTAX_ATTRIBUTETYPES_OID ) )
		{
			AttributeType *asserted_at = at_find( asserted->bv_val );
			AttributeType *stored_at = at_find( stored );

			if( asserted_at == NULL ) {
				rc = SLAPD_COMPARE_UNDEFINED;
			} else {
				match = asserted_at != stored_at;
			}

		} else if ( !strcmp( syntax->ssyn_oid,
			SLAP_SYNTAX_OBJECTCLASSES_OID ) )
		{
			ObjectClass *asserted_oc = oc_find( asserted->bv_val );
			ObjectClass *stored_oc = oc_find( stored );

			if( asserted_oc == NULL ) {
				rc = SLAPD_COMPARE_UNDEFINED;
			} else {
				match = asserted_oc != stored_oc;
			}
		}

		ch_free( stored );
	}

	Debug( LDAP_DEBUG_ARGS, "objectIdentifierFirstComponentMatch "
		"%d\n\t\"%s\"\n\t\"%s\"\n",
	    match, value->bv_val, asserted->bv_val );

	if( rc == LDAP_SUCCESS ) *matchp = match;
	return rc;
}

static int
check_time_syntax (struct berval *val,
	int start,
	int *parts)
{
	static int ceiling[9] = { 99, 99, 11, 30, 23, 59, 59, 12, 59 };
	static int mdays[12] = { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	char *p, *e;
	int part, c, neg = 0;

	if( val->bv_len == 0 )
		return LDAP_INVALID_SYNTAX;

	p = (char *)val->bv_val;
	e = p + val->bv_len;

	/* Ignore initial whitespace */
	while ( ( p < e ) && ASCII_SPACE( *p ) ) {
		p++;
	}

	if (e - p < 13 - (2 * start))
		return LDAP_INVALID_SYNTAX;

	for (part = 0; part < 9; part++)
		parts[part] = 0;

	for (part = start; part < 7; part++) {
		c = *p;
		if ((part == 6)
			&& (c == 'Z'
				|| c == '+'
				|| c == '-'))
		{
			part++;
			break;
		}
		p++;
		c -= '0';
		if (p == e)
			return LDAP_INVALID_SYNTAX;
		if (c < 0 || c > 9)
			return LDAP_INVALID_SYNTAX;
		parts[part] = c;

		c = *p++ - '0';
		if (p == e)
			return LDAP_INVALID_SYNTAX;
		if (c < 0 || c > 9)
			return LDAP_INVALID_SYNTAX;
		parts[part] *= 10;
		parts[part] += c;

		if (part == 2 || part == 3)
			parts[part]--;
		if (parts[part] < 0)
			return LDAP_INVALID_SYNTAX;
		if (parts[part] > ceiling[part])
			return LDAP_INVALID_SYNTAX;
	}
	if (parts[2] == 1) {
		if (parts[3] > mdays[parts[2]])
			return LDAP_INVALID_SYNTAX;
		if (parts[1] & 0x03) {
			/* FIXME:  This is an incomplete leap-year
			 * check that fails in 2100, 2200, 2300,
			 * 2500, 2600, 2700, ...
			 */
			if (parts[3] > mdays[parts[2]] - 1)
				return LDAP_INVALID_SYNTAX;
		}
	}
	c = *p++;
	if (c == 'Z') {
		/* all done */
	} else if (c != '+' && c != '-') {
		return LDAP_INVALID_SYNTAX;
	} else {
		if (c == '-')
			neg = 1;
		if (p > e - 4)
			return LDAP_INVALID_SYNTAX;
		for (part = 7; part < 9; part++) {
			c = *p++ - '0';
			if (c < 0 || c > 9)
				return LDAP_INVALID_SYNTAX;
			parts[part] = c;

			c = *p++ - '0';
			if (c < 0 || c > 9)
				return LDAP_INVALID_SYNTAX;
			parts[part] *= 10;
			parts[part] += c;
			if (parts[part] < 0 || parts[part] > ceiling[part])
				return LDAP_INVALID_SYNTAX;
		}
	}

	/* Ignore trailing whitespace */
	while ( ( p < e ) && ASCII_SPACE( *p ) ) {
		p++;
	}
	if (p != e)
		return LDAP_INVALID_SYNTAX;

	if (neg == 0) {
		parts[4] += parts[7];
		parts[5] += parts[8];
		for (part = 7; --part > 0; ) {
			if (part != 3)
				c = ceiling[part];
			else {
				/* FIXME:  This is an incomplete leap-year
				 * check that fails in 2100, 2200, 2300,
				 * 2500, 2600, 2700, ...
				 */
				c = mdays[parts[2]];
				if (parts[2] == 1)
					c--;
			}
			if (parts[part] > c) {
				parts[part] -= c + 1;
				parts[part - 1]++;
			}
		}
	} else {
		parts[4] -= parts[7];
		parts[5] -= parts[8];
		for (part = 7; --part > 0; ) {
			if (part != 3)
				c = ceiling[part];
			else {
				/* FIXME:  This is an incomplete leap-year
				 * check that fails in 2100, 2200, 2300,
				 * 2500, 2600, 2700, ...
				 */
				c = mdays[(parts[2] - 1) % 12];
				if (parts[2] == 2)
					c--;
			}
			if (parts[part] < 0) {
				parts[part] += c + 1;
				parts[part - 1]--;
			}
		}
	}

	return LDAP_SUCCESS;
}

static int
utcTimeNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *out;
	int parts[9], rc;

	rc = check_time_syntax(val, 1, parts);
	if (rc != LDAP_SUCCESS) {
		return rc;
	}

	*normalized = NULL;
	out = ch_malloc( sizeof(struct berval) );
	if( out == NULL )
		return LBER_ERROR_MEMORY;

	out->bv_val = ch_malloc( 14 );
	if ( out->bv_val == NULL ) {
		ch_free( out );
		return LBER_ERROR_MEMORY;
	}

	sprintf( out->bv_val, "%02ld%02ld%02ld%02ld%02ld%02ldZ",
				parts[1], parts[2] + 1, parts[3] + 1,
				parts[4], parts[5], parts[6] );
	out->bv_len = 13;
	*normalized = out;

	return LDAP_SUCCESS;
}

static int
utcTimeValidate(
	Syntax *syntax,
	struct berval *in )
{
	int parts[9];

	return check_time_syntax(in, 1, parts);
}

static int
generalizedTimeNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *out;
	int parts[9], rc;

	rc = check_time_syntax(val, 0, parts);
	if (rc != LDAP_SUCCESS) {
		return rc;
	}

	*normalized = NULL;
	out = ch_malloc( sizeof(struct berval) );
	if( out == NULL )
		return LBER_ERROR_MEMORY;

	out->bv_val = ch_malloc( 16 );
	if ( out->bv_val == NULL ) {
		ch_free( out );
		return LBER_ERROR_MEMORY;
	}

	sprintf( out->bv_val, "%02ld%02ld%02ld%02ld%02ld%02ld%02ldZ",
				parts[0], parts[1], parts[2] + 1, parts[3] + 1,
				parts[4], parts[5], parts[6] );
	out->bv_len = 15;
	*normalized = out;

	return LDAP_SUCCESS;
}

static int
generalizedTimeValidate(
	Syntax *syntax,
	struct berval *in )
{
	int parts[9];

	return check_time_syntax(in, 0, parts);
}

struct syntax_defs_rec {
	char *sd_desc;
	int sd_flags;
	slap_syntax_validate_func *sd_validate;
	slap_syntax_transform_func *sd_normalize;
	slap_syntax_transform_func *sd_pretty;
#ifdef SLAPD_BINARY_CONVERSION
	slap_syntax_transform_func *sd_ber2str;
	slap_syntax_transform_func *sd_str2ber;
#endif
};

#define X_HIDE "X-HIDE 'TRUE' "
#define X_BINARY "X-BINARY-TRANSFER-REQUIRED 'TRUE' "
#define X_NOT_H_R "X-NOT-HUMAN-READABLE 'TRUE' "

struct syntax_defs_rec syntax_defs[] = {
	{"( 1.3.6.1.4.1.1466.115.121.1.1 DESC 'ACI Item' " X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.2 DESC 'Access Point' " X_NOT_H_R ")",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' " X_NOT_H_R ")",
		SLAP_SYNTAX_BLOB, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' " X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )",
		0, bitStringValidate, bitStringNormalize, NULL },
	{"( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )",
		0, booleanValidate, booleanNormalize, booleanPretty},
	{"( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.9 DESC 'Certificate List' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.10 DESC 'Certificate Pair' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'Distinguished Name' )",
		0, dnValidate, dnNormalize, dnPretty},
	{"( 1.3.6.1.4.1.1466.115.121.1.13 DESC 'Data Quality' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'Delivery Method' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )",
		0, UTF8StringValidate, UTF8StringNormalize, NULL},
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
		0, IA5StringValidate, faxNumberNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.23 DESC 'Fax' " X_NOT_H_R ")",
		SLAP_SYNTAX_BLOB, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )",
		0, generalizedTimeValidate, generalizedTimeNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
		0, IA5StringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )",
		0, integerValidate, integerNormalize, integerPretty},
	{"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' " X_NOT_H_R ")",
		SLAP_SYNTAX_BLOB, NULL, NULL, NULL},
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
		0, IA5StringValidate, numericStringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		0, oidValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )",
		0, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )",
		0, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.42 DESC 'Protocol Information' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'Presentation Address' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )",
		0, printableStringValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'Supported Algorithm' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )",
		0, IA5StringValidate, phoneNumberNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )",
		0, IA5StringValidate, telexNumberNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTC Time' )",
		0, utcTimeValidate, utcTimeNormalize, NULL},
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
	{"( 1.3.6.1.4.1.4203.666.2.1 DESC 'OpenLDAP Experimental ACI' )",
		0, IA5StringValidate /* THIS WILL CHANGE FOR NEW ACI SYNTAX */, NULL, NULL},
	{"( 1.3.6.1.4.1.4203.666.2.2 DESC 'OpenLDAP authPassword' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.4203.666.2.3 DESC 'OpenLDAP void' " X_HIDE ")" ,
		SLAP_SYNTAX_HIDE, inValidate, NULL, NULL},
#if 0 /* not needed */
	{"( 1.3.6.1.4.1.4203.666.2.4 DESC 'OpenLDAP DN' " X_HIDE ")" ,
		SLAP_SYNTAX_HIDE, inValidate, NULL, NULL},
#endif

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

struct mrule_defs_rec mrule_defs[] = {
	{"( 2.5.13.0 NAME 'objectIdentifierMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, objectIdentifierMatch,
		caseIgnoreIA5Indexer, caseIgnoreIA5Filter},

	{"( 2.5.13.1 NAME 'distinguishedNameMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, dnMatch, dnIndexer, dnFilter},

	{"( 2.5.13.2 NAME 'caseIgnoreMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreMatch, caseIgnoreIndexer, caseIgnoreFilter},

	{"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING,
		NULL, NULL, caseIgnoreOrderingMatch, NULL, NULL},

	{"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreSubstringsMatch,
		caseIgnoreSubstringsIndexer, caseIgnoreSubstringsFilter},

	/* Next three are not in the RFC's, but are needed for compatibility */
	{"( 2.5.13.5 NAME 'caseExactMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, caseExactMatch, caseExactIndexer, caseExactFilter},

	{"( 2.5.13.6 NAME 'caseExactOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING,
		NULL, NULL, caseExactOrderingMatch, NULL, NULL},

	{"( 2.5.13.7 NAME 'caseExactSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL, caseExactSubstringsMatch,
		caseExactSubstringsIndexer, caseExactSubstringsFilter},

	{"( 2.5.13.8 NAME 'numericStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreIA5Match, NULL, NULL},

	{"( 2.5.13.10 NAME 'numericStringSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreIA5SubstringsMatch,
		caseIgnoreIA5SubstringsIndexer, caseIgnoreIA5SubstringsFilter},

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
		NULL, NULL, octetStringMatch, octetStringIndexer, octetStringFilter},

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
		NULL, NULL, caseExactIA5Match, caseExactIA5Indexer, caseExactIA5Filter},

	{"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL, caseIgnoreIA5Match, caseExactIA5Indexer, caseExactIA5Filter},

	{"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_SUBSTR,
		NULL, NULL, caseIgnoreIA5SubstringsMatch,
		caseIgnoreIA5SubstringsIndexer, caseIgnoreIA5SubstringsFilter},

	{"( 1.3.6.1.4.1.4203.666.4.1 NAME 'authPasswordMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		SLAP_MR_EQUALITY,
		NULL, NULL, authPasswordMatch, NULL, NULL},

	{"( 1.3.6.1.4.1.4203.666.4.2 NAME 'OpenLDAPaciMatch' "
		"SYNTAX 1.3.6.1.4.1.4203.666.2.1 )",
		SLAP_MR_EQUALITY,
		NULL, NULL, OpenLDAPaciMatch, NULL, NULL},

	{NULL, SLAP_MR_NONE, NULL, NULL, NULL}
};

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
		    syntax_defs[i].sd_normalize,
			syntax_defs[i].sd_pretty
#ifdef SLAPD_BINARY_CONVERSION
			,
		    syntax_defs[i].sd_ber2str,
			syntax_defs[i].sd_str2ber
#endif
		);

		if ( res ) {
			fprintf( stderr, "schema_init: Error registering syntax %s\n",
				 syntax_defs[i].sd_desc );
			return LDAP_OTHER;
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
			return LDAP_OTHER;
		}
	}
	schema_init_done = 1;
	return LDAP_SUCCESS;
}
