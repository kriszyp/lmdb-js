/* schema_init.c - init builtin schema */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <limits.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"
#include "lber_pvt.h"

#include "ldap_utf8.h"

#include "lutil_hash.h"
#define HASH_BYTES				LUTIL_HASH_BYTES
#define HASH_CONTEXT			lutil_HASH_CTX
#define HASH_Init(c)			lutil_HASHInit(c)
#define HASH_Update(c,buf,len)	lutil_HASHUpdate(c,buf,len)
#define HASH_Final(d,c)			lutil_HASHFinal(d,c)

/* recycled validatation routines */
#define berValidate						blobValidate

/* unimplemented pretters */
#define integerPretty					NULL

/* recycled matching routines */
#define bitStringMatch					octetStringMatch
#define numericStringMatch				caseIgnoreIA5Match
#define objectIdentifierMatch			octetStringMatch
#define telephoneNumberMatch			caseIgnoreIA5Match
#define telephoneNumberSubstringsMatch	caseIgnoreIA5SubstringsMatch
#define generalizedTimeMatch			caseIgnoreIA5Match
#define generalizedTimeOrderingMatch	caseIgnoreIA5Match
#define uniqueMemberMatch				dnMatch
#define integerFirstComponentMatch		integerMatch

/* approx matching rules */
#define directoryStringApproxMatchOID	"1.3.6.1.4.1.4203.666.4.4"
#define directoryStringApproxMatch	approxMatch
#define directoryStringApproxIndexer	approxIndexer
#define directoryStringApproxFilter	approxFilter
#define IA5StringApproxMatchOID			"1.3.6.1.4.1.4203.666.4.5"
#define IA5StringApproxMatch			approxMatch
#define IA5StringApproxIndexer			approxIndexer
#define IA5StringApproxFilter			approxFilter

/* ordering matching rules */
#define caseIgnoreOrderingMatch			caseIgnoreMatch
#define caseExactOrderingMatch			caseExactMatch
#define integerOrderingMatch			integerMatch

/* unimplemented matching routines */
#define caseIgnoreListMatch				NULL
#define caseIgnoreListSubstringsMatch	NULL
#define protocolInformationMatch		NULL

#ifdef SLAPD_ACI_ENABLED
#define OpenLDAPaciMatch				NULL
#endif
#ifdef SLAPD_AUTHPASSWD
#define authPasswordMatch				NULL
#endif

/* recycled indexing/filtering routines */
#define dnIndexer				caseExactIgnoreIndexer
#define dnFilter				caseExactIgnoreFilter
#define bitStringFilter			octetStringFilter
#define bitStringIndexer		octetStringIndexer

#define telephoneNumberIndexer			caseIgnoreIA5Indexer
#define telephoneNumberFilter			caseIgnoreIA5Filter
#define telephoneNumberSubstringsIndexer	caseIgnoreIA5SubstringsIndexer
#define telephoneNumberSubstringsFilter		caseIgnoreIA5SubstringsFilter

static MatchingRule *caseExactMatchingRule;
static MatchingRule *caseExactSubstringsMatchingRule;
static MatchingRule *integerFirstComponentMatchingRule;

static const struct MatchingRulePtr {
	const char   *oid;
	MatchingRule **mr;
} mr_ptr [] = {
	/* must match OIDs below */
	{ "2.5.13.5",  &caseExactMatchingRule },
	{ "2.5.13.7",  &caseExactSubstringsMatchingRule },
	{ "2.5.13.29", &integerFirstComponentMatchingRule }
};


static char *bvcasechr( struct berval *bv, unsigned char c, ber_len_t *len )
{
	ber_len_t i;
	char lower = TOLOWER( c );
	char upper = TOUPPER( c );

	if( c == 0 ) return NULL;
	
	for( i=0; i < bv->bv_len; i++ ) {
		if( upper == bv->bv_val[i] || lower == bv->bv_val[i] ) {
			*len = i;
			return &bv->bv_val[i];
		}
	}

	return NULL;
}

static int
octetStringMatch(
	int *matchp,
	slap_mask_t flags,
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
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* just count them */
	}

	/* we should have at least one value at this point */
	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval ) * (i+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			values[i].bv_val, values[i].bv_len );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[i], &digest );
	}

	keys[i].bv_val = NULL;
	keys[i].bv_len = 0;

	*keysp = keys;

	return LDAP_SUCCESS;
}

/* Index generation function */
int octetStringFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval *value = (struct berval *) assertedValue;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	keys = ch_malloc( sizeof( struct berval ) * 2 );

	HASH_Init( &HASHcontext );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		HASH_Update( &HASHcontext,
			prefix->bv_val, prefix->bv_len );
	}
	HASH_Update( &HASHcontext,
		syntax->ssyn_oid, slen );
	HASH_Update( &HASHcontext,
		mr->smr_oid, mlen );
	HASH_Update( &HASHcontext,
		value->bv_val, value->bv_len );
	HASH_Final( HASHdigest, &HASHcontext );

	ber_dupbv( keys, &digest );
	keys[1].bv_val = NULL;
	keys[1].bv_len = 0;

	*keysp = keys;

	return LDAP_SUCCESS;
}

static int
inValidate(
	Syntax *syntax,
	struct berval *in )
{
	/* no value allowed */
	return LDAP_INVALID_SYNTAX;
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
bitStringValidate(
	Syntax *syntax,
	struct berval *in )
{
	ber_len_t i;

	/* very unforgiving validation, requires no normalization
	 * before simplistic matching
	 */
	if( in->bv_len < 3 ) {
		return LDAP_INVALID_SYNTAX;
	}

	/*
	 * rfc 2252 section 6.3 Bit String
	 * bitstring = "'" *binary-digit "'"
	 * binary-digit = "0" / "1"
	 * example: '0101111101'B
	 */
	
	if( in->bv_val[0] != '\'' ||
		in->bv_val[in->bv_len-2] != '\'' ||
		in->bv_val[in->bv_len-1] != 'B' )
	{
		return LDAP_INVALID_SYNTAX;
	}

	for( i=in->bv_len-3; i>0; i-- ) {
		if( in->bv_val[i] != '0' && in->bv_val[i] != '1' ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
}

static int
bitStringNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	/*
	 * A normalized bitString is has no extaneous (leading) zero bits.
	 * That is, '00010'B is normalized to '10'B
	 * However, as a special case, '0'B requires no normalization.
	 */
	char *p;

	/* start at the first bit */
	p = &val->bv_val[1];

	/* Find the first non-zero bit */
	while ( *p == '0' ) p++;

	if( *p == '\'' ) {
		/* no non-zero bits */
		ber_str2bv( "\'0\'B", sizeof("\'0\'B") - 1, 1, normalized );
		goto done;
	}

	normalized->bv_val = ch_malloc( val->bv_len + 1 );

	normalized->bv_val[0] = '\'';
	normalized->bv_len = 1;

	for( ; *p != '\0'; p++ ) {
		normalized->bv_val[normalized->bv_len++] = *p;
	}

	normalized->bv_val[normalized->bv_len] = '\0';

done:
	return LDAP_SUCCESS;
}

static int
nameUIDValidate(
	Syntax *syntax,
	struct berval *in )
{
	int rc;
	struct berval dn;

	if( in->bv_len == 0 ) return LDAP_SUCCESS;

	ber_dupbv( &dn, in );
	if( !dn.bv_val ) return LDAP_OTHER;

	if( dn.bv_val[dn.bv_len-1] == 'B'
		&& dn.bv_val[dn.bv_len-2] == '\'' )
	{
		/* assume presence of optional UID */
		ber_len_t i;

		for(i=dn.bv_len-3; i>1; i--) {
			if( dn.bv_val[i] != '0' &&	dn.bv_val[i] != '1' ) {
				break;
			}
		}
		if( dn.bv_val[i] != '\'' || dn.bv_val[i-1] != '#' ) {
			ber_memfree( dn.bv_val );
			return LDAP_INVALID_SYNTAX;
		}

		/* trim the UID to allow use of dnValidate */
		dn.bv_val[i-1] = '\0';
		dn.bv_len = i-1;
	}

	rc = dnValidate( NULL, &dn );

	ber_memfree( dn.bv_val );
	return rc;
}

static int
nameUIDNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	struct berval out;
	int rc;

	ber_dupbv( &out, val );
	if( out.bv_len != 0 ) {
		struct berval uidin = { 0, NULL };
		struct berval uidout = { 0, NULL };

		if( out.bv_val[out.bv_len-1] == 'B'
			&& out.bv_val[out.bv_len-2] == '\'' )
		{
			/* assume presence of optional UID */
			uidin.bv_val = strrchr( out.bv_val, '#' );

			if( uidin.bv_val == NULL ) {
				free( out.bv_val );
				return LDAP_INVALID_SYNTAX;
			}

			uidin.bv_len = out.bv_len - (uidin.bv_val - out.bv_val);
			out.bv_len -= uidin.bv_len--;

			/* temporarily trim the UID */
			*(uidin.bv_val++) = '\0';

			rc = bitStringNormalize( syntax, &uidin, &uidout );

			if( rc != LDAP_SUCCESS ) {
				free( out.bv_val );
				return LDAP_INVALID_SYNTAX;
			}
		}

#ifdef USE_DN_NORMALIZE
		rc = dnNormalize2( NULL, &out, normalized );
#else
		rc = dnPretty2( NULL, &out, normalized );
#endif

		if( rc != LDAP_SUCCESS ) {
			free( out.bv_val );
			free( uidout.bv_val );
			return LDAP_INVALID_SYNTAX;
		}

		if( uidout.bv_len ) {
			normalized->bv_val = ch_realloc( normalized->bv_val,
				normalized->bv_len + uidout.bv_len + sizeof("#") );

			/* insert the separator */
			normalized->bv_val[normalized->bv_len++] = '#';

			/* append the UID */
			AC_MEMCPY( &normalized->bv_val[normalized->bv_len],
				uidout.bv_val, uidout.bv_len );
			normalized->bv_len += uidout.bv_len;

			/* terminate */
			normalized->bv_val[normalized->bv_len] = '\0';
		}

		free( out.bv_val );
	}

	return LDAP_SUCCESS;
}

/*
 * Handling boolean syntax and matching is quite rigid.
 * A more flexible approach would be to allow a variety
 * of strings to be normalized and prettied into TRUE
 * and FALSE.
 */
static int
booleanValidate(
	Syntax *syntax,
	struct berval *in )
{
	/* very unforgiving validation, requires no normalization
	 * before simplistic matching
	 */

	if( in->bv_len == 4 ) {
		if( !memcmp( in->bv_val, "TRUE", 4 ) ) {
			return LDAP_SUCCESS;
		}
	} else if( in->bv_len == 5 ) {
		if( !memcmp( in->bv_val, "FALSE", 5 ) ) {
			return LDAP_SUCCESS;
		}
	}

	return LDAP_INVALID_SYNTAX;
}

static int
booleanMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	/* simplistic matching allowed by rigid validation */
	struct berval *asserted = (struct berval *) assertedValue;
	*matchp = value->bv_len != asserted->bv_len;
	return LDAP_SUCCESS;
}

/*-------------------------------------------------------------------
LDAP/X.500 string syntax / matching rules have a few oddities.  This
comment attempts to detail how slapd(8) treats them.

Summary:
  StringSyntax		X.500	LDAP	Matching
  DirectoryString	CHOICE	UTF8	i/e + ignore insignificant spaces
  PrintableString	subset	subset	i/e + ignore insignificant spaces
  NumericString		subset	subset  ignore all spaces
  IA5String			ASCII	ASCII	i/e + ignore insignificant spaces
  TeletexString		T.61	T.61	i/e + ignore insignificant spaces

  TelephoneNumber subset  subset  i + ignore all spaces and "-"

  See draft-ietf-ldapbis-strpro for details (once published).


Directory String -
  In X.500(93), a directory string can be either a PrintableString,
  a bmpString, or a UniversalString (e.g., UCS (a subset of Unicode)).
  In later versions, more CHOICEs were added.  In all cases the string
  must be non-empty.

  In LDAPv3, a directory string is a UTF-8 encoded UCS string.

  For matching, there are both case ignore and exact rules.  Both
  also require that "insignificant" spaces be ignored.
	spaces before the first non-space are ignored;
	spaces after the last non-space are ignored;
	spaces after a space are ignored.
  Note: by these rules (and as clarified in X.520), a string of only
  spaces is to be treated as if held one space, not empty (which
  would be a syntax error).

NumericString
  In ASN.1, numeric string is just a string of digits and spaces
  and could be empty.  However, in X.500, all attribute values of
  numeric string carry a non-empty constraint.  For example:

	internationalISDNNumber ATTRIBUTE ::= {
		WITH SYNTAX InternationalISDNNumber
		EQUALITY MATCHING RULE numericStringMatch
		SUBSTRINGS MATCHING RULE numericStringSubstringsMatch
		ID id-at-internationalISDNNumber }
	InternationalISDNNumber ::=
	    NumericString (SIZE(1..ub-international-isdn-number))

  Unforunately, some assertion values are don't carry the same
  constraint (but its unclear how such an assertion could ever
  be true). In LDAP, there is one syntax (numericString) not two
  (numericString with constraint, numericString without constraint).
  This should be treated as numericString with non-empty constraint.
  Note that while someone may have no ISDN number, there are no ISDN
  numbers which are zero length.

  In matching, spaces are ignored.

PrintableString
  In ASN.1, Printable string is just a string of printable characters
  and can be empty.  In X.500, semantics much like NumericString (see
  serialNumber for a like example) excepting uses insignificant space
  handling instead of ignore all spaces.  

IA5String
  Basically same as PrintableString.  There are no examples in X.500,
  but same logic applies.  So we require them to be non-empty as
  well.

-------------------------------------------------------------------*/

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
		len = LDAP_UTF8_CHARLEN2( u, len );

		/* very basic checks */
		switch( len ) {
			case 6:
				if( (u[5] & 0xC0) != 0x80 ) {
					return LDAP_INVALID_SYNTAX;
				}
			case 5:
				if( (u[4] & 0xC0) != 0x80 ) {
					return LDAP_INVALID_SYNTAX;
				}
			case 4:
				if( (u[3] & 0xC0) != 0x80 ) {
					return LDAP_INVALID_SYNTAX;
				}
			case 3:
				if( (u[2] & 0xC0 )!= 0x80 ) {
					return LDAP_INVALID_SYNTAX;
				}
			case 2:
				if( (u[1] & 0xC0) != 0x80 ) {
					return LDAP_INVALID_SYNTAX;
				}
			case 1:
				/* CHARLEN already validated it */
				break;
			default:
				return LDAP_INVALID_SYNTAX;
		}

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
	struct berval *normalized )
{
	char *p, *q, *s, *e;
	int len = 0;

	/* validator should have refused an empty string */
	assert( val->bv_len );

	p = val->bv_val;

	/* Ignore initial whitespace */
	/* All space is ASCII. All ASCII is 1 byte */
	for ( ; p < val->bv_val + val->bv_len && ASCII_SPACE( p[ 0 ] ); p++ );

	normalized->bv_len = val->bv_len - (p - val->bv_val);

	if( !normalized->bv_len ) {
		ber_mem2bv( " ", 1, 1, normalized );
		return LDAP_SUCCESS;
	}

	ber_mem2bv( p, normalized->bv_len, 1, normalized );
	e = normalized->bv_val + normalized->bv_len;

	assert( normalized->bv_val );

	p = q = normalized->bv_val;
	s = NULL;

	while ( p < e ) {
		q += len;
		if ( ASCII_SPACE( *p ) ) {
			s = q - len;
			len = 1;
			*q = *p++;

			/* Ignore the extra whitespace */
			while ( ASCII_SPACE( *p ) ) {
				p++;
			}
		} else {
			len = LDAP_UTF8_COPY(q,p);
			s=NULL;
			p+=len;
		}
	}

	assert( normalized->bv_val <= p );
	assert( q+len <= p );

	/* cannot start with a space */
	assert( !ASCII_SPACE( normalized->bv_val[0] ) );

	/*
	 * If the string ended in space, backup the pointer one
	 * position.  One is enough because the above loop collapsed
	 * all whitespace to a single space.
	 */

	if ( s != NULL ) {
		len = q - s;
		q = s;
	}

	/* cannot end with a space */
	assert( !ASCII_SPACE( *q ) );

	q += len;

	/* null terminate */
	*q = '\0';

	normalized->bv_len = q - normalized->bv_val;

	return LDAP_SUCCESS;
}

/* Returns Unicode canonically normalized copy of a substring assertion
 * Skipping attribute description */
static SubstringsAssertion *
UTF8SubstringsassertionNormalize(
	SubstringsAssertion *sa,
	unsigned casefold )
{
	SubstringsAssertion *nsa;
	int i;

	nsa = (SubstringsAssertion *)ch_calloc( 1, sizeof(SubstringsAssertion) );
	if( nsa == NULL ) {
		return NULL;
	}

	if( sa->sa_initial.bv_val != NULL ) {
		UTF8bvnormalize( &sa->sa_initial, &nsa->sa_initial, casefold );
		if( nsa->sa_initial.bv_val == NULL ) {
			goto err;
		}
	}

	if( sa->sa_any != NULL ) {
		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			/* empty */
		}
		nsa->sa_any = (struct berval *)
			ch_malloc( (i + 1) * sizeof(struct berval) );

		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			UTF8bvnormalize( &sa->sa_any[i], &nsa->sa_any[i], 
				casefold );
			if( nsa->sa_any[i].bv_val == NULL ) {
				goto err;
			}
		}
		nsa->sa_any[i].bv_val = NULL;
	}

	if( sa->sa_final.bv_val != NULL ) {
		UTF8bvnormalize( &sa->sa_final, &nsa->sa_final, casefold );
		if( nsa->sa_final.bv_val == NULL ) {
			goto err;
		}
	}

	return nsa;

err:
	if ( nsa->sa_final.bv_val ) free( nsa->sa_final.bv_val );
	if ( nsa->sa_any ) ber_bvarray_free( nsa->sa_any );
	if ( nsa->sa_initial.bv_val ) free( nsa->sa_initial.bv_val );
	ch_free( nsa );
	return NULL;
}

#ifndef SLAPD_APPROX_OLDSINGLESTRING

#if defined(SLAPD_APPROX_INITIALS)
#define SLAPD_APPROX_DELIMITER "._ "
#define SLAPD_APPROX_WORDLEN 2
#else
#define SLAPD_APPROX_DELIMITER " "
#define SLAPD_APPROX_WORDLEN 1
#endif

static int
approxMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *nval, *assertv;
	char *val, **values, **words, *c;
	int i, count, len, nextchunk=0, nextavail=0;

	/* Yes, this is necessary */
	nval = UTF8bvnormalize( value, NULL, LDAP_UTF8_APPROX );
	if( nval == NULL ) {
		*matchp = 1;
		return LDAP_SUCCESS;
	}

	/* Yes, this is necessary */
	assertv = UTF8bvnormalize( ((struct berval *)assertedValue),
		NULL, LDAP_UTF8_APPROX );
	if( assertv == NULL ) {
		ber_bvfree( nval );
		*matchp = 1;
		return LDAP_SUCCESS;
	}

	/* Isolate how many words there are */
	for ( c = nval->bv_val, count = 1; *c; c++ ) {
		c = strpbrk( c, SLAPD_APPROX_DELIMITER );
		if ( c == NULL ) break;
		*c = '\0';
		count++;
	}

	/* Get a phonetic copy of each word */
	words = (char **)ch_malloc( count * sizeof(char *) );
	values = (char **)ch_malloc( count * sizeof(char *) );
	for ( c = nval->bv_val, i = 0;  i < count; i++, c += strlen(c) + 1 ) {
		words[i] = c;
		values[i] = phonetic(c);
	}

	/* Work through the asserted value's words, to see if at least some
	   of the words are there, in the same order. */
	len = 0;
	while ( (ber_len_t) nextchunk < assertv->bv_len ) {
		len = strcspn( assertv->bv_val + nextchunk, SLAPD_APPROX_DELIMITER);
		if( len == 0 ) {
			nextchunk++;
			continue;
		}
#if defined(SLAPD_APPROX_INITIALS)
		else if( len == 1 ) {
			/* Single letter words need to at least match one word's initial */
			for( i=nextavail; i<count; i++ )
				if( !strncasecmp( assertv->bv_val + nextchunk, words[i], 1 )) {
					nextavail=i+1;
					break;
				}
		}
#endif
		else {
			/* Isolate the next word in the asserted value and phonetic it */
			assertv->bv_val[nextchunk+len] = '\0';
			val = phonetic( assertv->bv_val + nextchunk );

			/* See if this phonetic chunk is in the remaining words of *value */
			for( i=nextavail; i<count; i++ ){
				if( !strcmp( val, values[i] ) ){
					nextavail = i+1;
					break;
				}
			}
			ch_free( val );
		}

		/* This chunk in the asserted value was NOT within the *value. */
		if( i >= count ) {
			nextavail=-1;
			break;
		}

		/* Go on to the next word in the asserted value */
		nextchunk += len+1;
	}

	/* If some of the words were seen, call it a match */
	if( nextavail > 0 ) {
		*matchp = 0;
	}
	else {
		*matchp = 1;
	}

	/* Cleanup allocs */
	ber_bvfree( assertv );
	for( i=0; i<count; i++ ) {
		ch_free( values[i] );
	}
	ch_free( values );
	ch_free( words );
	ber_bvfree( nval );

	return LDAP_SUCCESS;
}

static int 
approxIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	char *c;
	int i,j, len, wordcount, keycount=0;
	struct berval *newkeys;
	BerVarray keys=NULL;

	for( j=0; values[j].bv_val != NULL; j++ ) {
		struct berval val = { 0, NULL };
		/* Yes, this is necessary */
		UTF8bvnormalize( &values[j], &val, LDAP_UTF8_APPROX );
		assert( val.bv_val != NULL );

		/* Isolate how many words there are. There will be a key for each */
		for( wordcount = 0, c = val.bv_val; *c; c++) {
			len = strcspn(c, SLAPD_APPROX_DELIMITER);
			if( len >= SLAPD_APPROX_WORDLEN ) wordcount++;
			c+= len;
			if (*c == '\0') break;
			*c = '\0';
		}

		/* Allocate/increase storage to account for new keys */
		newkeys = (struct berval *)ch_malloc( (keycount + wordcount + 1) 
			* sizeof(struct berval) );
		AC_MEMCPY( newkeys, keys, keycount * sizeof(struct berval) );
		if( keys ) ch_free( keys );
		keys = newkeys;

		/* Get a phonetic copy of each word */
		for( c = val.bv_val, i = 0; i < wordcount; c += len + 1 ) {
			len = strlen( c );
			if( len < SLAPD_APPROX_WORDLEN ) continue;
			ber_str2bv( phonetic( c ), 0, 0, &keys[keycount] );
			keycount++;
			i++;
		}

		ber_memfree( val.bv_val );
	}
	keys[keycount].bv_val = NULL;
	*keysp = keys;

	return LDAP_SUCCESS;
}

static int 
approxFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	char *c;
	int i, count, len;
	struct berval *val;
	BerVarray keys;

	/* Yes, this is necessary */
	val = UTF8bvnormalize( ((struct berval *)assertedValue),
		NULL, LDAP_UTF8_APPROX );
	if( val == NULL || val->bv_val == NULL ) {
		keys = (struct berval *)ch_malloc( sizeof(struct berval) );
		keys[0].bv_val = NULL;
		*keysp = keys;
		ber_bvfree( val );
		return LDAP_SUCCESS;
	}

	/* Isolate how many words there are. There will be a key for each */
	for( count = 0,c = val->bv_val; *c; c++) {
		len = strcspn(c, SLAPD_APPROX_DELIMITER);
		if( len >= SLAPD_APPROX_WORDLEN ) count++;
		c+= len;
		if (*c == '\0') break;
		*c = '\0';
	}

	/* Allocate storage for new keys */
	keys = (struct berval *)ch_malloc( (count + 1) * sizeof(struct berval) );

	/* Get a phonetic copy of each word */
	for( c = val->bv_val, i = 0; i < count; c += len + 1 ) {
		len = strlen(c);
		if( len < SLAPD_APPROX_WORDLEN ) continue;
		ber_str2bv( phonetic( c ), 0, 0, &keys[i] );
		i++;
	}

	ber_bvfree( val );

	keys[count].bv_val = NULL;
	*keysp = keys;

	return LDAP_SUCCESS;
}


#else
/* No other form of Approximate Matching is defined */

static int
approxMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	char *vapprox, *avapprox;
	char *s, *t;

	/* Yes, this is necessary */
	s = UTF8normalize( value, UTF8_NOCASEFOLD );
	if( s == NULL ) {
		*matchp = 1;
		return LDAP_SUCCESS;
	}

	/* Yes, this is necessary */
	t = UTF8normalize( ((struct berval *)assertedValue),
			   UTF8_NOCASEFOLD );
	if( t == NULL ) {
		free( s );
		*matchp = -1;
		return LDAP_SUCCESS;
	}

	vapprox = phonetic( strip8bitChars( s ) );
	avapprox = phonetic( strip8bitChars( t ) );

	free( s );
	free( t );

	*matchp = strcmp( vapprox, avapprox );

	ch_free( vapprox );
	ch_free( avapprox );

	return LDAP_SUCCESS;
}

static int 
approxIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	BerVarray *keys;
	char *s;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* empty - just count them */
	}

	/* we should have at least one value at this point */
	assert( i > 0 );

	keys = (struct berval *)ch_malloc( sizeof( struct berval ) * (i+1) );

	/* Copy each value and run it through phonetic() */
	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* Yes, this is necessary */
		s = UTF8normalize( &values[i], UTF8_NOCASEFOLD );

		/* strip 8-bit chars and run through phonetic() */
		ber_str2bv( phonetic( strip8bitChars( s ) ), 0, 0, &keys[i] );
		free( s );
	}
	keys[i].bv_val = NULL;

	*keysp = keys;
	return LDAP_SUCCESS;
}


static int 
approxFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	BerVarray keys;
	char *s;

	keys = (struct berval *)ch_malloc( sizeof( struct berval * ) * 2 );

	/* Yes, this is necessary */
	s = UTF8normalize( ((struct berval *)assertedValue),
			     UTF8_NOCASEFOLD );
	if( s == NULL ) {
		keys[0] = NULL;
	} else {
		/* strip 8-bit chars and run through phonetic() */
		keys[0] = ber_bvstr( phonetic( strip8bitChars( s ) ) );
		free( s );
		keys[1] = NULL;
	}

	*keysp = keys;
	return LDAP_SUCCESS;
}
#endif


static int
caseExactMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	*matchp = UTF8bvnormcmp( value,
		(struct berval *) assertedValue,
		LDAP_UTF8_NOCASEFOLD );
	return LDAP_SUCCESS;
}

static int
caseExactIgnoreSubstringsMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = 0;
	SubstringsAssertion *sub = NULL;
	struct berval left = { 0, NULL };
	int i;
	ber_len_t inlen=0;
	char *nav = NULL;
	unsigned casefold;

	casefold = ( mr != caseExactSubstringsMatchingRule )
		? LDAP_UTF8_CASEFOLD : LDAP_UTF8_NOCASEFOLD;

	if ( UTF8bvnormalize( value, &left, casefold ) == NULL ) {
		match = 1;
		goto done;
	}
	nav = left.bv_val;

	sub = UTF8SubstringsassertionNormalize( assertedValue, casefold );
	if( sub == NULL ) {
		match = -1;
		goto done;
	}

	/* Add up asserted input length */
	if( sub->sa_initial.bv_val ) {
		inlen += sub->sa_initial.bv_len;
	}
	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i].bv_val != NULL; i++) {
			inlen += sub->sa_any[i].bv_len;
		}
	}
	if( sub->sa_final.bv_val ) {
		inlen += sub->sa_final.bv_len;
	}

	if( sub->sa_initial.bv_val ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = memcmp( sub->sa_initial.bv_val, left.bv_val,
			sub->sa_initial.bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_val += sub->sa_initial.bv_len;
		left.bv_len -= sub->sa_initial.bv_len;
		inlen -= sub->sa_initial.bv_len;
	}

	if( sub->sa_final.bv_val ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = memcmp( sub->sa_final.bv_val,
			&left.bv_val[left.bv_len - sub->sa_final.bv_len],
			sub->sa_final.bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_len -= sub->sa_final.bv_len;
		inlen -= sub->sa_final.bv_len;
	}

	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i].bv_val; i++) {
			ber_len_t idx;
			char *p;

retry:
			if( inlen > left.bv_len ) {
				/* not enough length */
				match = 1;
				goto done;
			}

			if( sub->sa_any[i].bv_len == 0 ) {
				continue;
			}

			p = ber_bvchr( &left, *sub->sa_any[i].bv_val );
			if ( p == NULL ) {
				match = 1;
				goto done;
			}

			idx = p - left.bv_val;

			if( idx >= left.bv_len ) {
				/* this shouldn't happen */
				free( nav );
				if ( sub->sa_final.bv_val )
					ch_free( sub->sa_final.bv_val );
				if ( sub->sa_any )
					ber_bvarray_free( sub->sa_any );
				if ( sub->sa_initial.bv_val )
					ch_free( sub->sa_initial.bv_val );
				ch_free( sub );
				return LDAP_OTHER;
			}

			left.bv_val = p;
			left.bv_len -= idx;

			if( sub->sa_any[i].bv_len > left.bv_len ) {
				/* not enough left */
				match = 1;
				goto done;
			}

			match = memcmp( left.bv_val,
				sub->sa_any[i].bv_val,
				sub->sa_any[i].bv_len );

			if( match != 0 ) {
				left.bv_val++;
				left.bv_len--;
				goto retry;
			}

			left.bv_val += sub->sa_any[i].bv_len;
			left.bv_len -= sub->sa_any[i].bv_len;
			inlen -= sub->sa_any[i].bv_len;
		}
	}

done:
	free( nav );
	if( sub != NULL ) {
		if ( sub->sa_final.bv_val ) free( sub->sa_final.bv_val );
		if ( sub->sa_any ) ber_bvarray_free( sub->sa_any );
		if ( sub->sa_initial.bv_val ) free( sub->sa_initial.bv_val );
		ch_free( sub );
	}
	*matchp = match;
	return LDAP_SUCCESS;
}

/* Index generation function */
static int caseExactIgnoreIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	unsigned casefold;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* empty - just count them */
	}

	/* we should have at least one value at this point */
	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval ) * (i+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	casefold = ( mr != caseExactMatchingRule )
		? LDAP_UTF8_CASEFOLD : LDAP_UTF8_NOCASEFOLD;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		struct berval value;
		UTF8bvnormalize( &values[i], &value, casefold );

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			value.bv_val, value.bv_len );
		HASH_Final( HASHdigest, &HASHcontext );

		free( value.bv_val );

		ber_dupbv( &keys[i], &digest );
	}

	keys[i].bv_val = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
static int caseExactIgnoreFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	unsigned casefold;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval value = { 0, NULL };
	struct berval digest;

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	casefold = ( mr != caseExactMatchingRule )
		? LDAP_UTF8_CASEFOLD : LDAP_UTF8_NOCASEFOLD;

	UTF8bvnormalize( (struct berval *) assertedValue, &value, casefold );
	/* This usually happens if filter contains bad UTF8 */
	if( value.bv_val == NULL ) {
		keys = ch_malloc( sizeof( struct berval ) );
		keys[0].bv_val = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval ) * 2 );

	HASH_Init( &HASHcontext );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		HASH_Update( &HASHcontext,
			prefix->bv_val, prefix->bv_len );
	}
	HASH_Update( &HASHcontext,
		syntax->ssyn_oid, slen );
	HASH_Update( &HASHcontext,
		mr->smr_oid, mlen );
	HASH_Update( &HASHcontext,
		value.bv_val, value.bv_len );
	HASH_Final( HASHdigest, &HASHcontext );

	ber_dupbv( keys, &digest );
	keys[1].bv_val = NULL;

	free( value.bv_val );

	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
static int caseExactIgnoreSubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	unsigned casefold;
	ber_len_t i, nkeys;
	size_t slen, mlen;
	BerVarray keys;
	BerVarray nvalues;

	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	nkeys=0;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* empty - just count them */
	}

	/* we should have at least one value at this point */
	assert( i > 0 );

	casefold = ( mr != caseExactSubstringsMatchingRule )
		? LDAP_UTF8_CASEFOLD : LDAP_UTF8_NOCASEFOLD;

	nvalues = ch_malloc( sizeof( struct berval ) * (i+1) );
	for( i=0; values[i].bv_val != NULL; i++ ) {
		UTF8bvnormalize( &values[i], &nvalues[i], casefold );
	}
	nvalues[i].bv_val = NULL;
	values = nvalues;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i].bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		ber_bvarray_free( nvalues );
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval ) * (nkeys+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	nkeys=0;
	for( i=0; values[i].bv_val != NULL; i++ ) {
		ber_len_t j,max;

		if( values[i].bv_len < SLAP_INDEX_SUBSTR_MINLEN ) continue;

		if( ( flags & SLAP_INDEX_SUBSTR_ANY ) &&
			( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) )
		{
			char pre = SLAP_INDEX_SUBSTR_PREFIX;
			max = values[i].bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1);

			for( j=0; j<max; j++ ) {
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}

				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&values[i].bv_val[j],
					SLAP_INDEX_SUBSTR_MAXLEN );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}
		}

		max = SLAP_INDEX_SUBSTR_MAXLEN < values[i].bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : values[i].bv_len;

		for( j=SLAP_INDEX_SUBSTR_MINLEN; j<=max; j++ ) {
			char pre;

			if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
				pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					values[i].bv_val, j );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

			if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
				pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&values[i].bv_val[values[i].bv_len-j], j );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

		}

	}

	if( nkeys > 0 ) {
		keys[nkeys].bv_val = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	ber_bvarray_free( nvalues );

	return LDAP_SUCCESS;
}

static int caseExactIgnoreSubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	SubstringsAssertion *sa;
	char pre;
	unsigned casefold;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;

	casefold = ( mr != caseExactSubstringsMatchingRule )
		? LDAP_UTF8_CASEFOLD : LDAP_UTF8_NOCASEFOLD;

	sa = UTF8SubstringsassertionNormalize( assertedValue, casefold );
	if( sa == NULL ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial.bv_val != NULL &&
		sa->sa_initial.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			if( sa->sa_any[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i].bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final.bv_val != NULL &&
		sa->sa_final.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		if ( sa->sa_final.bv_val ) free( sa->sa_final.bv_val );
		if ( sa->sa_any ) ber_bvarray_free( sa->sa_any );
		if ( sa->sa_initial.bv_val ) free( sa->sa_initial.bv_val );
		ch_free( sa );
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	keys = ch_malloc( sizeof( struct berval ) * (nkeys+1) );
	nkeys = 0;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial.bv_val != NULL &&
		sa->sa_initial.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		value = &sa->sa_initial;

		klen = SLAP_INDEX_SUBSTR_MAXLEN < value->bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value->bv_len;

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			&pre, sizeof( pre ) );
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			value->bv_val, klen );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[nkeys++], &digest );
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			if( sa->sa_any[i].bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			value = &sa->sa_any[i];

			for(j=0;
				j <= value->bv_len - SLAP_INDEX_SUBSTR_MAXLEN;
				j += SLAP_INDEX_SUBSTR_STEP )
			{
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value->bv_val[j], klen ); 
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final.bv_val != NULL &&
		sa->sa_final.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		value = &sa->sa_final;

		klen = SLAP_INDEX_SUBSTR_MAXLEN < value->bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value->bv_len;

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			&pre, sizeof( pre ) );
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			&value->bv_val[value->bv_len-klen], klen );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[nkeys++], &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys].bv_val = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}
	if ( sa->sa_final.bv_val ) free( sa->sa_final.bv_val );
	if ( sa->sa_any ) ber_bvarray_free( sa->sa_any );
	if ( sa->sa_initial.bv_val ) free( sa->sa_initial.bv_val );
	ch_free( sa );

	return LDAP_SUCCESS;
}

static int
caseIgnoreMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	*matchp = UTF8bvnormcmp( value,
		(struct berval *) assertedValue,
		LDAP_UTF8_CASEFOLD );
	return LDAP_SUCCESS;
}
	
/* Remove all spaces and '-' characters */
static int
telephoneNumberNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	char *p, *q;

	/* validator should have refused an empty string */
	assert( val->bv_len );

	q = normalized->bv_val = ch_malloc( val->bv_len + 1 );

	for( p = val->bv_val; *p; p++ ) {
		if ( ! ( ASCII_SPACE( *p ) || *p == '-' )) {
			*q++ = *p;
		}
	}
	*q = '\0';

	normalized->bv_len = q - normalized->bv_val;

	if( normalized->bv_len == 0 ) {
		free( normalized->bv_val );
		return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
oidValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( val->bv_len == 0 ) {
		/* disallow empty strings */
		return LDAP_INVALID_SYNTAX;
	}

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
integerMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	char *v, *av;
	int vsign = 1, avsign = 1;	/* default sign = '+' */
	struct berval *asserted;
	ber_len_t vlen, avlen;
	int match;

	/* Skip leading space/sign/zeroes, and get the sign of the *value number */
	v = value->bv_val;
	vlen = value->bv_len;
	if( mr == integerFirstComponentMatchingRule ) {
		char *tmp = memchr( v, '$', vlen );
		if( tmp )
			vlen = tmp - v;
		while( vlen && ASCII_SPACE( v[vlen-1] ))
			vlen--;
	}
	for( ; vlen && ( *v < '1' || '9' < *v ); v++, vlen-- ) /* ANSI 2.2.1 */
		if( *v == '-' )
			vsign = -1;
	if( vlen == 0 )
		vsign = 0;

	/* Do the same with the *assertedValue number */
	asserted = (struct berval *) assertedValue;
	av = asserted->bv_val;
	avlen = asserted->bv_len;
	for( ; avlen && ( *av < '1' || '9' < *av ); av++, avlen-- )
		if( *av == '-' )
			avsign = -1;
	if( avlen == 0 )
		avsign = 0;

	match = vsign - avsign;
	if( match == 0 ) {
		match = (vlen != avlen
			     ? ( vlen < avlen ? -1 : 1 )
			     : memcmp( v, av, vlen ));
		if( vsign < 0 )
			match = -match;
	}

	*matchp = match;
	return LDAP_SUCCESS;
}
	
static int
integerValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( !val->bv_len ) return LDAP_INVALID_SYNTAX;

	if(( val->bv_val[0] == '+' ) || ( val->bv_val[0] == '-' )) {
		if( val->bv_len < 2 ) return LDAP_INVALID_SYNTAX;
	} else if( !ASCII_DIGIT(val->bv_val[0]) ) {
		return LDAP_INVALID_SYNTAX;
	}

	for( i=1; i < val->bv_len; i++ ) {
		if( !ASCII_DIGIT(val->bv_val[i]) ) return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
integerNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	char *p;
	int negative=0;
	ber_len_t len;


	p = val->bv_val;
	len = val->bv_len;

	/* Ignore leading spaces */
	while ( len && ( *p == ' ' )) {
		p++;
		len--;
	}

	/* save sign */
	if( len ) {
		negative = ( *p == '-' );
		if(( *p == '-' ) || ( *p == '+' )) {
			p++;
			len--;
		}
	}

	/* Ignore leading zeros */
	while ( len && ( *p == '0' )) {
		p++;
		len--;
	}

	/* If there are no non-zero digits left, the number is zero, otherwise
	   allocate space for the number and copy it into the buffer */
	if( len == 0 ) {
		normalized->bv_val = ch_strdup("0");
		normalized->bv_len = 1;
	}
	else {
		normalized->bv_len = len+negative;
		normalized->bv_val = ch_malloc( normalized->bv_len + 1 );
		if( negative ) {
			normalized->bv_val[0] = '-';
		}
		AC_MEMCPY( normalized->bv_val + negative, p, len );
		normalized->bv_val[len+negative] = '\0';
	}

	return LDAP_SUCCESS;
}

/* Index generation function */
static int integerIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* empty - just count them */
	}

	/* we should have at least one value at this point */
	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval ) * (i+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		struct berval norm;
		integerNormalize( syntax, &values[i], &norm );

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			norm.bv_val, norm.bv_len );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[i], &digest );
		ch_free( norm.bv_val );
	}

	keys[i].bv_val = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
static int integerFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval norm;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	integerNormalize( syntax, assertedValue, &norm );

	keys = ch_malloc( sizeof( struct berval ) * 2 );

	HASH_Init( &HASHcontext );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		HASH_Update( &HASHcontext,
			prefix->bv_val, prefix->bv_len );
	}
	HASH_Update( &HASHcontext,
		syntax->ssyn_oid, slen );
	HASH_Update( &HASHcontext,
		mr->smr_oid, mlen );
	HASH_Update( &HASHcontext,
		norm.bv_val, norm.bv_len );
	HASH_Final( HASHdigest, &HASHcontext );

	ber_dupbv( &keys[0], &digest );
	keys[1].bv_val = NULL;
	ch_free( norm.bv_val );

	*keysp = keys;
	return LDAP_SUCCESS;
}


static int
countryStringValidate(
	Syntax *syntax,
	struct berval *val )
{
	if( val->bv_len != 2 ) return LDAP_INVALID_SYNTAX;

	if( !SLAP_PRINTABLE(val->bv_val[0]) ) {
		return LDAP_INVALID_SYNTAX;
	}
	if( !SLAP_PRINTABLE(val->bv_val[1]) ) {
		return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
printableStringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( val->bv_len == 0 ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < val->bv_len; i++) {
		if( !SLAP_PRINTABLE(val->bv_val[i]) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
}

static int
printablesStringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i, len;

	if( val->bv_len == 0 ) return LDAP_INVALID_SYNTAX;

	for(i=0,len=0; i < val->bv_len; i++) {
		int c = val->bv_val[i];

		if( c == '$' ) {
			if( len == 0 ) {
				return LDAP_INVALID_SYNTAX;
			}
			len = 0;

		} else if ( SLAP_PRINTABLE(c) ) {
			len++;
		} else {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if( len == 0 ) {
		return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
IA5StringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

	if( val->bv_len == 0 ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < val->bv_len; i++) {
		if( !LDAP_ASCII(val->bv_val[i]) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
}

static int
IA5StringNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	char *p, *q;

	assert( val->bv_len );

	p = val->bv_val;

	/* Ignore initial whitespace */
	while ( ASCII_SPACE( *p ) ) {
		p++;
	}

	normalized->bv_val = ch_strdup( p );
	p = q = normalized->bv_val;

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

	assert( normalized->bv_val <= p );
	assert( q <= p );

	/*
	 * If the string ended in space, backup the pointer one
	 * position.  One is enough because the above loop collapsed
	 * all whitespace to a single space.
	 */

	if ( ASCII_SPACE( q[-1] ) ) {
		--q;
	}

	/* null terminate */
	*q = '\0';

	normalized->bv_len = q - normalized->bv_val;

	if( normalized->bv_len == 0 ) {
		normalized->bv_val = ch_realloc( normalized->bv_val, 2 );
		normalized->bv_val[0] = ' ';
		normalized->bv_val[1] = '\0';
		normalized->bv_len = 1;
	}

	return LDAP_SUCCESS;
}

static int
caseExactIA5Match(
	int *matchp,
	slap_mask_t flags,
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
	slap_mask_t flags,
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
	if( sub->sa_initial.bv_val ) {
		inlen += sub->sa_initial.bv_len;
	}
	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i].bv_val != NULL; i++) {
			inlen += sub->sa_any[i].bv_len;
		}
	}
	if( sub->sa_final.bv_val ) {
		inlen += sub->sa_final.bv_len;
	}

	if( sub->sa_initial.bv_val ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncmp( sub->sa_initial.bv_val, left.bv_val,
			sub->sa_initial.bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_val += sub->sa_initial.bv_len;
		left.bv_len -= sub->sa_initial.bv_len;
		inlen -= sub->sa_initial.bv_len;
	}

	if( sub->sa_final.bv_val ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncmp( sub->sa_final.bv_val,
			&left.bv_val[left.bv_len - sub->sa_final.bv_len],
			sub->sa_final.bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_len -= sub->sa_final.bv_len;
		inlen -= sub->sa_final.bv_len;
	}

	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i].bv_val; i++) {
			ber_len_t idx;
			char *p;

retry:
			if( inlen > left.bv_len ) {
				/* not enough length */
				match = 1;
				goto done;
			}

			if( sub->sa_any[i].bv_len == 0 ) {
				continue;
			}

			p = strchr( left.bv_val, *sub->sa_any[i].bv_val );

			if( p == NULL ) {
				match = 1;
				goto done;
			}

			idx = p - left.bv_val;

			if( idx >= left.bv_len ) {
				/* this shouldn't happen */
				return LDAP_OTHER;
			}

			left.bv_val = p;
			left.bv_len -= idx;

			if( sub->sa_any[i].bv_len > left.bv_len ) {
				/* not enough left */
				match = 1;
				goto done;
			}

			match = strncmp( left.bv_val,
				sub->sa_any[i].bv_val,
				sub->sa_any[i].bv_len );

			if( match != 0 ) {
				left.bv_val++;
				left.bv_len--;
				goto retry;
			}

			left.bv_val += sub->sa_any[i].bv_len;
			left.bv_len -= sub->sa_any[i].bv_len;
			inlen -= sub->sa_any[i].bv_len;
		}
	}

done:
	*matchp = match;
	return LDAP_SUCCESS;
}

/* Index generation function */
static int caseExactIA5Indexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* empty - just count them */
	}

	/* we should have at least one value at this point */
	assert( i > 0 );

	keys = ch_malloc( sizeof( struct berval ) * (i+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		struct berval *value = &values[i];

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			value->bv_val, value->bv_len );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[i], &digest );
	}

	keys[i].bv_val = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
static int caseExactIA5Filter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	value = (struct berval *) assertedValue;

	keys = ch_malloc( sizeof( struct berval ) * 2 );

	HASH_Init( &HASHcontext );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		HASH_Update( &HASHcontext,
			prefix->bv_val, prefix->bv_len );
	}
	HASH_Update( &HASHcontext,
		syntax->ssyn_oid, slen );
	HASH_Update( &HASHcontext,
		mr->smr_oid, mlen );
	HASH_Update( &HASHcontext,
		value->bv_val, value->bv_len );
	HASH_Final( HASHdigest, &HASHcontext );

	ber_dupbv( &keys[0], &digest );
	keys[1].bv_val = NULL;

	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
static int caseExactIA5SubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	ber_len_t i, nkeys;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0].bv_val != NULL );

	nkeys=0;
	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i].bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval ) * (nkeys+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	nkeys=0;
	for( i=0; values[i].bv_val != NULL; i++ ) {
		ber_len_t j,max;
		struct berval *value;

		value = &values[i];
		if( value->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) continue;

		if( ( flags & SLAP_INDEX_SUBSTR_ANY ) &&
			( value->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) )
		{
			char pre = SLAP_INDEX_SUBSTR_PREFIX;
			max = value->bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1);

			for( j=0; j<max; j++ ) {
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}

				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value->bv_val[j],
					SLAP_INDEX_SUBSTR_MAXLEN );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}
		}

		max = SLAP_INDEX_SUBSTR_MAXLEN < value->bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value->bv_len;

		for( j=SLAP_INDEX_SUBSTR_MINLEN; j<=max; j++ ) {
			char pre;

			if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
				pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					value->bv_val, j );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

			if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
				pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value->bv_val[value->bv_len-j], j );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

		}
	}

	if( nkeys > 0 ) {
		keys[nkeys].bv_val = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}

static int caseExactIA5SubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	SubstringsAssertion *sa = assertedValue;
	char pre;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial.bv_val != NULL &&
		sa->sa_initial.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			if( sa->sa_any[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i].bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final.bv_val != NULL &&
		sa->sa_final.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	keys = ch_malloc( sizeof( struct berval ) * (nkeys+1) );
	nkeys = 0;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial.bv_val != NULL &&
		sa->sa_initial.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		value = &sa->sa_initial;

		klen = SLAP_INDEX_SUBSTR_MAXLEN < value->bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value->bv_len;

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			&pre, sizeof( pre ) );
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			value->bv_val, klen );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[nkeys++], &digest );
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			if( sa->sa_any[i].bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			value = &sa->sa_any[i];

			for(j=0;
				j <= value->bv_len - SLAP_INDEX_SUBSTR_MAXLEN;
				j += SLAP_INDEX_SUBSTR_STEP )
			{
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value->bv_val[j], klen ); 
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final.bv_val != NULL &&
		sa->sa_final.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		value = &sa->sa_final;

		klen = SLAP_INDEX_SUBSTR_MAXLEN < value->bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value->bv_len;

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			&pre, sizeof( pre ) );
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			&value->bv_val[value->bv_len-klen], klen );
		HASH_Final( HASHdigest, &HASHcontext );

		ber_dupbv( &keys[nkeys++], &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys].bv_val = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}
	
static int
caseIgnoreIA5Match(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	int match = value->bv_len - ((struct berval *) assertedValue)->bv_len;

	if( match == 0 && value->bv_len ) {
		match = strncasecmp( value->bv_val,
			((struct berval *) assertedValue)->bv_val,
			value->bv_len );
	}

	*matchp = match;
	return LDAP_SUCCESS;
}

static int
caseIgnoreIA5SubstringsMatch(
	int *matchp,
	slap_mask_t flags,
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
	if( sub->sa_initial.bv_val ) {
		inlen += sub->sa_initial.bv_len;
	}
	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i].bv_val != NULL; i++) {
			inlen += sub->sa_any[i].bv_len;
		}
	}
	if( sub->sa_final.bv_val ) {
		inlen += sub->sa_final.bv_len;
	}

	if( sub->sa_initial.bv_val ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncasecmp( sub->sa_initial.bv_val, left.bv_val,
			sub->sa_initial.bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_val += sub->sa_initial.bv_len;
		left.bv_len -= sub->sa_initial.bv_len;
		inlen -= sub->sa_initial.bv_len;
	}

	if( sub->sa_final.bv_val ) {
		if( inlen > left.bv_len ) {
			match = 1;
			goto done;
		}

		match = strncasecmp( sub->sa_final.bv_val,
			&left.bv_val[left.bv_len - sub->sa_final.bv_len],
			sub->sa_final.bv_len );

		if( match != 0 ) {
			goto done;
		}

		left.bv_len -= sub->sa_final.bv_len;
		inlen -= sub->sa_final.bv_len;
	}

	if( sub->sa_any ) {
		for(i=0; sub->sa_any[i].bv_val; i++) {
			ber_len_t idx;
			char *p;

retry:
			if( inlen > left.bv_len ) {
				/* not enough length */
				match = 1;
				goto done;
			}

			if( sub->sa_any[i].bv_len == 0 ) {
				continue;
			}

			p = bvcasechr( &left, *sub->sa_any[i].bv_val, &idx );

			if( p == NULL ) {
				match = 1;
				goto done;
			}

			assert( idx < left.bv_len );
			if( idx >= left.bv_len ) {
				/* this shouldn't happen */
				return LDAP_OTHER;
			}

			left.bv_val = p;
			left.bv_len -= idx;

			if( sub->sa_any[i].bv_len > left.bv_len ) {
				/* not enough left */
				match = 1;
				goto done;
			}

			match = strncasecmp( left.bv_val,
				sub->sa_any[i].bv_val,
				sub->sa_any[i].bv_len );

			if( match != 0 ) {
				left.bv_val++;
				left.bv_len--;

				goto retry;
			}

			left.bv_val += sub->sa_any[i].bv_len;
			left.bv_len -= sub->sa_any[i].bv_len;
			inlen -= sub->sa_any[i].bv_len;
		}
	}

done:
	*matchp = match;
	return LDAP_SUCCESS;
}

/* Index generation function */
static int caseIgnoreIA5Indexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	int rc = LDAP_SUCCESS;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0].bv_val != NULL );

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* just count them */
	}

	keys = ch_malloc( sizeof( struct berval ) * (i+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	for( i=0; values[i].bv_val != NULL; i++ ) {
		struct berval value;

		if( mr->smr_normalize ) {
			rc = (mr->smr_normalize)( use, syntax, mr, &values[i], &value );
			if( rc != LDAP_SUCCESS ) {
				break;
			}
		} else if ( mr->smr_syntax->ssyn_normalize ) {
			rc = (mr->smr_syntax->ssyn_normalize)( syntax, &values[i], &value );
			if( rc != LDAP_SUCCESS ) {
				break;
			}
		} else {
			ber_dupbv( &value, &values[i] );
		}

		ldap_pvt_str2lower( value.bv_val );

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			value.bv_val, value.bv_len );
		HASH_Final( HASHdigest, &HASHcontext );

		free( value.bv_val );

		ber_dupbv( &keys[i], &digest );
	}

	keys[i].bv_val = NULL;
	if( rc != LDAP_SUCCESS ) {
		ber_bvarray_free( keys );
		keys = NULL;
	}
	*keysp = keys;
	return rc;
}

/* Index generation function */
static int caseIgnoreIA5Filter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval value;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	ber_dupbv( &value, (struct berval *) assertedValue );
	ldap_pvt_str2lower( value.bv_val );

	keys = ch_malloc( sizeof( struct berval ) * 2 );

	HASH_Init( &HASHcontext );
	if( prefix != NULL && prefix->bv_len > 0 ) {
		HASH_Update( &HASHcontext,
			prefix->bv_val, prefix->bv_len );
	}
	HASH_Update( &HASHcontext,
		syntax->ssyn_oid, slen );
	HASH_Update( &HASHcontext,
		mr->smr_oid, mlen );
	HASH_Update( &HASHcontext,
		value.bv_val, value.bv_len );
	HASH_Final( HASHdigest, &HASHcontext );

	ber_dupbv( &keys[0], &digest );
	keys[1].bv_val = NULL;

	free( value.bv_val );

	*keysp = keys;

	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
static int caseIgnoreIA5SubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	ber_len_t i, nkeys;
	size_t slen, mlen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0].bv_val != NULL );

	nkeys=0;
	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i].bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i].bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval ) * (nkeys+1) );

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	nkeys=0;
	for( i=0; values[i].bv_val != NULL; i++ ) {
		int j,max;
		struct berval value;

		if( values[i].bv_len < SLAP_INDEX_SUBSTR_MINLEN ) continue;

		ber_dupbv( &value, &values[i] );
		ldap_pvt_str2lower( value.bv_val );

		if( ( flags & SLAP_INDEX_SUBSTR_ANY ) &&
			( value.bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) )
		{
			char pre = SLAP_INDEX_SUBSTR_PREFIX;
			max = value.bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1);

			for( j=0; j<max; j++ ) {
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}

				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value.bv_val[j],
					SLAP_INDEX_SUBSTR_MAXLEN );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}
		}

		max = SLAP_INDEX_SUBSTR_MAXLEN < value.bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value.bv_len;

		for( j=SLAP_INDEX_SUBSTR_MINLEN; j<=max; j++ ) {
			char pre;

			if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
				pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					value.bv_val, j );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

			if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
				pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value.bv_val[value.bv_len-j], j );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

		}

		free( value.bv_val );
	}

	if( nkeys > 0 ) {
		keys[nkeys].bv_val = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}

static int caseIgnoreIA5SubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	SubstringsAssertion *sa = assertedValue;
	char pre;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	BerVarray keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char	HASHdigest[HASH_BYTES];
	struct berval value;
	struct berval digest;

	if((flags & SLAP_INDEX_SUBSTR_INITIAL) && sa->sa_initial.bv_val != NULL &&
		sa->sa_initial.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if((flags & SLAP_INDEX_SUBSTR_ANY) && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			if( sa->sa_any[i].bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i].bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if((flags & SLAP_INDEX_SUBSTR_FINAL) && sa->sa_final.bv_val != NULL &&
		sa->sa_final.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = syntax->ssyn_oidlen;
	mlen = mr->smr_oidlen;

	keys = ch_malloc( sizeof( struct berval ) * (nkeys+1) );
	nkeys = 0;

	if((flags & SLAP_INDEX_SUBSTR_INITIAL) && sa->sa_initial.bv_val != NULL &&
		sa->sa_initial.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		ber_dupbv( &value, &sa->sa_initial );
		ldap_pvt_str2lower( value.bv_val );

		klen = SLAP_INDEX_SUBSTR_MAXLEN < value.bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value.bv_len;

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			&pre, sizeof( pre ) );
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			value.bv_val, klen );
		HASH_Final( HASHdigest, &HASHcontext );

		free( value.bv_val );
		ber_dupbv( &keys[nkeys++], &digest );
	}

	if((flags & SLAP_INDEX_SUBSTR_ANY) && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i].bv_val != NULL; i++ ) {
			if( sa->sa_any[i].bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			ber_dupbv( &value, &sa->sa_any[i] );
			ldap_pvt_str2lower( value.bv_val );

			for(j=0;
				j <= value.bv_len - SLAP_INDEX_SUBSTR_MAXLEN;
				j += SLAP_INDEX_SUBSTR_STEP )
			{
				HASH_Init( &HASHcontext );
				if( prefix != NULL && prefix->bv_len > 0 ) {
					HASH_Update( &HASHcontext,
						prefix->bv_val, prefix->bv_len );
				}
				HASH_Update( &HASHcontext,
					&pre, sizeof( pre ) );
				HASH_Update( &HASHcontext,
					syntax->ssyn_oid, slen );
				HASH_Update( &HASHcontext,
					mr->smr_oid, mlen );
				HASH_Update( &HASHcontext,
					&value.bv_val[j], klen );
				HASH_Final( HASHdigest, &HASHcontext );

				ber_dupbv( &keys[nkeys++], &digest );
			}

			free( value.bv_val );
		}
	}

	if((flags & SLAP_INDEX_SUBSTR_FINAL) && sa->sa_final.bv_val != NULL &&
		sa->sa_final.bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		ber_dupbv( &value, &sa->sa_final );
		ldap_pvt_str2lower( value.bv_val );

		klen = SLAP_INDEX_SUBSTR_MAXLEN < value.bv_len
			? SLAP_INDEX_SUBSTR_MAXLEN : value.bv_len;

		HASH_Init( &HASHcontext );
		if( prefix != NULL && prefix->bv_len > 0 ) {
			HASH_Update( &HASHcontext,
				prefix->bv_val, prefix->bv_len );
		}
		HASH_Update( &HASHcontext,
			&pre, sizeof( pre ) );
		HASH_Update( &HASHcontext,
			syntax->ssyn_oid, slen );
		HASH_Update( &HASHcontext,
			mr->smr_oid, mlen );
		HASH_Update( &HASHcontext,
			&value.bv_val[value.bv_len-klen], klen );
		HASH_Final( HASHdigest, &HASHcontext );

		free( value.bv_val );
		ber_dupbv( &keys[nkeys++], &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys].bv_val = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}
	
static int
numericStringValidate(
	Syntax *syntax,
	struct berval *in )
{
	ber_len_t i;

	if( in->bv_len == 0 ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < in->bv_len; i++) {
		if( !SLAP_NUMERIC(in->bv_val[i]) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
}

static int
numericStringNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	/* removal all spaces */
	char *p, *q;

	assert( val->bv_len );

	normalized->bv_val = ch_malloc( val->bv_len + 1 );

	p = val->bv_val;
	q = normalized->bv_val;

	while ( *p ) {
		if ( ASCII_SPACE( *p ) ) {
			/* Ignore whitespace */
			p++;
		} else {
			*q++ = *p++;
		}
	}

	/* we should have copied no more then is in val */
	assert( (q - normalized->bv_val) <= (p - val->bv_val) );

	/* null terminate */
	*q = '\0';

	normalized->bv_len = q - normalized->bv_val;

	if( normalized->bv_len == 0 ) {
		normalized->bv_val = ch_realloc( normalized->bv_val, 2 );
		normalized->bv_val[0] = ' ';
		normalized->bv_val[1] = '\0';
		normalized->bv_len = 1;
	}

	return LDAP_SUCCESS;
}

static int
objectIdentifierFirstComponentMatch(
	int *matchp,
	slap_mask_t flags,
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
		rc = objectIdentifierMatch( &match, flags, syntax, mr, &oid, asserted );

	} else {
		if ( !strcmp( syntax->ssyn_oid, SLAP_SYNTAX_MATCHINGRULES_OID ) ) {
			MatchingRule *asserted_mr = mr_bvfind( asserted );
			MatchingRule *stored_mr = mr_bvfind( &oid );

			if( asserted_mr == NULL ) {
				rc = SLAPD_COMPARE_UNDEFINED;
			} else {
				match = asserted_mr != stored_mr;
			}

		} else if ( !strcmp( syntax->ssyn_oid,
			SLAP_SYNTAX_ATTRIBUTETYPES_OID ) )
		{
			AttributeType *asserted_at = at_bvfind( asserted );
			AttributeType *stored_at = at_bvfind( &oid );

			if( asserted_at == NULL ) {
				rc = SLAPD_COMPARE_UNDEFINED;
			} else {
				match = asserted_at != stored_at;
			}

		} else if ( !strcmp( syntax->ssyn_oid,
			SLAP_SYNTAX_OBJECTCLASSES_OID ) )
		{
			ObjectClass *asserted_oc = oc_bvfind( asserted );
			ObjectClass *stored_oc = oc_bvfind( &oid );

			if( asserted_oc == NULL ) {
				rc = SLAPD_COMPARE_UNDEFINED;
			} else {
				match = asserted_oc != stored_oc;
			}
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONFIG, ENTRY, 
		"objectIdentifierFirstComponentMatch: %d\n %s\n %s\n",
		match, value->bv_val, asserted->bv_val );
#else
	Debug( LDAP_DEBUG_ARGS, "objectIdentifierFirstComponentMatch "
		"%d\n\t\"%s\"\n\t\"%s\"\n",
		match, value->bv_val, asserted->bv_val );
#endif


	if( rc == LDAP_SUCCESS ) *matchp = match;
	return rc;
}

static int
integerBitAndMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	long lValue, lAssertedValue;

	/* safe to assume integers are NUL terminated? */
	lValue = strtoul(value->bv_val, NULL, 10);
	if(( lValue == LONG_MIN || lValue == LONG_MAX) && errno == ERANGE )
		return LDAP_CONSTRAINT_VIOLATION;

	lAssertedValue = strtol(((struct berval *)assertedValue)->bv_val, NULL, 10);
	if(( lAssertedValue == LONG_MIN || lAssertedValue == LONG_MAX) && errno == ERANGE )
		return LDAP_CONSTRAINT_VIOLATION;

	*matchp = (lValue & lAssertedValue) ? 0 : 1;
	return LDAP_SUCCESS;
}

static int
integerBitOrMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	long lValue, lAssertedValue;

	/* safe to assume integers are NUL terminated? */
	lValue = strtoul(value->bv_val, NULL, 10);
	if(( lValue == LONG_MIN || lValue == LONG_MAX) && errno == ERANGE )
		return LDAP_CONSTRAINT_VIOLATION;

	lAssertedValue = strtol(((struct berval *)assertedValue)->bv_val, NULL, 10);
	if(( lAssertedValue == LONG_MIN || lAssertedValue == LONG_MAX) && errno == ERANGE )
		return LDAP_CONSTRAINT_VIOLATION;

	*matchp = (lValue | lAssertedValue) ? 0 : -1;
	return LDAP_SUCCESS;
}

#ifdef HAVE_TLS
#include <openssl/x509.h>
#include <openssl/err.h>
char digit[] = "0123456789";

/*
 * Next function returns a string representation of a ASN1_INTEGER.
 * It works for unlimited lengths.
 */

static struct berval *
asn1_integer2str(ASN1_INTEGER *a, struct berval *bv)
{
	char buf[256];
	char *p;
  
	/* We work backwards, make it fill from the end of buf */
	p = buf + sizeof(buf) - 1;
	*p = '\0';

	if ( a == NULL || a->length == 0 ) {
		*--p = '0';
	} else {
		int i;
		int n = a->length;
		int base = 0;
		unsigned int *copy;

		/* We want to preserve the original */
		copy = ch_malloc(n*sizeof(unsigned int));
		for (i = 0; i<n; i++) {
			copy[i] = a->data[i];
		}

		/* 
		 * base indicates the index of the most significant
		 * byte that might be nonzero.  When it goes off the
		 * end, we now there is nothing left to do.
		 */
		while (base < n) {
			unsigned int carry;

			carry = 0;
			for (i = base; i<n; i++ ) {
				copy[i] += carry*256;
				carry = copy[i] % 10;
				copy[i] /= 10;
			}
			if (p <= buf+1) {
				/*
				 * Way too large, we need to leave
				 * room for sign if negative
				 */
				free(copy);
				return NULL;
			}
			*--p = digit[carry];
			if (copy[base] == 0)
				base++;
		}
		free(copy);
	}

	if ( a->type == V_ASN1_NEG_INTEGER ) {
		*--p = '-';
	}

	return ber_str2bv( p, 0, 1, bv );
}

/*
 * Given a certificate in DER format, extract the corresponding
 * assertion value for certificateExactMatch
 */
static int
certificateExactConvert(
	struct berval * in,
	struct berval * out )
{
	X509 *xcert;
	unsigned char *p = in->bv_val;
	struct berval serial;
	struct berval issuer_dn;

	xcert = d2i_X509(NULL, &p, in->bv_len);
	if ( !xcert ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ENTRY, 
			"certificateExactConvert: error parsing cert: %s\n",
			ERR_error_string(ERR_get_error(),NULL), 0, 0 );
#else
		Debug( LDAP_DEBUG_ARGS, "certificateExactConvert: "
		       "error parsing cert: %s\n",
		       ERR_error_string(ERR_get_error(),NULL), NULL, NULL );
#endif
		return LDAP_INVALID_SYNTAX;
	}

	if ( !asn1_integer2str(xcert->cert_info->serialNumber, &serial) ) {
		X509_free(xcert);
		return LDAP_INVALID_SYNTAX;
	}
	if ( dnX509normalize(X509_get_issuer_name(xcert), &issuer_dn ) != LDAP_SUCCESS ) {
		X509_free(xcert);
		ber_memfree(serial.bv_val);
		return LDAP_INVALID_SYNTAX;
	}

	X509_free(xcert);

	out->bv_len = serial.bv_len + issuer_dn.bv_len + sizeof(" $ ");
	out->bv_val = ch_malloc(out->bv_len);
	p = out->bv_val;
	AC_MEMCPY(p, serial.bv_val, serial.bv_len);
	p += serial.bv_len;
	AC_MEMCPY(p, " $ ", sizeof(" $ ")-1);
	p += 3;
	AC_MEMCPY(p, issuer_dn.bv_val, issuer_dn.bv_len);
	p += issuer_dn.bv_len;
	*p++ = '\0';

#ifdef NEW_LOGGING
	LDAP_LOG( CONFIG, ARGS, 
		"certificateExactConvert: \n	%s\n", out->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "certificateExactConvert "
		"\n\t\"%s\"\n",
		out->bv_val, NULL, NULL );
#endif

	ber_memfree(serial.bv_val);
	ber_memfree(issuer_dn.bv_val);

	return LDAP_SUCCESS;
}

static int
serial_and_issuer_parse(
	struct berval *assertion,
	struct berval *serial,
	struct berval *issuer_dn
)
{
	char *begin;
	char *end;
	char *p;
	struct berval bv;

	begin = assertion->bv_val;
	end = assertion->bv_val+assertion->bv_len-1;
	for (p=begin; p<=end && *p != '$'; p++)
		;
	if ( p > end )
		return LDAP_INVALID_SYNTAX;

	/* p now points at the $ sign, now use begin and end to delimit the
	   serial number */
	while (ASCII_SPACE(*begin))
		begin++;
	end = p-1;
	while (ASCII_SPACE(*end))
		end--;

	bv.bv_len = end-begin+1;
	bv.bv_val = begin;
	ber_dupbv(serial, &bv);

	/* now extract the issuer, remember p was at the dollar sign */
	if ( issuer_dn ) {
		begin = p+1;
		end = assertion->bv_val+assertion->bv_len-1;
		while (ASCII_SPACE(*begin))
			begin++;
		/* should we trim spaces at the end too? is it safe always? */

		bv.bv_len = end-begin+1;
		bv.bv_val = begin;
		dnNormalize2( NULL, &bv, issuer_dn );
	}

	return LDAP_SUCCESS;
}

static int
certificateExactMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	X509 *xcert;
	unsigned char *p = value->bv_val;
	struct berval serial;
	struct berval issuer_dn;
	struct berval asserted_serial;
	struct berval asserted_issuer_dn;
	int ret;

	xcert = d2i_X509(NULL, &p, value->bv_len);
	if ( !xcert ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ENTRY, 
			"certificateExactMatch: error parsing cert: %s\n",
			ERR_error_string(ERR_get_error(),NULL), 0, 0 );
#else
		Debug( LDAP_DEBUG_ARGS, "certificateExactMatch: "
		       "error parsing cert: %s\n",
		       ERR_error_string(ERR_get_error(),NULL), NULL, NULL );
#endif
		return LDAP_INVALID_SYNTAX;
	}

	asn1_integer2str(xcert->cert_info->serialNumber, &serial);
	dnX509normalize(X509_get_issuer_name(xcert), &issuer_dn);

	X509_free(xcert);

	serial_and_issuer_parse(assertedValue,
				&asserted_serial,
				&asserted_issuer_dn);

	ret = integerMatch(
		matchp,
		flags,
		slap_schema.si_syn_integer,
		slap_schema.si_mr_integerMatch,
		&serial,
		&asserted_serial);
	if ( ret == LDAP_SUCCESS ) {
		if ( *matchp == 0 ) {
			/* We need to normalize everything for dnMatch */
			ret = dnMatch(
				matchp,
				flags,
				slap_schema.si_syn_distinguishedName,
				slap_schema.si_mr_distinguishedNameMatch,
				&issuer_dn,
				&asserted_issuer_dn);
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONFIG, ARGS, "certificateExactMatch "
		"%d\n\t\"%s $ %s\"\n",
		*matchp, serial.bv_val, issuer_dn.bv_val );
	LDAP_LOG( CONFIG, ARGS, "\t\"%s $ %s\"\n",
		asserted_serial.bv_val, asserted_issuer_dn.bv_val,
		0 );
#else
	Debug( LDAP_DEBUG_ARGS, "certificateExactMatch "
		"%d\n\t\"%s $ %s\"\n",
		*matchp, serial.bv_val, issuer_dn.bv_val );
	Debug( LDAP_DEBUG_ARGS, "\t\"%s $ %s\"\n",
		asserted_serial.bv_val, asserted_issuer_dn.bv_val,
		NULL );
#endif

	ber_memfree(serial.bv_val);
	ber_memfree(issuer_dn.bv_val);
	ber_memfree(asserted_serial.bv_val);
	ber_memfree(asserted_issuer_dn.bv_val);

	return ret;
}

/* 
 * Index generation function
 * We just index the serials, in most scenarios the issuer DN is one of
 * a very small set of values.
 */
static int certificateExactIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp )
{
	int i;
	BerVarray keys;
	X509 *xcert;
	unsigned char *p;
	struct berval serial;

	/* we should have at least one value at this point */
	assert( values != NULL && values[0].bv_val != NULL );

	for( i=0; values[i].bv_val != NULL; i++ ) {
		/* empty -- just count them */
	}

	keys = ch_malloc( sizeof( struct berval ) * (i+1) );

	for( i=0; values[i].bv_val != NULL; i++ ) {
		p = values[i].bv_val;
		xcert = d2i_X509(NULL, &p, values[i].bv_len);
		if ( !xcert ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, ENTRY, 
				"certificateExactIndexer: error parsing cert: %s\n",
				ERR_error_string(ERR_get_error(),NULL), 0, 0);
#else
			Debug( LDAP_DEBUG_ARGS, "certificateExactIndexer: "
			       "error parsing cert: %s\n",
			       ERR_error_string(ERR_get_error(),NULL),
			       NULL, NULL );
#endif
			/* Do we leak keys on error? */
			return LDAP_INVALID_SYNTAX;
		}

		asn1_integer2str(xcert->cert_info->serialNumber, &serial);
		X509_free(xcert);
		integerNormalize( slap_schema.si_syn_integer,
				  &serial,
				  &keys[i] );
		ber_memfree(serial.bv_val);
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ENTRY, 
			"certificateExactIndexer: returning: %s\n", keys[i].bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ARGS, "certificateExactIndexer: "
		       "returning: %s\n",
		       keys[i].bv_val,
		       NULL, NULL );
#endif
	}

	keys[i].bv_val = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
/* We think this is always called with a value in matching rule syntax */
static int certificateExactFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertedValue,
	BerVarray *keysp )
{
	BerVarray keys;
	struct berval asserted_serial;

	serial_and_issuer_parse(assertedValue,
				&asserted_serial,
				NULL);

	keys = ch_malloc( sizeof( struct berval ) * 2 );
	integerNormalize( syntax, &asserted_serial, &keys[0] );
	keys[1].bv_val = NULL;
	*keysp = keys;

	ber_memfree(asserted_serial.bv_val);
	return LDAP_SUCCESS;
}
#endif

static int
check_time_syntax (struct berval *val,
	int start,
	int *parts)
{
	static int ceiling[9] = { 99, 99, 11, 30, 23, 59, 59, 12, 59 };
	static int mdays[2][12] = {
		/* non-leap years */
		{ 30, 27, 30, 29, 30, 29, 30, 30, 29, 30, 29, 30 },
		/* leap years */
		{ 30, 28, 30, 29, 30, 29, 30, 30, 29, 30, 29, 30 }
	};
	char *p, *e;
	int part, c, tzoffset, leapyear = 0 ;

	if( val->bv_len == 0 ) {
		return LDAP_INVALID_SYNTAX;
	}

	p = (char *)val->bv_val;
	e = p + val->bv_len;

	/* Ignore initial whitespace */
	while ( ( p < e ) && ASCII_SPACE( *p ) ) {
		p++;
	}

	if (e - p < 13 - (2 * start)) {
		return LDAP_INVALID_SYNTAX;
	}

	for (part = 0; part < 9; part++) {
		parts[part] = 0;
	}

	for (part = start; part < 7; part++) {
		c = *p;
		if ((part == 6) && (c == 'Z' || c == '+' || c == '-')) {
			part++;
			break;
		}
		p++;
		c -= '0';
		if (p == e) {
			return LDAP_INVALID_SYNTAX;
		}
		if (c < 0 || c > 9) {
			return LDAP_INVALID_SYNTAX;
		}
		parts[part] = c;

		c = *p++ - '0';
		if (p == e) {
			return LDAP_INVALID_SYNTAX;
		}
		if (c < 0 || c > 9) {
			return LDAP_INVALID_SYNTAX;
		}
		parts[part] *= 10;
		parts[part] += c;

		if (part == 2 || part == 3) {
			parts[part]--;
		}
		if (parts[part] < 0) {
			return LDAP_INVALID_SYNTAX;
		}
		if (parts[part] > ceiling[part]) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	/* leapyear check for the Gregorian calendar (year>1581) */
	if (((parts[1] % 4 == 0) && (parts[1] != 0)) ||
		((parts[0] % 4 == 0) && (parts[1] == 0)))
	{
		leapyear = 1;
	}

	if (parts[3] > mdays[leapyear][parts[2]]) {
		return LDAP_INVALID_SYNTAX;
	}
	
	c = *p++;
	if (c == 'Z') {
		tzoffset = 0; /* UTC */
	} else if (c != '+' && c != '-') {
		return LDAP_INVALID_SYNTAX;
	} else {
		if (c == '-') {
			tzoffset = -1;
		} else /* c == '+' */ {
			tzoffset = 1;
		}

		if (p > e - 4) {
			return LDAP_INVALID_SYNTAX;
		}

		for (part = 7; part < 9; part++) {
			c = *p++ - '0';
			if (c < 0 || c > 9) {
				return LDAP_INVALID_SYNTAX;
			}
			parts[part] = c;

			c = *p++ - '0';
			if (c < 0 || c > 9) {
				return LDAP_INVALID_SYNTAX;
			}
			parts[part] *= 10;
			parts[part] += c;
			if (parts[part] < 0 || parts[part] > ceiling[part]) {
				return LDAP_INVALID_SYNTAX;
			}
		}
	}

	/* Ignore trailing whitespace */
	while ( ( p < e ) && ASCII_SPACE( *p ) ) {
		p++;
	}
	if (p != e) {
		return LDAP_INVALID_SYNTAX;
	}

	switch ( tzoffset ) {
	case -1: /* negativ offset to UTC, ie west of Greenwich	 */
		parts[4] += parts[7];
		parts[5] += parts[8];
		for (part = 6; --part > 0; ) { /* offset is just hhmm, no seconds */
			if (part != 3) {
				c = ceiling[part];
			} else {
				c = mdays[leapyear][parts[2]];
			}
			if (parts[part] > c) {
				parts[part] -= c + 1;
				parts[part - 1]++;
			}
		}
		break;
	case 1: /* positive offset to UTC, ie east of Greenwich */
		parts[4] -= parts[7];
		parts[5] -= parts[8];
		for (part = 6; --part > 0; ) {
			if (part != 3) {
				c = ceiling[part];
			} else {
				/* first arg to % needs to be non negativ */
				c = mdays[leapyear][(parts[2] - 1 + 12) % 12];
			}
			if (parts[part] < 0) {
				parts[part] += c + 1;
				parts[part - 1]--;
			}
		}
		break;
	case 0: /* already UTC */
		break;
	}

	return LDAP_SUCCESS;
}

#ifdef SUPPORT_OBSOLETE_UTC_SYNTAX
static int
utcTimeNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	int parts[9], rc;

	rc = check_time_syntax(val, 1, parts);
	if (rc != LDAP_SUCCESS) {
		return rc;
	}

	normalized->bv_val = ch_malloc( 14 );
	if ( normalized->bv_val == NULL ) {
		return LBER_ERROR_MEMORY;
	}

	sprintf( normalized->bv_val, "%02d%02d%02d%02d%02d%02dZ",
		parts[1], parts[2] + 1, parts[3] + 1,
		parts[4], parts[5], parts[6] );
	normalized->bv_len = 13;

	return LDAP_SUCCESS;
}
#endif

#ifdef SUPPORT_OBSOLETE_UTC_SYNTAX
static int
utcTimeValidate(
	Syntax *syntax,
	struct berval *in )
{
	int parts[9];

	return check_time_syntax(in, 1, parts);
}
#endif

static int
generalizedTimeValidate(
	Syntax *syntax,
	struct berval *in )
{
	int parts[9];

	return check_time_syntax(in, 0, parts);
}

static int
generalizedTimeNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval *normalized )
{
	int parts[9], rc;

	rc = check_time_syntax(val, 0, parts);
	if (rc != LDAP_SUCCESS) {
		return rc;
	}

	normalized->bv_val = ch_malloc( 16 );
	if ( normalized->bv_val == NULL ) {
		return LBER_ERROR_MEMORY;
	}

	sprintf( normalized->bv_val, "%02d%02d%02d%02d%02d%02d%02dZ",
		parts[0], parts[1], parts[2] + 1, parts[3] + 1,
		parts[4], parts[5], parts[6] );
	normalized->bv_len = 15;

	return LDAP_SUCCESS;
}

static int
nisNetgroupTripleValidate(
	Syntax *syntax,
	struct berval *val )
{
	char *p, *e;
	int commas = 0;

	if ( val->bv_len == 0 ) {
		return LDAP_INVALID_SYNTAX;
	}

	p = (char *)val->bv_val;
	e = p + val->bv_len;

	if ( *p != '(' /*')'*/ ) {
		return LDAP_INVALID_SYNTAX;
	}

	for ( p++; ( p < e ) && ( *p != /*'('*/ ')' ); p++ ) {
		if ( *p == ',' ) {
			commas++;
			if ( commas > 2 ) {
				return LDAP_INVALID_SYNTAX;
			}

		} else if ( !AD_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if ( ( commas != 2 ) || ( *p != /*'('*/ ')' ) ) {
		return LDAP_INVALID_SYNTAX;
	}

	p++;

	if (p != e) {
		return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
bootParameterValidate(
	Syntax *syntax,
	struct berval *val )
{
	char *p, *e;

	if ( val->bv_len == 0 ) {
		return LDAP_INVALID_SYNTAX;
	}

	p = (char *)val->bv_val;
	e = p + val->bv_len;

	/* key */
	for (; ( p < e ) && ( *p != '=' ); p++ ) {
		if ( !AD_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if ( *p != '=' ) {
		return LDAP_INVALID_SYNTAX;
	}

	/* server */
	for ( p++; ( p < e ) && ( *p != ':' ); p++ ) {
		if ( !AD_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if ( *p != ':' ) {
		return LDAP_INVALID_SYNTAX;
	}

	/* path */
	for ( p++; p < e; p++ ) {
		if ( !SLAP_PRINTABLE( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
}

#define X_BINARY "X-BINARY-TRANSFER-REQUIRED 'TRUE' "
#define X_NOT_H_R "X-NOT-HUMAN-READABLE 'TRUE' "

static slap_syntax_defs_rec syntax_defs[] = {
	{"( 1.3.6.1.4.1.1466.115.121.1.1 DESC 'ACI Item' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.2 DESC 'Access Point' " X_NOT_H_R ")",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.4 DESC 'Audio' "
		X_NOT_H_R ")",
		SLAP_SYNTAX_BLOB, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' "
		X_NOT_H_R ")",
		SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )",
		0, bitStringValidate, bitStringNormalize, NULL },
	{"( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )",
		0, booleanValidate, NULL, NULL},
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
		0, countryStringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'Distinguished Name' )",
		0, dnValidate, dnNormalize2, dnPretty2},
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
		0, printablesStringValidate, telephoneNumberNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.23 DESC 'Fax' " X_NOT_H_R ")",
		SLAP_SYNTAX_BLOB, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )",
		0, generalizedTimeValidate, generalizedTimeNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )",
		0, IA5StringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'Integer' )",
		0, integerValidate, integerNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' " X_NOT_H_R ")",
		SLAP_SYNTAX_BLOB, blobValidate, NULL, NULL},
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
		0, nameUIDValidate, nameUIDNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )",
		0, numericStringValidate, numericStringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		0, oidValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )",
		0, IA5StringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )",
		0, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )",
		0, UTF8StringValidate, UTF8StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.42 DESC 'Protocol Information' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'Presentation Address' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )",
		0, printableStringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.45 DESC 'SubtreeSpecification' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'Supported Algorithm' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )",
		0, printableStringValidate, telephoneNumberNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )",
		0, printablesStringValidate, IA5StringNormalize, NULL},
#ifdef SUPPORT_OBSOLETE_UTC_SYNTAX
	{"( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTC Time' )",
		0, utcTimeValidate, utcTimeNormalize, NULL},
#endif
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

	/* RFC 2307 NIS Syntaxes */
	{"( 1.3.6.1.1.1.0.0  DESC 'RFC2307 NIS Netgroup Triple' )",
		0, nisNetgroupTripleValidate, NULL, NULL},
	{"( 1.3.6.1.1.1.0.1  DESC 'RFC2307 Boot Parameter' )",
		0, bootParameterValidate, NULL, NULL},

#ifdef HAVE_TLS
	/* From PKIX */
	/* These OIDs are not published yet, but will be in the next
	 * I-D for PKIX LDAPv3 schema as have been advanced by David
	 * Chadwick in private mail.
	 */
	{"( 1.2.826.0.1.3344810.7.1 DESC 'Serial Number and Issuer' )",
		0, NULL, NULL, NULL},
#endif

	/* OpenLDAP Experimental Syntaxes */
#ifdef SLAPD_ACI_ENABLED
	{"( 1.3.6.1.4.1.4203.666.2.1 DESC 'OpenLDAP Experimental ACI' )",
		SLAP_SYNTAX_HIDE,
		UTF8StringValidate /* THIS WILL CHANGE FOR NEW ACI SYNTAX */,
		NULL, NULL},
#endif

#ifdef SLAPD_AUTHPASSWD
	/* needs updating */
	{"( 1.3.6.1.4.1.4203.666.2.2 DESC 'OpenLDAP authPassword' )",
		SLAP_SYNTAX_HIDE, NULL, NULL, NULL},
#endif

	/* OpenLDAP Void Syntax */
	{"( 1.3.6.1.4.1.4203.1.1.1 DESC 'OpenLDAP void' )" ,
		SLAP_SYNTAX_HIDE, inValidate, NULL, NULL},
	{NULL, 0, NULL, NULL, NULL}
};

#ifdef HAVE_TLS
char *certificateExactMatchSyntaxes[] = {
	"1.3.6.1.4.1.1466.115.121.1.8" /* certificate */,
	NULL
};
#endif
char *directoryStringSyntaxes[] = {
	"1.3.6.1.4.1.1466.115.121.1.44" /* printableString */,
	NULL
};
char *integerFirstComponentMatchSyntaxes[] = {
	"1.3.6.1.4.1.1466.115.121.1.27" /* INTEGER */,
	"1.3.6.1.4.1.1466.115.121.1.17" /* ditStructureRuleDescription */,
	NULL
};
char *objectIdentifierFirstComponentMatchSyntaxes[] = {
	"1.3.6.1.4.1.1466.115.121.1.38" /* OID */,
	"1.3.6.1.4.1.1466.115.121.1.3"  /* attributeTypeDescription */,
	"1.3.6.1.4.1.1466.115.121.1.16" /* ditContentRuleDescription */,
	"1.3.6.1.4.1.1466.115.121.1.54" /* ldapSyntaxDescription */,
	"1.3.6.1.4.1.1466.115.121.1.30" /* matchingRuleDescription */,
	"1.3.6.1.4.1.1466.115.121.1.31" /* matchingRuleUseDescription */,
	"1.3.6.1.4.1.1466.115.121.1.35" /* nameFormDescription */,
	"1.3.6.1.4.1.1466.115.121.1.37" /* objectClassDescription */,
	NULL
};

/*
 * Other matching rules in X.520 that we do not use (yet):
 *
 * 2.5.13.9		numericStringOrderingMatch
 * 2.5.13.18	octetStringOrderingMatch
 * 2.5.13.19	octetStringSubstringsMatch
 * 2.5.13.25	uTCTimeMatch
 * 2.5.13.26	uTCTimeOrderingMatch
 * 2.5.13.31	directoryStringFirstComponentMatch
 * 2.5.13.32	wordMatch
 * 2.5.13.33	keywordMatch
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
static slap_mrule_defs_rec mrule_defs[] = {
	/*
	 * EQUALITY matching rules must be listed after associated APPROX
	 * matching rules.  So, we list all APPROX matching rules first.
	 */
	{"( " directoryStringApproxMatchOID " NAME 'directoryStringApproxMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_HIDE | SLAP_MR_EQUALITY_APPROX | SLAP_MR_EXT, NULL,
		NULL, NULL,
		directoryStringApproxMatch,
		directoryStringApproxIndexer, 
		directoryStringApproxFilter,
		NULL},

	{"( " IA5StringApproxMatchOID " NAME 'IA5StringApproxMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_HIDE | SLAP_MR_EQUALITY_APPROX | SLAP_MR_EXT, NULL,
		NULL, NULL,
		IA5StringApproxMatch,
		IA5StringApproxIndexer, 
		IA5StringApproxFilter,
		NULL},

	/*
	 * Other matching rules
	 */
	
	{"( 2.5.13.0 NAME 'objectIdentifierMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		objectIdentifierMatch, caseIgnoreIA5Indexer, caseIgnoreIA5Filter,
		NULL},

	{"( 2.5.13.1 NAME 'distinguishedNameMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		dnMatch, dnIndexer, dnFilter,
		NULL},

	{"( 2.5.13.2 NAME 'caseIgnoreMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT | SLAP_MR_DN_FOLD,
			directoryStringSyntaxes,
		NULL, NULL,
		caseIgnoreMatch, caseExactIgnoreIndexer, caseExactIgnoreFilter,
		directoryStringApproxMatchOID },

	{"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING, directoryStringSyntaxes,
		NULL, NULL,
		caseIgnoreOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR, NULL,
		NULL, NULL,
		caseExactIgnoreSubstringsMatch,
		caseExactIgnoreSubstringsIndexer,
		caseExactIgnoreSubstringsFilter,
		NULL},

	{"( 2.5.13.5 NAME 'caseExactMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, directoryStringSyntaxes,
		NULL, NULL,
		caseExactMatch, caseExactIgnoreIndexer, caseExactIgnoreFilter,
		directoryStringApproxMatchOID },

	{"( 2.5.13.6 NAME 'caseExactOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING, directoryStringSyntaxes,
		NULL, NULL,
		caseExactOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.7 NAME 'caseExactSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR, directoryStringSyntaxes,
		NULL, NULL,
		caseExactIgnoreSubstringsMatch,
		caseExactIgnoreSubstringsIndexer,
		caseExactIgnoreSubstringsFilter,
		NULL},

	{"( 2.5.13.8 NAME 'numericStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT | SLAP_MR_DN_FOLD, NULL,
		NULL, NULL,
		caseIgnoreIA5Match,
		caseIgnoreIA5Indexer,
		caseIgnoreIA5Filter,
		NULL},

	{"( 2.5.13.10 NAME 'numericStringSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR, NULL,
		NULL, NULL,
		caseIgnoreIA5SubstringsMatch,
		caseIgnoreIA5SubstringsIndexer,
		caseIgnoreIA5SubstringsFilter,
		NULL},

	{"( 2.5.13.11 NAME 'caseIgnoreListMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT | SLAP_MR_DN_FOLD, NULL,
		NULL, NULL,
		caseIgnoreListMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.12 NAME 'caseIgnoreListSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR, NULL,
		NULL, NULL,
		caseIgnoreListSubstringsMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.13 NAME 'booleanMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		booleanMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.14 NAME 'integerMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		integerMatch, integerIndexer, integerFilter,
		NULL},

	{"( 2.5.13.15 NAME 'integerOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_ORDERING, NULL,
		NULL, NULL,
		integerOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.16 NAME 'bitStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		bitStringMatch, bitStringIndexer, bitStringFilter,
		NULL},

	{"( 2.5.13.17 NAME 'octetStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		octetStringMatch, octetStringIndexer, octetStringFilter,
		NULL},

	{"( 2.5.13.20 NAME 'telephoneNumberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT | SLAP_MR_DN_FOLD, NULL,
		NULL, NULL,
		telephoneNumberMatch,
		telephoneNumberIndexer,
		telephoneNumberFilter,
		NULL},

	{"( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR, NULL,
		NULL, NULL,
		telephoneNumberSubstringsMatch,
		telephoneNumberSubstringsIndexer,
		telephoneNumberSubstringsFilter,
		NULL},

	{"( 2.5.13.22 NAME 'presentationAddressMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		NULL, NULL, NULL,
		NULL},

	{"( 2.5.13.23 NAME 'uniqueMemberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		uniqueMemberMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.24 NAME 'protocolInformationMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		protocolInformationMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.27 NAME 'generalizedTimeMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		generalizedTimeMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		SLAP_MR_ORDERING, NULL,
		NULL, NULL,
		generalizedTimeOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.29 NAME 'integerFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, integerFirstComponentMatchSyntaxes,
		NULL, NULL,
		integerFirstComponentMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
			objectIdentifierFirstComponentMatchSyntaxes,
		NULL, NULL,
		objectIdentifierFirstComponentMatch, NULL, NULL,
		NULL},

#ifdef HAVE_TLS
	{"( 2.5.13.34 NAME 'certificateExactMatch' "
		"SYNTAX 1.2.826.0.1.3344810.7.1 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, certificateExactMatchSyntaxes,
		certificateExactConvert, NULL,
		certificateExactMatch,
		certificateExactIndexer, certificateExactFilter,
		NULL},
#endif

	{"( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT, NULL,
		NULL, NULL,
		caseExactIA5Match, caseExactIA5Indexer, caseExactIA5Filter,
		IA5StringApproxMatchOID },

	{"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT | SLAP_MR_DN_FOLD, NULL,
		NULL, NULL,
		caseIgnoreIA5Match, caseIgnoreIA5Indexer, caseIgnoreIA5Filter,
		IA5StringApproxMatchOID },

	{"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_SUBSTR, NULL,
		NULL, NULL,
		caseIgnoreIA5SubstringsMatch,
		caseIgnoreIA5SubstringsIndexer,
		caseIgnoreIA5SubstringsFilter,
		NULL},

	{"( 1.3.6.1.4.1.4203.1.2.1 NAME 'caseExactIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_SUBSTR, NULL,
		NULL, NULL,
		caseExactIA5SubstringsMatch,
		caseExactIA5SubstringsIndexer,
		caseExactIA5SubstringsFilter,
		NULL},

#ifdef SLAPD_AUTHPASSWD
	/* needs updating */
	{"( 1.3.6.1.4.1.4203.666.4.1 NAME 'authPasswordMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		SLAP_MR_EQUALITY, NULL,
		NULL, NULL,
		authPasswordMatch, NULL, NULL,
		NULL},
#endif

#ifdef SLAPD_ACI_ENABLED
	{"( 1.3.6.1.4.1.4203.666.4.2 NAME 'OpenLDAPaciMatch' "
		"SYNTAX 1.3.6.1.4.1.4203.666.2.1 )",
		SLAP_MR_EQUALITY, NULL,
		NULL, NULL,
		OpenLDAPaciMatch, NULL, NULL,
		NULL},
#endif

	{"( 1.2.840.113556.1.4.803 NAME 'integerBitAndMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EXT, NULL,
		NULL, NULL,
		integerBitAndMatch, NULL, NULL,
		NULL},

	{"( 1.2.840.113556.1.4.804 NAME 'integerBitOrMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EXT, NULL,
		NULL, NULL,
		integerBitOrMatch, NULL, NULL,
		NULL},

	{NULL, SLAP_MR_NONE, NULL,
		NULL, NULL, NULL, NULL, NULL,
		NULL }
};

int
slap_schema_init( void )
{
	int		res;
	int		i = 0;

	/* we should only be called once (from main) */
	assert( schema_init_done == 0 );

	for ( i=0; syntax_defs[i].sd_desc != NULL; i++ ) {
		res = register_syntax( &syntax_defs[i] );

		if ( res ) {
			fprintf( stderr, "slap_schema_init: Error registering syntax %s\n",
				 syntax_defs[i].sd_desc );
			return LDAP_OTHER;
		}
	}

	for ( i=0; mrule_defs[i].mrd_desc != NULL; i++ ) {
		if( mrule_defs[i].mrd_usage == SLAP_MR_NONE &&
			mrule_defs[i].mrd_compat_syntaxes == NULL )
		{
			fprintf( stderr,
				"slap_schema_init: Ingoring unusable matching rule %s\n",
				 mrule_defs[i].mrd_desc );
			continue;
		}

		res = register_matching_rule( &mrule_defs[i] );

		if ( res ) {
			fprintf( stderr,
				"slap_schema_init: Error registering matching rule %s\n",
				 mrule_defs[i].mrd_desc );
			return LDAP_OTHER;
		}
	}

	for ( i=0; i < (int)(sizeof(mr_ptr)/sizeof(mr_ptr[0])); i++ )
		*mr_ptr[i].mr = mr_find( mr_ptr[i].oid );

	res = slap_schema_load();
	schema_init_done = 1;
	return res;
}

void
schema_destroy( void )
{
	int i;
	oidm_destroy();
	oc_destroy();
	at_destroy();
	for ( i=0; i < (int)(sizeof(mr_ptr)/sizeof(mr_ptr[0])); i++ )
		*mr_ptr[i].mr = NULL;
	mr_destroy();
	mru_destroy();
	syn_destroy();
}
