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

#define UTF8MATCH 1

#ifdef USE_MD5
#include "lutil_md5.h"
/* We should replace MD5 with a faster hash */
#define HASH_BYTES				LUTIL_MD5_BYTES
#define HASH_CONTEXT			lutil_MD5_CTX
#define HASH_Init(c)			lutil_MD5Init(c)
#define HASH_Update(c,buf,len)	lutil_MD5Update(c,buf,len)
#define HASH_Final(d,c)			lutil_MD5Final(d,c)
#else
#include "lutil_hash.h"
/* We should replace MD5 with a faster hash */
#define HASH_BYTES				LUTIL_HASH_BYTES
#define HASH_CONTEXT			lutil_HASH_CTX
#define HASH_Init(c)			lutil_HASHInit(c)
#define HASH_Update(c,buf,len)	lutil_HASHUpdate(c,buf,len)
#define HASH_Final(d,c)			lutil_HASHFinal(d,c)
#endif

/* recycled validatation routines */
#define berValidate						blobValidate

/* unimplemented pretters */
#define dnPretty						NULL
#define integerPretty					NULL

/* recycled matching routines */
#define bitStringMatch					octetStringMatch
#define integerMatch					caseIgnoreIA5Match
#define numericStringMatch				caseIgnoreMatch
#define objectIdentifierMatch			numericStringMatch
#define telephoneNumberMatch			numericStringMatch
#define telephoneNumberSubstringsMatch	caseIgnoreIA5SubstringsMatch
#define generalizedTimeMatch			numericStringMatch
#define generalizedTimeOrderingMatch	numericStringMatch
#define uniqueMemberMatch				dnMatch

/* approx matching rules */
#define directoryStringApproxMatchOID	"1.3.6.1.4.1.4203.666.4.4"
#define directoryStringApproxMatch  	approxMatch
#define directoryStringApproxIndexer 	approxIndexer
#define directoryStringApproxFilter  	approxFilter
#define IA5StringApproxMatchOID			"1.3.6.1.4.1.4203.666.4.5"
#define IA5StringApproxMatch  			approxMatch
#define IA5StringApproxIndexer			approxIndexer
#define IA5StringApproxFilter  			approxFilter

/* orderring matching rules */
#define caseIgnoreOrderingMatch			caseIgnoreMatch
#define caseExactOrderingMatch			caseExactMatch

/* unimplemented matching routines */
#define caseIgnoreListMatch				NULL
#define caseIgnoreListSubstringsMatch	NULL
#define presentationAddressMatch		NULL
#define protocolInformationMatch		NULL
#define integerFirstComponentMatch		NULL

#define OpenLDAPaciMatch				NULL
#define authPasswordMatch				NULL

/* recycled indexing/filtering routines */
#define dnIndexer						caseIgnoreIndexer
#define dnFilter						caseIgnoreFilter
#define integerIndexer					caseIgnoreIA5Indexer
#define integerFilter					caseIgnoreIA5Filter

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
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
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
			values[i]->bv_val, values[i]->bv_len );
		HASH_Final( HASHdigest, &HASHcontext );

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;

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
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value = (struct berval *) assertValue;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

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
	slap_mask_t flags,
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
nameUIDValidate(
	Syntax *syntax,
	struct berval *in )
{
	int rc;
	struct berval *dn;

	if( in->bv_len == 0 ) return LDAP_SUCCESS;

	dn = ber_bvdup( in );

	if( dn->bv_val[dn->bv_len-1] == '\'' ) {
		/* assume presence of optional UID */
		ber_len_t i;

		for(i=dn->bv_len-2; i>2; i--) {
			if( dn->bv_val[i] != '0' &&	dn->bv_val[i] != '1' ) {
				break;
			}
		}
		if( dn->bv_val[i] != '\'' ) {
			return LDAP_INVALID_SYNTAX;
		}
		if( dn->bv_val[i-1] != 'B' ) {
			return LDAP_INVALID_SYNTAX;
		}
		if( dn->bv_val[i-2] != '#' ) {
			return LDAP_INVALID_SYNTAX;
		}

		/* trim the UID to allow use of dn_validate */
		dn->bv_val[i-2] = '\0';
	}

	rc = dn_validate( dn->bv_val ) == NULL
		? LDAP_INVALID_SYNTAX : LDAP_SUCCESS;

	ber_bvfree( dn );
	return rc;
}

static int
nameUIDNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *out = ber_bvdup( val );

	if( out->bv_len != 0 ) {
		char *dn;
		ber_len_t dnlen;
		char *uid = NULL;
		ber_len_t uidlen = 0;

		if( out->bv_val[out->bv_len-1] == '\'' ) {
			/* assume presence of optional UID */
			uid = strrchr( out->bv_val, '#' );

			if( uid == NULL ) {
				ber_bvfree( out );
				return LDAP_INVALID_SYNTAX;
			}

			uidlen = out->bv_len - (out->bv_val - uid);
			/* temporarily trim the UID */
			*uid = '\0';
		}

#ifdef USE_DN_NORMALIZE
		dn = dn_normalize( out->bv_val );
#else
		dn = dn_validate( out->bv_val );
#endif

		if( dn == NULL ) {
			ber_bvfree( out );
			return LDAP_INVALID_SYNTAX;
		}

		dnlen = strlen(dn);

		if( uidlen ) {
			/* restore the separator */
			*uid = '#';
			/* shift the UID */
			SAFEMEMCPY( &dn[dnlen], uid, uidlen );
		}

		out->bv_val = dn;
		out->bv_len = dnlen + uidlen;
	}

	*normalized = out;
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
	if( in->bv_val[0] != 'B' ||
		in->bv_val[1] != '\'' ||
		in->bv_val[in->bv_len-1] != '\'' )
	{
		return LDAP_INVALID_SYNTAX;
	}

	for( i=in->bv_len-2; i>1; i-- ) {
		if( in->bv_val[i] != '0' && in->bv_val[i] != '1' ) {
			return LDAP_INVALID_SYNTAX;
		}
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

#if UTF8MATCH
static int
UTF8casecmp(
	struct berval *right,
	struct berval *left )
{
	ber_len_t r, l;
	int rlen, llen;
	ldap_unicode_t ru, lu;
	ldap_unicode_t ruu, luu;

	for( r=0, l=0;
		r < right->bv_len && l < left->bv_len;
		r+=rlen, l+=llen )
	{
		/*
		 * XXYYZ: we convert to ucs4 even though -llunicode
		 * expects ucs2 in an unsigned long
		 */
		ru = ldap_utf8_to_ucs4( &right->bv_val[r] );
		if( ru == LDAP_UCS4_INVALID ) {
			return 1;
		}

		lu = ldap_utf8_to_ucs4( &left->bv_val[l] );
		if( lu == LDAP_UCS4_INVALID ) {
			return -1;
		}

		ruu = uctoupper( ru );
		luu = uctoupper( lu );

		if( ruu > luu ) {
			return 1;
		} else if( luu > ruu ) {
			return -1;
		}

		rlen = LDAP_UTF8_CHARLEN( &right->bv_val[r] );
		llen = LDAP_UTF8_CHARLEN( &left->bv_val[l] );
	}

	if( r < right->bv_len ) {
		/* less left */
		return -1;
	}

	if( l < left->bv_len ) {
		/* less right */
		return 1;
	}

	return 0;
}

/* case insensitive UTF8 strncmp with offset for second string */
static int
UTF8oncasecmp(
	struct berval *right,
	struct berval *left,
	ber_len_t len,
	ber_len_t offset )
{
	ber_len_t r, l;
	int rlen, llen;
	int rslen, lslen;
	ldap_unicode_t ru, lu;
	ldap_unicode_t ruu, luu;

	rslen = len < right->bv_len ? len : right->bv_len;
	lslen = len + offset < left->bv_len ? len : left->bv_len;

	for( r = 0, l = offset;
		r < rslen && l < lslen;
		r+=rlen, l+=llen )
	{
		/*
		 * XXYYZ: we convert to ucs4 even though -llunicode
		 * expects ucs2 in an unsigned long
		 */
		ru = ldap_utf8_to_ucs4( &right->bv_val[r] );
		if( ru == LDAP_UCS4_INVALID ) {
			return 1;
		}

		lu = ldap_utf8_to_ucs4( &left->bv_val[l] );
		if( lu == LDAP_UCS4_INVALID ) {
			return -1;
		}

		ruu = uctoupper( ru );
		luu = uctoupper( lu );

		if( ruu > luu ) {
			return 1;
		} else if( luu > ruu ) {
			return -1;
		}

		rlen = LDAP_UTF8_CHARLEN( &right->bv_val[r] );
		llen = LDAP_UTF8_CHARLEN( &left->bv_val[l] );
	}

	if( r < rslen ) {
		/* less left */
		return -1;
	}

	if( l < lslen ) {
		/* less right */
		return 1;
	}

	return 0;
}

static char *UTF8casechr( const char *str, const char *c )
{
	char *p, *lower, *upper;
	ldap_ucs4_t tch, ch = ldap_utf8_to_ucs4(c);

	tch = uctolower ( ch );
	for( p = (char *) str; *p != '\0'; LDAP_UTF8_INCR(p) ) {
		if( ldap_utf8_to_ucs4( p ) == tch ) {
			break;
		} 
	}
	lower = *p != '\0' ? p : NULL;

	tch = uctoupper ( ch );
	for( p = (char *) str; *p != '\0'; LDAP_UTF8_INCR(p) ) {
		if( ldap_utf8_to_ucs4( p ) == tch ) {
			break;
		} 
	}
	upper = *p != '\0' ? p : NULL;
	
	if( lower && upper ) {
		return lower < upper ? lower : upper;
	} else if ( lower ) {
		return lower;
	} else {
		return upper;
	}
}
#endif

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
	assert( q <= p );

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

#if defined(SLAPD_APPROX_MULTISTRING)

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
	char *val, *assertv, **values, **words, *c;
	int i, count, len, nextchunk=0, nextavail=0;


	/* Isolate how many words there are */
	val = ch_strdup( value->bv_val );
	for( c=val,count=1; *c; c++ ) {
		c = strpbrk( c, SLAPD_APPROX_DELIMITER );
		if ( c == NULL ) break;
		*c = '\0';
		count++;
	}

	/* Get a phonetic copy of each word */
	words = (char **)ch_malloc( count * sizeof(char *) );
	values = (char **)ch_malloc( count * sizeof(char *) );
	for( c=val,i=0;  i<count;  i++,c+=strlen(c)+1 ) {
		words[i] = c;
		values[i] = phonetic(c);
	}


	/* Work through the asserted value's words, to see if  at least some
	   of the words are there, in the same order. */
	assertv = ch_strdup( ((struct berval *)assertedValue)->bv_val );
	len = 0;
	while ( nextchunk < ((struct berval *)assertedValue)->bv_len ) {
		len = strcspn( assertv + nextchunk, SLAPD_APPROX_DELIMITER);
		if( len == 0 ) {
			nextchunk++;
			continue;
		}
#if defined(SLAPD_APPROX_INITIALS)
		else if( len == 1 ) {
			/* Single letter words need to at least match one word's initial */
			for( i=nextavail; i<count; i++ )
				if( !strncasecmp( assertv+nextchunk, words[i], 1 )) {
					nextavail=i+1;
					break;
				}
		}
#endif
		else {
			/* Isolate the next word in the asserted value and phonetic it */
			assertv[nextchunk+len] = '\0';
			val = phonetic( assertv + nextchunk );

			/* See if this phonetic chunk is in the remaining words of *value */
			for( i=nextavail; i<count; i++ ){
				if( !strcmp( val, values[i] ) ){
					nextavail = i+1;
					break;
				}
			}
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
	ch_free( assertv );
	for( i=0; i<count; i++ ) {
		ch_free( values[i] );
	}
	ch_free( values );
	ch_free( words );
	ch_free( val );

	return LDAP_SUCCESS;
}


int 
approxIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	char *val, *c;
	int i,j, len, wordcount, keycount=0;
	struct berval **newkeys, **keys=NULL;


	for( j=0; values[j] != NULL; j++ ) {

		/* Isolate how many words there are. There will be a key for each */
		val = ch_strdup( values[j]->bv_val );
		for( wordcount=0,c=val;  *c;  c++) {
			len = strcspn(c, SLAPD_APPROX_DELIMITER);
			if( len >= SLAPD_APPROX_WORDLEN ) wordcount++;
			c+= len;
			if (*c == '\0') break;
			*c = '\0';
		}

		/* Allocate/increase storage to account for new keys */
		newkeys = (struct berval **)ch_malloc( (keycount + wordcount + 1) 
		   * sizeof(struct berval *) );
		memcpy( newkeys, keys, keycount * sizeof(struct berval *) );
		if( keys ) ch_free( keys );
		keys = newkeys;

		/* Get a phonetic copy of each word */
		for( c=val,i=0;  i<wordcount;  c+=len+1  ) {
			len = strlen( c );
			if( len < SLAPD_APPROX_WORDLEN ) continue;
			keys[keycount] = (struct berval *)ch_malloc( sizeof(struct berval) );
			keys[keycount]->bv_val = phonetic( c );
			keys[keycount]->bv_len = strlen( keys[keycount]->bv_val );
			keycount++;
			i++;
		}

		ch_free( val );
	}
	keys[keycount] = NULL;
	*keysp = keys;

	return LDAP_SUCCESS;
}


int 
approxFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	char *val, *c;
	int i, count, len;
	struct berval **keys;


	/* Isolate how many words there are. There will be a key for each */
	val = ch_strdup( ((struct berval *)assertValue)->bv_val );
	for( count=0,c=val;  *c;  c++) {
		len = strcspn(c, SLAPD_APPROX_DELIMITER);
		if( len >= SLAPD_APPROX_WORDLEN ) count++;
		c+= len;
		if (*c == '\0') break;
		*c = '\0';
	}

	/* Allocate storage for new keys */
	keys = (struct berval **)ch_malloc( (count + 1) * sizeof(struct berval *) );

	/* Get a phonetic copy of each word */
	for( c=val,i=0;  i<count; c+=len+1 ) {
		len = strlen(c);
		if( len < SLAPD_APPROX_WORDLEN ) continue;
		keys[i] = (struct berval *)ch_malloc( sizeof(struct berval) );
		keys[i]->bv_val = phonetic( c );
		keys[i]->bv_len = strlen( keys[i]->bv_val );
		i++;
	}

	ch_free( val );

	keys[count] = NULL;
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

	vapprox = phonetic( value->bv_val );
	avapprox = phonetic( ((struct berval *)assertedValue)->bv_val);

	*matchp = strcmp( vapprox, avapprox );

	ch_free( vapprox );
	ch_free( avapprox );

	return LDAP_SUCCESS;
}

int 
approxIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	struct berval **keys;


	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}
	assert( i > 0 );

	keys = (struct berval **)ch_malloc( sizeof( struct berval * ) * (i+1) );

	/* Copy each value and run it through phonetic() */
	for( i=0; values[i] != NULL; i++ ) {
		keys[i] = ch_malloc( sizeof( struct berval * ) );
		keys[i]->bv_val = phonetic( values[i]->bv_val );
		keys[i]->bv_len = strlen( keys[i]->bv_val );
	}
	keys[i] = NULL;

	*keysp = keys;
	return LDAP_SUCCESS;
}


int 
approxFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	struct berval **keys;


	keys = (struct berval **)ch_malloc( sizeof( struct berval * ) * 2 );

	/* Copy the value and run it through phonetic() */
	keys[0] = ch_malloc( sizeof( struct berval * ) );
	keys[0]->bv_val = phonetic( ((struct berval *)assertValue)->bv_val );
	keys[0]->bv_len = strlen( keys[0]->bv_val );
	keys[1] = NULL;

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
caseExactSubstringsMatch(
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
int caseExactIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		struct berval *value = values[i];

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

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseExactFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	value = (struct berval *) assertValue;

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

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

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
int caseExactSubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	ber_len_t i, nkeys;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i]->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		ber_len_t j,max;
		struct berval *value;

		value = values[i];
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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
			}

		}
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}

int caseExactSubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	SubstringsAssertion *sa = assertValue;
	char pre;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i]->bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );
	nkeys = 0;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		value = sa->sa_initial;

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

		keys[nkeys++] = ber_bvdup( &digest );
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			value = sa->sa_any[i];

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

				keys[nkeys++] = ber_bvdup( &digest );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		value = sa->sa_final;

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

		keys[nkeys++] = ber_bvdup( &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

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
#if UTF8MATCH
	*matchp = UTF8casecmp( value, (struct berval *) assertedValue );
#else
	int match = value->bv_len - ((struct berval *) assertedValue)->bv_len;

	if( match == 0 ) {
		match = strncasecmp( value->bv_val,
			((struct berval *) assertedValue)->bv_val,
			value->bv_len );
	}

	*matchp = match;
#endif
	return LDAP_SUCCESS;
}

static int
caseIgnoreSubstringsMatch(
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

#if UTF8MATCH
		match = UTF8oncasecmp( sub->sa_initial, &left,
				     sub->sa_initial->bv_len, 0 );
#else		
		match = strncasecmp( sub->sa_initial->bv_val, left.bv_val,
			sub->sa_initial->bv_len );
#endif

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

#if UTF8MATCH
		match = UTF8oncasecmp( sub->sa_final, &left,
				       sub->sa_final->bv_len,
				       left.bv_len - sub->sa_final->bv_len );
#else		
		match = strncasecmp( sub->sa_final->bv_val,
			&left.bv_val[left.bv_len - sub->sa_final->bv_len],
			sub->sa_final->bv_len );
#endif

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

#if UTF8MATCH
			p = UTF8casechr( left.bv_val, sub->sa_any[i]->bv_val );
#else
			p = strcasechr( left.bv_val, *sub->sa_any[i]->bv_val );
#endif

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

#if UTF8MATCH
			match = UTF8oncasecmp( &left, sub->sa_any[i],
					       sub->sa_any[i]->bv_len, 0 );

			if( match != 0 ) {
				int len = LDAP_UTF8_CHARLEN( left.bv_val );
				left.bv_val += len;
				left.bv_len -= len;
				goto retry;
			}
#else			
			match = strncasecmp( left.bv_val,
				sub->sa_any[i]->bv_val,
				sub->sa_any[i]->bv_len );

			if( match != 0 ) {
				left.bv_val++;
				left.bv_len--;

				goto retry;
			}
#endif

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
int caseIgnoreIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		struct berval *value = ber_bvdup( values[i] );
		ldap_pvt_str2upper( value->bv_val );

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

		ber_bvfree( value );

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseIgnoreFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	value = ber_bvdup( (struct berval *) assertValue );
	ldap_pvt_str2upper( value->bv_val );

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

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

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	ber_bvfree( value );

	*keysp = keys;

	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
int caseIgnoreSubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	ber_len_t i, nkeys;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i]->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		int j,max;
		struct berval *value;

		if( values[i]->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) continue;

		value = ber_bvdup( values[i] );
		ldap_pvt_str2upper( value->bv_val );

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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
			}

		}

		ber_bvfree( value );
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}

int caseIgnoreSubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	SubstringsAssertion *sa = assertValue;
	char pre;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;

	if((flags & SLAP_INDEX_SUBSTR_INITIAL) && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if((flags & SLAP_INDEX_SUBSTR_ANY) && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i]->bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if((flags & SLAP_INDEX_SUBSTR_FINAL) && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );
	nkeys = 0;

	if((flags & SLAP_INDEX_SUBSTR_INITIAL) && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		value = ber_bvdup( sa->sa_initial );
		ldap_pvt_str2upper( value->bv_val );

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

		ber_bvfree( value );
		keys[nkeys++] = ber_bvdup( &digest );
	}

	if((flags & SLAP_INDEX_SUBSTR_ANY) && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			value = ber_bvdup( sa->sa_any[i] );
			ldap_pvt_str2upper( value->bv_val );

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

				keys[nkeys++] = ber_bvdup( &digest );
			}

			ber_bvfree( value );
		}
	}

	if((flags & SLAP_INDEX_SUBSTR_FINAL) && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		value = ber_bvdup( sa->sa_final );
		ldap_pvt_str2upper( value->bv_val );

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

		ber_bvfree( value );
		keys[nkeys++] = ber_bvdup( &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

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

	if( val->bv_val[0] == '+' || val->bv_val[0] == '-' ) {
		if( val->bv_len < 2 ) return LDAP_INVALID_SYNTAX;
	} else if( !ASCII_DIGIT(val->bv_val[0]) ) {
		return LDAP_INVALID_SYNTAX;
	}

	for(i=1; i < val->bv_len; i++) {
		if( !ASCII_DIGIT(val->bv_val[i]) ) return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

static int
integerNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	int negative;
	struct berval *newval;
	char *p;

	p = val->bv_val;

	/* save sign */
	negative = ( *p == '-' );
	if( *p == '-' || *p == '+' ) p++;

	/* Ignore leading zeros */
	while ( *p == '0' ) p++;

	newval = (struct berval *) ch_malloc( sizeof(struct berval) );

	if( *p == '\0' ) {
		newval->bv_val = ch_strdup("0");
		newval->bv_len = 1;
		goto done;
	}

	newval->bv_val = ch_malloc( val->bv_len + 1 );
	newval->bv_len = 0;

	if( negative ) {
		newval->bv_val[newval->bv_len++] = '-';
	}

	for( ; *p != '\0'; p++ ) {
		newval->bv_val[newval->bv_len++] = *p;
	}

done:
	*normalized = newval;
	return LDAP_SUCCESS;
}

static int
countryStringValidate(
	Syntax *syntax,
	struct berval *val )
{
	ber_len_t i;

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

	if( !val->bv_len ) return LDAP_INVALID_SYNTAX;

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
	ber_len_t i;

	if( !val->bv_len ) return LDAP_INVALID_SYNTAX;

	for(i=0; i < val->bv_len; i++) {
		if( !SLAP_PRINTABLES(val->bv_val[i]) ) {
			return LDAP_INVALID_SYNTAX;
		}
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

	if( *p == '\0' ) {
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
	assert( q <= p );

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
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		struct berval *value = values[i];

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

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseExactIA5Filter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	value = (struct berval *) assertValue;

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

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

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
int caseExactIA5SubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	ber_len_t i, nkeys;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i]->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		ber_len_t j,max;
		struct berval *value;

		value = values[i];
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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
			}

		}
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}

int caseExactIA5SubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	SubstringsAssertion *sa = assertValue;
	char pre;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i]->bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );
	nkeys = 0;

	if( flags & SLAP_INDEX_SUBSTR_INITIAL && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		value = sa->sa_initial;

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

		keys[nkeys++] = ber_bvdup( &digest );
	}

	if( flags & SLAP_INDEX_SUBSTR_ANY && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			value = sa->sa_any[i];

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

				keys[nkeys++] = ber_bvdup( &digest );
			}
		}
	}

	if( flags & SLAP_INDEX_SUBSTR_FINAL && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		value = sa->sa_final;

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

		keys[nkeys++] = ber_bvdup( &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
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

	if( match == 0 ) {
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
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	int i;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	for( i=0; values[i] != NULL; i++ ) {
		/* just count them */
	}

	keys = ch_malloc( sizeof( struct berval * ) * (i+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	for( i=0; values[i] != NULL; i++ ) {
		struct berval *value = ber_bvdup( values[i] );
		ldap_pvt_str2upper( value->bv_val );

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

		ber_bvfree( value );

		keys[i] = ber_bvdup( &digest );
	}

	keys[i] = NULL;
	*keysp = keys;
	return LDAP_SUCCESS;
}

/* Index generation function */
int caseIgnoreIA5Filter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	value = ber_bvdup( (struct berval *) assertValue );
	ldap_pvt_str2upper( value->bv_val );

	keys = ch_malloc( sizeof( struct berval * ) * 2 );

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

	keys[0] = ber_bvdup( &digest );
	keys[1] = NULL;

	ber_bvfree( value );

	*keysp = keys;

	return LDAP_SUCCESS;
}

/* Substrings Index generation function */
int caseIgnoreIA5SubstringsIndexer(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	struct berval **values,
	struct berval ***keysp )
{
	ber_len_t i, nkeys;
	size_t slen, mlen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval digest;
	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	/* we should have at least one value at this point */
	assert( values != NULL && values[0] != NULL );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		/* count number of indices to generate */
		if( values[i]->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) {
			continue;
		}

		if( flags & SLAP_INDEX_SUBSTR_INITIAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_ANY ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}

		if( flags & SLAP_INDEX_SUBSTR_FINAL ) {
			if( values[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				nkeys += SLAP_INDEX_SUBSTR_MAXLEN -
					( SLAP_INDEX_SUBSTR_MINLEN - 1);
			} else {
				nkeys += values[i]->bv_len - ( SLAP_INDEX_SUBSTR_MINLEN - 1 );
			}
		}
	}

	if( nkeys == 0 ) {
		/* no keys to generate */
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	nkeys=0;
	for( i=0; values[i] != NULL; i++ ) {
		int j,max;
		struct berval *value;

		if( values[i]->bv_len < SLAP_INDEX_SUBSTR_MINLEN ) continue;

		value = ber_bvdup( values[i] );
		ldap_pvt_str2upper( value->bv_val );

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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
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

				keys[nkeys++] = ber_bvdup( &digest );
			}

		}

		ber_bvfree( value );
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

	return LDAP_SUCCESS;
}

int caseIgnoreIA5SubstringsFilter(
	slap_mask_t use,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	void * assertValue,
	struct berval ***keysp )
{
	SubstringsAssertion *sa = assertValue;
	char pre;
	ber_len_t nkeys = 0;
	size_t slen, mlen, klen;
	struct berval **keys;
	HASH_CONTEXT   HASHcontext;
	unsigned char   HASHdigest[HASH_BYTES];
	struct berval *value;
	struct berval digest;

	if((flags & SLAP_INDEX_SUBSTR_INITIAL) && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if((flags & SLAP_INDEX_SUBSTR_ANY) && sa->sa_any != NULL ) {
		ber_len_t i;
		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len >= SLAP_INDEX_SUBSTR_MAXLEN ) {
				/* don't bother accounting for stepping */
				nkeys += sa->sa_any[i]->bv_len -
					( SLAP_INDEX_SUBSTR_MAXLEN - 1 );
			}
		}
	}

	if((flags & SLAP_INDEX_SUBSTR_FINAL) && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		nkeys++;
	}

	if( nkeys == 0 ) {
		*keysp = NULL;
		return LDAP_SUCCESS;
	}

	digest.bv_val = HASHdigest;
	digest.bv_len = sizeof(HASHdigest);

	slen = strlen( syntax->ssyn_oid );
	mlen = strlen( mr->smr_oid );

	keys = ch_malloc( sizeof( struct berval * ) * (nkeys+1) );
	nkeys = 0;

	if((flags & SLAP_INDEX_SUBSTR_INITIAL) && sa->sa_initial != NULL &&
		sa->sa_initial->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_INITIAL_PREFIX;
		value = ber_bvdup( sa->sa_initial );
		ldap_pvt_str2upper( value->bv_val );

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

		ber_bvfree( value );
		keys[nkeys++] = ber_bvdup( &digest );
	}

	if((flags & SLAP_INDEX_SUBSTR_ANY) && sa->sa_any != NULL ) {
		ber_len_t i, j;
		pre = SLAP_INDEX_SUBSTR_PREFIX;
		klen = SLAP_INDEX_SUBSTR_MAXLEN;

		for( i=0; sa->sa_any[i] != NULL; i++ ) {
			if( sa->sa_any[i]->bv_len < SLAP_INDEX_SUBSTR_MAXLEN ) {
				continue;
			}

			value = ber_bvdup( sa->sa_any[i] );
			ldap_pvt_str2upper( value->bv_val );

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

				keys[nkeys++] = ber_bvdup( &digest );
			}

			ber_bvfree( value );
		}
	}

	if((flags & SLAP_INDEX_SUBSTR_FINAL) && sa->sa_final != NULL &&
		sa->sa_final->bv_len >= SLAP_INDEX_SUBSTR_MINLEN )
	{
		pre = SLAP_INDEX_SUBSTR_FINAL_PREFIX;
		value = ber_bvdup( sa->sa_final );
		ldap_pvt_str2upper( value->bv_val );

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

		ber_bvfree( value );
		keys[nkeys++] = ber_bvdup( &digest );
	}

	if( nkeys > 0 ) {
		keys[nkeys] = NULL;
		*keysp = keys;
	} else {
		ch_free( keys );
		*keysp = NULL;
	}

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

	if( *p == '\0' ) {
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
	assert( q <= p );

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
		char *stored = ch_malloc( oid.bv_len + 1 );
		AC_MEMCPY( stored, oid.bv_val, oid.bv_len );
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
	case -1: /* negativ offset to UTC, ie west of Greenwich  */
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
	if( out == NULL ) {
		return LBER_ERROR_MEMORY;
	}

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
	if( out == NULL ) {
		return LBER_ERROR_MEMORY;
	}

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

#if 0
	/* syntax does not allow leading white space */
	/* Ignore initial whitespace */
	while ( ( p < e ) && ASCII_SPACE( *p ) ) {
		p++;
	}
#endif

	if ( *p != '(' /*')'*/ ) {
		return LDAP_INVALID_SYNTAX;
	}

	for ( p++; ( p < e ) && ( *p != ')' ); p++ ) {
		if ( *p == ',' ) {
			commas++;
			if ( commas > 2 ) {
				return LDAP_INVALID_SYNTAX;
			}

		} else if ( !ATTR_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if ( ( commas != 2 ) || ( *p != /*'('*/ ')' ) ) {
		return LDAP_INVALID_SYNTAX;
	}

	p++;

#if 0
	/* syntax does not allow trailing white space */
	/* Ignore trailing whitespace */
	while ( ( p < e ) && ASCII_SPACE( *p ) ) {
		p++;
	}
#endif

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
		if ( !ATTR_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if ( *p != '=' ) {
		return LDAP_INVALID_SYNTAX;
	}

	/* server */
	for ( p++; ( p < e ) && ( *p != ':' ); p++ ) {
		if ( !ATTR_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	if ( *p != ':' ) {
		return LDAP_INVALID_SYNTAX;
	}

	/* path */
	for ( p++; p < e; p++ ) {
		if ( !ATTR_CHAR( *p ) ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

	return LDAP_SUCCESS;
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
	{"( 1.3.6.1.4.1.1466.115.121.1.5 DESC 'Binary' " X_NOT_H_R ")",
		SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )",
		0, bitStringValidate, NULL, NULL },
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
		0, printablesStringValidate, IA5StringNormalize, NULL},
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
		0, IA5StringValidate, numericStringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )",
		0, oidValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )",
		0, IA5StringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )",
		0, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )",
		0, blobValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.42 DESC 'Protocol Information' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'Presentation Address' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )",
		0, printableStringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.49 DESC 'Supported Algorithm' "
		X_BINARY X_NOT_H_R ")",
		SLAP_SYNTAX_BINARY|SLAP_SYNTAX_BER, berValidate, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )",
		0, printableStringValidate, IA5StringNormalize, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )",
		0, NULL, NULL, NULL},
	{"( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )",
		0, printableStringValidate, IA5StringNormalize, NULL},
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

	/* RFC 2307 NIS Syntaxes */
	{"( 1.3.6.1.1.1.0.0  DESC 'RFC2307 NIS Netgroup Triple' )",
		0, nisNetgroupTripleValidate, NULL, NULL},
	{"( 1.3.6.1.1.1.0.1  DESC 'RFC2307 Boot Parameter' )",
		0, bootParameterValidate, NULL, NULL},

	/* OpenLDAP Experimental Syntaxes */
	{"( 1.3.6.1.4.1.4203.666.2.1 DESC 'OpenLDAP Experimental ACI' )",
		0, IA5StringValidate /* THIS WILL CHANGE FOR NEW ACI SYNTAX */,
		NULL, NULL},
	{"( 1.3.6.1.4.1.4203.666.2.2 DESC 'OpenLDAP authPassword' )",
		0, NULL, NULL, NULL},

	/* OpenLDAP Void Syntax */
	{"( 1.3.6.1.4.1.4203.1.1.1 DESC 'OpenLDAP void' )" ,
		SLAP_SYNTAX_HIDE, inValidate, NULL, NULL},
	{NULL, 0, NULL, NULL, NULL}
};

struct mrule_defs_rec {
	char *						mrd_desc;
	slap_mask_t					mrd_usage;
	slap_mr_convert_func *		mrd_convert;
	slap_mr_normalize_func *	mrd_normalize;
	slap_mr_match_func *		mrd_match;
	slap_mr_indexer_func *		mrd_indexer;
	slap_mr_filter_func *		mrd_filter;

	char *						mrd_associated;
};

/*
 * Other matching rules in X.520 that we do not use (yet):
 *
 * 2.5.13.9		numericStringOrderingMatch
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
	/*
	 * EQUALITY matching rules must be listed after associated APPROX
	 * matching rules.  So, we list all APPROX matching rules first.
	 */
	{"( " directoryStringApproxMatchOID " NAME 'directoryStringApproxMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY_APPROX | SLAP_MR_EXT,
		NULL, NULL,
		directoryStringApproxMatch, directoryStringApproxIndexer, 
		directoryStringApproxFilter,
		NULL},

	{"( " IA5StringApproxMatchOID " NAME 'IA5StringApproxMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY_APPROX | SLAP_MR_EXT,
		NULL, NULL,
		IA5StringApproxMatch, IA5StringApproxIndexer, 
		IA5StringApproxFilter,
		NULL},

	/*
	 * Other matching rules
	 */
	
	{"( 2.5.13.0 NAME 'objectIdentifierMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		objectIdentifierMatch, caseIgnoreIA5Indexer, caseIgnoreIA5Filter,
		NULL},

	{"( 2.5.13.1 NAME 'distinguishedNameMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		dnMatch, dnIndexer, dnFilter,
		NULL},

	{"( 2.5.13.2 NAME 'caseIgnoreMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreMatch, caseIgnoreIndexer, caseIgnoreFilter,
		directoryStringApproxMatchOID },

	{"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING,
		NULL, NULL,
		caseIgnoreOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreSubstringsMatch,
		caseIgnoreSubstringsIndexer,
		caseIgnoreSubstringsFilter,
		NULL},

	{"( 2.5.13.5 NAME 'caseExactMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		caseExactMatch, caseExactIndexer, caseExactFilter,
		directoryStringApproxMatchOID },

	{"( 2.5.13.6 NAME 'caseExactOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		SLAP_MR_ORDERING,
		NULL, NULL,
		caseExactOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.7 NAME 'caseExactSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL,
		caseExactSubstringsMatch,
		caseExactSubstringsIndexer,
		caseExactSubstringsFilter,
		NULL},

	{"( 2.5.13.8 NAME 'numericStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreIA5Match,
		caseIgnoreIA5Indexer,
		caseIgnoreIA5Filter,
		NULL},

	{"( 2.5.13.10 NAME 'numericStringSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreIA5SubstringsMatch,
		caseIgnoreIA5SubstringsIndexer,
		caseIgnoreIA5SubstringsFilter,
		NULL},

	{"( 2.5.13.11 NAME 'caseIgnoreListMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreListMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.12 NAME 'caseIgnoreListSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreListSubstringsMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.13 NAME 'booleanMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		booleanMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.14 NAME 'integerMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		integerMatch, integerIndexer, integerFilter,
		NULL},

	{"( 2.5.13.16 NAME 'bitStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		bitStringMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.17 NAME 'octetStringMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		octetStringMatch, octetStringIndexer, octetStringFilter,
		NULL},

	{"( 2.5.13.20 NAME 'telephoneNumberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		telephoneNumberMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.21 NAME 'telephoneNumberSubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.58 )",
		SLAP_MR_SUBSTR | SLAP_MR_EXT,
		NULL, NULL,
		telephoneNumberSubstringsMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.22 NAME 'presentationAddressMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.43 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		presentationAddressMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.23 NAME 'uniqueMemberMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		uniqueMemberMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.24 NAME 'protocolInformationMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.42 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		protocolInformationMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.27 NAME 'generalizedTimeMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		generalizedTimeMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		SLAP_MR_ORDERING,
		NULL, NULL,
		generalizedTimeOrderingMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.29 NAME 'integerFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		integerFirstComponentMatch, NULL, NULL,
		NULL},

	{"( 2.5.13.30 NAME 'objectIdentifierFirstComponentMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		objectIdentifierFirstComponentMatch, NULL, NULL,
		NULL},

	{"( 1.3.6.1.4.1.1466.109.114.1 NAME 'caseExactIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		caseExactIA5Match, caseExactIA5Indexer, caseExactIA5Filter,
		IA5StringApproxMatchOID },

	{"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_EQUALITY | SLAP_MR_EXT,
		NULL, NULL,
		caseIgnoreIA5Match, caseIgnoreIA5Indexer, caseIgnoreIA5Filter,
		IA5StringApproxMatchOID },

	{"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_SUBSTR,
		NULL, NULL,
		caseIgnoreIA5SubstringsMatch,
		caseIgnoreIA5SubstringsIndexer,
		caseIgnoreIA5SubstringsFilter,
		NULL},

	{"( 1.3.6.1.4.1.4203.1.2.1 NAME 'caseExactIA5SubstringsMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )",
		SLAP_MR_SUBSTR,
		NULL, NULL,
		caseExactIA5SubstringsMatch,
		caseExactIA5SubstringsIndexer,
		caseExactIA5SubstringsFilter,
		NULL},

	{"( 1.3.6.1.4.1.4203.666.4.1 NAME 'authPasswordMatch' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
		SLAP_MR_EQUALITY,
		NULL, NULL,
		authPasswordMatch, NULL, NULL,
		NULL},

	{"( 1.3.6.1.4.1.4203.666.4.2 NAME 'OpenLDAPaciMatch' "
		"SYNTAX 1.3.6.1.4.1.4203.666.2.1 )",
		SLAP_MR_EQUALITY,
		NULL, NULL,
		OpenLDAPaciMatch, NULL, NULL,
		NULL},

	{NULL, SLAP_MR_NONE, NULL, NULL, NULL, NULL}
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
			mrule_defs[i].mrd_filter,
			mrule_defs[i].mrd_associated );

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
