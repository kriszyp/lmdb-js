/* dn.c - routines for dealing with distinguished names */
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

#include "ldap_pvt.h"

#include "slap.h"

#define SLAP_LDAPDN_PRETTY 0x1

/*
 * The DN syntax-related functions take advantage of the dn representation
 * handling functions ldap_str2dn/ldap_dn2str.  The latter are not schema-
 * aware, so the attributes and their values need be validated (and possibly
 * normalized).  In the current implementation the required validation/nor-
 * malization/"pretty"ing are done on newly created DN structural represen-
 * tations; however the idea is to move towards DN handling in structural
 * representation instead of the current string representation.  To this
 * purpose, we need to do only the required operations and keep track of
 * what has been done to minimize their impact on performances.
 *
 * Developers are strongly encouraged to use this feature, to speed-up
 * its stabilization.
 */

#define	AVA_PRIVATE( ava ) ( ( AttributeDescription * )(ava)->la_private )

/*
 * In-place, schema-aware validation of the
 * structural representation of a distinguished name.
 */
static int
LDAPDN_validate( LDAPDN *dn )
{
	int 		iRDN;
	int 		rc;

	assert( dn );

	for ( iRDN = 0; dn[ iRDN ]; iRDN++ ) {
		LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
		int		iAVA;

		assert( rdn );

		for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
			LDAPAVA			*ava = rdn[ iAVA ][ 0 ];
			AttributeDescription	*ad;
			slap_syntax_validate_func *validate = NULL;

			assert( ava );
			
			if ( ( ad = AVA_PRIVATE( ava ) ) == NULL ) {
				const char	*text = NULL;

				rc = slap_bv2ad( ava->la_attr, &ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}

				ava->la_private = ( void * )ad;
			}

			/* 
			 * Replace attr oid/name with the canonical name
			 */
			ber_bvfree( ava->la_attr );
			ava->la_attr = ber_bvdup( &ad->ad_cname );

			validate = ad->ad_type->sat_syntax->ssyn_validate;

			if ( validate ) {
				/*
			 	 * validate value by validate function
				 */
				rc = ( *validate )( ad->ad_type->sat_syntax,
					ava->la_value );
			
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
			}
		}
	}

	return LDAP_SUCCESS;
}

/*
 * dn validate routine
 */
int
dnValidate(
	Syntax *syntax,
	struct berval *in )
{
	int		rc;
	LDAPDN		*dn = NULL;

	assert( in );

	if ( in->bv_len == 0 ) {
		return( LDAP_SUCCESS );
	}

	rc = ldap_str2dn( in->bv_val, &dn, LDAP_DN_FORMAT_LDAP );

	/*
	 * Schema-aware validate
	 */
	if ( rc == LDAP_SUCCESS ) {
		rc = LDAPDN_validate( dn );
	}
	
	ldap_dnfree( dn );
	
	if ( rc != LDAP_SUCCESS ) {
		return( LDAP_INVALID_SYNTAX );
	}

	return( LDAP_SUCCESS );
}

/*
 * AVA sorting inside a RDN
 *
 * rule: sort attributeTypes in alphabetical order; in case of multiple
 * occurrences of the same attributeType, sort values in byte order
 * (use memcmp, which implies alphabetical order in case of IA5 value;
 * this should guarantee the repeatability of the operation).
 *
 * uses a linear search; should be fine since the number of AVAs in
 * a RDN should be limited.
 */
static void
AVA_Sort( LDAPRDN *rdn, int iAVA )
{
	int		i;
	LDAPAVA		*ava_in = rdn[ iAVA ][ 0 ];

	assert( rdn );
	assert( ava_in );
	
	for ( i = 0; i < iAVA; i++ ) {
		LDAPAVA		*ava = rdn[ i ][ 0 ];
		int		a, j;

		assert( ava );

		a = strcmp( ava_in->la_attr->bv_val, ava->la_attr->bv_val );

		if ( a > 0 ) {
			break;
		}

		while ( a == 0 ) {
			int		v, d;

			d = ava_in->la_value->bv_len - ava->la_value->bv_len;

			v = memcmp( ava_in->la_value->bv_val, 
					ava->la_value->bv_val,
					d <= 0 ? ava_in->la_value->bv_len 
						: ava->la_value->bv_len );

			if ( v == 0 && d != 0 ) {
				v = d;
			}

			if ( v <= 0 ) {
				/* 
				 * got it!
				 */
				break;
			}

			if ( ++i == iAVA ) {
				/*
				 * already sorted
				 */
				return;
			}

			ava = rdn[ i ][ 0 ];
			a = strcmp( ava_in->la_value->bv_val, 
					ava->la_value->bv_val );
		}

		/*
		 * move ahead
		 */
		for ( j = iAVA; j > i; j-- ) {
			rdn[ j ][ 0 ] = rdn[ j - 1 ][ 0 ];
		}
		rdn[ i ][ 0 ] = ava_in;

		return;
	}
}

/*
 * In-place, schema-aware normalization / "pretty"ing of the
 * structural representation of a distinguished name.
 */
static int
LDAPDN_rewrite( LDAPDN *dn, unsigned flags )
{
	int 		iRDN;
	int 		rc;

	assert( dn );

	for ( iRDN = 0; dn[ iRDN ]; iRDN++ ) {
		LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
		int		iAVA;

		assert( rdn );

		for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
			LDAPAVA			*ava = rdn[ iAVA ][ 0 ];
			AttributeDescription	*ad;
			slap_syntax_transform_func *transf = NULL;
			MatchingRule *mr;
			struct berval		*bv = NULL;

			assert( ava );

			if ( ( ad = AVA_PRIVATE( ava ) ) == NULL ) {
				const char	*text = NULL;

				rc = slap_bv2ad( ava->la_attr, &ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
				
				ava->la_private = ( void * )ad;
			}

			/* 
			 * Replace attr oid/name with the canonical name
			 */
			ber_bvfree( ava->la_attr );
			ava->la_attr = ber_bvdup( &ad->ad_cname );

			if( flags & SLAP_LDAPDN_PRETTY ) {
				transf = ad->ad_type->sat_syntax->ssyn_pretty;
				mr = NULL;
			} else {
				transf = ad->ad_type->sat_syntax->ssyn_normalize;
				mr = ad->ad_type->sat_equality;
			}

			if ( transf ) {
				/*
			 	 * transform value by normalize/pretty function
				 */
				rc = ( *transf )( ad->ad_type->sat_syntax,
					ava->la_value, &bv );
			
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
			}

			if( mr && ( mr->smr_usage & SLAP_MR_DN_FOLD ) ) {
				struct berval *s = bv;

				bv = ber_bvstr( UTF8normalize( bv ? bv : ava->la_value, 
					UTF8_CASEFOLD ) );

				ber_bvfree( s );
			}

			if( bv ) {
				ber_bvfree( ava->la_value );
				ava->la_value = bv;
			}

			AVA_Sort( rdn, iAVA );
		}
	}

	return LDAP_SUCCESS;
}

/*
 * dn normalize routine
 */
int
dnNormalize(
	Syntax *syntax,
	struct berval *val,
	struct berval **normalized )
{
	struct berval *out = NULL;

	Debug( LDAP_DEBUG_TRACE, ">>> dnNormalize: <%s>\n", val->bv_val, 0, 0 );

	assert( val );
	assert( normalized );

	if ( val->bv_len != 0 ) {
		LDAPDN		*dn = NULL;
		char		*dn_out = NULL;
		int		rc;

		/*
		 * Go to structural representation
		 */
		rc = ldap_str2dn( val->bv_val, &dn, LDAP_DN_FORMAT_LDAP );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		/*
		 * Schema-aware rewrite
		 */
		if ( LDAPDN_rewrite( dn, 0 ) != LDAP_SUCCESS ) {
			ldap_dnfree( dn );
			return LDAP_INVALID_SYNTAX;
		}

		/*
		 * Back to string representation
		 */
		rc = ldap_dn2str( dn, &dn_out, LDAP_DN_FORMAT_LDAPV3 );

		ldap_dnfree( dn );

		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		out = ber_bvstr( dn_out );

	} else {
		out = ber_bvdup( val );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dnNormalize: <%s>\n", out->bv_val, 0, 0 );

	*normalized = out;

	return LDAP_SUCCESS;
}

/*
 * dn "pretty"ing routine
 */
int
dnPretty(
	Syntax *syntax,
	struct berval *val,
	struct berval **pretty)
{
	struct berval *out = NULL;

	Debug( LDAP_DEBUG_TRACE, ">>> dnPretty: <%s>\n", val->bv_val, 0, 0 );

	assert( val );
	assert( pretty );

	if ( val->bv_len != 0 ) {
		LDAPDN		*dn = NULL;
		char		*dn_out = NULL;
		int		rc;

		/* FIXME: should be liberal in what we accept */
		rc = ldap_str2dn( val->bv_val, &dn, LDAP_DN_FORMAT_LDAP );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		/*
		 * Schema-aware rewrite
		 */
		if ( LDAPDN_rewrite( dn, SLAP_LDAPDN_PRETTY ) != LDAP_SUCCESS ) {
			ldap_dnfree( dn );
			return LDAP_INVALID_SYNTAX;
		}

		/* FIXME: not sure why the default isn't pretty */
		/* RE: the default is the form that is used as
		 * an internal representation; the pretty form
		 * is a variant */
		rc = ldap_dn2str( dn, &dn_out,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY );

		ldap_dnfree( dn );

		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		out = ber_bvstr( dn_out );

	} else {
		out = ber_bvdup( val );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dnPretty: <%s>\n", out->bv_val, 0, 0 );

	*pretty = out;

	return LDAP_SUCCESS;
}

/*
 * dnMatch routine
 *
 * note: uses exact string match (strcmp) because it is supposed to work
 * on normalized DNs.
 */
int
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

	assert( matchp );
	assert( value );
	assert( assertedValue );
	
	match = value->bv_len - asserted->bv_len;

	if ( match == 0 ) {
		match = strcmp( value->bv_val, asserted->bv_val );
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "schema", LDAP_LEVEL_ENTRY,
		"dnMatch: %d\n    %s\n    %s\n", match,
		value->bv_val, asserted->bv_val ));
#else
	Debug( LDAP_DEBUG_ARGS, "dnMatch %d\n\t\"%s\"\n\t\"%s\"\n",
		match, value->bv_val, asserted->bv_val );
#endif

	*matchp = match;
	return( LDAP_SUCCESS );
}

#ifdef SLAP_DN_MIGRATION
/*
 * these routines are provided for migration purposes only!
 *	dn_validate is deprecated in favor of dnValidate
 *	dn_normalize is deprecated in favor of dnNormalize
 *	strcmp/strcasecmp for DNs is deprecated in favor of dnMatch
 *
 * other routines are likewise deprecated but may not yet have
 * replacement functions.
 */

/*
 * dn_validate - validate and compress dn.  the dn is
 * compressed in place are returned if valid.
 * Deprecated in favor of dnValidate()
 */
char *
dn_validate( char *dn )
{
	struct berval val, *pretty;
	int		rc;

	if ( dn == NULL || dn[0] == '\0' ) {
		return dn;
	}

	val.bv_val = dn;
	val.bv_len = strlen( dn );

	rc = dnPretty( NULL, &val, &pretty );
	if ( rc != LDAP_SUCCESS ) {
		return NULL;
	}

	if ( val.bv_len < pretty->bv_len ) {
		ber_bvfree( pretty );
		return NULL;
	}

	AC_MEMCPY( dn, pretty->bv_val, pretty->bv_len + 1 );
	ber_bvfree( pretty );

	return dn;
}

/*
 * dn_normalize - put dn into a canonical form suitable for storing
 * in a hash database.	this involves normalizing the case as well as
 * the format.	the dn is normalized in place as well as returned if valid.
 * Deprecated in favor of dnNormalize()
 */
char *
dn_normalize( char *dn )
{
	struct berval	val, *normalized;
	int		rc;

	if ( dn == NULL || dn[0] == '\0' ) {
		return dn;
	}

	val.bv_val = dn;
	val.bv_len = strlen( dn );

	rc = dnNormalize( NULL, &val, &normalized );
	if ( rc != LDAP_SUCCESS ) {
		return NULL;
	}

	if ( val.bv_len < normalized->bv_len ) {
		ber_bvfree( normalized );
		return NULL;
	}

	AC_MEMCPY( dn, normalized->bv_val, normalized->bv_len + 1 );
	ber_bvfree( normalized );

	return dn;
}


/*
 * dn_parent - return the dn's parent, in-place
 */
char *
dn_parent(
	Backend	*be,
	const char	*dn )
{
	const char	*s;
	int	inquote;

	if( dn == NULL ) {
		return NULL;
	}

	while(*dn != '\0' && ASCII_SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
		return NULL;
	}

	if ( be != NULL && be_issuffix( be, dn ) ) {
		return NULL;
	}

	/*
	 * assume it is an X.500-style name, which looks like
	 * foo=bar,sha=baz,...
	 */

	inquote = 0;
	for ( s = dn; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) ) {
				s++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *s == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *s ) ) {
				return (char *)s + 1;
			}
		}
	}

	return "";
}

int dn_rdnlen(
	Backend	*be,
	const char	*dn_in )
{
	char	*s;
	int	inquote;

	if( dn_in == NULL ) {
		return 0;
	}

	while(*dn_in && ASCII_SPACE(*dn_in)) {
		dn_in++;
	}

	if( *dn_in == '\0' ) {
		return( 0 );
	}

	if ( be != NULL && be_issuffix( be, dn_in ) ) {
		return( 0 );
	}

	inquote = 0;

	for ( s = (char *)dn_in; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) ) {
				s++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *s == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *s ) ) {
				break;
			}
		}
	}

	return( s - dn_in );
}

char * dn_rdn(
	Backend	*be,
	const char	*dn_in )
{
	char *rdn;
	int i = dn_rdnlen( be, dn_in );

	rdn = ch_malloc( i + 1 );
	strncpy(rdn, dn_in, i);
	rdn[i] = '\0';
	return rdn;
}

/*
 * return a charray of all subtrees to which the DN resides in
 */
char **dn_subtree(
	Backend	*be,
	const char	*dn )
{
	char **subtree = NULL;
	
	do {
		charray_add( &subtree, dn );

		dn = dn_parent( be, dn );

	} while ( dn != NULL );

	return subtree;
}

/*
 * dn_issuffix - tells whether suffix is a suffix of dn.
 * Both dn and suffix must be normalized.
 *	deprecated in favor of dnIsSuffix()
 */
int
dn_issuffix(
	const char	*dn,
	const char	*suffix
)
{
	struct berval	bvdn, bvsuffix;

	assert( dn );
	assert( suffix );

	bvdn.bv_val = (char *) dn;
	bvdn.bv_len = strlen( dn );
	bvsuffix.bv_val = (char *) suffix;
	bvsuffix.bv_len = strlen( suffix );

	return dnIsSuffix( &bvdn, &bvsuffix );
}

/*
 * get_next_substring(), rdn_attr_type(), rdn_attr_value(), and
 * build_new_dn().
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

/* get_next_substring:
 *
 * Gets next substring in s, using d (or the end of the string '\0') as a
 * string delimiter, and places it in a duplicated memory space. Leading
 * spaces are ignored. String s **must** be null-terminated.
 */

static char *
get_next_substring( const char * s, char d )
{

	char	*str, *r;

	r = str = ch_malloc( strlen(s) + 1 );

	/* Skip leading spaces */
	
	while ( *s && ASCII_SPACE(*s) ) {
		s++;
	}
	
	/* Copy word */

	while ( *s && (*s != d) ) {

		/* Don't stop when you see trailing spaces may be a multi-word
		* string, i.e. name=John Doe!
		*/

		*str++ = *s++;
	}
	
	*str = '\0';
	
	return r;
	
}


/* rdn_attr_type:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns the type of an attribute, that is the
 * string "attribute_type" which is placed in newly allocated
 * memory. The returned string will be null-terminated.
 */

char * rdn_attr_type( const char * s )
{
	return get_next_substring( s, '=' );
}


/* rdn_attr_value:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns "attribute_type" which is placed in newly allocated
 * memory. The returned string will be null-terminated and may contain
 * spaces (i.e. "John Doe\0").
 */

char *
rdn_attr_value( const char * rdn )
{

	const char	*str;

	if ( (str = strchr( rdn, '=' )) != NULL ) {
		return get_next_substring(++str, '\0');
	}

	return NULL;

}


/* rdn_attrs:
 *
 * Given a string (i.e. an rdn) of the form:
 *   "attribute_type=attribute_value[+attribute_type=attribute_value[...]]"
 * this function stores the types of the attributes in ptypes, that is the
 * array of strings "attribute_type" which is placed in newly allocated
 * memory, and the values of the attributes in pvalues, that is the
 * array of strings "attribute_value" which is placed in newly allocated
 * memory. Returns 0 on success, -1 on failure.
 *
 * note: got part of the code from dn_validate
 */

int
rdn_attrs( const char * rdn_in, char ***ptypes, char ***pvalues)
{
	char **parts, **p;

	*ptypes = NULL;
	*pvalues = NULL;

	/*
	 * explode the rdn in parts
	 */
	parts = ldap_explode_rdn( rdn_in, 0 );

	if ( parts == NULL ) {
		return( -1 );
	}

	for ( p = parts; p[0]; p++ ) {
		char *s, *e, *d;
		
		/* split each rdn part in type value */
		s = strchr( p[0], '=' );
		if ( s == NULL ) {
			charray_free( *ptypes );
			charray_free( *pvalues );
			charray_free( parts );
			return( -1 );
		}
		
		/* type should be fine */
		charray_add_n( ptypes, p[0], ( s-p[0] ) );

		/* value needs to be unescaped
		 * (maybe this should be moved to ldap_explode_rdn?) */
		for ( e = d = s + 1; e[0]; e++ ) {
			if ( *e != '\\' ) {
				*d++ = *e;
			}
		}
		d[0] = '\0';
		charray_add( pvalues, s + 1 );
	}

	/* free array */
	charray_free( parts );

	return( 0 );
}


/* rdn_validate:
 *
 * 1 if rdn is a legal rdn;
 * 0 otherwise (including a sequence of rdns)
 *
 * note: got it from dn_rdn; it should be rewritten
 * according to dn_validate
 */
int
rdn_validate( const char * rdn )
{
	int	inquote;

	if ( rdn == NULL ) {
		return( 0 );
	}

	if ( strchr( rdn, '=' ) == NULL ) {
		return( 0 );
	}

	while ( *rdn && ASCII_SPACE( *rdn ) ) {
		rdn++;
	}

	if( *rdn == '\0' ) {
		return( 0 );
	}

	inquote = 0;

	for ( ; *rdn; rdn++ ) {
		if ( *rdn == '\\' ) {
			if ( *(rdn + 1) ) {
				rdn++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *rdn == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *rdn == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *rdn ) ) {
				return( 0 );
			}
		}
	}

	return( 1 );
}


/* build_new_dn:
 *
 * Used by ldbm/bdb2 back_modrdn to create the new dn of entries being
 * renamed.
 *
 * new_dn = parent (p_dn) + separator(s) + rdn (newrdn) + null.
 */

void
build_new_dn( char ** new_dn,
	const char *e_dn,
	const char * p_dn,
	const char * newrdn )
{

	if ( p_dn == NULL ) {
		*new_dn = ch_strdup( newrdn );
		return;
	}

	*new_dn = (char *) ch_malloc( strlen( p_dn ) + strlen( newrdn ) + 3 );

	strcpy( *new_dn, newrdn );
	strcat( *new_dn, "," );
	strcat( *new_dn, p_dn );
}

#endif /* SLAP_DN_MIGRATION */

/*
 * dnIsSuffix - tells whether suffix is a suffix of dn.
 * Both dn and suffix must be normalized.
 */
int
dnIsSuffix(
	const struct berval *dn,
	const struct berval *suffix )
{
	int	d = dn->bv_len - suffix->bv_len;

	assert( dn );
	assert( suffix );

	/* empty suffix matches any dn */
	if ( suffix->bv_len == 0 ) {
		return 1;
	}

	/* suffix longer than dn */
	if ( d < 0 ) {
		return 0;
	}

	/* no rdn separator or escaped rdn separator */
	if ( d > 1 && ( !DN_SEPARATOR( dn->bv_val[ d - 1 ] ) 
				|| DN_ESCAPE( dn->bv_val[ d - 2 ] ) ) ) {
		return 0;
	}

	/* no possible match or malformed dn */
	if ( d == 1 ) {
		return 0;
	}

	/* compare */
	return( strcmp( dn->bv_val + d, suffix->bv_val ) == 0 );
}
