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

	for ( iRDN = 0; dn[ 0 ][ iRDN ]; iRDN++ ) {
		LDAPRDN		*rdn = dn[ 0 ][ iRDN ];
		int		iAVA;

		assert( rdn );

		for ( iAVA = 0; rdn[ 0 ][ iAVA ]; iAVA++ ) {
			LDAPAVA			*ava = rdn[ 0 ][ iAVA ];
			AttributeDescription	*ad;
			slap_syntax_validate_func *validate = NULL;

			assert( ava );
			
			if ( ( ad = AVA_PRIVATE( ava ) ) == NULL ) {
				const char	*text = NULL;

				rc = slap_bv2ad( &ava->la_attr, &ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}

				ava->la_private = ( void * )ad;
			}

			/* 
			 * Replace attr oid/name with the canonical name
			 */
			ava->la_attr = ad->ad_cname;

			validate = ad->ad_type->sat_syntax->ssyn_validate;

			if ( validate ) {
				/*
			 	 * validate value by validate function
				 */
				rc = ( *validate )( ad->ad_type->sat_syntax,
					&ava->la_value );
			
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
		ldap_dnfree( dn );
	}
	
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
	LDAPAVA		*ava_in = rdn[ 0 ][ iAVA ];

	assert( rdn );
	assert( ava_in );
	
	for ( i = 0; i < iAVA; i++ ) {
		LDAPAVA		*ava = rdn[ 0 ][ i ];
		int		a, j;

		assert( ava );

		a = strcmp( ava_in->la_attr.bv_val, ava->la_attr.bv_val );

		if ( a > 0 ) {
			break;
		}

		while ( a == 0 ) {
			int		v, d;

			d = ava_in->la_value.bv_len - ava->la_value.bv_len;

			v = memcmp( ava_in->la_value.bv_val, 
					ava->la_value.bv_val,
					d <= 0 ? ava_in->la_value.bv_len 
						: ava->la_value.bv_len );

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

			ava = rdn[ 0 ][ i ];
			a = strcmp( ava_in->la_value.bv_val, 
					ava->la_value.bv_val );
		}

		/*
		 * move ahead
		 */
		for ( j = iAVA; j > i; j-- ) {
			rdn[ 0 ][ j ] = rdn[ 0 ][ j - 1 ];
		}
		rdn[ 0 ][ i ] = ava_in;

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

	for ( iRDN = 0; dn[ 0 ][ iRDN ]; iRDN++ ) {
		LDAPRDN		*rdn = dn[ 0 ][ iRDN ];
		int		iAVA;

		assert( rdn );

		for ( iAVA = 0; rdn[ 0 ][ iAVA ]; iAVA++ ) {
			LDAPAVA			*ava = rdn[ 0 ][ iAVA ];
			AttributeDescription	*ad;
			slap_syntax_transform_func *transf = NULL;
			MatchingRule *mr;
			struct berval		bv = { 0, NULL };
			int			do_sort = 0;

			assert( ava );

			if ( ( ad = AVA_PRIVATE( ava ) ) == NULL ) {
				const char	*text = NULL;

				rc = slap_bv2ad( &ava->la_attr, &ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
				
				ava->la_private = ( void * )ad;
				do_sort = 1;
			}

			/* 
			 * Replace attr oid/name with the canonical name
			 */
			ava->la_attr = ad->ad_cname;

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
					&ava->la_value, &bv );
			
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
			}

			if( mr && ( mr->smr_usage & SLAP_MR_DN_FOLD ) ) {
				char *s = bv.bv_val;

				ber_str2bv( UTF8normalize( bv.bv_val ? &bv
					: &ava->la_value, LDAP_UTF8_CASEFOLD ),
					0, 0, &bv );
				free( s );
			}

			if( bv.bv_val ) {
				free( ava->la_value.bv_val );
				ava->la_value = bv;
			}

			if( do_sort ) AVA_Sort( rdn, iAVA );
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
	struct berval *out;
	int rc;

	assert( normalized && *normalized == NULL );

	out = ch_malloc( sizeof( struct berval ) );
	rc = dnNormalize2( syntax, val, out );
	if ( rc != LDAP_SUCCESS )
		free( out );
	else
		*normalized = out;
	return rc;
}

int
dnNormalize2(
	Syntax *syntax,
	struct berval *val,
	struct berval *out )
{
	assert( val );
	assert( out );

	Debug( LDAP_DEBUG_TRACE, ">>> dnNormalize: <%s>\n", val->bv_val, 0, 0 );

	if ( val->bv_len != 0 ) {
		LDAPDN		*dn = NULL;
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
		rc = ldap_dn2bv( dn, out, LDAP_DN_FORMAT_LDAPV3 );

		ldap_dnfree( dn );

		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}
	} else {
		ber_dupbv( out, val );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dnNormalize: <%s>\n", out->bv_val, 0, 0 );

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
	struct berval *out;
	int rc;

	assert( pretty && *pretty == NULL );

	out = ch_malloc( sizeof( struct berval ) );
	rc = dnPretty2( syntax, val, out );
	if ( rc != LDAP_SUCCESS )
		free( out );
	else
		*pretty = out;
	return rc;
}

int
dnPretty2(
	Syntax *syntax,
	struct berval *val,
	struct berval *out)
{
	assert( val );
	assert( out );

	Debug( LDAP_DEBUG_TRACE, ">>> dnPretty: <%s>\n", val->bv_val, 0, 0 );

	if ( val->bv_len != 0 ) {
		LDAPDN		*dn = NULL;
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
		rc = ldap_dn2bv( dn, out,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY );

		ldap_dnfree( dn );

		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}
	} else {
		ber_dupbv( out, val );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dnPretty: <%s>\n", out->bv_val, 0, 0 );

	return LDAP_SUCCESS;
}

/*
 * Combination of both dnPretty and dnNormalize
 */
int
dnPrettyNormal(
	Syntax *syntax,
	struct berval *val,
	struct berval *pretty,
	struct berval *normal)
{
	Debug( LDAP_DEBUG_TRACE, ">>> dnPrettyNormal: <%s>\n", val->bv_val, 0, 0 );

	assert( val );
	assert( pretty );
	assert( normal );

	if ( val->bv_len != 0 ) {
		LDAPDN		*dn = NULL;
		int		rc;

		pretty->bv_val = NULL;
		normal->bv_val = NULL;
		pretty->bv_len = 0;
		normal->bv_len = 0;

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

		rc = ldap_dn2bv( dn, pretty,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY );

		if ( rc != LDAP_SUCCESS ) {
			ldap_dnfree( dn );
			return LDAP_INVALID_SYNTAX;
		}

		if ( LDAPDN_rewrite( dn, 0 ) != LDAP_SUCCESS ) {
			ldap_dnfree( dn );
			free( pretty->bv_val );
			pretty->bv_val = NULL;
			pretty->bv_len = 0;
			return LDAP_INVALID_SYNTAX;
		}

		rc = ldap_dn2bv( dn, normal, LDAP_DN_FORMAT_LDAPV3 );

		ldap_dnfree( dn );
		if ( rc != LDAP_SUCCESS ) {
			free( pretty->bv_val );
			pretty->bv_val = NULL;
			pretty->bv_len = 0;
			return LDAP_INVALID_SYNTAX;
		}
	} else {
		ber_dupbv( pretty, val );
		ber_dupbv( normal, val );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dnPrettyNormal: <%s>, <%s>\n",
		pretty->bv_val, normal->bv_val, 0 );

	return LDAP_SUCCESS;
}

/*
 * dnMatch routine
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
	struct berval val;
	struct berval *pretty = NULL;
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
	struct berval val;
	struct berval *normalized = NULL;
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
 * dnParent - dn's parent, in-place
 */
int
dnParent( 
	const char	*dn, 
	const char	**pdn )
{
	const char	*p;
	int		rc;

	rc = ldap_str2rdn( dn, NULL, &p, LDAP_DN_FORMAT_LDAP | LDAP_DN_SKIP );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	/* Parent is root */
	if (*p == '\0') {
		*pdn = "";
		return LDAP_SUCCESS;
	}

	assert( DN_SEPARATOR( p[ 0 ] ) );
	p++;

	while ( ASCII_SPACE( p[ 0 ] ) ) {
		p++;
	}

	*pdn = p;

	return LDAP_SUCCESS;
}

/*
 * dn_parent - return the dn's parent, in-place
 * FIXME: should be replaced by dnParent()
 */
char *
dn_parent(
	Backend		*be,
	const char	*dn )
{
	const char	*pdn;

	if ( dn == NULL ) {
		return NULL;
	}

	while ( dn[ 0 ] != '\0' && ASCII_SPACE( dn[ 0 ] ) ) {
		dn++;
	}

	if ( dn[ 0 ] == '\0' ) {
		return NULL;
	}

	if ( be != NULL && be_issuffix( be, dn ) ) {
		return NULL;
	}

	if ( dnParent( dn, &pdn ) != LDAP_SUCCESS ) {
		return NULL;
	}
	
	return ( char * )pdn;
}

int
dnExtractRdn( 
	struct berval	*dn, 
	struct berval 	*rdn )
{
	LDAPRDN		*tmpRDN;
	const char	*p;
	int		rc;

	assert( dn );
	assert( rdn );

	if( dn->bv_len == 0 ) {
		return LDAP_OTHER;
	}

	rc = ldap_str2rdn( dn->bv_val, &tmpRDN, &p, LDAP_DN_FORMAT_LDAP );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	rc = ldap_rdn2bv( tmpRDN, rdn, LDAP_DN_FORMAT_LDAPV3 );
	ldap_rdnfree( tmpRDN );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	return LDAP_SUCCESS;
}

/*
 * FIXME: should be replaced by dnExtractRdn() (together with dn_rdn)
 */
int 
dn_rdnlen(
	Backend		*be,
	struct berval	*dn_in )
{
	int		rc;
	const char	*p;

	assert( dn_in );

	if ( dn_in == NULL ) {
		return 0;
	}

	if ( !dn_in->bv_len ) {
		return 0;
	}

	if ( be != NULL && be_issuffix( be, dn_in->bv_val ) ) {
		return 0;
	}

	rc = ldap_str2rdn( dn_in->bv_val, NULL, &p, 
			LDAP_DN_FORMAT_LDAP | LDAP_DN_SKIP );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	return p - dn_in->bv_val;
}

/*
 * FIXME: should be replaced by dnExtractRdn() (together with dn_rdnlen)
 */
char * dn_rdn(
	Backend	*be,
	struct berval	*dn_in )
{
	struct berval	rdn;

	assert( dn_in );

	if ( dn_in == NULL ) {
		return NULL;
	}

	if ( !dn_in->bv_len ) {
		return NULL;
	}

	if ( be != NULL && be_issuffix( be, dn_in->bv_val ) ) {
		return NULL;
	}

	if ( dnExtractRdn( dn_in, &rdn ) != LDAP_SUCCESS ) {
		return NULL;
	}

	return rdn.bv_val;
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

/* rdn_attr_type:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns the type of an attribute, that is the
 * string "attribute_type" which is placed in newly allocated
 * memory. The returned string will be null-terminated.
 *
 * Deprecated
 */

char * rdn_attr_type( const char * s )
{
	char 	**attrs = NULL, **values = NULL, *retval;

	if ( rdn_attrs( s, &attrs, &values ) != LDAP_SUCCESS ) {
		return NULL;
	}

	retval = ch_strdup( attrs[ 0 ] );

	charray_free( attrs );
	charray_free( values );

	return retval;
}


/* rdn_attr_value:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns "attribute_type" which is placed in newly allocated
 * memory. The returned string will be null-terminated and may contain
 * spaces (i.e. "John Doe\0").
 *
 * Deprecated
 */

char *
rdn_attr_value( const char * rdn )
{
	char 	**values = NULL, *retval;

	if ( rdn_attrs( rdn, NULL, &values ) != LDAP_SUCCESS ) {
		return NULL;
	}

	retval = ch_strdup( values[ 0 ] );

	charray_free( values );

	return retval;
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
 *
 * Deprecated; directly use LDAPRDN from ldap_str2rdn
 */
int
rdn_attrs( const char * rdn, char ***types, char ***values)
{
	LDAPRDN		*tmpRDN;
	const char	*p;
	int		iAVA;
	int		rc;
	
	assert( rdn );
	assert( values );
	assert( *values == NULL );
	assert( types == NULL || *types == NULL );

	rc = ldap_str2rdn( rdn, &tmpRDN, &p, LDAP_DN_FORMAT_LDAP );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

#if 0
	/*
	 * FIXME: should we complain if the rdn is actually a dn?
	 */
	if ( p[ 0 ] != '\0' ) {
		ldap_rdnfree( tmpRDN );
		return LDAP_INVALID_DN_SYNTAX;
	}
#endif

	for ( iAVA = 0; tmpRDN[ 0 ][ iAVA ]; iAVA++ ) {
		LDAPAVA		*ava = tmpRDN[ 0 ][ iAVA ];

		assert( ava );
		assert( ava->la_attr.bv_val );
		assert( ava->la_value.bv_val );

		if ( types ) {
			charray_add_n( types, ava->la_attr.bv_val, 
					ava->la_attr.bv_len );
		}
		charray_add_n( values, ava->la_value.bv_val, 
				ava->la_value.bv_len );
	}

	ldap_rdnfree( tmpRDN );

	return LDAP_SUCCESS;
}


/* rdnValidate:
 *
 * LDAP_SUCCESS if rdn is a legal rdn;
 * LDAP_INVALID_SYNTAX otherwise (including a sequence of rdns)
 */
int
rdnValidate( struct berval *rdn )
{
#if 1
	/* Major cheat!
	 * input is a pretty or normalized DN
	 * hence, we can just search for ','
	 */
	if( rdn == NULL || rdn->bv_len == 0 ) {
		return LDAP_INVALID_SYNTAX;
	}

	return strchr( rdn->bv_val, ',' ) == NULL
		? LDAP_SUCCESS : LDAP_INVALID_SYNTAX;

#else
	LDAPRDN		*RDN, **DN[ 2 ] = { &RDN, NULL };
	const char	*p;
	int		rc;

	/*
	 * must be non-empty
	 */
	if ( rdn == NULL || rdn == '\0' ) {
		return 0;
	}

	/*
	 * must be parsable
	 */
	rc = ldap_str2rdn( rdn, &RDN, &p, LDAP_DN_FORMAT_LDAP );
	if ( rc != LDAP_SUCCESS ) {
		return 0;
	}

	/*
	 * Must be one-level
	 */
	if ( p[ 0 ] != '\0' ) {
		return 0;
	}

	/*
	 * Schema-aware validate
	 */
	if ( rc == LDAP_SUCCESS ) {
		rc = LDAPDN_validate( DN );
	}
	ldap_rdnfree( RDN );

	/*
	 * Must validate (there's a repeated parsing ...)
	 */
	return ( rc == LDAP_SUCCESS );
#endif
}


/* build_new_dn:
 *
 * Used by ldbm/bdb2 back_modrdn to create the new dn of entries being
 * renamed.
 *
 * new_dn = parent (p_dn) + separator + rdn (newrdn) + null.
 */

void
build_new_dn( struct berval * new_dn,
	struct berval * parent_dn,
	struct berval * newrdn )
{
	char *ptr;

	if ( parent_dn == NULL ) {
		ber_dupbv( new_dn, newrdn );
		return;
	}

	new_dn->bv_len = parent_dn->bv_len + newrdn->bv_len + 1;
	new_dn->bv_val = (char *) ch_malloc( new_dn->bv_len + 1 );

	ptr = slap_strcopy( new_dn->bv_val, newrdn->bv_val );
	*ptr++ = ',';
	strcpy( ptr, parent_dn->bv_val );
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
