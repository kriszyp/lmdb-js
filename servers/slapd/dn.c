/* dn.c - routines for dealing with distinguished names */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "ldap_pvt.h" /* must be after slap.h, to get ldap_bv2dn_x() & co */
#include "lutil.h"

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
LDAPDN_validate( LDAPDN dn )
{
	int 		iRDN;
	int 		rc;

	assert( dn );

	for ( iRDN = 0; dn[ iRDN ]; iRDN++ ) {
		LDAPRDN		rdn = dn[ iRDN ];
		int		iAVA;

		assert( rdn );

		for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
			LDAPAVA			*ava = rdn[ iAVA ];
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
	LDAPDN		dn = NULL;

	assert( in );

	if ( in->bv_len == 0 ) {
		return LDAP_SUCCESS;

	} else if ( in->bv_len > SLAP_LDAPDN_MAXLEN ) {
		return LDAP_INVALID_SYNTAX;
	}

	rc = ldap_bv2dn( in, &dn, LDAP_DN_FORMAT_LDAP );
	if ( rc != LDAP_SUCCESS ) {
		return LDAP_INVALID_SYNTAX;
	}

	assert( strlen( in->bv_val ) == in->bv_len );

	/*
	 * Schema-aware validate
	 */
	rc = LDAPDN_validate( dn );
	ldap_dnfree( dn );

	if ( rc != LDAP_SUCCESS ) {
		return LDAP_INVALID_SYNTAX;
	}

	return LDAP_SUCCESS;
}

/*
 * AVA sorting inside a RDN
 *
 * rule: sort attributeTypes in alphabetical order; in case of multiple
 * occurrences of the same attributeType, sort values in byte order
 * (use memcmp, which implies alphabetical order in case of IA5 value;
 * this should guarantee the repeatability of the operation).
 *
 * Note: the sorting can be slightly improved by sorting first
 * by attribute type length, then by alphabetical order.
 *
 * uses a linear search; should be fine since the number of AVAs in
 * a RDN should be limited.
 */
static void
AVA_Sort( LDAPRDN rdn, int iAVA )
{
	int		i;
	LDAPAVA		*ava_in = rdn[ iAVA ];

	assert( rdn );
	assert( ava_in );
	
	for ( i = 0; i < iAVA; i++ ) {
		LDAPAVA		*ava = rdn[ i ];
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

			ava = rdn[ i ];
			a = strcmp( ava_in->la_attr.bv_val, 
					ava->la_attr.bv_val );
		}

		/*
		 * move ahead
		 */
		for ( j = iAVA; j > i; j-- ) {
			rdn[ j ] = rdn[ j - 1 ];
		}
		rdn[ i ] = ava_in;

		return;
	}
}

/*
 * In-place, schema-aware normalization / "pretty"ing of the
 * structural representation of a distinguished name.
 */
static int
LDAPDN_rewrite( LDAPDN dn, unsigned flags, void *ctx )
{
	int 		iRDN;
	int 		rc;

	assert( dn );

	for ( iRDN = 0; dn[ iRDN ]; iRDN++ ) {
		LDAPRDN		rdn = dn[ iRDN ];
		int		iAVA;

		assert( rdn );

		for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
			LDAPAVA			*ava = rdn[ iAVA ];
			AttributeDescription	*ad;
			slap_syntax_validate_func *validf = NULL;
			slap_mr_normalize_func *normf = NULL;
			slap_syntax_transform_func *transf = NULL;
			MatchingRule *mr = NULL;
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

			if( ava->la_flags & LDAP_AVA_BINARY ) {
				if( ava->la_value.bv_len == 0 ) {
					/* BER encoding is empty */
					return LDAP_INVALID_SYNTAX;
				}

				/* AVA is binary encoded, don't muck with it */
			} else if( flags & SLAP_LDAPDN_PRETTY ) {
				transf = ad->ad_type->sat_syntax->ssyn_pretty;
				if( !transf ) {
					validf = ad->ad_type->sat_syntax->ssyn_validate;
				}
			} else { /* normalization */
				validf = ad->ad_type->sat_syntax->ssyn_validate;
				mr = ad->ad_type->sat_equality;
				if( mr ) normf = mr->smr_normalize;
			}

			if ( validf ) {
				/* validate value before normalization */
				rc = ( *validf )( ad->ad_type->sat_syntax,
					ava->la_value.bv_len
						? &ava->la_value
						: (struct berval *) &slap_empty_bv );

				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
			}

			if ( transf ) {
				/*
			 	 * transform value by pretty function
				 *	if value is empty, use empty_bv
				 */
				rc = ( *transf )( ad->ad_type->sat_syntax,
					ava->la_value.bv_len
						? &ava->la_value
						: (struct berval *) &slap_empty_bv,
					&bv, ctx );
			
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
			}

			if ( normf ) {
				/*
			 	 * normalize value
				 *	if value is empty, use empty_bv
				 */
				rc = ( *normf )(
					0,
					ad->ad_type->sat_syntax,
					mr,
					ava->la_value.bv_len
						? &ava->la_value
						: (struct berval *) &slap_empty_bv,
					&bv, ctx );
			
				if ( rc != LDAP_SUCCESS ) {
					return LDAP_INVALID_SYNTAX;
				}
			}


			if( bv.bv_val ) {
				if ( ava->la_flags & LDAP_AVA_FREE_VALUE )
					ber_memfree_x( ava->la_value.bv_val, ctx );
				ava->la_value = bv;
				ava->la_flags |= LDAP_AVA_FREE_VALUE;
			}

			if( do_sort ) AVA_Sort( rdn, iAVA );
		}
	}

	return LDAP_SUCCESS;
}

int
dnNormalize(
    slap_mask_t use,
    Syntax *syntax,
    MatchingRule *mr,
    struct berval *val,
    struct berval *out,
    void *ctx)
{
	assert( val );
	assert( out );

	Debug( LDAP_DEBUG_TRACE, ">>> dnNormalize: <%s>\n", val->bv_val, 0, 0 );

	if ( val->bv_len != 0 ) {
		LDAPDN		dn = NULL;
		int		rc;

		/*
		 * Go to structural representation
		 */
		rc = ldap_bv2dn_x( val, &dn, LDAP_DN_FORMAT_LDAP, ctx );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		assert( strlen( val->bv_val ) == val->bv_len );

		/*
		 * Schema-aware rewrite
		 */
		if ( LDAPDN_rewrite( dn, 0, ctx ) != LDAP_SUCCESS ) {
			ldap_dnfree_x( dn, ctx );
			return LDAP_INVALID_SYNTAX;
		}

		/*
		 * Back to string representation
		 */
		rc = ldap_dn2bv_x( dn, out,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY, ctx );

		ldap_dnfree_x( dn, ctx );

		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}
	} else {
		ber_dupbv_x( out, val, ctx );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dnNormalize: <%s>\n", out->bv_val, 0, 0 );

	return LDAP_SUCCESS;
}

int
dnPretty(
	Syntax *syntax,
	struct berval *val,
	struct berval *out,
	void *ctx)
{
	assert( val );
	assert( out );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, ">>> dnPretty: <%s>\n", val->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, ">>> dnPretty: <%s>\n", val->bv_val, 0, 0 );
#endif

	if ( val->bv_len == 0 ) {
		ber_dupbv_x( out, val, ctx );

	} else if ( val->bv_len > SLAP_LDAPDN_MAXLEN ) {
		return LDAP_INVALID_SYNTAX;

	} else {
		LDAPDN		dn = NULL;
		int		rc;

		/* FIXME: should be liberal in what we accept */
		rc = ldap_bv2dn_x( val, &dn, LDAP_DN_FORMAT_LDAP, ctx );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		assert( strlen( val->bv_val ) == val->bv_len );

		/*
		 * Schema-aware rewrite
		 */
		if ( LDAPDN_rewrite( dn, SLAP_LDAPDN_PRETTY, ctx ) != LDAP_SUCCESS ) {
			ldap_dnfree_x( dn, ctx );
			return LDAP_INVALID_SYNTAX;
		}

		/* FIXME: not sure why the default isn't pretty */
		/* RE: the default is the form that is used as
		 * an internal representation; the pretty form
		 * is a variant */
		rc = ldap_dn2bv_x( dn, out,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY, ctx );

		ldap_dnfree_x( dn, ctx );

		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, "<<< dnPretty: <%s>\n", out->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<<< dnPretty: <%s>\n", out->bv_val, 0, 0 );
#endif

	return LDAP_SUCCESS;
}

int
dnPrettyNormalDN(
	Syntax *syntax,
	struct berval *val,
	LDAPDN *dn,
	int flags,
	void *ctx )
{
	assert( val );
	assert( dn );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, ">>> dn%sDN: <%s>\n", 
			flags == SLAP_LDAPDN_PRETTY ? "Pretty" : "Normal", 
			val->bv_val, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, ">>> dn%sDN: <%s>\n", 
			flags == SLAP_LDAPDN_PRETTY ? "Pretty" : "Normal", 
			val->bv_val, 0 );
#endif

	if ( val->bv_len == 0 ) {
		return LDAP_SUCCESS;

	} else if ( val->bv_len > SLAP_LDAPDN_MAXLEN ) {
		return LDAP_INVALID_SYNTAX;

	} else {
		int		rc;

		/* FIXME: should be liberal in what we accept */
		rc = ldap_bv2dn_x( val, dn, LDAP_DN_FORMAT_LDAP, ctx );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		assert( strlen( val->bv_val ) == val->bv_len );

		/*
		 * Schema-aware rewrite
		 */
		if ( LDAPDN_rewrite( *dn, flags, ctx ) != LDAP_SUCCESS ) {
			ldap_dnfree_x( *dn, ctx );
			*dn = NULL;
			return LDAP_INVALID_SYNTAX;
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<<< dn%sDN\n", 
			flags == SLAP_LDAPDN_PRETTY ? "Pretty" : "Normal",
			0, 0 );

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
	struct berval *normal,
	void *ctx)
{
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, ">>> dnPrettyNormal: <%s>\n", val->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, ">>> dnPrettyNormal: <%s>\n", val->bv_val, 0, 0 );
#endif

	assert( val );
	assert( pretty );
	assert( normal );

	if ( val->bv_len == 0 ) {
		ber_dupbv_x( pretty, val, ctx );
		ber_dupbv_x( normal, val, ctx );

	} else if ( val->bv_len > SLAP_LDAPDN_MAXLEN ) {
		/* too big */
		return LDAP_INVALID_SYNTAX;

	} else {
		LDAPDN		dn = NULL;
		int		rc;

		pretty->bv_val = NULL;
		normal->bv_val = NULL;
		pretty->bv_len = 0;
		normal->bv_len = 0;

		/* FIXME: should be liberal in what we accept */
		rc = ldap_bv2dn_x( val, &dn, LDAP_DN_FORMAT_LDAP, ctx );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		assert( strlen( val->bv_val ) == val->bv_len );

		/*
		 * Schema-aware rewrite
		 */
		if ( LDAPDN_rewrite( dn, SLAP_LDAPDN_PRETTY, ctx ) != LDAP_SUCCESS ) {
			ldap_dnfree_x( dn, ctx );
			return LDAP_INVALID_SYNTAX;
		}

		rc = ldap_dn2bv_x( dn, pretty,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY, ctx );

		if ( rc != LDAP_SUCCESS ) {
			ldap_dnfree_x( dn, ctx );
			return LDAP_INVALID_SYNTAX;
		}

		if ( LDAPDN_rewrite( dn, 0, ctx ) != LDAP_SUCCESS ) {
			ldap_dnfree_x( dn, ctx );
			ber_memfree_x( pretty->bv_val, ctx );
			pretty->bv_val = NULL;
			pretty->bv_len = 0;
			return LDAP_INVALID_SYNTAX;
		}

		rc = ldap_dn2bv_x( dn, normal,
			LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY, ctx );

		ldap_dnfree_x( dn, ctx );
		if ( rc != LDAP_SUCCESS ) {
			ber_memfree_x( pretty->bv_val, ctx );
			pretty->bv_val = NULL;
			pretty->bv_len = 0;
			return LDAP_INVALID_SYNTAX;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG (OPERATION, RESULTS, "<<< dnPrettyNormal: <%s>, <%s>\n",
		pretty->bv_val, normal->bv_val, 0  );
#else
	Debug( LDAP_DEBUG_TRACE, "<<< dnPrettyNormal: <%s>, <%s>\n",
		pretty->bv_val, normal->bv_val, 0 );
#endif

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
		match = memcmp( value->bv_val, asserted->bv_val, 
				value->bv_len );
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONFIG, ENTRY, "dnMatch: %d\n    %s\n    %s\n", 
		match, value->bv_val, asserted->bv_val  );
#else
	Debug( LDAP_DEBUG_ARGS, "dnMatch %d\n\t\"%s\"\n\t\"%s\"\n",
		match, value->bv_val, asserted->bv_val );
#endif

	*matchp = match;
	return( LDAP_SUCCESS );
}

/*
 * dnParent - dn's parent, in-place
 *
 * note: the incoming dn is assumed to be normalized/prettyfied,
 * so that escaped rdn/ava separators are in '\'+hexpair form
 */
void
dnParent( 
	struct berval	*dn, 
	struct berval	*pdn )
{
	char	*p;

	p = strchr( dn->bv_val, ',' );

	/* one-level dn */
	if ( p == NULL ) {
		pdn->bv_len = 0;
		pdn->bv_val = dn->bv_val + dn->bv_len;
		return;
	}

	assert( DN_SEPARATOR( p[ 0 ] ) );
	p++;

	assert( ATTR_LEADCHAR( p[ 0 ] ) );
	pdn->bv_val = p;
	pdn->bv_len = dn->bv_len - (p - dn->bv_val);

	return;
}

int
dnExtractRdn( 
	struct berval	*dn, 
	struct berval 	*rdn,
	void *ctx )
{
	LDAPRDN		tmpRDN;
	const char	*p;
	int		rc;

	assert( dn );
	assert( rdn );

	if( dn->bv_len == 0 ) {
		return LDAP_OTHER;
	}

	rc = ldap_bv2rdn_x( dn, &tmpRDN, (char **)&p, LDAP_DN_FORMAT_LDAP, ctx );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	rc = ldap_rdn2bv_x( tmpRDN, rdn, LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PRETTY, ctx );

	ldap_rdnfree_x( tmpRDN, ctx );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	return LDAP_SUCCESS;
}

/*
 * We can assume the input is a prettied or normalized DN
 */
int 
dn_rdnlen(
	Backend		*be,
	struct berval	*dn_in )
{
	const char	*p;

	assert( dn_in );

	if ( dn_in == NULL ) {
		return 0;
	}

	if ( !dn_in->bv_len ) {
		return 0;
	}

	if ( be != NULL && be_issuffix( be, dn_in ) ) {
		return 0;
	}

	p = strchr( dn_in->bv_val, ',' );

	return p ? p - dn_in->bv_val : dn_in->bv_len;
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
	if( rdn == NULL || rdn->bv_len == 0 ||
		rdn->bv_len > SLAP_LDAPDN_MAXLEN )
	{
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
	rc = ldap_bv2rdn( rdn, &RDN, (char **)&p, LDAP_DN_FORMAT_LDAP );
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
	struct berval * newrdn,
	void *memctx )
{
	char *ptr;

	if ( parent_dn == NULL ) {
		ber_dupbv( new_dn, newrdn );
		return;
	}

	new_dn->bv_len = parent_dn->bv_len + newrdn->bv_len + 1;
	new_dn->bv_val = (char *) sl_malloc( new_dn->bv_len + 1, memctx );

	ptr = lutil_strcopy( new_dn->bv_val, newrdn->bv_val );
	*ptr++ = ',';
	strcpy( ptr, parent_dn->bv_val );
}


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
	if ( d > 1 && !DN_SEPARATOR( dn->bv_val[ d - 1 ] ) ) {
		return 0;
	}

	/* no possible match or malformed dn */
	if ( d == 1 ) {
		return 0;
	}

	/* compare */
	return( strcmp( dn->bv_val + d, suffix->bv_val ) == 0 );
}

#ifdef HAVE_TLS
/*
 * Convert an X.509 DN into a normalized LDAP DN
 */
int
dnX509normalize( void *x509_name, struct berval *out )
{
	/* Invoke the LDAP library's converter with our schema-rewriter */
	int rc = ldap_X509dn2bv( x509_name, out, LDAPDN_rewrite, 0 );

	Debug( LDAP_DEBUG_TRACE,
		"dnX509Normalize: <%s>\n", out->bv_val, 0, 0 );

	return rc;
}

/*
 * Get the TLS session's peer's DN into a normalized LDAP DN
 */
int
dnX509peerNormalize( void *ssl, struct berval *dn )
{

	return ldap_pvt_tls_get_peer_dn( ssl, dn, (LDAPDN_rewrite_dummy *)LDAPDN_rewrite, 0 );
}
#endif
