/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1994 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getdn.c
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/* extension to UFN that turns trailing "dc=value" rdns in DNS style,
 * e.g. "ou=People,dc=openldap,dc=org" => "People, openldap.org" */
#define DC_IN_UFN

static int dn2dn( const char *dnin, unsigned fin, char **dnout, unsigned fout );

/* from libraries/libldap/schema.c */
extern char * parse_numericoid(const char **sp, int *code, const int flags);

/* parsing/printing routines */
static int str2strval( const char *str, struct berval **val, 
		const char **next, unsigned flags, unsigned *retFlags );
static int DCE2strval( const char *str, struct berval **val, 
		const char **next, unsigned flags );
static int IA52strval( const char *str, struct berval **val, 
		const char **next, unsigned flags );
static int quotedIA52strval( const char *str, struct berval **val, 
		const char **next, unsigned flags );
static int hexstr2binval( const char *str, struct berval **val, 
		const char **next, unsigned flags );
static int hexstr2bin( const char *str, char *c );
static int byte2hexpair( const char *val, char *pair );
static int binval2hexstr( struct berval *val, char *str );
static int strval2strlen( struct berval *val, unsigned flags, 
		ber_len_t *len );
static int strval2str( struct berval *val, char *str, unsigned flags, 
		ber_len_t *len );
static int strval2IA5strlen( struct berval *val, unsigned flags,
		ber_len_t *len );
static int strval2IA5str( struct berval *val, char *str, unsigned flags, 
		ber_len_t *len );
static int strval2DCEstrlen( struct berval *val, unsigned flags,
		ber_len_t *len );
static int strval2DCEstr( struct berval *val, char *str, unsigned flags, 
		ber_len_t *len );
static int strval2ADstrlen( struct berval *val, unsigned flags,
		ber_len_t *len );
static int strval2ADstr( struct berval *val, char *str, unsigned flags, 
		ber_len_t *len );
static int dn2domain( LDAPDN *dn, char *str, int *iRDN );

/* AVA helpers */
LDAPAVA * ldapava_new( const struct berval *attr, const struct berval *val, 
		unsigned flags );
void ldapava_free( LDAPAVA *ava );
LDAPRDN * ldapava_append_to_rdn( LDAPRDN *rdn, LDAPAVA *ava );
LDAPRDN * ldapava_insert_into_rdn( LDAPRDN *rdn, LDAPAVA *ava, unsigned where );
/* void ldapava_free_rdn( LDAPRDN *rdn ); in ldap.h */
LDAPDN * ldapava_append_to_dn( LDAPDN *dn, LDAPRDN *rdn );
LDAPDN * ldapava_insert_into_dn( LDAPDN *dn, LDAPRDN *rdn, unsigned where );
/* void ldapava_free_dn( LDAPDN *dn ); in ldap.h */

/* Higher level helpers */
static int rdn2strlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len,
		int ( *s2l )( struct berval *, unsigned, ber_len_t * ) );
static int rdn2str( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len,
		int ( *s2s )( struct berval *, char *, unsigned, ber_len_t * ));
static int rdn2UFNstrlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len  );
static int rdn2UFNstr( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len );
static int rdn2DCEstrlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len );
static int rdn2DCEstr( LDAPRDN *rdn, char *str, unsigned flag, ber_len_t *len, int first );
static int rdn2ADstrlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len );
static int rdn2ADstr( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len, int first );
	
#ifndef USE_LDAP_DN_PARSING	/* deprecated */
#define NAME_TYPE_LDAP_RDN	0
#define NAME_TYPE_LDAP_DN	1
#define NAME_TYPE_DCE_DN	2

static char **explode_name( const char *name, int notypes, int is_type );
#endif /* !USE_LDAP_DN_PARSING */

/*
 * RFC 1823 ldap_get_dn
 */
char *
ldap_get_dn( LDAP *ld, LDAPMessage *entry )
{
	char		*dn;
	BerElement	tmp;

	Debug( LDAP_DEBUG_TRACE, "ldap_get_dn\n", 0, 0, 0 );

	if ( entry == NULL ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return( NULL );
	}

	tmp = *entry->lm_ber;	/* struct copy */
	if ( ber_scanf( &tmp, "{a" /*}*/, &dn ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	return( dn );
}

/*
 * RFC 1823 ldap_dn2ufn
 */
char *
ldap_dn2ufn( LDAP_CONST char *dn )
{
#ifndef USE_LDAP_DN_PARSING	/* deprecated */
	char	*ufn;
	char	**vals;
	int i;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2ufn\n", 0, 0, 0 );

	/* produces completely untyped UFNs */

	if( dn == NULL ) {
		return NULL;
	}

	vals = ldap_explode_dn( dn , 0 );
	if( vals == NULL ) {
		return NULL;
	}

	for ( i = 0; vals[i]; i++ ) {
		char **rvals;

		rvals = ldap_explode_rdn( vals[i] , 1 );
		if ( rvals == NULL ) {
			LDAP_VFREE( vals );
			return NULL;
		}

		LDAP_FREE( vals[i] );
		vals[i] = ldap_charray2str( rvals, " + " );
		LDAP_VFREE( rvals );
	}

	ufn = ldap_charray2str( vals, ", " );

	LDAP_VFREE( vals );
	return ufn;
#else /* USE_LDAP_DN_PARSING */
	char	*out = NULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2ufn\n", 0, 0, 0 );

	( void )dn2dn( dn, LDAP_DN_FORMAT_LDAP, &out, LDAP_DN_FORMAT_UFN );
	
	return( out );
#endif /* USE_LDAP_DN_PARSING */
}

/*
 * RFC 1823 ldap_explode_dn
 */
char **
ldap_explode_dn( LDAP_CONST char *dn, int notypes )
{
#ifndef USE_LDAP_DN_PARSING	/* deprecated */
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_dn\n", 0, 0, 0 );

	return explode_name( dn, notypes, NAME_TYPE_LDAP_DN );
#else /* USE_LDAP_DN_PARSING */
	LDAPDN	*tmpDN;
	char	**values = NULL;
	int	iRDN;
	unsigned flag = notypes ? LDAP_DN_FORMAT_UFN : LDAP_DN_FORMAT_LDAPV3;
	
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_dn\n", 0, 0, 0 );

	if ( ldap_str2dn( dn, &tmpDN, LDAP_DN_FORMAT_LDAP ) 
			!= LDAP_SUCCESS ) {
		return( NULL );
	}

	for ( iRDN = 0; tmpDN[ iRDN ]; iRDN++ ) {
		char	*str, **v = NULL;
		
		ldap_rdn2str( tmpDN[ iRDN ][ 0 ], &str, flag );

		v = LDAP_REALLOC( values, sizeof( char * ) * ( 2 + iRDN ) );
		if ( v == NULL ) {
			LBER_VFREE( values );
			ldapava_free_dn( tmpDN );
			return( NULL );
		}
		values = v;
		values[ iRDN ] = str;
	}
	values[ iRDN ] = NULL;

	return( values );
#endif /* USE_LDAP_DN_PARSING */
}

char **
ldap_explode_rdn( LDAP_CONST char *rdn, int notypes )
{
#ifndef USE_LDAP_DN_PARSING	/* deprecated */
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_rdn\n", 0, 0, 0 );

	return explode_name( rdn, notypes, NAME_TYPE_LDAP_RDN );
#else /* USE_LDAP_DN_PARSING */
	LDAPDN	*tmpDN;
	char	**values = NULL;
	int	iAVA;
	unsigned flag = notypes ? LDAP_DN_FORMAT_UFN : LDAP_DN_FORMAT_LDAPV3;
	
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_rdn\n", 0, 0, 0 );

	/*
	 * we assume this dn is made of one rdn only
	 */
	if ( ldap_str2dn( rdn, &tmpDN, LDAP_DN_FORMAT_LDAP ) 
			!= LDAP_SUCCESS ) {
		return( NULL );
	}

	for ( iAVA = 0; tmpDN[ 0 ][ 0 ][ iAVA ]; iAVA++ ) {
		ber_len_t	l = 0, vl, al = 0;
		char		*str, **v = NULL;
		LDAPAVA		*ava = tmpDN[ 0 ][ 0 ][ iAVA ][ 0 ];
		
		v = LDAP_REALLOC( values, sizeof( char * ) * ( 2 + iAVA ) );
		if ( v == NULL ) {
			goto error_return;
		}
		values = v;
		
		if ( ava->la_flags == LDAP_AVA_BINARY ) {
			vl = 1 + 2 * ava->la_value->bv_len;

		} else {
			if ( strval2strlen( ava->la_value, 
						ava->la_flags, &vl ) ) {
				goto error_return;
			}
		}
		
		if ( !notypes ) {
			al = ava->la_attr->bv_len;
			l = vl + ava->la_attr->bv_len + 1;

			str = LDAP_MALLOC( l + 1 );
			AC_MEMCPY( str, ava->la_attr->bv_val, 
					ava->la_attr->bv_len );
			str[ al++ ] = '=';

		} else {
			l = vl;
			str = LDAP_MALLOC( l + 1 );
		}
		
		if ( ava->la_flags == LDAP_AVA_BINARY ) {
			str[ al++ ] = '#';
			if ( binval2hexstr( ava->la_value, &str[ al ] ) ) {
				goto error_return;
			}

		} else {
			if ( strval2str( ava->la_value, &str[ al ], 
					ava->la_flags, &vl ) ) {
				goto error_return;
			}
		}

		str[ l ] = '\0';
		values[ iAVA ] = str;
	}
	values[ iAVA ] = NULL;

	ldapava_free_dn( tmpDN );

	return( values );

error_return:;
	LBER_VFREE( values );
	ldapava_free_dn( tmpDN );
	return( NULL );
#endif /* USE_LDAP_DN_PARSING */
}

char *
ldap_dn2dcedn( LDAP_CONST char *dn )
{
#ifndef USE_LDAP_DN_PARSING	/* deprecated */
	char *dce, *q, **rdns, **p;
	int len = 0;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2dcedn\n", 0, 0, 0 );

	rdns = explode_name( dn, 0, NAME_TYPE_LDAP_DN );
	if ( rdns == NULL ) {
		return NULL;
	}
	
	for ( p = rdns; *p != NULL; p++ ) {
		len += strlen( *p ) + 1;
	}

	q = dce = LDAP_MALLOC( len + 1 );
	if ( dce == NULL ) {
		return NULL;
	}

	p--; /* get back past NULL */

	for ( ; p != rdns; p-- ) {
		strcpy( q, "/" );
		q++;
		strcpy( q, *p );
		q += strlen( *p );
	}

	strcpy( q, "/" );
	q++;
	strcpy( q, *p );
	
	return dce;
#else /* USE_LDAP_DN_PARSING */
	char	*out = NULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2dcedn\n", 0, 0, 0 );

	( void )dn2dn( dn, LDAP_DN_FORMAT_LDAP, &out, LDAP_DN_FORMAT_DCE );

	return( out );
#endif /* USE_LDAP_DN_PARSING */
}

char *
ldap_dcedn2dn( LDAP_CONST char *dce )
{
#ifndef USE_LDAP_DN_PARSING
	char *dn, *q, **rdns, **p;
	int len;

	Debug( LDAP_DEBUG_TRACE, "ldap_dcedn2dn\n", 0, 0, 0 );

	rdns = explode_name( dce, 0, NAME_TYPE_DCE_DN );
	if ( rdns == NULL ) {
		return NULL;
	}

	len = 0;

	for ( p = rdns; *p != NULL; p++ ) {
		len += strlen( *p ) + 1;
	}

	q = dn = LDAP_MALLOC( len );
	if ( dn == NULL ) {
		return NULL;
	}

	p--;

	for ( ; p != rdns; p-- ) {
		strcpy( q, *p );
		q += strlen( *p );
		strcpy( q, "," );
		q++;
	}

	if ( *dce == '/' ) {
		/* the name was fully qualified, thus the most-significant
		 * RDN was empty. trash the last comma */
		q--;
		*q = '\0';
	} else {
		/* the name was relative. copy the most significant RDN */
		strcpy( q, *p );
	}

	return dn;
#else /* USE_LDAP_DN_PARSING */
	char	*out = NULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_dcedn2dn\n", 0, 0, 0 );

	( void )dn2dn( dce, LDAP_DN_FORMAT_DCE, &out, LDAP_DN_FORMAT_LDAPV3 );

	return( out );
#endif /* USE_LDAP_DN_PARSING */
}

char *
ldap_dn2ad_canonical( LDAP_CONST char *dn )
{
	char	*out = NULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2ad_canonical\n", 0, 0, 0 );

	( void )dn2dn( dn, LDAP_DN_FORMAT_LDAP, 
		       &out, LDAP_DN_FORMAT_AD_CANONICAL );

	return( out );
}

#ifndef USE_LDAP_DN_PARSING	/* deprecated */
#define INQUOTE		1
#define OUTQUOTE	2

static char **
explode_name( const char *name, int notypes, int is_type )
{
	const char *p, *q, *rdn;
	char **parts = NULL;
	int	offset, state, have_equals, count = 0, endquote, len;

	/* safe guard */
	if(name == NULL) name = "";

	/* skip leading whitespace */
	while( ldap_utf8_isspace( name )) {
		LDAP_UTF8_INCR( name );
	}

	p = rdn = name;
	offset = 0;
	state = OUTQUOTE;
	have_equals=0;

	do {
		/* step forward */
		p += offset;
		offset = 1;

		switch ( *p ) {
		case '\\':
			if ( p[1] != '\0' ) {
				offset = LDAP_UTF8_OFFSET(++p);
			}
			break;
		case '"':
			if ( state == INQUOTE )
				state = OUTQUOTE;
			else
				state = INQUOTE;
			break;
		case '=':
			if( state == OUTQUOTE ) have_equals++;
			break;
		case '+':
			if (is_type == NAME_TYPE_LDAP_RDN)
				goto end_part;
			break;
		case '/':
			if (is_type == NAME_TYPE_DCE_DN)
				goto end_part;
			break;
		case ';':
		case ',':
			if (is_type == NAME_TYPE_LDAP_DN)
				goto end_part;
			break;
		case '\0':
		end_part:
			if ( state == OUTQUOTE ) {
				++count;
				have_equals=0;

				if ( parts == NULL ) {
					if (( parts = (char **)LDAP_MALLOC( 8
						 * sizeof( char *))) == NULL )
						return( NULL );
				} else if ( count >= 8 ) {
					if (( parts = (char **)LDAP_REALLOC( parts,
						(count+1) * sizeof( char *)))
						== NULL )
						return( NULL );
				}

				parts[ count ] = NULL;
				endquote = 0;

				if ( notypes ) {
					for ( q = rdn; q < p && *q != '='; ++q ) {
						/* EMPTY */;
					}

					if ( q < p ) {
						rdn = ++q;
					}

					if ( *rdn == '"' ) {
						++rdn;
					}
					
					if ( p[-1] == '"' ) {
						endquote = 1;
						--p;
					}
				}

				len = p - rdn;

				if (( parts[ count-1 ] = (char *)LDAP_CALLOC( 1,
				    len + 1 )) != NULL )
				{
				   	AC_MEMCPY( parts[ count-1 ], rdn, len );

					if( !endquote ) {
						/* skip trailing spaces */
						while( len > 0 && ldap_utf8_isspace(
							&parts[count-1][len-1] ) )
						{
							--len;
						}
					}

					parts[ count-1 ][ len ] = '\0';
				}

				/*
				 *  Don't forget to increment 'p' back to where
				 *  it should be.  If we don't, then we will
				 *  never get past an "end quote."
				 */
				if ( endquote == 1 )
					p++;

				rdn = *p ? &p[1] : p;
				while ( ldap_utf8_isspace( rdn ) )
					++rdn;
			} break;
		}
	} while ( *p );

	return( parts );
}
#endif /* !USE_LDAP_DN_PARSING */

int
ldap_dn_normalize( const char *in, unsigned iflags, char **out, unsigned oflags ) 
{
	assert( out );

#ifdef USE_LDAP_DN_PARSING
	Debug( LDAP_DEBUG_TRACE, "ldap_dn_normalize\n", 0, 0, 0 );

	return dn2dn( in, iflags, out, oflags);
#else /* !USE_LDAP_DN_PARSING */
	return( LDAP_OTHER );
#endif /* !USE_LDAP_DN_PARSING */
}

/*
 * helper that changes the string representation of dnin
 * from ( fin & LDAP_DN_FORMAT_MASK ) to ( fout & LDAP_DN_FORMAT_MASK )
 * 
 * fin can be one of:
 * 	LDAP_DN_FORMAT_LDAP		(rfc 2253 and ldapbis liberal, 
 * 					plus some rfc 1779)
 * 	LDAP_DN_FORMAT_LDAPV3		(rfc 2253 and ldapbis)
 * 	LDAP_DN_FORMAT_LDAPV2		(rfc 1779)
 * 	LDAP_DN_FORMAT_DCE		(?)
 *
 * fout can be any of the above except
 * 	LDAP_DN_FORMAT_LDAP
 * plus:
 * 	LDAP_DN_FORMAT_UFN		(rfc 1781, partial and with extensions)
 * 	LDAP_DN_FORMAT_AD_CANONICAL	(?)
 */
static int
dn2dn( const char *dnin, unsigned fin, char **dnout, unsigned fout )
{
	int	rc;
	LDAPDN	*tmpDN = NULL;

	assert( dnout );

	*dnout = NULL;

	if ( dnin == NULL ) {
		return( LDAP_SUCCESS );
	}

	rc = ldap_str2dn( dnin , &tmpDN, fin );
	if ( rc != LDAP_SUCCESS ) {
		return( rc );
	}

	rc = ldap_dn2str( tmpDN, dnout, fout );

	ldapava_free_dn( tmpDN );

	return( rc );
}

/* States */
#define B4AVA			0x0000

/* #define	B4ATTRTYPE		0x0001 */
#define B4OIDATTRTYPE		0x0002
#define B4STRINGATTRTYPE	0x0003

#define B4AVAEQUALS		0x0100
#define B4AVASEP		0x0200
#define B4RDNSEP		0x0300
#define GOTAVA			0x0400

#define B4ATTRVALUE		0x0010
#define B4STRINGVALUE		0x0020
#define B4IA5VALUEQUOTED	0x0030
#define B4IA5VALUE		0x0040
#define B4BINARYVALUE		0x0050

/* Helpers (mostly from slapd.h; maybe it should be rewritten from this) */
#define LDAP_DN_ASCII_SPACE(c) \
	( (c) == ' ' || (c) == '\t' || (c) == '\n' || (c) == '\r' )
#define LDAP_DN_ASCII_LOWER(c)		( (c) >= 'a' && (c) <= 'z' )
#define LDAP_DN_ASCII_UPPER(c)		( (c) >= 'A' && (c) <= 'Z' )
#define LDAP_DN_ASCII_ALPHA(c) \
	( LDAP_DN_ASCII_LOWER(c) || LDAP_DN_ASCII_UPPER(c) )
#define LDAP_DN_ASCII_DIGIT(c)		( (c) >= '0' && (c) <= '9' )
#define LDAP_DN_ASCII_LCASE_HEXALPHA(c)	( (c) >= 'a' && (c) <= 'f' )
#define LDAP_DN_ASCII_UCASE_HEXALPHA(c)	( (c) >= 'A' && (c) <= 'F' )
#define LDAP_DN_ASCII_HEXDIGIT(c) \
	( LDAP_DN_ASCII_DIGIT(c) \
	  || LDAP_DN_ASCII_LCASE_HEXALPHA(c) \
	  || LDAP_DN_ASCII_UCASE_HEXALPHA(c) )
#define LDAP_DN_ASCII_ALNUM(c) \
	( LDAP_DN_ASCII_ALPHA(c) || LDAP_DN_ASCII_DIGIT(c) )
#define LDAP_DN_ASCII_PRINTABLE(c)	( (c) >= ' ' && (c) <= '~' )

/* attribute type */
#define LDAP_DN_OID_LEADCHAR(c)		( LDAP_DN_ASCII_DIGIT(c) )
#define LDAP_DN_DESC_LEADCHAR(c)	( LDAP_DN_ASCII_ALPHA(c) )
#define LDAP_DN_DESC_CHAR(c)		( LDAP_DN_ASCII_ALNUM(c) || (c) == '-' )
#define LDAP_DN_LANG_SEP(c)		( (c) == ';' )
#define LDAP_DN_ATTRDESC_CHAR(c) \
	( LDAP_DN_DESC_CHAR(c) || LDAP_DN_LANG_SEP(c) )

/* special symbols */
#define LDAP_DN_AVA_EQUALS(c)		( (c) == '=' )
#define LDAP_DN_AVA_SEP(c)		( (c) == '+' )
#define LDAP_DN_RDN_SEP(c)		( (c) == ',' )
#define LDAP_DN_RDN_SEP_V2(c)		( LDAP_DN_RDN_SEP(c) || (c) == ';' )
#define LDAP_DN_OCTOTHORPE(c)		( (c) == '#' )
#define LDAP_DN_QUOTES(c)		( (c) == '\"' )
#define LDAP_DN_ESCAPE(c)		( (c) == '\\' )
#define LDAP_DN_VALUE_END(c) \
	( LDAP_DN_RDN_SEP(c) || LDAP_DN_AVA_SEP(c) )
#define LDAP_DN_NE(c) \
	( LDAP_DN_RDN_SEP_V2(c) || LDAP_DN_AVA_SEP(c) \
	  || LDAP_DN_QUOTES(c) || (c) == '<' || (c) == '>' )
#define LDAP_DN_NEEDESCAPE(c) \
	( LDAP_DN_ESCAPE(c) || LDAP_DN_NE(c) )
#define LDAP_DN_NEEDESCAPE_LEAD(c) \
	( LDAP_DN_ASCII_SPACE(c) || LDAP_DN_OCTOTHORPE(c) || LDAP_DN_NE(c) )
#define LDAP_DN_NEEDESCAPE_TRAIL(c) \
	( LDAP_DN_ASCII_SPACE(c) || LDAP_DN_NEEDESCAPE(c) )
#define LDAP_DN_WILLESCAPE_CHAR( c) \
	( LDAP_DN_RDN_SEP(c) || LDAP_DN_AVA_SEP(c) )
#define LDAP_DN_WILLESCAPE(f, c) \
	( ( !( (f) & LDAP_DN_PRETTY ) ) && LDAP_DN_WILLESCAPE_CHAR(c) )

/* LDAPv2 */
#define	LDAP_DN_VALUE_END_V2(c) \
	( LDAP_DN_RDN_SEP_V2(c) || LDAP_DN_AVA_SEP(c) )
/* RFC 1779 */
#define	LDAP_DN_V2_SPECIAL(c) \
	  ( LDAP_DN_RDN_SEP_V2(c) || LDAP_DN_AVA_EQUALS(c) \
	    || LDAP_DN_AVA_SEP(c) || (c) == '<' || (c) == '>' \
	    || LDAP_DN_OCTOTHORPE(c) )
#define LDAP_DN_V2_PAIR(c) \
	  ( LDAP_DN_V2_SPECIAL(c) || LDAP_DN_ESCAPE(c) || LDAP_DN_QUOTES(c) )

/*
 * DCE (mostly from Luke Howard and IBM implementation for AIX)
 *
 * From: "Application Development Guide - Directory Services" (FIXME: add link?)
 * Here escapes and valid chars for GDS are considered; as soon as more
 * specific info is found, the macros will be updated.
 *
 * Chars:	'a'-'z', 'A'-'Z', '0'-'9', 
 *		'.', ':', ',', ''', '+', '-', '=', '(', ')', '?', '/', ' '.
 *
 * Metachars:	'/', ',', '=', '\'.
 *
 * the '\' is used to escape other metachars.
 *
 * Assertion:		'='
 * RDN separator:	'/'
 * AVA separator:	','
 * 
 * Attribute types must start with alphabetic chars and can contain 
 * alphabetic chars and digits (FIXME: no '-'?). OIDs are allowed.
 */
#define LDAP_DN_RDN_SEP_DCE(c)		( (c) == '/' )
#define LDAP_DN_AVA_SEP_DCE(c)		( (c) == ',' )
#define LDAP_DN_ESCAPE_DCE(c)		( LDAP_DN_ESCAPE(c) )
#define	LDAP_DN_VALUE_END_DCE(c) \
	( LDAP_DN_RDN_SEP_DCE(c) || LDAP_DN_AVA_SEP_DCE(c) )
#define LDAP_DN_NEEDESCAPE_DCE(c) \
	( LDAP_DN_VALUE_END_DCE(c) || LDAP_DN_AVA_EQUALS(c) )

/* AD Canonical */
#define LDAP_DN_RDN_SEP_AD(c)		( (c) == '/' )
#define LDAP_DN_ESCAPE_AD(c)		( LDAP_DN_ESCAPE(c) )
#define LDAP_DN_AVA_SEP_AD(c)		( (c) == ',' )	/* assume same as DCE */
#define	LDAP_DN_VALUE_END_AD(c) \
	( LDAP_DN_RDN_SEP_AD(c) || LDAP_DN_AVA_SEP_AD(c) )
#define LDAP_DN_NEEDESCAPE_AD(c) \
	( LDAP_DN_VALUE_END_AD(c) || LDAP_DN_AVA_EQUALS(c) )

/* generics */
#define LDAP_DN_HEXPAIR(s) \
	( LDAP_DN_ASCII_HEXDIGIT((s)[0]) && LDAP_DN_ASCII_HEXDIGIT((s)[1]) )
#define	LDAP_DC_ATTR			"dc"
/* better look at the AttributeDescription? */

/* FIXME: no composite rdn or non-"dc" types, right?
 * (what about "dc" in OID form?) */
/* FIXME: we do not allow binary values in domain, right? */
/* NOTE: use this macro only when ABSOLUTELY SURE rdn IS VALID! */
#define LDAP_DN_IS_RDN_DC( rdn ) \
	( ( rdn ) && ( rdn )[ 0 ][ 0 ] && !( rdn )[ 1 ] \
	  && ( ( rdn )[ 0 ][ 0 ]->la_flags == LDAP_AVA_STRING ) \
	  && ! strcasecmp( ( rdn )[ 0 ][ 0 ]->la_attr->bv_val, LDAP_DC_ATTR ) )

/* Composite rules */
#define LDAP_DN_ALLOW_ONE_SPACE(f) \
	( LDAP_DN_LDAPV2(f) \
	  || !( (f) & LDAP_DN_P_NOSPACEAFTERRDN ) )
#define LDAP_DN_ALLOW_SPACES(f) \
	( LDAP_DN_LDAPV2(f) \
	  || !( (f) & ( LDAP_DN_P_NOLEADTRAILSPACES | LDAP_DN_P_NOSPACEAFTERRDN ) ) )
#define LDAP_DN_LDAP(f) \
	( ( (f) & LDAP_DN_FORMAT_MASK ) == LDAP_DN_FORMAT_LDAP )
#define LDAP_DN_LDAPV3(f) \
	( ( (f) & LDAP_DN_FORMAT_MASK ) == LDAP_DN_FORMAT_LDAPV3 )
#define LDAP_DN_LDAPV2(f) \
	( ( (f) & LDAP_DN_FORMAT_MASK ) == LDAP_DN_FORMAT_LDAPV2 )
#define LDAP_DN_DCE(f) \
	( ( (f) & LDAP_DN_FORMAT_MASK ) == LDAP_DN_FORMAT_DCE )
#define LDAP_DN_UFN(f) \
	( ( (f) & LDAP_DN_FORMAT_MASK ) == LDAP_DN_FORMAT_UFN )
#define LDAP_DN_ADC(f) \
	( ( (f) & LDAP_DN_FORMAT_MASK ) == LDAP_DN_FORMAT_AD_CANONICAL )
#define LDAP_DN_FORMAT(f)		( (f) & LDAP_DN_FORMAT_MASK )

/*
 * LDAPAVA helpers (will become part of the API for operations 
 * on structural representations of DNs).
 */
LDAPAVA *
ldapava_new( const struct berval *attr, const struct berval *val, 
		unsigned flags )
{
	LDAPAVA	*ava;

	assert( attr );
	assert( val );

	ava = LDAP_MALLOC( sizeof( LDAPAVA ) );
	
	/* should we test it? */
	if ( ava == NULL ) {
		return( NULL );
	}

	ava->la_attr = ( struct berval * )attr;
	ava->la_value = ( struct berval * )val;
	ava->la_flags = flags;

	ava->la_private = NULL;

	return( ava );
}

void
ldapava_free( LDAPAVA *ava )
{
	assert( ava );

	ber_bvfree( ava->la_attr );
	ber_bvfree( ava->la_value );

	LDAP_FREE( ava );
}

LDAPRDN *
ldapava_append_to_rdn( LDAPRDN *rdn, LDAPAVA *ava )
{
	LDAPRDN 	*newRDN;
	unsigned	i = 0U;

	assert( ava );

	if ( rdn != NULL ) {
		for ( i = 0U; rdn[ i ]; i++ ) {
			/* no op */
		}
	}
	newRDN = LDAP_REALLOC( rdn, ( i + 2 ) * sizeof( LDAPAVA ** ) );
	newRDN[ i ] = LDAP_MALLOC( sizeof( LDAPAVA * ) );
	newRDN[ i ][ 0 ] = ava;
	newRDN[ i + 1 ] = NULL;

	return( newRDN );
}

LDAPRDN *
ldapava_insert_into_rdn( LDAPRDN *rdn, LDAPAVA *ava, unsigned where )
{
	LDAPRDN 	*newRDN;
	unsigned	i = 0U;

	assert( ava );

	if ( rdn != NULL ) {
		for ( i = 0U; rdn[ i ]; i++ ) {
			/* no op */
		}
	}
	if ( where > i ) {
		where = i;
		/* assume "at end", which corresponds to
		 * ldapava_append_to_rdn */
	}
	
	newRDN = LDAP_REALLOC( rdn, ( i + 2 ) * sizeof( LDAPAVA ** ) );
	
	/* data after insert point */
	AC_MEMCPY( &newRDN[ where + 1 ], &newRDN[ where ],
			( i - where ) * sizeof( LDAPRDN * ) );

	newRDN[ where ] = LDAP_MALLOC( sizeof( LDAPAVA * ) );
	newRDN[ where ][ 0 ] = ava;
	newRDN[ i + 1 ] = NULL;

	return( newRDN );
}

void
ldapava_free_rdn( LDAPRDN *rdn )
{
	int iAVA;
	
	if ( rdn == NULL ) {
		return;
	}

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		assert( rdn[ iAVA ][ 0 ] );

		ldapava_free( rdn[ iAVA ][ 0 ] );
	}

	LDAP_VFREE( rdn );
}

LDAPDN *
ldapava_append_to_dn( LDAPDN *dn, LDAPRDN *rdn )
{
	LDAPDN 		*newDN;
	unsigned	i = 0U;

	assert( rdn );

	if ( dn != NULL ) {
		for ( i = 0U; dn[ i ]; i++ ) {
			/* no op */
		}
	}
	newDN = LDAP_REALLOC( dn, ( i + 2 ) * sizeof( LDAPRDN ** ) );
	newDN[ i ] = LDAP_MALLOC( sizeof( LDAPRDN * ) );
	newDN[ i ][ 0 ] = rdn;
	newDN[ i + 1 ] = NULL;

	return( newDN );
}

LDAPDN *
ldapava_insert_into_dn( LDAPDN *dn, LDAPRDN *rdn, unsigned where )
{
	LDAPDN 		*newDN;
	unsigned	i = 0U;

	assert( rdn );

	if ( dn != NULL ) {
		for ( i = 0U; dn[ i ]; i++ ) {
			/* no op */
		}
	}
	if ( where > i ) {
		where = i;
		/* assume "at end", which corresponds to
		 * ldapava_append_to_dn */
	}
	
	newDN = LDAP_REALLOC( dn, ( i + 2 ) * sizeof( LDAPRDN ** ) );
	
	/* data after insert point */
	AC_MEMCPY( &newDN[ where + 1 ], &newDN[ where ],
			( i - where ) * sizeof( LDAPDN * ) );

	newDN[ where ] = LDAP_MALLOC( sizeof( LDAPRDN * ) );
	newDN[ where ][ 0 ] = rdn;
	newDN[ i + 1 ] = NULL;

	return( newDN );
}

void
ldapava_free_dn( LDAPDN *dn )
{
	int iRDN;
	
	if ( dn == NULL ) {
		return;
	}

	for ( iRDN = 0; dn[ iRDN ]; iRDN++ ) {
		assert( dn[ iRDN ][ 0 ] );

		ldapava_free_rdn( dn[ iRDN ][ 0 ] );
	}

	LDAP_VFREE( dn );
}

/*
 * Converts a string representation of a DN (in LDAPv3, LDAPv2 or DCE)
 * into a structural representation of the DN, by separating attribute
 * types and values encoded in the more appropriate form, which is
 * string or OID for attribute types and binary form of the BER encoded
 * value or Unicode string. Formats different from LDAPv3 are parsed
 * according to their own rules and turned into the more appropriate
 * form according to LDAPv3.
 *
 * NOTE: I realize the code is getting spaghettish; it is rather
 * experimental and will hopefully turn into something more simple
 * and readable as soon as it works as expected.
 */

int
ldap_str2dn( const char *str, LDAPDN **dn, unsigned flags )
{
	const char 	*p;
	int		rc = LDAP_INVALID_DN_SYNTAX;

	LDAPDN		*newDN = NULL;
	LDAPRDN		*newRDN = NULL;
	
	assert( str );
	assert( dn );

	Debug( LDAP_DEBUG_TRACE, "=> ldap_str2dn(%s,%u)\n%s", str, flags, "" );

	*dn = NULL;

	switch ( LDAP_DN_FORMAT( flags ) ) {
	case LDAP_DN_FORMAT_LDAP:
	case LDAP_DN_FORMAT_LDAPV3:
	case LDAP_DN_FORMAT_LDAPV2:
	case LDAP_DN_FORMAT_DCE:
		break;

	/* unsupported in str2dn */
	case LDAP_DN_FORMAT_UFN:
	case LDAP_DN_FORMAT_AD_CANONICAL:
		return( LDAP_INVALID_DN_SYNTAX );

	default:
		return( LDAP_OTHER );
	}

	if ( str[ 0 ] == '\0' ) {
		return( LDAP_SUCCESS );
	}

	p = str;
	if ( LDAP_DN_DCE( flags ) ) {
		
		/* 
		 * (from Luke Howard: thnx) A RDN separator is required
		 * at the beginning of an (absolute) DN.
		 */
		if ( !LDAP_DN_RDN_SEP_DCE( p[ 0 ] ) ) {
			goto parsing_error;
		}
		p++;
		
	} else if ( LDAP_DN_LDAP( flags ) ) {
		/*
		 * if dn starts with '/' let's make it a DCE dn
		 */
		if ( LDAP_DN_RDN_SEP_DCE( p[ 0 ] ) ) {
			flags |= LDAP_DN_FORMAT_DCE;
			p++;
		}
	}

	for ( ; p[ 0 ]; p++ ) {
		LDAPDN 		*dn;
		
		rc = ldap_str2rdn( p, &newRDN, &p, flags );
		if ( rc != LDAP_SUCCESS ) {
			goto parsing_error;
		}

		/* 
		 * We expect a rdn separator
		 */
		if ( p[ 0 ] ) {
			switch ( LDAP_DN_FORMAT( flags ) ) {
			case LDAP_DN_FORMAT_LDAPV3:
				if ( !LDAP_DN_RDN_SEP( p[ 0 ] ) ) {
					rc = LDAP_OTHER;
					goto parsing_error;
				}
				break;
	
			case LDAP_DN_FORMAT_LDAP:
			case LDAP_DN_FORMAT_LDAPV2:
				if ( !LDAP_DN_RDN_SEP_V2( p[ 0 ] ) ) {
					rc = LDAP_OTHER;
					goto parsing_error;
				}
				break;
	
			case LDAP_DN_FORMAT_DCE:
				if ( !LDAP_DN_RDN_SEP_DCE( p[ 0 ] ) ) {
					rc = LDAP_OTHER;
					goto parsing_error;
				}
				break;
			}
		}


		if ( LDAP_DN_DCE( flags ) ) {
			/* add in reversed order */
			dn = ldapava_insert_into_dn( newDN, newRDN, 0 );
		} else {
			dn = ldapava_append_to_dn( newDN, newRDN );
		}

		if ( dn == NULL ) {
			rc = LDAP_NO_MEMORY;
			goto parsing_error;
		}

		newDN = dn;
		newRDN = NULL;
				
		if ( p[ 0 ] == '\0' ) {
					
			/* 
			 * the DN is over, phew
			 */
			rc = LDAP_SUCCESS;
			goto return_result;
		}
	}
	
parsing_error:;
	if ( newRDN ) {
		ldapava_free_rdn( newRDN );
	}

	if ( newDN ) {
		ldapava_free_dn( newDN );
		newDN = NULL;
	}

return_result:;

	Debug( LDAP_DEBUG_TRACE, "<= ldap_str2dn(%s,%u)=%d\n", str, flags, rc );
	*dn = newDN;
	
	return( rc );
}

/*
 * ldap_str2rdn
 *
 * Parses a relative DN according to flags up to a rdn separator 
 * or to the end of str.
 * Returns the rdn and a pointer to the string continuation, which
 * corresponds to the rdn separator or to '\0' in case the string is over.
 */
int
ldap_str2rdn( const char *str, LDAPRDN **rdn, const char **n, unsigned flags )
{
	const char 	*p;
	int 		state = B4AVA;
	int		rc = LDAP_INVALID_DN_SYNTAX;
	int		attrTypeEncoding = LDAP_AVA_STRING, 
			attrValueEncoding = LDAP_AVA_STRING;

	struct berval	*attrType = NULL;
	struct berval 	*attrValue = NULL;

	LDAPRDN		*newRDN = NULL;
	
	assert( str );
	assert( rdn );
	assert( n );

	Debug( LDAP_DEBUG_TRACE, "=> ldap_str2rdn(%s,%u)\n%s", str, flags, "" );

	*rdn = NULL;
	*n = NULL;

	switch ( LDAP_DN_FORMAT( flags ) ) {
	case LDAP_DN_FORMAT_LDAP:
	case LDAP_DN_FORMAT_LDAPV3:
	case LDAP_DN_FORMAT_LDAPV2:
	case LDAP_DN_FORMAT_DCE:
		break;

	/* unsupported in str2dn */
	case LDAP_DN_FORMAT_UFN:
	case LDAP_DN_FORMAT_AD_CANONICAL:
		return( LDAP_INVALID_DN_SYNTAX );

	default:
		return( LDAP_OTHER );
	}

	if ( str[ 0 ] == '\0' ) {
		return( LDAP_SUCCESS );
	}

	p = str;
	for ( ; p[ 0 ] || state == GOTAVA; ) {
		
		/*
		 * The parser in principle advances one token a time,
		 * or toggles state if preferable.
		 */
		switch (state) {

		/*
		 * an AttributeType can be encoded as:
		 * - its string representation; in detail, implementations
		 *   MUST recognize AttributeType string type names listed 
		 *   in section 2.3 of draft-ietf-ldapbis-dn-XX.txt, and
		 *   MAY recognize other names.
		 * - its numeric OID (a dotted decimal string); in detail
		 *   RFC 2253 asserts that ``Implementations MUST allow 
		 *   an oid in the attribute type to be prefixed by one 
		 *   of the character strings "oid." or "OID."''.  As soon
		 *   as draft-ietf-ldapbis-dn-XX.txt obsoletes RFC 2253 
		 *   I'm not sure whether this is required or not any 
		 *   longer; to be liberal, we still implement it.
		 */
		case B4AVA:
			if ( LDAP_DN_ASCII_SPACE( p[ 0 ] ) ) {
				if ( !LDAP_DN_ALLOW_ONE_SPACE( flags ) ) {
					/* error */
					goto parsing_error;
				}
				p++;
			}

			if ( LDAP_DN_ASCII_SPACE( p[ 0 ] ) ) {
				if ( !LDAP_DN_ALLOW_SPACES( flags ) ) {
					/* error */
					goto parsing_error;
				}

				/* whitespace is allowed (and trimmed) */
				p++;
				while ( p[ 0 ] && LDAP_DN_ASCII_SPACE( p[ 0 ] ) ) {
					p++;
				}

				if ( !p[ 0 ] ) {
					/* error: we expected an AVA */
					goto parsing_error;
				}
			}

			/* oid */
			if ( LDAP_DN_OID_LEADCHAR( p[ 0 ] ) ) {
				state = B4OIDATTRTYPE;
				break;
			}
			
			/* else must be alpha */
			if ( !LDAP_DN_DESC_LEADCHAR( p[ 0 ] ) ) {
				goto parsing_error;
			}
			
			/* LDAPv2 "oid." prefix */
			if ( LDAP_DN_LDAPV2( flags ) ) {
				/*
				 * to be overly pedantic, we only accept
				 * "OID." or "oid."
				 */
				if ( flags & LDAP_DN_PEDANTIC ) {
					if ( !strncmp( p, "OID.", 4 )
						|| !strncmp( p, "oid.", 4 ) ) {
						p += 4;
						state = B4OIDATTRTYPE;
						break;
					}
				} else {
				       if ( !strncasecmp( p, "oid.", 4 ) ) {
					       p += 4;
					       state = B4OIDATTRTYPE;
					       break;
				       }
				}
			}

			state = B4STRINGATTRTYPE;
			break;
		
		case B4OIDATTRTYPE: {
			int 		err = LDAP_SUCCESS;
			char		*type;
			
			type = parse_numericoid( &p, &err, 0 );
			if ( type == NULL ) {
				goto parsing_error;
			}
			attrType = LDAP_MALLOC( sizeof( struct berval ) );
			if ( attrType== NULL ) {
				rc = LDAP_NO_MEMORY;
				goto parsing_error;
			}
			attrType->bv_val = type;
			attrType->bv_len = strlen( type );
			attrTypeEncoding = LDAP_AVA_BINARY;

			state = B4AVAEQUALS;
			break;
		}

		case B4STRINGATTRTYPE: {
			const char 	*startPos, *endPos = NULL;
			ber_len_t 	len;
			
			/* 
			 * the starting char has been found to be
			 * a LDAP_DN_DESC_LEADCHAR so we don't re-check it
			 * FIXME: DCE attr types seem to have a more
			 * restrictive syntax (no '-' ...) 
			 */
			for ( startPos = p++; p[ 0 ]; p++ ) {
				if ( LDAP_DN_DESC_CHAR( p[ 0 ] ) ) {
					continue;
				}

				if ( LDAP_DN_LANG_SEP( p[ 0 ] ) ) {
					
					/*
					 * RFC 2253 does not explicitly
					 * allow lang extensions to attribute 
					 * types in DNs ... 
					 */
					if ( flags & LDAP_DN_PEDANTIC ) {
						goto parsing_error;
					}

					/*
					 * we trim ';' and following lang 
					 * and so from attribute types
					 */
					endPos = p;
					for ( ; LDAP_DN_ATTRDESC_CHAR( p[ 0 ] )
							|| LDAP_DN_LANG_SEP( p[ 0 ] ); p++ ) {
						/* no op */ ;
					}
					break;
				}
				break;
			}

			len = ( endPos ? endPos : p ) - startPos;
			if ( len == 0 ) {
				goto parsing_error;
			}
			
			assert( attrType == NULL );
			attrType = LDAP_MALLOC( sizeof( struct berval ) );
			if ( attrType == NULL ) {
				rc = LDAP_NO_MEMORY;
				goto parsing_error;
			}
			attrType->bv_val = LDAP_STRNDUP( startPos, len );
			if ( attrType->bv_val == NULL ) {
				rc = LDAP_NO_MEMORY;
				goto parsing_error;
			}
			attrType->bv_len = len;
			attrTypeEncoding = LDAP_AVA_STRING;

			/*
			 * here we need to decide whether to use it as is 
			 * or turn it in OID form; as a consequence, we
			 * need to decide whether to binary encode the value
			 */
			
			state = B4AVAEQUALS;
			break;
		}
				
		case B4AVAEQUALS:
			/* spaces may not be allowed */
			if ( LDAP_DN_ASCII_SPACE( p[ 0 ] ) ) {
				if ( !LDAP_DN_ALLOW_SPACES( flags ) ) {
					goto parsing_error;
				}
			
				/* trim spaces */
				for ( p++; LDAP_DN_ASCII_SPACE( p[ 0 ] ); p++ ) {
					/* no op */
				}
			}

			/* need equal sign */
			if ( !LDAP_DN_AVA_EQUALS( p[ 0 ] ) ) {
				goto parsing_error;
			}
			p++;

			/* spaces may not be allowed */
			if ( LDAP_DN_ASCII_SPACE( p[ 0 ] ) ) {
				if ( !LDAP_DN_ALLOW_SPACES( flags ) ) {
					goto parsing_error;
				}

				/* trim spaces */
				for ( p++; LDAP_DN_ASCII_SPACE( p[ 0 ] ); p++ ) {
					/* no op */
				}
			}

			/*
			 * octothorpe means a BER encoded value will follow
			 * FIXME: I don't think DCE will allow it
			 */
			if ( LDAP_DN_OCTOTHORPE( p[ 0 ] ) ) {
				p++;
				attrValueEncoding = LDAP_AVA_BINARY;
				state = B4BINARYVALUE;
				break;
			}

			/* STRING value expected */

			/* 
			 * if we're pedantic, an attribute type in OID form
			 * SHOULD imply a BER encoded attribute value; we
			 * should at least issue a warning
			 */
			if ( ( flags & LDAP_DN_PEDANTIC )
				&& ( attrTypeEncoding == LDAP_AVA_BINARY ) ) {
				/* OID attrType SHOULD use binary encoding */
				goto parsing_error;
			}

			attrValueEncoding = LDAP_AVA_STRING;

			/* 
			 * LDAPv2 allows the attribute value to be quoted;
			 * also, IA5 values are expected, in principle
			 */
			if ( LDAP_DN_LDAPV2( flags ) || LDAP_DN_LDAP( flags ) ) {
				if ( LDAP_DN_QUOTES( p[ 0 ] ) ) {
					p++;
					state = B4IA5VALUEQUOTED;
					break;
				}

				if ( LDAP_DN_LDAPV2( flags ) ) {
					state = B4IA5VALUE;
					break;
				}
			}

			/*
			 * here STRING means RFC 2253 string
			 * FIXME: what about DCE strings? 
			 */
			state = B4STRINGVALUE;
			break;

		case B4BINARYVALUE:
			if ( hexstr2binval( p, &attrValue, &p, flags ) ) {
				goto parsing_error;
			}

			state = GOTAVA;
			break;

		case B4STRINGVALUE:
			switch ( LDAP_DN_FORMAT( flags ) ) {
			case LDAP_DN_FORMAT_LDAP:
			case LDAP_DN_FORMAT_LDAPV3:
				if ( str2strval( p, &attrValue, &p, flags, 
							&attrValueEncoding ) ) {
					goto parsing_error;
				}
				break;

			case LDAP_DN_FORMAT_DCE:
				if ( DCE2strval( p, &attrValue, &p, flags ) ) {
					goto parsing_error;
				}
				break;

			default:
				assert( 0 );
			}

			state = GOTAVA;
			break;

		case B4IA5VALUE:
			if ( IA52strval( p, &attrValue, &p, flags ) ) {
				goto parsing_error;
			}

			state = GOTAVA;
			break;
		
		case B4IA5VALUEQUOTED:

			/* lead quote already stripped */
			if ( quotedIA52strval( p, &attrValue, 
						&p, flags ) ) {
				goto parsing_error;
			}

			state = GOTAVA;
			break;

		case GOTAVA: {
			LDAPAVA *ava;
			LDAPRDN *rdn;
			int	rdnsep = 0;

			/*
			 * we accept empty values
			 */
			ava = ldapava_new( attrType, attrValue, 
					attrValueEncoding );
			if ( ava == NULL ) {
				rc = LDAP_NO_MEMORY;
				goto parsing_error;
			}

			rdn = ldapava_append_to_rdn( newRDN, ava );
			if ( rdn == NULL ) {
				rc = LDAP_NO_MEMORY;
				goto parsing_error;
			}
			newRDN = rdn;
			
			/* 
			 * if we got an AVA separator ('+', or ',' for DCE ) 
			 * we expect a new AVA for this RDN; otherwise 
			 * we add the RDN to the DN
			 */
			switch ( LDAP_DN_FORMAT( flags ) ) {
			case LDAP_DN_FORMAT_LDAP:
			case LDAP_DN_FORMAT_LDAPV3:
			case LDAP_DN_FORMAT_LDAPV2:
				if ( !LDAP_DN_AVA_SEP( p[ 0 ] ) ) {
					rdnsep = 1;
				}
				break;

			case LDAP_DN_FORMAT_DCE:
				if ( !LDAP_DN_AVA_SEP_DCE( p[ 0 ] ) ) {
					rdnsep = 1;
				}
				break;
			}

			if ( rdnsep ) {
				/* 
				 * the RDN is over, phew
				 */
				*n = p;
				rc = LDAP_SUCCESS;
				goto return_result;
			}

			/* they should have been used in an AVA */
			attrType = NULL;
			attrValue = NULL;
			
			p++;
			state = B4AVA;
			break;
		}

		default:
			assert( 0 );
			goto parsing_error;
		}
	}
	
parsing_error:;
	/* They are set to NULL after they're used in an AVA */
	if ( attrType ) {
		ber_bvfree( attrType );
	}

	if ( attrValue ) {
		ber_bvfree( attrValue );
	}

	if ( newRDN ) {
		ldapava_free_rdn( newRDN );
		newRDN = NULL;
	}

return_result:;

	Debug( LDAP_DEBUG_TRACE, "<= ldap_str2rdn(%*s)=%d\n", 
			*n - p, str, rc );
	*rdn = newRDN;
	
	return( rc );
}

/*
 * reads in a UTF-8 string value, unescaping stuff:
 * '\' + LDAP_DN_NEEDESCAPE(c) -> 'c'
 * '\' + HEXPAIR(p) -> unhex(p)
 */
static int
str2strval( const char *str, struct berval **val, const char **next, unsigned flags, unsigned *retFlags )
{
	const char 	*p, *startPos, *endPos = NULL;
	ber_len_t	len, escapes, unescapes;

	assert( str );
	assert( val );
	assert( next );

	*val = NULL;
	*next = NULL;

	for ( startPos = p = str, escapes = 0, unescapes = 0; p[ 0 ]; p++ ) {
		if ( LDAP_DN_ESCAPE( p[ 0 ] ) ) {
			p++;
			if ( p[ 0 ] == '\0' ) {
				return( 1 );
			}
			if ( ( p == startPos + 1 && LDAP_DN_NEEDESCAPE_LEAD( p[ 0 ] ) )
					|| ( LDAP_DN_VALUE_END( p[ 1 ] ) && LDAP_DN_NEEDESCAPE_TRAIL( p[ 0 ] ) )
					|| LDAP_DN_NEEDESCAPE( p[ 0 ] ) ) {
				escapes++;
				continue;
			}

			if ( LDAP_DN_HEXPAIR( p ) ) {
				char c;

				hexstr2bin( p, &c );
				escapes += 2;

				if ( !LDAP_DN_ASCII_PRINTABLE( c ) ) {

					/*
					 * we assume the string is UTF-8
					 */
					*retFlags = LDAP_AVA_NONPRINTABLE;
				}
				p++;

				continue;
			}

			if ( LDAP_DN_PEDANTIC & flags ) {
				return( 1 );
			}
			/* 
			 * FIXME: we allow escaping 
			 * of chars that don't need 
			 * to and do not belong to 
			 * HEXDIGITS (we also allow
			 * single hexdigit; maybe we 
			 * shouldn't).
			 */
			unescapes++;

		} else if ( ( LDAP_DN_LDAP( flags ) && LDAP_DN_VALUE_END_V2( p[ 0 ] ) ) 
				|| ( LDAP_DN_LDAPV3( flags ) && LDAP_DN_VALUE_END( p[ 0 ] ) ) ) {
			break;

		} else if ( LDAP_DN_NEEDESCAPE( p[ 0 ] ) ) {
			/* 
			 * FIXME: maybe we can add 
			 * escapes if not pedantic?
			 */
			return( 1 );
		}
	}

	/*
	 * we do allow unescaped spaces at the end
	 * of the value only in non-pedantic mode
	 */
	if ( p > startPos + 1 && LDAP_DN_ASCII_SPACE( p[ -1 ] ) &&
			!LDAP_DN_ESCAPE( p[ -2 ] ) ) {
		if ( flags & LDAP_DN_PEDANTIC ) {
			return( 1 );
		}

		/* strip trailing (unescaped) spaces */
		for ( endPos = p - 1; 
				endPos > startPos + 1 && 
				LDAP_DN_ASCII_SPACE( endPos[ -1 ] ) &&
				!LDAP_DN_ESCAPE( endPos[ -2 ] );
				endPos-- ) {
			/* no op */
		}
	}

	/*
	 * FIXME: test memory?
	 */
	len = ( endPos ? endPos : p ) - startPos - escapes - unescapes;
	*val = LDAP_MALLOC( sizeof( struct berval ) );
	( *val )->bv_len = len;

	if ( escapes == 0 && unescapes == 0 ) {
		( *val )->bv_val = LDAP_STRNDUP( startPos, len );

	} else {
		ber_len_t	s, d;

		( *val )->bv_val = LDAP_MALLOC( len + 1 );
		for ( s = 0, d = 0; d < len; ) {
			if ( LDAP_DN_ESCAPE( startPos[ s ] ) ) {
				s++;
				if ( ( s == 0 && LDAP_DN_NEEDESCAPE_LEAD( startPos[ s ] ) )
						|| ( s == len - 1 && LDAP_DN_NEEDESCAPE_TRAIL( startPos[ s ] ) )
						|| LDAP_DN_NEEDESCAPE( startPos[ s ] ) ) {
					( *val )->bv_val[ d++ ] = 
						startPos[ s++ ];
					
				} else if ( LDAP_DN_HEXPAIR( &startPos[ s ] ) ) {
					char 	c;

					hexstr2bin( &startPos[ s ], &c );
					( *val )->bv_val[ d++ ] = c;
					s += 2;
					
				} else {
					/*
					 * we allow escaping of chars
					 * that do not need to 
					 */
					( *val )->bv_val[ d++ ] = 
						startPos[ s++ ];
				}

			} else {
				( *val )->bv_val[ d++ ] = startPos[ s++ ];
			}
		}

		( *val )->bv_val[ d ] = '\0';
		assert( strlen( ( *val )->bv_val ) == len );
	}


	*next = p;

	return( 0 );
}

static int
DCE2strval( const char *str, struct berval **val, const char **next, unsigned flags )
{
	const char 	*p, *startPos, *endPos = NULL;
	ber_len_t	len, escapes;

	assert( str );
	assert( val );
	assert( next );

	*val = NULL;
	*next = NULL;
	
	for ( startPos = p = str, escapes = 0; p[ 0 ]; p++ ) {
		if ( LDAP_DN_ESCAPE_DCE( p[ 0 ] ) ) {
			p++;
			if ( LDAP_DN_NEEDESCAPE_DCE( p[ 0 ] ) ) {
				escapes++;

			} else {
				return( 1 );
			}

		} else if ( LDAP_DN_VALUE_END_DCE( p[ 0 ] ) ) {
			break;
		}

		/*
		 * FIXME: can we accept anything else? I guess we need
		 * to stop if a value is not legal
		 */
	}

	/* 
	 * (unescaped) trailing spaces are trimmed must be silently ignored;
	 * so we eat them
	 */
	if ( p > startPos + 1 && LDAP_DN_ASCII_SPACE( p[ -1 ] ) &&
			!LDAP_DN_ESCAPE( p[ -2 ] ) ) {
		if ( flags & LDAP_DN_PEDANTIC ) {
			return( 1 );
		}

		/* strip trailing (unescaped) spaces */
		for ( endPos = p - 1; 
				endPos > startPos + 1 && 
				LDAP_DN_ASCII_SPACE( endPos[ -1 ] ) &&
				!LDAP_DN_ESCAPE( endPos[ -2 ] );
				endPos-- ) {
			/* no op */
		}
	}


	len = ( endPos ? endPos : p ) - startPos - escapes;
	*val = LDAP_MALLOC( sizeof( struct berval ) );
	( *val )->bv_len = len;
	if ( escapes == 0 ){
		( *val )->bv_val = LDAP_STRNDUP( startPos, len );

	} else {
		ber_len_t	s, d;

		( *val )->bv_val = LDAP_MALLOC( len + 1 );
		for ( s = 0, d = 0; d < len; ) {
			/*
			 * This point is reached only if escapes 
			 * are properly used, so all we need to
			 * do is eat them
			 */
			if (  LDAP_DN_ESCAPE_DCE( startPos[ s ] ) ) {
				s++;

			}
			( *val )->bv_val[ d++ ] = startPos[ s++ ];
		}
		( *val )->bv_val[ d ] = '\0';
		assert( strlen( ( *val )->bv_val ) == len );
	}
	
	*next = p;
	
	return( 0 );
}

static int
IA52strval( const char *str, struct berval **val, const char **next, unsigned flags )
{
	const char 	*p, *startPos, *endPos = NULL;
	ber_len_t	len, escapes;

	assert( str );
	assert( val );
	assert( next );

	*val = NULL;
	*next = NULL;

	/*
	 * LDAPv2 (RFC 1779)
	 */
	
	for ( startPos = p = str, escapes = 0; p[ 0 ]; p++ ) {
		if ( LDAP_DN_ESCAPE( p[ 0 ] ) ) {
			p++;
			if ( p[ 0 ] == '\0' ) {
				return( 1 );
			}

			if ( !LDAP_DN_NEEDESCAPE( p[ 0 ] )
					&& ( LDAP_DN_PEDANTIC & flags ) ) {
				return( 1 );
			}
			escapes++;

		} else if ( LDAP_DN_VALUE_END_V2( p[ 0 ] ) ) {
			break;
		}

		/*
		 * FIXME: can we accept anything else? I guess we need
		 * to stop if a value is not legal
		 */
	}

	/* strip trailing (unescaped) spaces */
	for ( endPos = p; 
			endPos > startPos + 1 && 
			LDAP_DN_ASCII_SPACE( endPos[ -1 ] ) &&
			!LDAP_DN_ESCAPE( endPos[ -2 ] );
			endPos-- ) {
		/* no op */
	}

	*val = LDAP_MALLOC( sizeof( struct berval ) );
	len = ( endPos ? endPos : p ) - startPos - escapes;
	( *val )->bv_len = len;
	if ( escapes == 0 ) {
		( *val )->bv_val = LDAP_STRNDUP( startPos, len );

	} else {
		ber_len_t	s, d;
		
		( *val )->bv_val = LDAP_MALLOC( len + 1 );
		for ( s = 0, d = 0; d < len; ) {
			if ( LDAP_DN_ESCAPE( startPos[ s ] ) ) {
				s++;
			}
			( *val )->bv_val[ d++ ] = startPos[ s++ ];
		}
		( *val )->bv_val[ d ] = '\0';
		assert( strlen( ( *val )->bv_val ) == len );
	}
	*next = p;

	return( 0 );
}

static int
quotedIA52strval( const char *str, struct berval **val, const char **next, unsigned flags )
{
	const char 	*p, *startPos, *endPos = NULL;
	ber_len_t	len;
	unsigned	escapes = 0;

	assert( str );
	assert( val );
	assert( next );

	*val = NULL;
	*next = NULL;

	/* initial quote already eaten */
	for ( startPos = p = str; p[ 0 ]; p++ ) {
		/* 
		 * According to RFC 1779, the quoted value can
		 * contain escaped as well as unescaped special values;
		 * as a consequence we tolerate escaped values 
		 * (e.g. '"\,"' -> '\,') and escape unescaped specials
		 * (e.g. '","' -> '\,').
		 */
		if ( LDAP_DN_ESCAPE( p[ 0 ] ) ) {
			if ( p[ 1 ] == '\0' ) {
				return( 1 );
			}
			p++;

			if ( !LDAP_DN_V2_PAIR( p[ 0 ] )
					&& ( LDAP_DN_PEDANTIC & flags ) ) {
				/*
				 * do we allow to escape normal chars?
				 * LDAPv2 does not allow any mechanism 
				 * for escaping chars with '\' and hex 
				 * pair
				 */
				return( 1 );
			}
			escapes++;

		} else if ( LDAP_DN_QUOTES( p[ 0 ] ) ) {
			endPos = p;
			/* eat closing quotes */
			p++;
			break;
		}

		/*
		 * FIXME: can we accept anything else? I guess we need
		 * to stop if a value is not legal
		 */
	}

	if ( endPos == NULL ) {
		return( 1 );
	}

	/* Strip trailing (unescaped) spaces */
	for ( ; p[ 0 ] && LDAP_DN_ASCII_SPACE( p[ 0 ] ); p++ ) {
		/* no op */
	}

	len = endPos - startPos - escapes;
	assert( len >= 0 );
	*val = LDAP_MALLOC( sizeof( struct berval ) );
	( *val )->bv_len = len;
	if ( escapes == 0 ) {
		( *val )->bv_val = LDAP_STRNDUP( startPos, len );

	} else {
		ber_len_t	s, d;
		
		( *val )->bv_val = LDAP_MALLOC( len + 1 );
		( *val )->bv_len = len;

		for ( s = d = 0; d < len; ) {
			if ( LDAP_DN_ESCAPE( str[ s ] ) ) {
				s++;
			}
			( *val )->bv_val[ d++ ] = str[ s++ ];
		}
		( *val )->bv_val[ d ] = '\0';
		assert( strlen( ( *val )->bv_val ) == len );
	}

	*next = p;

	return( 0 );
}

static int
hexstr2bin( const char *str, char *c )
{
	char	c1, c2;

	assert( str );
	assert( c );

	c1 = str[ 0 ];
	c2 = str[ 1 ];

	if ( LDAP_DN_ASCII_DIGIT( c1 ) ) {
		*c = c1 - '0';

	} else {
		c1 = tolower( c1 );

		if ( LDAP_DN_ASCII_LCASE_HEXALPHA( c1 ) ) {
			*c = c1 - 'a' + 10;
		}
	}

	*c <<= 4;

	if ( LDAP_DN_ASCII_DIGIT( c2 ) ) {
		*c += c2 - '0';
		
	} else {
		c2 = tolower( c2 );

		if ( LDAP_DN_ASCII_LCASE_HEXALPHA( c2 ) ) {
			*c += c2 - 'a' + 10;
		}
	}

	return( 0 );
}

static int
hexstr2binval( const char *str, struct berval **val, const char **next, unsigned flags )
{
	const char 	*p, *startPos, *endPos = NULL;
	ber_len_t	len;
	ber_len_t	s, d;

	assert( str );
	assert( val );
	assert( next );

	*val = NULL;
	*next = NULL;

	for ( startPos = p = str; p[ 0 ]; p += 2 ) {
		switch ( LDAP_DN_FORMAT( flags ) ) {
		case LDAP_DN_FORMAT_LDAPV3:
			if ( LDAP_DN_VALUE_END( p[ 0 ] ) ) {
				goto end_of_value;
			}
			break;

		case LDAP_DN_FORMAT_LDAP:
		case LDAP_DN_FORMAT_LDAPV2:
			if ( LDAP_DN_VALUE_END_V2( p[ 0 ] ) ) {
				goto end_of_value;
			}
			break;

		case LDAP_DN_FORMAT_DCE:
			if ( LDAP_DN_VALUE_END_DCE( p[ 0 ] ) ) {
				goto end_of_value;
			}
			break;
		}

		if ( LDAP_DN_ASCII_SPACE( p[ 0 ] ) ) {
			if ( flags & LDAP_DN_PEDANTIC ) {
				return( 1 );
			}
			endPos = p;

			for ( ; p[ 0 ]; p++ ) {
				switch ( LDAP_DN_FORMAT( flags ) ) {
				case LDAP_DN_FORMAT_LDAPV3:
					if ( LDAP_DN_VALUE_END( p[ 0 ] ) ) {
						goto end_of_value;
					}
					break;

				case LDAP_DN_FORMAT_LDAP:
				case LDAP_DN_FORMAT_LDAPV2:
					if ( LDAP_DN_VALUE_END_V2( p[ 0 ] ) ) {
						goto end_of_value;
					}
					break;

				case LDAP_DN_FORMAT_DCE:
					if ( LDAP_DN_VALUE_END_DCE( p[ 0 ] ) ) {
						goto end_of_value;
					}
					break;
				}
			}
			break;
		}
		
		if ( !LDAP_DN_HEXPAIR( p ) ) {
			return( 1 );
		}
	}

end_of_value:;

	len = ( ( endPos ? endPos : p ) - startPos ) / 2;
	/* must be even! */
	assert( 2 * len == (ber_len_t) (( endPos ? endPos : p ) - startPos ));

	*val = LDAP_MALLOC( sizeof( struct berval ) );
	if ( *val == NULL ) {
		return( LDAP_NO_MEMORY );
	}

	( *val )->bv_len = len;
	( *val )->bv_val = LDAP_MALLOC( len + 1 );
	if ( ( *val )->bv_val == NULL ) {
		LDAP_FREE( *val );
		return( LDAP_NO_MEMORY );
	}

	for ( s = 0, d = 0; d < len; s += 2, d++ ) {
		char 	c;

		hexstr2bin( &startPos[ s ], &c );

		( *val )->bv_val[ d ] = c;
	}

	( *val )->bv_val[ d ] = '\0';
	*next = p;

	return( 0 );
}

/*
 * convert a byte in a hexadecimal pair
 */
static int
byte2hexpair( const char *val, char *pair )
{
	static const char	hexdig[] = "0123456789abcdef";

	assert( val );
	assert( pair );

	/* 
	 * we assume the string has enough room for the hex encoding
	 * of the value
	 */

	pair[ 0 ] = hexdig[ 0x0f & ( val[ 0 ] >> 4 ) ];
	pair[ 1 ] = hexdig[ 0x0f & val[ 0 ] ];
	
	return( 0 );
}

/*
 * convert a binary value in hexadecimal pairs
 */
static int
binval2hexstr( struct berval *val, char *str )
{
	ber_len_t	s, d;

	assert( val );
	assert( str );

	if ( val->bv_len == 0 ) {
		return( 0 );
	}

	/* 
	 * we assume the string has enough room for the hex encoding
	 * of the value
	 */

	for ( s = 0, d = 0; s < val->bv_len; s++, d += 2 ) {
		byte2hexpair( &val->bv_val[ s ], &str[ d ] );
	}
	
	return( 0 );
}

/*
 * Length of the string representation, accounting for escaped hex
 * of UTF-8 chars
 */
static int
strval2strlen( struct berval *val, unsigned flags, ber_len_t *len )
{
	ber_len_t	l, cl = 1;
	char		*p;
	
	assert( val );
	assert( len );

	*len = 0;
	if ( val->bv_len == 0 ) {
		return( 0 );
	}

	for ( l = 0, p = val->bv_val; p[ 0 ]; p += cl ) {
		cl = ldap_utf8_charlen( p );
		if ( cl == 0 ) {
			/* illegal utf-8 char! */
			return( -1 );

		} else if ( cl > 1 ) {
			ber_len_t cnt;

			for ( cnt = 1; cnt < cl; cnt++ ) {
				if ( ( p[ cnt ] & 0x80 ) == 0x00 ) {
					return( -1 );
				}
			}
			/* need to escape it */
			l += 3 * cl;
		
		/* 
		 * there might be some chars we want to escape in form
		 * of a couple of hexdigits for optimization purposes
		 */
		} else if ( LDAP_DN_WILLESCAPE( flags, p[ 0 ] ) ) {
			l += 3;

		} else if ( LDAP_DN_NEEDESCAPE( p[ 0 ] )
				|| ( p == val->bv_val && LDAP_DN_NEEDESCAPE_LEAD( p[ 0 ] ) )
				|| ( !p[ 1 ] && LDAP_DN_NEEDESCAPE_TRAIL( p[ 0 ] ) ) ) {
			l += 2;

		} else {
			l++;
		}
	}

	*len = l;

	return( 0 );
}

/*
 * convert to string representation, escaping with hex the UTF-8 stuff;
 * assume the destination has enough room for escaping
 */
static int
strval2str( struct berval *val, char *str, unsigned flags, ber_len_t *len )
{
	ber_len_t	s, d, end;

	assert( val );
	assert( str );
	assert( len );

	if ( val->bv_len == 0 ) {
		*len = 0;
		return( 0 );
	}

	/* 
	 * we assume the string has enough room for the hex encoding
	 * of the value
	 */
	for ( s = 0, d = 0, end = val->bv_len - 1; s < val->bv_len; ) {
		ber_len_t	cl = ldap_utf8_charlen( &val->bv_val[ s ] );
		
		/* 
		 * there might be some chars we want to escape in form
		 * of a couple of hexdigits for optimization purposes
		 */
		if ( cl > 1 || LDAP_DN_WILLESCAPE( flags, val->bv_val[ s ] ) ) {
			for ( ; cl--; ) {
				str[ d++ ] = '\\';
				byte2hexpair( &val->bv_val[ s ], &str[ d ] );
				s++;
				d += 2;
			}

		} else {
			if ( LDAP_DN_NEEDESCAPE( val->bv_val[ s ] )
					|| ( d == 0 && LDAP_DN_NEEDESCAPE_LEAD( val->bv_val[ s ] ) )
					|| ( s == end && LDAP_DN_NEEDESCAPE_TRAIL( val->bv_val[ s ] ) ) ) {
				str[ d++ ] = '\\';
			}
			str[ d++ ] = val->bv_val[ s++ ];
		}
	}

	*len = d;
	
	return( 0 );
}

/*
 * Length of the IA5 string representation (no UTF-8 allowed)
 */
static int
strval2IA5strlen( struct berval *val, unsigned flags, ber_len_t *len )
{
	ber_len_t	l;
	char		*p;

	assert( val );
	assert( len );

	*len = 0;
	if ( val->bv_len == 0 ) {
		return( 0 );
	}

	if ( flags & LDAP_AVA_NONPRINTABLE ) {
		/*
		 * Turn value into a binary encoded BER
		 */
		return( -1 );

	} else {
		for ( l = 0, p = val->bv_val; p[ 0 ]; p++ ) {
			if ( LDAP_DN_NEEDESCAPE( p[ 0 ] )
					|| ( p == val->bv_val && LDAP_DN_NEEDESCAPE_LEAD( p[ 0 ] ) )
					|| ( !p[ 1 ] && LDAP_DN_NEEDESCAPE_TRAIL( p[ 0 ] ) ) ) {
				l += 2;

			} else {
				l++;
			}
		}
	}

	*len = l;
	
	return( 0 );
}

/*
 * convert to string representation (np UTF-8)
 * assume the destination has enough room for escaping
 */
static int
strval2IA5str( struct berval *val, char *str, unsigned flags, ber_len_t *len )
{
	ber_len_t	s, d, end;

	assert( val );
	assert( str );
	assert( len );

	if ( val->bv_len == 0 ) {
		*len = 0;
		return( 0 );
	}

	if ( flags & LDAP_AVA_NONPRINTABLE ) {
		/*
		 * Turn value into a binary encoded BER
		 */
		*len = 0;
		return( -1 );

	} else {
		/* 
		 * we assume the string has enough room for the hex encoding
		 * of the value
		 */

		for ( s = 0, d = 0, end = val->bv_len - 1; s < val->bv_len; ) {
			if ( LDAP_DN_NEEDESCAPE( val->bv_val[ s ] )
					|| ( s == 0 && LDAP_DN_NEEDESCAPE_LEAD( val->bv_val[ s ] ) )
					|| ( s == end && LDAP_DN_NEEDESCAPE_TRAIL( val->bv_val[ s ] ) ) ) {
				str[ d++ ] = '\\';
			}
			str[ d++ ] = val->bv_val[ s++ ];
		}
	}

	*len = d;
	
	return( 0 );
}

/*
 * Length of the (supposedly) DCE string representation, 
 * accounting for escaped hex of UTF-8 chars
 */
static int
strval2DCEstrlen( struct berval *val, unsigned flags, ber_len_t *len )
{
	ber_len_t	l;
	char		*p;

	assert( val );
	assert( len );

	*len = 0;
	if ( val->bv_len == 0 ) {
		return( 0 );
	}

	if ( flags & LDAP_AVA_NONPRINTABLE ) {
		/* 
		 * FIXME: Turn the value into a binary encoded BER?
		 */
		return( -1 );
		
	} else {
		for ( l = 0, p = val->bv_val; p[ 0 ]; p++ ) {
			if ( LDAP_DN_NEEDESCAPE_DCE( p[ 0 ] ) ) {
				l += 2;

			} else {
				l++;
			}
		}
	}

	*len = l;

	return( 0 );
}

/*
 * convert to (supposedly) DCE string representation, 
 * escaping with hex the UTF-8 stuff;
 * assume the destination has enough room for escaping
 */
static int
strval2DCEstr( struct berval *val, char *str, unsigned flags, ber_len_t *len )
{
	ber_len_t	s, d;

	assert( val );
	assert( str );
	assert( len );

	if ( val->bv_len == 0 ) {
		*len = 0;
		return( 0 );
	}

	if ( flags & LDAP_AVA_NONPRINTABLE ) {
		/*
		 * FIXME: Turn the value into a binary encoded BER?
		 */
		*len = 0;
		return( -1 );
		
	} else {

		/* 
		 * we assume the string has enough room for the hex encoding
		 * of the value
		 */

		for ( s = 0, d = 0; s < val->bv_len; ) {
			if ( LDAP_DN_NEEDESCAPE_DCE( val->bv_val[ s ] ) ) {
				str[ d++ ] = '\\';
			}
			str[ d++ ] = val->bv_val[ s++ ];
		}
	}

	*len = d;
	
	return( 0 );
}

/*
 * Length of the (supposedly) AD canonical string representation, 
 * accounting for escaped hex of UTF-8 chars
 */
static int
strval2ADstrlen( struct berval *val, unsigned flags, ber_len_t *len )
{
	ber_len_t	l;
	char		*p;

	assert( val );
	assert( len );

	*len = 0;
	if ( val->bv_len == 0 ) {
		return( 0 );
	}

	if ( flags & LDAP_AVA_NONPRINTABLE ) {
		/* 
		 * FIXME: Turn the value into a binary encoded BER?
		 */
		return( -1 );
		
	} else {
		for ( l = 0, p = val->bv_val; p[ 0 ]; p++ ) {
			if ( LDAP_DN_NEEDESCAPE_AD( p[ 0 ] ) ) {
				l += 2;

			} else {
				l++;
			}
		}
	}

	*len = l;
	
	return( 0 );
}

/*
 * convert to (supposedly) AD string representation, 
 * escaping with hex the UTF-8 stuff;
 * assume the destination has enough room for escaping
 */
static int
strval2ADstr( struct berval *val, char *str, unsigned flags, ber_len_t *len )
{
	ber_len_t	s, d;

	assert( val );
	assert( str );
	assert( len );

	if ( val->bv_len == 0 ) {
		*len = 0;
		return( 0 );
	}

	if ( flags & LDAP_AVA_NONPRINTABLE ) {
		/*
		 * FIXME: Turn the value into a binary encoded BER?
		 */
		*len = 0;
		return( -1 );
		
	} else {

		/* 
		 * we assume the string has enough room for the hex encoding
		 * of the value
		 */

		for ( s = 0, d = 0; s < val->bv_len; ) {
			if ( LDAP_DN_NEEDESCAPE_AD( val->bv_val[ s ] ) ) {
				str[ d++ ] = '\\';
			}
			str[ d++ ] = val->bv_val[ s++ ];
		}
	}

	*len = d;
	
	return( 0 );
}

/*
 * If the DN is terminated by single-AVA RDNs with attribute type of "dc",
 * the forst part of the AD representation of the DN is written in DNS
 * form, i.e. dot separated domain name components (as suggested 
 * by Luke Howard, http://www.padl.com/~lukeh)
 */
static int
dn2domain( LDAPDN *dn, char *str, int *iRDN )
{
	int 		i;
	int		domain = 0, first = 1;
	ber_len_t	l = 1; /* we move the null also */

	/* we are guaranteed there's enough memory in str */

	/* sanity */
	assert( dn );
	assert( str );
	assert( iRDN );
	assert( *iRDN > 0 );

	for ( i = *iRDN; i >= 0; i-- ) {
		LDAPRDN		*rdn;
		LDAPAVA		*ava;

		assert( dn[ i ][ 0 ] );
		rdn = dn[ i ][ 0 ];

		assert( rdn[ 0 ][ 0 ] );
		ava = rdn[ 0 ][ 0 ];

		if ( !LDAP_DN_IS_RDN_DC( rdn ) ) {
			break;
		}

		domain = 1;
		
		if ( first ) {
			first = 0;
			AC_MEMCPY( str, ava->la_value->bv_val, 
					ava->la_value->bv_len + 1);
			l += ava->la_value->bv_len;

		} else {
			AC_MEMCPY( str + ava->la_value->bv_len + 1, str, l);
			AC_MEMCPY( str, ava->la_value->bv_val, 
					ava->la_value->bv_len );
			str[ ava->la_value->bv_len ] = '.';
			l += ava->la_value->bv_len + 1;
		}
	}

	*iRDN = i;

	return( domain );
}

static int
rdn2strlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len,
	 int ( *s2l )( struct berval *v, unsigned f, ber_len_t *l ) )
{
	int		iAVA;
	ber_len_t	l = 0;

	*len = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		/* len(type) + '=' + '+' | ',' */
		l += ava->la_attr->bv_len + 2;

		if ( ava->la_flags & LDAP_AVA_BINARY ) {
			/* octothorpe + twice the length */
			l += 1 + 2 * ava->la_value->bv_len;

		} else {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;
			
			if ( ( *s2l )( ava->la_value, f, &vl ) ) {
				return( -1 );
			}
			l += vl;
		}
	}
	
	*len = l;
	
	return( 0 );
}

static int
rdn2str( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len,
	int ( *s2s ) ( struct berval *v, char * s, unsigned f, ber_len_t *l ) )
{
	int		iAVA;
	ber_len_t	l = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		AC_MEMCPY( &str[ l ], ava->la_attr->bv_val, 
				ava->la_attr->bv_len );
		l += ava->la_attr->bv_len;

		str[ l++ ] = '=';

		if ( ava->la_flags & LDAP_AVA_BINARY ) {
			str[ l++ ] = '#';
			if ( binval2hexstr( ava->la_value, &str[ l ] ) ) {
				return( -1 );
			}
			l += 2 * ava->la_value->bv_len;

		} else {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;

			if ( ( *s2s )( ava->la_value, &str[ l ], f, &vl ) ) {
				return( -1 );
			}
			l += vl;
		}
		str[ l++ ] = ( rdn[ iAVA + 1 ] ? '+' : ',' );
	}

	*len = l;

	return( 0 );
}

static int
rdn2DCEstrlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len )
{
	int		iAVA;
	ber_len_t	l = 0;

	*len = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		/* len(type) + '=' + ',' | '/' */
		l += ava->la_attr->bv_len + 2;

		switch ( ava->la_flags ) {
		case LDAP_AVA_BINARY:
			/* octothorpe + twice the length */
			l += 1 + 2 * ava->la_value->bv_len;
			break;

		case LDAP_AVA_STRING: {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;
			
			if ( strval2DCEstrlen( ava->la_value, f, &vl ) ) {
				return( -1 );
			}
			l += vl;
			break;
		}

		default:
			return( -1 );
		}
	}
	
	*len = l;
	
	return( 0 );
}

static int
rdn2DCEstr( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len, int first )
{
	int		iAVA;
	ber_len_t	l = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		if ( first ) {
			first = 0;
		} else {
			str[ l++ ] = ( iAVA ? ',' : '/' );
		}

		AC_MEMCPY( &str[ l ], ava->la_attr->bv_val, 
				ava->la_attr->bv_len );
		l += ava->la_attr->bv_len;

		str[ l++ ] = '=';

		switch ( ava->la_flags ) {
			case LDAP_AVA_BINARY:
			str[ l++ ] = '#';
			if ( binval2hexstr( ava->la_value, &str[ l ] ) ) {
				return( -1 );
			}
			l += 2 * ava->la_value->bv_len;
			break;

		case LDAP_AVA_STRING: {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;

			if ( strval2DCEstr( ava->la_value, &str[ l ], f, &vl ) ) {
				return( -1 );
			}
			l += vl;
			break;
		}
				      
		default:
			return( -1 );
		}
	}

	*len = l;

	return( 0 );
}

static int
rdn2UFNstrlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len )
{
	int		iAVA;
	ber_len_t	l = 0;

	assert( rdn );
	assert( len );

	*len = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		/* ' + ' | ', ' */
		l += ( rdn[ iAVA + 1 ] ? 3 : 2 );

		/* FIXME: are binary values allowed in UFN? */
		if ( ava->la_flags & LDAP_AVA_BINARY ) {
			/* octothorpe + twice the value */
			l += 1 + 2 * ava->la_value->bv_len;

		} else {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;

			if ( strval2strlen( ava->la_value, f, &vl ) ) {
				return( -1 );
			}
			l += vl;
		}
	}
	
	*len = l;
	
	return( 0 );
}

static int
rdn2UFNstr( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len )
{
	int		iAVA;
	ber_len_t	l = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		if ( ava->la_flags & LDAP_AVA_BINARY ) {
			str[ l++ ] = '#';
			if ( binval2hexstr( ava->la_value, &str[ l ] ) ) {
				return( -1 );
			}
			l += 2 * ava->la_value->bv_len;
			
		} else {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;
			
			if ( strval2str( ava->la_value, &str[ l ], f, &vl ) ) {
				return( -1 );
			}
			l += vl;
		}

		if ( rdn[ iAVA + 1 ]) {
			AC_MEMCPY( &str[ l ], " + ", 3 );
			l += 3;

		} else {
			AC_MEMCPY( &str[ l ], ", ", 2 );
			l += 2;
		}
	}

	*len = l;

	return( 0 );
}

static int
rdn2ADstrlen( LDAPRDN *rdn, unsigned flags, ber_len_t *len )
{
	int		iAVA;
	ber_len_t	l = 0;

	assert( rdn );
	assert( len );

	*len = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		/* ',' | '/' */
		l++;

		/* FIXME: are binary values allowed in UFN? */
		switch ( ava->la_flags ) {
		case LDAP_AVA_BINARY:
			/* octothorpe + twice the value */
			l += 1 + 2 * ava->la_value->bv_len;
			break;

		case LDAP_AVA_STRING: {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;

			if ( strval2ADstrlen( ava->la_value, f, &vl ) ) {
				return( -1 );
			}
			l += vl;
			break;
		}

		default:
			return( -1 );
		}
	}
	
	*len = l;
	
	return( 0 );
}

static int
rdn2ADstr( LDAPRDN *rdn, char *str, unsigned flags, ber_len_t *len, int first )
{
	int		iAVA;
	ber_len_t	l = 0;

	for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
		LDAPAVA 	*ava = rdn[ iAVA ][ 0 ];

		if ( first ) {
			first = 0;
		} else {
			str[ l++ ] = ( iAVA ? ',' : '/' );
		}

		switch ( ava->la_flags ) {
		case LDAP_AVA_BINARY:
			str[ l++ ] = '#';
			if ( binval2hexstr( ava->la_value, &str[ l ] ) ) {
				return( -1 );
			}
			l += 2 * ava->la_value->bv_len;
			break;
			
		case LDAP_AVA_STRING: {
			ber_len_t	vl;
			unsigned	f = flags | ava->la_flags;
			
			if ( strval2ADstr( ava->la_value, &str[ l ], f, &vl ) ) {
				return( -1 );
			}
			l += vl;
			break;
		}

		default:
			return( -1 );
		}
	}

	*len = l;

	return( 0 );
}

/*
 * ldap_rdn2str
 *
 * Returns in str a string representation of rdn based on flags.
 * There is some duplication of code between this and ldap_dn2str;
 * this is wanted to reduce the allocation of temporary buffers.
 */
int
ldap_rdn2str( LDAPRDN *rdn, char **str, unsigned flags )
{
	int		rc, back;
	ber_len_t	l;
	
	assert( str );

	if ( rdn == NULL ) {
		*str = LDAP_STRDUP( "" );
		return( LDAP_SUCCESS );
	}

	/*
	 * This routine wastes "back" bytes at the end of the string
	 */

	*str = NULL;
	switch ( LDAP_DN_FORMAT( flags ) ) {
	case LDAP_DN_FORMAT_LDAPV3:
		if ( rdn2strlen( rdn, flags, &l, strval2strlen ) ) {
			return( LDAP_OTHER );
		}
		break;

	case LDAP_DN_FORMAT_LDAPV2:
		if ( rdn2strlen( rdn, flags, &l, strval2IA5strlen ) ) {
			return( LDAP_OTHER );
		}
		break;

	case LDAP_DN_FORMAT_UFN:
		if ( rdn2UFNstrlen( rdn, flags, &l ) ) {
			return( LDAP_OTHER );
		}
		break;

	case LDAP_DN_FORMAT_DCE:
		if ( rdn2DCEstrlen( rdn, flags, &l ) ) {
			return( LDAP_OTHER );
		}
		break;

	case LDAP_DN_FORMAT_AD_CANONICAL:
		if ( rdn2ADstrlen( rdn, flags, &l ) ) {
			return( LDAP_OTHER );
		}
		break;

	default:
		return( LDAP_INVALID_DN_SYNTAX );
	}

	*str = LDAP_MALLOC( l + 1 );

	switch ( LDAP_DN_FORMAT( flags ) ) {
	case LDAP_DN_FORMAT_LDAPV3:
		rc = rdn2str( rdn, *str, flags, &l, strval2str );
		back = 1;
		break;

	case LDAP_DN_FORMAT_LDAPV2:
		rc = rdn2str( rdn, *str, flags, &l, strval2IA5str );
		back = 1;
		break;

	case LDAP_DN_FORMAT_UFN:
		rc = rdn2UFNstr( rdn, *str, flags, &l );
		back = 2;
		break;

	case LDAP_DN_FORMAT_DCE:
		rc = rdn2DCEstr( rdn, *str, flags, &l, 1 );
		back = 0;
		break;

	case LDAP_DN_FORMAT_AD_CANONICAL:
		rc = rdn2ADstr( rdn, *str, flags, &l, 1 );
		back = 0;
		break;

	default:
		/* need at least one of the previous */
		return( LDAP_OTHER );
	}

	if ( rc ) {
		ldap_memfree( *str );
		return( LDAP_OTHER );
	}

	( *str )[ l - back ] = '\0';

	return( LDAP_SUCCESS );
}

/*
 * Very bulk implementation; many optimizations can be performed
 *   - a NULL dn results in an empty string ""
 * 
 * FIXME: doubts
 *   a) what do we do if a UTF-8 string must be converted in LDAPv2?
 *      we must encode it in binary form ('#' + HEXPAIRs)
 *   b) does DCE/AD support UTF-8?
 *      no clue; don't think so.
 *   c) what do we do when binary values must be converted in UTF/DCE/AD?
 *      use binary encoded BER
 */ 
int ldap_dn2str( LDAPDN *dn, char **str, unsigned flags )
{
	int		iRDN;
	int		rc = LDAP_OTHER;
	ber_len_t	len, l;

	/* stringifying helpers for LDAPv3/LDAPv2 */
	int ( *sv2l ) ( struct berval *v, unsigned f, ber_len_t *l );
	int ( *sv2s ) ( struct berval *v, char *s, unsigned f, ber_len_t *l );

	assert( str );

	Debug( LDAP_DEBUG_TRACE, "=> ldap_dn2str(%u)\n%s%s", flags, "", "" );

	*str = NULL;

	/* 
	 * a null dn means an empty dn string 
	 * FIXME: better raise an error?
	 */
	if ( dn == NULL ) {
		*str = LDAP_STRDUP( "" );
		return( LDAP_SUCCESS );
	}

	switch ( LDAP_DN_FORMAT( flags ) ) {
	case LDAP_DN_FORMAT_LDAPV3:
		sv2l = strval2strlen;
		sv2s = strval2str;
		goto got_funcs;

	case LDAP_DN_FORMAT_LDAPV2:
		sv2l = strval2IA5strlen;
		sv2s = strval2IA5str;
got_funcs:
		
		for ( iRDN = 0, len = 0; dn[ iRDN ]; iRDN++ ) {
			ber_len_t	rdnl;
			LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
			if ( rdn2strlen( rdn, flags, &rdnl, sv2l ) ) {
				goto return_results;
			}

			len += rdnl;
		}

		if ( ( *str = LDAP_MALLOC( len + 1 ) ) == NULL ) {
			rc = LDAP_NO_MEMORY;
			break;
		}

		for ( l = 0, iRDN = 0; dn[ iRDN ]; iRDN++ ) {
			ber_len_t	rdnl;
			LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
			if ( rdn2str( rdn, &( *str )[ l ], flags, 
					&rdnl, sv2s ) ) {
				LDAP_FREE( *str );
				*str = NULL;
				goto return_results;
			}
			l += rdnl;
		}

		assert( l == len );

		/* 
		 * trim the last ',' (the allocated memory 
		 * is one byte longer than required)
		 */
		( *str )[ len - 1 ] = '\0';

		rc = LDAP_SUCCESS;
		break;

	case LDAP_DN_FORMAT_UFN: {

		/*
		 * FIXME: quoting from RFC 1781:
		 *
   To take a distinguished name, and generate a name of this format with
   attribute types omitted, the following steps are followed.

    1.  If the first attribute is of type CommonName, the type may be
	omitted.

    2.  If the last attribute is of type Country, the type may be
        omitted.

    3.  If the last attribute is of type Country, the last
        Organisation attribute may have the type omitted.

    4.  All attributes of type OrganisationalUnit may have the type
        omitted, unless they are after an Organisation attribute or
        the first attribute is of type OrganisationalUnit.

         * this should be the pedantic implementation.
		 *
		 * Here the standard implementation reflects
		 * the one historically provided by OpenLDAP
		 * (and UMIch, I presume), with the variant
		 * of spaces and plusses (' + ') separating 
		 * rdn components.
		 * 
		 * A non-standard but nice implementation could
		 * be to turn the  final "dc" attributes into a 
		 * dot-separated domain.
		 *
		 * Other improvements could involve the use of
		 * friendly country names and so.
		 */
#ifdef DC_IN_UFN
		int	leftmost_dc = -1;
		int	last_iRDN = -1;
#endif /* DC_IN_UFN */

		for ( iRDN = 0, len = 0; dn[ iRDN ]; iRDN++ ) {
			ber_len_t	rdnl;
			LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
			if ( rdn2UFNstrlen( rdn, flags, &rdnl ) ) {
				goto return_results;
			}
			len += rdnl;

#ifdef DC_IN_UFN
			if ( LDAP_DN_IS_RDN_DC( rdn ) ) {
				if ( leftmost_dc == -1 ) {
					leftmost_dc = iRDN;
				}
			} else {
				leftmost_dc = -1;
			}
#endif /* DC_IN_UFN */
		}

		if ( ( *str = LDAP_MALLOC( len + 1 ) ) == NULL ) {
			rc = LDAP_NO_MEMORY;
			break;
		}

#ifdef DC_IN_UFN
		if ( leftmost_dc == -1 ) {
#endif /* DC_IN_UFN */
			for ( l = 0, iRDN = 0; dn[ iRDN ]; iRDN++ ) {
				ber_len_t	vl;
				LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
				if ( rdn2UFNstr( rdn, &( *str )[ l ], 
						flags, &vl ) ) {
					LDAP_FREE( *str );
					*str = NULL;
					goto return_results;
				}
				l += vl;
			}

			/* 
			 * trim the last ', ' (the allocated memory 
			 * is two bytes longer than required)
			 */
			( *str )[ len - 2 ] = '\0';
#ifdef DC_IN_UFN
		} else {
			last_iRDN = iRDN - 1;

			for ( l = 0, iRDN = 0; iRDN < leftmost_dc; iRDN++ ) {
				ber_len_t	vl;
				LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
				if ( rdn2UFNstr( rdn, &( *str )[ l ], 
						flags, &vl ) ) {
					LDAP_FREE( *str );
					*str = NULL;
					goto return_results;
				}
				l += vl;
			}

			if ( !dn2domain( dn, &( *str )[ l ], &last_iRDN ) ) {
				LDAP_FREE( *str );
				*str = NULL;
				goto return_results;
			}

			/* the string is correctly terminated by dn2domain */
		}
#endif /* DC_IN_UFN */
		
		rc = LDAP_SUCCESS;
		break;
	}

	case LDAP_DN_FORMAT_DCE:

		for ( iRDN = 0, len = 0; dn[ iRDN ]; iRDN++ ) {
			ber_len_t	rdnl;
			LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
			if ( rdn2DCEstrlen( rdn, flags, &rdnl ) ) {
				goto return_results;
			}

			len += rdnl;
		}

		if ( ( *str = LDAP_MALLOC( len + 1 ) ) == NULL ) {
			rc = LDAP_NO_MEMORY;
			break;
		}

		for ( l = 0; iRDN--; ) {
			ber_len_t	rdnl;
			LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
			if ( rdn2DCEstr( rdn, &( *str )[ l ], flags, 
					&rdnl, 0 ) ) {
				LDAP_FREE( *str );
				*str = NULL;
				goto return_results;
			}
			l += rdnl;
		}

		assert( l == len );

		( *str )[ len ] = '\0';

		rc = LDAP_SUCCESS;
		break;

	case LDAP_DN_FORMAT_AD_CANONICAL: {
		
		/*
		 * Sort of UFN for DCE DNs: a slash ('/') separated
		 * global->local DN with no types; strictly speaking,
		 * the naming context should be a domain, which is
		 * written in DNS-style, e.g. dot-deparated.
		 * 
		 * Example:
		 * 
		 * 	"givenName=Bill+sn=Gates,ou=People,dc=microsoft,dc=com"
		 *
		 * will read
		 * 
		 * 	"microsoft.com/People/Bill,Gates"
		 */ 
		for ( iRDN = 0, len = -1; dn[ iRDN ]; iRDN++ ) {
			ber_len_t	rdnl;
			LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
			if ( rdn2ADstrlen( rdn, flags, &rdnl ) ) {
				goto return_results;
			}

			len += rdnl;
		}

		if ( ( *str = LDAP_MALLOC( len + 1 ) ) == NULL ) {
			rc = LDAP_NO_MEMORY;
			break;
		}

		iRDN--;
		if ( iRDN && dn2domain( dn, *str, &iRDN ) ) {
			for ( l = strlen( *str ); iRDN >= 0 ; iRDN-- ) {
				ber_len_t	rdnl;
				LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
				if ( rdn2ADstr( rdn, &( *str )[ l ], 
						flags, &rdnl, 0 ) ) {
					LDAP_FREE( *str );
					*str = NULL;
					goto return_results;
				}
				l += rdnl;
			}

		} else {
			int		first = 1;

			/*
			 * Strictly speaking, AD canonical requires
			 * a DN to be in the form "..., dc=smtg",
			 * i.e. terminated by a domain component
			 */
			if ( flags & LDAP_DN_PEDANTIC ) {
				LDAP_FREE( *str );
				*str = NULL;
				rc = LDAP_INVALID_DN_SYNTAX;
				break;
			}

			for ( l = 0; iRDN >= 0 ; iRDN-- ) {
				ber_len_t	rdnl;
				LDAPRDN		*rdn = dn[ iRDN ][ 0 ];
			
				if ( rdn2ADstr( rdn, &( *str )[ l ], 
						flags, &rdnl, first ) ) {
					LDAP_FREE( *str );
					*str = NULL;
					goto return_results;
				}
				if ( first ) {
					first = 0;
				}
				l += rdnl;
			}
		}

		( *str )[ len ] = '\0';

		rc = LDAP_SUCCESS;
		break;
	}

	default:
		return( LDAP_INVALID_DN_SYNTAX );

	}

	Debug( LDAP_DEBUG_TRACE, "<= ldap_dn2str(%s,%u)=%d\n", *str, flags, rc );
return_results:;
	return( rc );
}

