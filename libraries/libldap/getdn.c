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

#define NAME_TYPE_LDAP_RDN	0
#define NAME_TYPE_LDAP_DN	1
#define NAME_TYPE_DCE_DN	2

static char **explode_name( const char *name, int notypes, int is_type );

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

char *
ldap_dn2ufn( LDAP_CONST char *dn )
{
	char	*p, *ufn, *r;
	int	state;

	Debug( LDAP_DEBUG_TRACE, "ldap_dn2ufn\n", 0, 0, 0 );

	if( dn == NULL ) {
		return NULL;
	}

	if ( ldap_is_dns_dn( dn ) ||
		( p = ldap_utf8_strpbrk( dn, "=" ) ) == NULL )
	{
		return( LDAP_STRDUP( dn ) );
	}

	ufn = LDAP_STRDUP( ++p );

	if( ufn == NULL ) return NULL;

#define INQUOTE		1
#define OUTQUOTE	2
	state = OUTQUOTE;
	for ( p = ufn, r = ufn; *p; LDAP_UTF8_INCR(p) ) {
		switch ( *p ) {
		case '\\':
			if ( p[1] != '\0' ) {
				*r++ = '\\';
				LDAP_UTF8_COPY(r,++p);
				LDAP_UTF8_INCR(r);
			}
			break;

		case '"':
			if ( state == INQUOTE )
				state = OUTQUOTE;
			else
				state = INQUOTE;
			*r++ = *p;
			break;

		case ';':
		case ',':
			if ( state == OUTQUOTE )
				*r++ = ',';
			else
				*r++ = *p;
			break;

		case '=':
			if ( state == INQUOTE ) {
				*r++ = *p;
			} else {
				char	*rsave = r;

				*r = '\0';
				LDAP_UTF8_DECR( r );

				while ( !ldap_utf8_isspace( r )
					&& *r != ';' && *r != ',' && r > ufn )
				{
					LDAP_UTF8_DECR( r );
				}
				LDAP_UTF8_INCR( r );

				if ( strcasecmp( r, "c" )
				    && strcasecmp( r, "o" )
				    && strcasecmp( r, "ou" )
				    && strcasecmp( r, "st" )
				    && strcasecmp( r, "l" )
				    && strcasecmp( r, "cn" ) ) {
					r = rsave;
					*r++ = '=';
				}
			}
			break;

		default:
			LDAP_UTF8_COPY(r, p);
			LDAP_UTF8_INCR(r);
			break;
		}
	}
	*r = '\0';

	return( ufn );
}

char **
ldap_explode_dns( LDAP_CONST char *dn_in )
{
	char	*s;
	char	**rdns;
   	char    *tok_r;
	char	*dn;

	int ncomps;
	int maxcomps = 8;

	if ( (dn = LDAP_STRDUP( dn_in )) == NULL ) {
		return( NULL );
	}

	if ( (rdns = (char **) LDAP_MALLOC( maxcomps * sizeof(char *) )) == NULL ) {
		LDAP_FREE( dn );
		return( NULL );
	}

	ncomps = 0;
	for ( s = ldap_pvt_strtok( dn, "@.", &tok_r ); s != NULL; 
	      s = ldap_pvt_strtok( NULL, "@.", &tok_r ) )
	{
		if ( ncomps == maxcomps ) {
			maxcomps *= 2;
			if ( (rdns = (char **) LDAP_REALLOC( rdns, maxcomps *
			    sizeof(char *) )) == NULL )
			{
				LDAP_FREE( dn );
				return NULL;
			}
		}
		rdns[ncomps++] = LDAP_STRDUP( s );
	}
	LDAP_FREE(dn);

	rdns[ncomps] = NULL;

	/* trim rdns */
	rdns = (char **) LDAP_REALLOC( rdns, (ncomps+1) * sizeof(char*) );
	return( rdns );
}

char **
ldap_explode_dn( LDAP_CONST char *dn, int notypes )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_dn\n", 0, 0, 0 );

	if ( ldap_is_dns_dn( dn ) ) {
		return( ldap_explode_dns( dn ) );
	}
	return explode_name( dn, notypes, NAME_TYPE_LDAP_DN );
}

char **
ldap_explode_rdn( LDAP_CONST char *rdn, int notypes )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_rdn\n", 0, 0, 0 );
	return explode_name( rdn, notypes, NAME_TYPE_LDAP_RDN );
}

char *
ldap_dn2dcedn( LDAP_CONST char *dn )
{
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
}

char *
ldap_dcedn2dn( LDAP_CONST char *dce )
{
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
}

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
				   	SAFEMEMCPY( parts[ count-1 ], rdn, len );

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


int
ldap_is_dns_dn( LDAP_CONST char *dn )
{
	return dn[ 0 ] != '\0' && ldap_utf8_strpbrk( dn, "=,;" ) == NULL;
}

