/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

static char **explode_name( const char *name, int notypes, int is_dn );

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

	if ( ldap_is_dns_dn( dn ) ) {
		return( LDAP_STRDUP( dn ) );
	}

	ufn = LDAP_STRDUP( ++p );

#define INQUOTE		1
#define OUTQUOTE	2
	state = OUTQUOTE;
	for ( p = ufn, r = ufn; *p; p++ ) {
		switch ( *p ) {
		case '\\':
			if ( *++p == '\0' )
				p--;
			else {
				*r++ = '\\';
				*r++ = *p;
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
			if ( state == INQUOTE )
				*r++ = *p;
			else {
				char	*rsave = r;

				*r-- = '\0';
				while ( !isspace( (unsigned char) *r )
					&& *r != ';' && *r != ',' && r > ufn )
					r--;
				r++;

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
			*r++ = *p;
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
	return explode_name( dn, notypes, 1 );
}

char **
ldap_explode_rdn( LDAP_CONST char *rdn, int notypes )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_explode_rdn\n", 0, 0, 0 );
	return explode_name( rdn, notypes, 0 );
}

static char **
explode_name( const char *name, int notypes, int is_dn )
{
	const char *p, *q;
	char **parts = NULL;
	int	state, count = 0, endquote, len;

	p = name-1;
	state = OUTQUOTE;

	do {

		++p;
		switch ( *p ) {
		case '\\':
			if ( *++p == '\0' )
				p--;
			break;
		case '"':
			if ( state == INQUOTE )
				state = OUTQUOTE;
			else
				state = INQUOTE;
			break;
		case '+':
			if (!is_dn)
				goto end_part;
			break;
		case ';':
		case ',':
			if (!is_dn)
				break;
			goto end_part;
		case '\0':
		end_part:
			if ( state == OUTQUOTE ) {
				++count;
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
					for ( q = name;
					    q < p && *q != '='; ++q ) {
						;
					}
					if ( q < p ) {
						name = ++q;
					}
					if ( *name == '"' ) {
						++name;
					}
					
					if ( *(p-1) == '"' ) {
						endquote = 1;
						--p;
					}
				}

				len = p - name;
				if (( parts[ count-1 ] = (char *)LDAP_CALLOC( 1,
				    len + 1 )) != NULL ) {
				    	SAFEMEMCPY( parts[ count-1 ], name,
					    len );
					parts[ count-1 ][ len ] = '\0';
				}

				/*
				 *  Don't forget to increment 'p' back to where
				 *  it should be.  If we don't, then we will
				 *  never get past an "end quote."
				 */
				if ( endquote == 1 )
					p++;

				name = *p ? p + 1 : p;
				while ( isascii( *name ) && isspace( *name ) )
					++name;
			}
			break;
		}
	} while ( *p );

	return( parts );
}


int
ldap_is_dns_dn( LDAP_CONST char *dn )
{
	return( dn[ 0 ] != '\0'
		&& strchr( dn, '=' ) == NULL
		&& strchr( dn, ',' ) == NULL
		&& strchr( dn, ';' ) == NULL );
}

