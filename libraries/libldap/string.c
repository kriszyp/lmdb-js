/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/ctype.h>

#include "ldap-int.h"


#if defined ( HAVE_STRSPN )
#define int_strspn strspn
#else
static int int_strspn( const char *str, const char *delim )
{
	int pos;
	const char *p=delim;

	for( pos=0; (*str) ; pos++,str++) {
		if (*str!=*p) {
			for( p=delim; (*p) ; p++ ) {
				if (*str==*p) {
					break;
				}
		  	}
		}

		if (*p=='\0') {
			return pos;
		}
	}
	return pos;
}
#endif

#if defined( HAVE_STRPBRK )
#define int_strpbrk strpbrk
#else
static char *(int_strpbrk)( const char *str, const char *accept )
{
	const char *p;

	for( ; (*str) ; str++ ) {
		for( p=accept; (*p) ; p++) {
			if (*str==*p) {
				return str;
			}
		}
	}

	return NULL;
}
#endif

char *(ldap_pvt_strtok)( char *str, const char *delim, char **pos )
{
	char *p;

	if (pos==NULL) {
		return NULL;
	}

	if (str==NULL) {
		if (*pos==NULL) {
			return NULL;
		}

		str=*pos;
	}

	/* skip any initial delimiters */
	str += int_strspn( str, delim );
	if (*str == '\0') {
		return NULL;
	}

	p = int_strpbrk( str, delim );
	if (p==NULL) {
		*pos = NULL;

	} else {
		*p ='\0';
		*pos = p+1;
	}

	return str;
}

char *
(ldap_pvt_strdup)( const char *s )
{
	char    *p;
	size_t	len = strlen( s ) + 1;

	if ( (p = (char *) malloc( len )) == NULL ) {
		return( NULL );
	}

	memcpy( p, s, len );
	return( p );
}

char *
ldap_pvt_str2upper( char *str )
{
	char    *s;

	/* to upper */
	for ( s = str; *s; s++ ) {
		*s = TOUPPER( (unsigned char) *s );
	}

	return( str );
}

char *
ldap_pvt_str2lower( char *str )
{
	char    *s;

	/* to lower */
	for ( s = str; *s; s++ ) {
		*s = TOLOWER( (unsigned char) *s );
	}

	return( str );
}
