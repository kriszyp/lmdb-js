/* charray.c - routines for dealing with char * arrays */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

void
charray_add(
    char	***a,
    const char	*s
)
{
	int	n;

	if ( *a == NULL ) {
		*a = (char **) ch_malloc( 2 * sizeof(char *) );
		n = 0;
	} else {
		for ( n = 0; *a != NULL && (*a)[n] != NULL; n++ ) {
			;	/* NULL */
		}

		*a = (char **) ch_realloc( (char *) *a,
		    (n + 2) * sizeof(char *) );
	}

	(*a)[n++] = ch_strdup(s);
	(*a)[n] = NULL;
}

void
charray_merge(
    char	***a,
    char	**s
)
{
	int	i, n, nn;

	for ( n = 0; *a != NULL && (*a)[n] != NULL; n++ ) {
		;	/* NULL */
	}
	for ( nn = 0; s[nn] != NULL; nn++ ) {
		;	/* NULL */
	}

	*a = (char **) ch_realloc( (char *) *a, (n + nn + 1) * sizeof(char *) );

	for ( i = 0; i < nn; i++ ) {
		(*a)[n + i] = ch_strdup(s[i]);
	}
	(*a)[n + nn] = NULL;
}

void
charray_free( char **array )
{
	char	**a;

	if ( array == NULL ) {
		return;
	}

	for ( a = array; *a != NULL; a++ ) {
		if ( *a != NULL ) {
			free( *a );
		}
	}
	free( (char *) array );
}

int
charray_inlist(
    char	**a,
    const char	*s
)
{
	int	i;

	for ( i = 0; a[i] != NULL; i++ ) {
		if ( strcasecmp( s, a[i] ) == 0 ) {
			return( 1 );
		}
	}

	return( 0 );
}

char **
charray_dup( char **a )
{
	int	i;
	char	**new;

	for ( i = 0; a[i] != NULL; i++ )
		;	/* NULL */

	new = (char **) ch_malloc( (i + 1) * sizeof(char *) );

	for ( i = 0; a[i] != NULL; i++ ) {
		new[i] = ch_strdup( a[i] );
	}
	new[i] = NULL;

	return( new );
}


char *
charray2str( char **a )
{
	char *s;
	int i;
	size_t cur, len = 0;

	if( a == NULL ) return NULL;

	for( i=0 ; a[i] != NULL ; i++ ) {
		len += strlen( a[i] );
	}

	if( len == 0 ) return NULL;

	s = ch_malloc( len + 1 );

	cur = 0;
	for( i=0 ; a[i] != NULL ; i++ ) {
		len = strlen( a[i] );
		strncpy( &s[cur], a[i], len );
		cur += len;
	}
	s[len] = '\0';
	return s;
}


char **
str2charray( const char *str_in, const char *brkstr )
{
	char	*str;
	char	**res;
	char	*s;
	char	*lasts;
	int	i;

	/* protect the input string from strtok */
	str = ch_strdup( str_in );

	i = 1;
	for ( s = str; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			i++;
		}
	}

	res = (char **) ch_malloc( (i + 1) * sizeof(char *) );
	i = 0;

	for ( s = ldap_pvt_strtok( str, brkstr, &lasts );
		s != NULL;
		s = ldap_pvt_strtok( NULL, brkstr, &lasts ) )
	{
		res[i++] = ch_strdup( s );
	}

	res[i] = NULL;

	free( str );
	return( res );
}
