/* charray.c - routines for dealing with char * arrays */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

void
charray_add(
    char	***a,
    char	*s
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

	(*a)[n++] = s;
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
		(*a)[n + i] = s[i];
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
    char	*s
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
		new[i] = strdup( a[i] );
	}
	new[i] = NULL;

	return( new );
}

char **
str2charray( char *str_in, char *brkstr )
{
	char	**res;
	char	*s;
	int	i;

	/* protect the input string from strtok */
	char *str = strdup( str_in );

	i = 1;
	for ( s = str; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			i++;
		}
	}

	res = (char **) ch_malloc( (i + 1) * sizeof(char *) );
	i = 0;
	for ( s = strtok( str, brkstr ); s != NULL; s = strtok( NULL,
	    brkstr ) ) {
		res[i++] = strdup( s );
	}
	res[i] = NULL;

	free( str );
	return( res );
}
