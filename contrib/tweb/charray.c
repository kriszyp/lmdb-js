/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* charray.c..                                                              *
*                                                                          *
* Function:..Array-Handling-Functions                                      *
*                                                                          *
*            from LDAP3.2 University of Michigan                           *
*                                                                          *
*            Patch: NULL-Pointers are caught in Arrays/Strings             *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            April 16 1996                Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            December 21 1998           ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: charray.c,v 1.6 1999/09/10 15:01:16 zrnsk01 Exp $
 *
 */

#include "tgeneral.h"
#include "charray_exp.h"
#include "ch_malloc_exp.h"

/* charray.c - routines for dealing with char * arrays */


PUBLIC void charray_add( a, s )
char	***a;
char	*s;
{
	int	n;

	if ( s == NULL )
		return;

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

	(*a)[n++] = strdup(s);
	(*a)[n] = NULL;
}
/* end of function: charray_add */

PUBLIC void charray_merge( a, s )
char	***a;
char	**s;
{
	int	i, n, nn;

	if ( s == NULL )
		return;

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
/* end of function: charray_merge */

PUBLIC void charray_free( array )
char **array;
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
/* end of function: charray_free */

PUBLIC int charray_inlist( a, s )
    char	**a;
    char	*s;
{
	int	i;

	if (( a == NULL ) || ( s == NULL ))
		return( 0 );

	for ( i = 0; a[i] != NULL; i++ ) {
		if ( strcasecmp( s, a[i] ) == 0 ) {
			return( 1 );
		}
	}

	return( 0 );
}
/* end of function: charray_inlist */

PUBLIC char ** charray_dup( a )
char **a;
{
	int	i;
	char	**new;

	if ( a == NULL )
		return( NULL );

	for ( i = 0; a[i] != NULL; i++ )
		;	/* NULL */

	new = (char **) ch_malloc( (i + 1) * sizeof(char *) );

	for ( i = 0; a[i] != NULL; i++ ) {
		new[i] = strdup( a[i] );
	}
	new[i] = NULL;

	return( new );
}
/* end of function: charray_dup */

PUBLIC char ** str2charray( str, brkstr )
char *str;
char *brkstr;
{
	char	**res;
	char	*s;
	int	i;
	char *str1;

        if (( str == NULL ) || ( brkstr == NULL )) return( (char **) NULL );

	str1 = strdup(str);
	i = 1;
	for ( s = str1; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			i++;
		}
	}

	res = (char **) ch_malloc( (i + 1) * sizeof(char *) );
	i = 0;
	for ( s = strtok( str1, brkstr ); s != NULL; s = strtok( NULL,
	    brkstr ) ) {
		res[i++] = strdup( s );
	}
	res[i] = NULL;

	free(str1);
	return( res );
}
/* end of function: str2charray */
