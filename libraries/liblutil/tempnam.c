#include "portable.h"

#ifndef HAVE_TEMPNAM

#include <stdlib.h>
#include <stdlib.h>
#include <ac/string.h>
extern char *mktemp (char *);

#include "lutil.h"

char *
tempnam( char *dir, char *pfx )
{
    char	*s;

    if ( dir == NULL ) {
	dir = "/tmp";
    }

/*
 * allocate space for dir + '/' + pfx (up to 5 chars) + 6 trailing 'X's + 0 byte
 */
    if (( s = (char *)malloc( strlen( dir ) + 14 )) == NULL ) {
	return( NULL );
    }

    strcpy( s, dir );
    strcat( s, "/" );
    if ( pfx != NULL ) {
	strcat( s, pfx );
    }
    strcat( s, "XXXXXX" );
    mktemp( s );

    if ( *s == '\0' ) {
	free( s );
	s = NULL;
    }

    return( s );
}

#endif /* nextstep */
