#include "portable.h"

#ifndef HAVE_STRDUP

#include <ac/string.h>

char *strdup( const char *s )
{
        char    *p;

        if ( (p = (char *) malloc( strlen( s ) + 1 )) == NULL )
                return( NULL );

        strcpy( p, s );

        return( p );
}

#endif /* !strdup */
