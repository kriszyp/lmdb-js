#include "portable.h"

#ifndef HAVE_STRDUP

#include <stdlib.h>
#include <ac/string.h>
#include "lutil.h"

char *strdup( const char *s )
{
        char    *p;

        if ( (p = (char *) malloc( strlen( s ) + 1 )) == NULL )
                return( (char *)0 );

        strcpy( p, s );

        return( p );
}

#endif /* !strdup */
