#if defined( ultrix ) || defined( nextstep )

#include <string.h>


char *strdup( char *s )
{
        char    *p;

        if ( (p = (char *) malloc( strlen( s ) + 1 )) == NULL )
                return( NULL );

        strcpy( p, s );

        return( p );
}

#endif /* ultrix || nextstep */
