#include "portable.h"

#include <stdlib.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

char *(ldap_strdup)( const char *s )
{
        char    *p;

        if ( (p = (char *) malloc( strlen( s ) + 1 )) == NULL )
                return( (char *)0 );

        strcpy( p, s );

        return( p );
}
