/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdlib.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

char *
(ldap_pvt_strdup)( const char *s )
{
        char    *p;
	int	len;
	len = strlen( s ) + 1;
        if ( (p = (char *) malloc( len )) == NULL )
                return( (char *)0 );

        memcpy( p, s, len );

        return( p );
}
