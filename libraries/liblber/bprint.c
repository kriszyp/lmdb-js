
#include "portable.h"

#if defined( LDAP_DEBUG ) && defined( LDAP_LIBUI )
#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#endif /* LDAP_DEBUG && LDAP_LIBUI  */

#include "lber.h"

/*
 * Print arbitrary stuff, for debugging.
 */


void
lber_bprint( char *data, int len )
{
#if defined( LDAP_DEBUG ) && defined( LDAP_LIBUI )
#define BPLEN	48

    static char	hexdig[] = "0123456789abcdef";
    char	out[ BPLEN ];
    int		i = 0;

    memset( out, 0, BPLEN );
    for ( ;; ) {
	if ( len < 1 ) {
	    fprintf( stderr, "\t%s\n", ( i == 0 ) ? "(end)" : out );
	    break;
	}

#ifndef HEX
	if ( isgraph( (unsigned char)*data )) {
	    out[ i ] = ' ';
	    out[ i+1 ] = *data;
	} else {
#endif
	    out[ i ] = hexdig[ ( *data & 0xf0 ) >> 4 ];
	    out[ i+1 ] = hexdig[ *data & 0x0f ];
#ifndef HEX
	}
#endif
	i += 2;
	len--;
	data++;

	if ( i > BPLEN - 2 ) {
	    fprintf( stderr, "\t%s\n", out );
	    memset( out, 0, BPLEN );
	    i = 0;
	    continue;
	}
	out[ i++ ] = ' ';
    }

#endif /* LDAP_DEBUG && LDAP_LIBUI  */
}

