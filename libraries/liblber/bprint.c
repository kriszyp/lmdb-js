
#include "portable.h"

#include <stdio.h>

#if defined( LDAP_DEBUG ) && defined( LDAP_LIBUI )
#include <ac/ctype.h>
#endif /* LDAP_DEBUG && LDAP_LIBUI  */
#include <ac/string.h>

#include "lber-int.h"

/*
 * Print stuff
 */
void
ber_print_error( char *data)
{
	fputs( data, stderr );
	fflush( stderr );
}

/*
 * Print arbitrary stuff, for debugging.
 */

void
ber_bprint( char *data, int len )
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
		char data[128 + BPLEN];
	    sprintf( data, "\t%s\n", out );
		ber_print_error(data);
	    memset( out, 0, BPLEN );
	    i = 0;
	    continue;
	}
	out[ i++ ] = ' ';
    }

#endif /* LDAP_DEBUG && LDAP_LIBUI  */
}

