/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <ldap.h>

#include "ldif.h"

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-b] <attrtype>\n", name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	char	buf[BUFSIZ];
	char	*type, *out;
	int	len, binary = 0;

	if (argc < 2 || argc > 3 ) {
		usage( argv[0] );
	}
	if ( argc == 3 ) {
		if ( strcmp( argv[1], "-b" ) != 0 ) {
			usage( argv[0] );
		}
		binary = 1;
		type = argv[2];
	} else {
		if ( strcmp( argv[1], "-b" ) == 0 ) {
			usage( argv[0] );
		}
		type = argv[1];
	}

	/* if the -b flag was used, read single binary value from stdin */
	if ( binary ) {
		char	*val;
		int	nread, max, cur;

		if (( val = (char *) malloc( BUFSIZ )) == NULL ) {
			perror( "malloc" );
			return EXIT_FAILURE;
		}
		max = BUFSIZ;
		cur = 0;
		while ( (nread = read( 0, buf, BUFSIZ )) != 0 ) {
			if ( nread + cur > max ) {
				max += BUFSIZ;
				if (( val = (char *) realloc( val, max )) ==
				    NULL ) {
					perror( "realloc" );
					return EXIT_FAILURE;
				}
			}
			memcpy( val + cur, buf, nread );
			cur += nread;
		}

		if (( out = ldif_put( LDIF_PUT_BINARY, type, val, cur )) == NULL ) {
		    perror( "ldif_type_and_value" );
			return EXIT_FAILURE;
		}

		fputs( out, stdout );
		ber_memfree( out );
		free( val );
		return EXIT_SUCCESS;
	}

	/* not binary:  one value per line... */
	while ( fgets( buf, sizeof(buf), stdin ) != NULL ) {
		if( buf[len=strlen(buf)] == '\n') buf[len] = '\0';

		if (( out = ldif_put( LDIF_PUT_VALUE, type, buf, strlen( buf ) ))
		    == NULL ) {
		    	perror( "ldif_type_and_value" );
			return EXIT_FAILURE;
		}
		fputs( out, stdout );
		ber_memfree( out );
	}

	return EXIT_SUCCESS;
}
