/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "ldbm.h"
#include "../slap.h"

static void
usage( char *name )
{
        fprintf( stderr, "usage: %s [-n] <filename>\n", name );
}

int
main( int argc, char **argv )
{
        Datum               key, data;
        LDBM                dbp;
        char                *file, *s;
        int                printid = 1;

#ifdef HAVE_BERKELEY_DB2
        DBC        *cursorp;
#endif

        ldbm_datum_init( key );
        ldbm_datum_init( data );

        if ( argc < 2 || argc > 3 || ( argc == 3 && strcmp( argv[1], "-n" )
            != 0 )) {
                usage( argv[0] );
				return EXIT_FAILURE;
        }
        if ( argc == 3 && strcmp( argv[1], "-n" ) == 0 ) {
                printid = 0;
                file = argv[2];
        } else {
                file = argv[1];
        }

        if ( (dbp = ldbm_open( file, LDBM_READER, 0, 0 )) == NULL ) {
                perror( file );
				return EXIT_FAILURE;
        }

#ifdef HAVE_BERKELEY_DB2
        for ( key = ldbm_firstkey( dbp, &cursorp ); key.dptr != NULL;
            key = ldbm_nextkey( dbp, key, cursorp ) )
#else
        for ( key = ldbm_firstkey( dbp ); key.dptr != NULL;
            key = ldbm_nextkey( dbp, key ) )
#endif
        {
                data = ldbm_fetch( dbp, key );

                if (( s = data.dptr ) != NULL ) {

                    if ( !printid && isdigit( (unsigned char) *s )) {
                        if (( s = strchr( s, '\n' )) != NULL ) {
                                ++s;
                        }
                    }
                    if ( s != NULL ) {
                        puts( s );
                    }

                    ldbm_datum_free( dbp, data );
				}
        }

        ldbm_close( dbp );

		return EXIT_SUCCESS;
}
