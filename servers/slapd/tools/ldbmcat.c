#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "ldbm.h"
#include "../slap.h"

static void
usage( char *name )
{
        fprintf( stderr, "usage: %s [-n] <filename>\n", name );
        exit( 1 );
}

int
main( int argc, char **argv )
{
        Datum                key, last, data;
        LDBM                dbp;
        int                rc, type;
        long                id;
        char                *file, *s;
        int                printid = 1;

#ifdef HAVE_BERKELEY_DB2
        DBC        *cursorp;

        ldbm_datum_init( key );
        ldbm_datum_init( last );
        ldbm_datum_init( data );
#endif

        if ( argc < 2 || argc > 3 || ( argc == 3 && strcmp( argv[1], "-n" )
            != 0 )) {
                usage( argv[0] );
        }
        if ( argc == 3 && strcmp( argv[1], "-n" ) == 0 ) {
                printid = 0;
                file = argv[2];
        } else {
                file = argv[1];
        }

        if ( (dbp = ldbm_open( file, LDBM_READER, 0, 0 )) == NULL ) {
                perror( file );
                exit ( 1 );
        }

        last.dptr = NULL;

#ifdef HAVE_BERKELEY_DB2
        for ( key = ldbm_firstkey( dbp, &cursorp ); key.dptr != NULL;
            key = ldbm_nextkey( dbp, last, cursorp ) )
#else
        for ( key = ldbm_firstkey( dbp ); key.dptr != NULL;
            key = ldbm_nextkey( dbp, last ) )
#endif
        {
                if ( last.dptr != NULL )
                        ldbm_datum_free( dbp, last );
                data = ldbm_fetch( dbp, key );

                if (( s = data.dptr ) != NULL ) {

                    if ( !printid && isdigit( *s )) {
                        if (( s = strchr( s, '\n' )) != NULL ) {
                                ++s;
                        }
                    }
                    if ( s != NULL ) {
                        puts( s );
                    }

                    if ( data.dptr != NULL ) {
                        ldbm_datum_free( dbp, data );
                    }

                }

                last = key;
        }
        if ( last.dptr != NULL )
                ldbm_datum_free( dbp, last );
        ldbm_close( dbp );

        exit( 0 );
}
