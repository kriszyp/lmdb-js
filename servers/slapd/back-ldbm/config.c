/* config.c - ldbm backend configuration file routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"

void
ldbm_back_config(
    Backend	*be,
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: ldbm backend info is null!\n",
		    fname, lineno );
		exit( 1 );
	}

	/* directory where database files live */
	if ( strcasecmp( argv[0], "directory" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing dir in \"directory <dir>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		li->li_directory = strdup( argv[1] );

	/* mode with which to create new database files */
	} else if ( strcasecmp( argv[0], "mode" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
			"%s: line %d: missing mode in \"mode <mode>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		li->li_mode = strtol( argv[1], NULL, 0 );

	/* attribute to index */
	} else if ( strcasecmp( argv[0], "index" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
"%s: line %d: missing attr in \"index <attr> [pres,eq,approx,sub]\" line\n",
			    fname, lineno );
			exit( 1 );
		} else if ( argc > 3 ) {
			fprintf( stderr,
"%s: line %d: extra junk after \"index <attr> [pres,eq,approx,sub]\" line (ignored)\n",
			    fname, lineno );
		}
		attr_index_config( li, fname, lineno, argc - 1, &argv[1], 0 );

	/* size of the cache in entries */
	} else if ( strcasecmp( argv[0], "cachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing size in \"cachesize <size>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		li->li_cache.c_maxsize = atoi( argv[1] );

	/* size of each dbcache in bytes */
	} else if ( strcasecmp( argv[0], "dbcachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing size in \"dbcachesize <size>\" line\n",
			    fname, lineno );
			exit( 1 );
		}
		li->li_dbcachesize = atoi( argv[1] );

	/* no write sync */
	} else if ( strcasecmp( argv[0], "dbcachenowsync" ) == 0 ) {
		li->li_dbcachewsync = 0;

	/* anything else */
	} else {
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in ldbm database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}
}
