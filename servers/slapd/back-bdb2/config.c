/* config.c - bdb2 backend configuration file routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"

static int
bdb2i_back_db_config_internal(
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
		return( 1 );
	}

	/* directory where database files live */
	if ( strcasecmp( argv[0], "directory" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing dir in \"directory <dir>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->li_directory = ch_strdup( argv[1] );

		li->li_nextid_file =
			ch_malloc( strlen(li->li_directory) + sizeof("/NEXTID") );

		strcpy(li->li_nextid_file, li->li_directory);
		strcat(li->li_nextid_file, "/NEXTID");

	/* mode with which to create new database files */
	} else if ( strcasecmp( argv[0], "mode" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
			"%s: line %d: missing mode in \"mode <mode>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->li_mode = strtol( argv[1], NULL, 0 );

	/* attribute to index */
	} else if ( strcasecmp( argv[0], "index" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
"%s: line %d: missing attr in \"index <attr> [pres,eq,approx,sub]\" line\n",
			    fname, lineno );
			return( 1 );
		} else if ( argc > 3 ) {
			fprintf( stderr,
"%s: line %d: extra junk after \"index <attr> [pres,eq,approx,sub]\" line (ignored)\n",
			    fname, lineno );
		}
		bdb2i_attr_index_config( li, fname, lineno, argc - 1, &argv[1], 0 );

	/* size of the cache in entries */
	} else if ( strcasecmp( argv[0], "cachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing size in \"cachesize <size>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->li_cache.c_maxsize = atoi( argv[1] );

	/* size of each dbcache in bytes */
	} else if ( strcasecmp( argv[0], "dbcachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing size in \"dbcachesize <size>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->li_dbcachesize = atoi( argv[1] );
		/*  we should at least have the suggested 128k  */
		if ( li->li_dbcachesize < DEFAULT_DBCACHE_SIZE )
			li->li_dbcachesize = DEFAULT_DBCACHE_SIZE;

	/* no write sync */
	} else if ( strcasecmp( argv[0], "dbcachenowsync" ) == 0 ) {
		li->li_dbcachewsync = 0;

	/* anything else */
	} else {
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in ldbm database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}

	return 0;
}


int
bdb2_back_db_config(
    Backend	*be,
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	ret = bdb2i_back_db_config_internal( be, fname, lineno, argc, argv );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "CONFIG elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}

	return( ret );
}


