/* config.c - bdb backend configuration file routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

#ifdef DB_DIRTY_READ
#	define	SLAP_BDB_ALLOW_DIRTY_READ
#endif

int
bdb_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char	**argv )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	if ( bdb == NULL ) {
		fprintf( stderr, "%s: line %d: "
			"bdb database info is null!\n",
			fname, lineno );
		return 1;
	}

	/* directory is the DB_HOME */
	if ( strcasecmp( argv[0], "directory" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr, "%s: line %d: "
				"missing dir in \"directory <dir>\" line\n",
				fname, lineno );
			return 1;
		}
		if ( bdb->bi_dbenv_home ) {
			free( bdb->bi_dbenv_home );
		}
		bdb->bi_dbenv_home = ch_strdup( argv[1] );

#ifdef SLAP_BDB_ALLOW_DIRTY_READ
	} else if ( strcasecmp( argv[0], "dirtyread" ) == 0 ) {
		bdb->bi_db_opflags |= DB_DIRTY_READ;
#endif
	/* transaction checkpoint configuration */
	} else if ( strcasecmp( argv[0], "dbnosync" ) == 0 ) {
		bdb->bi_dbenv_xflags |= DB_TXN_NOSYNC;

	/* transaction checkpoint configuration */
	} else if ( strcasecmp( argv[0], "checkpoint" ) == 0 ) {
		if ( argc < 3 ) {
			fprintf( stderr, "%s: line %d: "
				"missing parameters in \"checkpoint <kbyte> <min>\" line\n",
				fname, lineno );
			return 1;
		}
		bdb->bi_txn_cp = 1;
		bdb->bi_txn_cp_kbyte = strtol( argv[1], NULL, 0 );
		bdb->bi_txn_cp_min = strtol( argv[2], NULL, 0 );

	/* lock detect configuration */
	} else if ( strcasecmp( argv[0], "lockdetect" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr, "%s: line %d: "
				"missing parameters in \"lockDetect <policy>\" line\n",
				fname, lineno );
			return 1;
		}

		if( strcasecmp( argv[1], "default" ) == 0 ) {
			bdb->bi_lock_detect = DB_LOCK_DEFAULT;

		} else if( strcasecmp( argv[1], "oldest" ) == 0 ) {
			bdb->bi_lock_detect = DB_LOCK_OLDEST;

		} else if( strcasecmp( argv[1], "random" ) == 0 ) {
			bdb->bi_lock_detect = DB_LOCK_RANDOM;

		} else if( strcasecmp( argv[1], "youngest" ) == 0 ) {
			bdb->bi_lock_detect = DB_LOCK_YOUNGEST;

		} else if( strcasecmp( argv[1], "fewest" ) == 0 ) {
			bdb->bi_lock_detect = DB_LOCK_MINLOCKS;

		} else {
			fprintf( stderr, "%s: line %d: "
				"bad policy (%s) in \"lockDetect <policy>\" line\n",
				fname, lineno, argv[1] );
			return 1;
		}

	/* mode with which to create new database files */
	} else if ( strcasecmp( argv[0], "mode" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr, "%s: line %d: "
				"missing mode in \"mode <mode>\" line\n",
				fname, lineno );
			return 1;
		}
		bdb->bi_dbenv_mode = strtol( argv[1], NULL, 0 );

	/* attribute to index */
	} else if ( strcasecmp( argv[0], "index" ) == 0 ) {
		int rc;
		if ( argc < 2 ) {
			fprintf( stderr, "%s: line %d: "
				"missing attr in \"index <attr> [pres,eq,approx,sub]\" line\n",
				fname, lineno );
			return 1;
		} else if ( argc > 3 ) {
			fprintf( stderr, "%s: line %d: "
				"extra junk after \"index <attr> [pres,eq,approx,sub]\" "
				"line (ignored)\n",
				fname, lineno );
		}
		rc = bdb_attr_index_config( bdb, fname, lineno, argc - 1, &argv[1] );

		if( rc != LDAP_SUCCESS ) return 1;

	/* size of the cache in entries */
        } else if ( strcasecmp( argv[0], "cachesize" ) == 0 ) {
                 if ( argc < 2 ) {
                         fprintf( stderr,
                 "%s: line %d: missing size in \"cachesize <size>\" line\n",
                             fname, lineno );
                         return( 1 );
                 }
                 bdb->bi_cache.c_maxsize = atoi( argv[1] );

	/* depth of search stack cache in units of (IDL)s */
        } else if ( strcasecmp( argv[0], "searchstack" ) == 0 ) {
                 if ( argc < 2 ) {
                         fprintf( stderr,
                 "%s: line %d: missing depth in \"searchstack <depth>\" line\n",
                             fname, lineno );
                         return( 1 );
                 }
                 bdb->bi_search_stack_depth = atoi( argv[1] );

#ifdef SLAP_IDL_CACHE
	/* size of the IDL cache in entries */
        } else if ( strcasecmp( argv[0], "idlcachesize" ) == 0 ) {
                 if ( argc < 2 ) {
                         fprintf( stderr,
                 "%s: line %d: missing size in \"idlcachesize <size>\" line\n",
                             fname, lineno );
                         return( 1 );
                 }
                 bdb->bi_idl_cache_max_size = atoi( argv[1] );
#endif

	/* anything else */
	} else {
		fprintf( stderr, "%s: line %d: "
			"unknown directive \"%s\" in bdb database definition (ignored)\n",
			fname, lineno, argv[0] );
	}

	return 0;
}
