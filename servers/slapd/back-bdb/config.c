/* config.c - ldbm backend configuration file routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

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
#ifndef NO_THREADS
		if ( argc < 3 ) {
			fprintf( stderr, "%s: line %d: "
				"missing parameters in \"lockDetect <policy> <seconds>\" line\n",
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

		} else {
			fprintf( stderr, "%s: line %d: "
				"bad policy (%s) in \"lockDetect <policy> <seconds>\" line\n",
				fname, lineno, argv[1] );
			return 1;
		}

		bdb->bi_lock_detect_seconds = strtol( argv[2], NULL, 0 );
		if( bdb->bi_lock_detect_seconds < 1 ) {
			fprintf( stderr, "%s: line %d: "
				"bad seconds (%s) in \"lockDetect <policy> <seconds>\" line\n",
				fname, lineno, argv[2] );
			return 1;
		}
#else
		fprintf( stderr, "%s: line %d: "
			"NO THREADS: lockDetect line ignored\n",
			fname, lineno );
#endif

	/* mode with which to create new database files */
	} else if ( strcasecmp( argv[0], "mode" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr, "%s: line %d: "
				"missing mode in \"mode <mode>\" line\n",
				fname, lineno );
			return 1;
		}
		bdb->bi_dbenv_mode = strtol( argv[1], NULL, 0 );

#if 0
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
		rc = attr_index_config( li, fname, lineno, argc - 1, &argv[1] );

		if( rc != LDAP_SUCCESS ) return 1;
#endif

	/* anything else */
	} else {
		fprintf( stderr, "%s: line %d: "
			"unknown directive \"%s\" in bdb database definition (ignored)\n",
			fname, lineno, argv[0] );
	}

	return 0;
}
