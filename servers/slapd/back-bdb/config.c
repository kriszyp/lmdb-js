/* config.c - bdb backend configuration file routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

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
	/* transaction logging configuration */
	} else if ( strcasecmp( argv[0], "dbnosync" ) == 0 ) {
		bdb->bi_dbenv_xflags |= DB_TXN_NOSYNC;

	/* slapadd/slapindex logging configuration */
	} else if ( strcasecmp( argv[0], "fasttool" ) == 0 ) {
		if ( slapMode & SLAP_TOOL_MODE )
		bdb->bi_dbenv_xflags |= DB_TXN_NOT_DURABLE;

	/* slapindex algorithm tuning */
	} else if ( strcasecmp( argv[0], "linearindex" ) == 0 ) {
		bdb->bi_linear_index = 1;

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

	/* unique key for shared memory regions */
	} else if ( strcasecmp( argv[0], "shm_key" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
				"%s: line %d: missing key in \"shm_key <key>\" line\n",
				fname, lineno );
			return( 1 );
		}
		bdb->bi_shm_key = atoi( argv[1] );

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
		if ( bdb->bi_search_stack_depth < MINIMUM_SEARCH_STACK_DEPTH ) {
			fprintf( stderr,
		"%s: line %d: depth %d too small, using %d\n",
			fname, lineno, bdb->bi_search_stack_depth,
			MINIMUM_SEARCH_STACK_DEPTH );
			bdb->bi_search_stack_depth = MINIMUM_SEARCH_STACK_DEPTH;
		}

	/* size of the IDL cache in entries */
	} else if ( strcasecmp( argv[0], "idlcachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
				"%s: line %d: missing size in \"idlcachesize <size>\" line\n",
				fname, lineno );
			return( 1 );
		}
		if ( !( slapMode & SLAP_TOOL_MODE ) )
			bdb->bi_idl_cache_max_size = atoi( argv[1] );
	} else if ( strcasecmp( argv[0], "sessionlog" ) == 0 ) {
		int se_id = 0, se_size = 0;
		struct slap_session_entry *sent;
		if ( argc < 3 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, CRIT,
				"%s: line %d: missing arguments in \"sessionlog <id> <size>\""
				" line.\n", fname, lineno , 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: missing arguments in \"sessionlog <id> <size>\""
				" line\n", fname, lineno, 0 );
#endif
			return( 1 );
		}

		se_id = atoi( argv[1] );

		if ( se_id < 0 || se_id > 999 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, CRIT,
				"%s: line %d: session log id %d is out of range [0..999]\n",
				fname, lineno , se_id );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: session log id %d is out of range [0..999]\n",
				fname, lineno , se_id );
#endif
			return( 1 );
		}

		se_size = atoi( argv[2] );
		if ( se_size < 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, CRIT,
				"%s: line %d: session log size %d is negative\n",
				fname, lineno , se_size );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: session log size %d is negative\n",
				fname, lineno , se_size );
#endif
			return( 1 );
		}

		LDAP_LIST_FOREACH( sent, &bdb->bi_session_list, se_link ) {
			if ( sent->se_id == se_id ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT,
					"%s: line %d: session %d already exists\n",
					fname, lineno , se_id );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: session %d already exists\n",
					fname, lineno , se_id );
#endif
				return( 1 );
			}
		}
		sent = (struct slap_session_entry *) ch_calloc( 1,
						sizeof( struct slap_session_entry ));
		sent->se_id = se_id;
		sent->se_size = se_size;
		LDAP_LIST_INSERT_HEAD( &bdb->bi_session_list, sent, se_link );

	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}
