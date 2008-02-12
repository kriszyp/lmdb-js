/* config.c - ldbm backend configuration file routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "lutil.h"

int
ldbm_back_db_config(
    Backend	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int rc;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: ldbm database info is null!\n",
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
		if ( li->li_directory )
			free( li->li_directory );
		li->li_directory = ch_strdup( argv[1] );

	/* mode with which to create new database files */
	} else if ( strcasecmp( argv[0], "mode" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
			"%s: line %d: missing mode in \"mode <mode>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if ( lutil_atoix( &li->li_mode, argv[1], 0 ) != 0 ) {
			fprintf( stderr,
			"%s: line %d: unable to parse mode=\"%s\" in \"mode <mode>\" line\n",
			    fname, lineno, argv[1] );
			return( 1 );
		}

	/* attribute to index */
	} else if ( strcasecmp( argv[0], "index" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
"%s: line %d: missing attr in \"index <attr> [pres,eq,approx,sub]\" line\n",
			    fname, lineno );
			return( 1 );
		} else if ( argc > 3 ) {
			fprintf( stderr,
"%s: line %d: extra junk after \"index <attr> [pres,eq,approx,sub]\" line" SLAPD_CONF_UNKNOWN_IGNORED ".\n",
			    fname, lineno );
#ifdef SLAPD_CONF_UNKNOWN_BAILOUT
			return( 1 );
#endif /* SLAPD_CONF_UNKNOWN_BAILOUT */
		}
		rc = attr_index_config( li, fname, lineno, argc - 1, &argv[1] );

		if( rc != LDAP_SUCCESS ) return 1;

	/* size of the cache in entries */
	} else if ( strcasecmp( argv[0], "cachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing size in \"cachesize <size>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if ( lutil_atoi( &li->li_cache.c_maxsize, argv[1] ) != 0 ) {
			fprintf( stderr,
		"%s: line %d: unable to parse cachesize \"%s\"\n",
			    fname, lineno, argv[1] );
			return( 1 );
		}

	/* size of each dbcache in bytes */
	} else if ( strcasecmp( argv[0], "dbcachesize" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
		"%s: line %d: missing size in \"dbcachesize <size>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if ( lutil_atoi( &li->li_dbcachesize, argv[1] ) ) {
			fprintf( stderr,
		"%s: line %d: unable to parse dbcachesize \"%s\"\n",
			    fname, lineno, argv[1] );
			return( 1 );
		}

	/* no locking (not safe) */
	} else if ( strcasecmp( argv[0], "dbnolocking" ) == 0 ) {
		li->li_dblocking = 0;

	/* no write sync (not safe) */
	} else if ( ( strcasecmp( argv[0], "dbnosync" ) == 0 )
		|| ( strcasecmp( argv[0], "dbcachenowsync" ) == 0 ) )
	{
		li->li_dbwritesync = 0;

	/* run sync thread */
	} else if ( strcasecmp( argv[0], "dbsync" ) == 0 ) {
#ifndef NO_THREADS
		int i;
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing frquency value in \"dbsync <frequency> [<wait-times> [wait-interval]]\" line\n",
			    fname, lineno, 0 );
			return 1;
		}

		if ( lutil_atoi( &i, argv[1] ) != 0 || i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
    "%s: line %d: frquency value (%d) invalid \"dbsync <frequency> [<wait-times> [wait-interval]]\" line\n",
			    fname, lineno, i );
			return 1;
		}

		li->li_dbsyncfreq = i;

		if ( argc > 2 ) {
			if ( lutil_atoi( &i, argv[2] ) != 0 || i < 0 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: frquency value (%d) invalid \"dbsync <frequency> [<wait-times> [wait-interval]]\" line\n",
				    fname, lineno, i );
				return 1;
			}
			li ->li_dbsyncwaitn = i;
		}

		if ( argc > 3 ) {
			if ( lutil_atoi( &i, argv[3] ) != 0 || i <= 0 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: frquency value (%d) invalid \"dbsync <frequency> [<wait-times> [wait-interval]]\" line\n",
				    fname, lineno, i );
				return 1;
			}
			li ->li_dbsyncwaitinterval = i;
		}

		/* turn off writesync when sync policy is in place */
		li->li_dbwritesync = 0;

#else
		Debug( LDAP_DEBUG_ANY,
    "\"dbsync\" policies not supported in non-threaded environments\n", 0, 0, 0);
		return 1;
#endif


	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}
