/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "ldif2common.h"
#include "../back-ldbm/back-ldbm.h"

int
main( int argc, char **argv )
{
	char		*buf;
	int         lineno;
	int         lmax;
	ID		id;
	ID		maxid;
	DBCache	*db;
	Backend		*be = NULL;
	struct ldbminfo *li;
	struct berval	bv;
	struct berval	*vals[2];

	slap_ldif_init( argc, argv, LDIF2ID2ENTRY, "ldbm", SLAP_TOOLID_MODE );

	slap_startup(dbnum);

	be = &backends[dbnum];

	/* disable write sync'ing */
	li = (struct ldbminfo *) be->be_private;
	li->li_dbcachewsync = 0;

	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_NEWDB ))
	    == NULL ) {
		perror( "id2entry file" );
		exit( EXIT_FAILURE );
	}

	id = 0;
	maxid = 0;
	buf = NULL;
	lmax = 0;
	vals[0] = &bv;
	vals[1] = NULL;
	while ( slap_read_ldif( &lineno, &buf, &lmax, &id, 1 ) ) {
		Datum		key, data;

		ldbm_datum_init( key );
		ldbm_datum_init( data );

				if ( id > maxid )
					maxid = id;
				key.dptr = (char *) &id;
				key.dsize = sizeof(ID);
				data.dptr = buf;
				data.dsize = strlen( buf ) + 1;
				if ( ldbm_store( db->dbc_db, key, data,
				    LDBM_INSERT ) != 0 ) {
					fputs("id2entry ldbm_store failed\n",
					      stderr);
					exit( EXIT_FAILURE );
				}
	}

	maxid++;
	put_nextid( be, maxid );

#ifdef SLAP_CLEANUP
	ldbm_cache_close( be, db );
#endif

	slap_shutdown(dbnum);

	slap_destroy();

	return( EXIT_SUCCESS );
}
