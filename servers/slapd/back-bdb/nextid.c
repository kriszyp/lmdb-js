/* init.c - initialize bdb backend */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

int bdb_next_id( BackendDB *be, DB_TXN *tid, ID *out )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	ID kid = NOID;
	ID id;
	DBT key, data;
	DB_TXN	*ltid;

	rc = txn_begin( bdb->bi_dbenv, tid, &ltid, 0 );
	if( rc != 0 ) {
		return rc;
	}

	DBTzero( &key );
	key.data = (char *) &kid;
	key.size = sizeof( kid );

	DBTzero( &data );
	data.data = (char *) &id;
	data.ulen = sizeof( id );
	data.flags = DB_DBT_USERMEM;

	/* get exiting value (with write lock) */
	rc = bdb->bi_nextid->bdi_db->get( bdb->bi_nextid->bdi_db,
		ltid, &key, &data, DB_RMW );

	if( rc == DB_NOTFOUND ) {
		/* must be first add */
		id = NOID;

	} else if( rc != 0 ) {
		goto done;

	} else if ( data.size != sizeof(ID) ) {
		/* size mismatch! */
		rc = -1;
		goto done;
	}

	id++;

	/* store new value */
	rc = bdb->bi_nextid->bdi_db->put( bdb->bi_nextid->bdi_db,
		ltid, &key, &data, 0 );

	*out = id;

done:
	if( rc != 0 ) {
		(void) txn_abort( ltid );
	} else {
		rc = txn_commit( ltid, 0 );
	}

	return rc;
}
