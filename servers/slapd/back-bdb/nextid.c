/* init.c - initialize bdb backend */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "back-bdb.h"

int bdb_next_id( BackendDB *be, DB_TXN *tid, ID *out )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	ID kid = NOID;
	ID id;
	DBT key, data;

	DBTzero( &key );
	key.data = (char *) &kid;
	key.size = sizeof( kid );

	DBTzero( &data );
	data.data = (char *) &id;
	data.ulen = sizeof( id );
	data.flags = DB_DBT_USERMEM;

	/* get exiting value (with write lock) */
	rc = bdb->bi_entries->bdi_db->get( bdb->bi_nextid->bdi_db,
		tid, &key, &data, DB_RMW );

	if( rc == DB_NOTFOUND ) {
		/* must be first add */
		id = NOID;

	} else if( rc != 0 ) {
		return rc;

	} else if ( data.size != sizeof(ID) ) {
		/* size mismatch! */
		return -1;
	}

	id++;

	/* store new value */
	rc = bdb->bi_entries->bdi_db->put( bdb->bi_nextid->bdi_db,
		tid, &key, &data, 0 );

	*out = id;
	return rc;
}
