/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

int bdb_id2entry_add(
	Backend *be,
	DB_TXN *tid,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval *bv;
	int rc;

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	DBTzero( &data );
	bv2DBT( bv, &data );

	rc = db->put( db, tid, &key, &data, DB_NOOVERWRITE );

	ber_bvfree( bv );
	return rc;
}

int bdb_id2entry(
	Backend *be,
	DB_TXN *tid,
	ID id,
	Entry **e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval bv;
	int rc;

	*e = NULL;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	DBTzero( &data );
	data.flags = DB_DBT_MALLOC;

	/* fetch it */
	rc = db->get( db, tid, &key, &data, 0 );

	if( rc != 0 ) {
		return rc;
	}

	DBT2bv( &data, &bv );

	rc = entry_decode( &bv, e );

	ch_free( data.data );
	return rc;
}

int bdb_id2entry_delete(
	Backend *be,
	DB_TXN *tid,
	ID id )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key;
	struct berval *bv;
	int rc;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	rc = db->del( db, tid, &key, 0 );

	ber_bvfree( bv );
	return rc;
}

int bdb_entry_return(
	Backend *be,
	Entry *e )
{
	entry_free( e );
	return 0;
}
