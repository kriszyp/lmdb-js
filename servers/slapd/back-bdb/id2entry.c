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
	BackendDB *be,
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

int bdb_id2entry_update(
	BackendDB *be,
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

	rc = db->put( db, tid, &key, &data, 0 );

	ber_bvfree( bv );
	return rc;
}

int bdb_id2entry(
	BackendDB *be,
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

	if( rc == 0 ) {
		(*e)->e_id = id;
	} else {
		/* only free on error. On success, the entry was
		 * decoded in place.
		 */
		ch_free( data.data );
	}
	return rc;
}

int bdb_id2entry_delete(
	BackendDB *be,
	DB_TXN *tid,
	ID id )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key;
	int rc;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	rc = db->del( db, tid, &key, 0 );

	return rc;
}

int bdb_entry_return(
	BackendDB *be,
	Entry *e )
{
	/* Our entries are almost always contiguous blocks, so a single
	 * free() on the Entry pointer suffices. The exception is when
	 * an entry has been modified, in which case the attr list will
	 * have been alloc'd separately and its address will no longer
	 * be a constant offset from (e).
	 */
	if( (void *) e->e_attrs != (void *) (e+1))
	{
		attrs_free(e->e_attrs);
	}

	ch_free(e);

	return 0;
}
int bdb_entry_release(
	BackendDB *be,
	Connection *c,
	Operation *o,
	Entry *e,
	int rw )
{
	/* A tool will call this with NULL Connection and Operation
	 * pointers. We don't need to do anything in that case,
	 * because the tool is getting entries into a realloc'd
	 * buffer.
	 */
	if (c && o)
		return bdb_entry_return(be, e);
}
