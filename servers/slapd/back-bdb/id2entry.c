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

int bdb_id2entry_put(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e,
	int flag )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval bv;
	int rc;
#ifdef BDB_HIER
	char *odn, *ondn;

	/* We only store rdns, and they go in the id2parent database. */

	odn = e->e_dn; ondn = e->e_ndn;

	e->e_dn = ""; e->e_ndn = "";
#endif
	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
#ifdef BDB_HIER
	e->e_dn = odn; e->e_ndn = ondn;
#endif
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	DBTzero( &data );
	bv2DBT( &bv, &data );

	rc = db->put( db, tid, &key, &data, flag );

	free( bv.bv_val );
	return rc;
}

int bdb_id2entry_add(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	return bdb_id2entry_put(be, tid, e, DB_NOOVERWRITE);
}

int bdb_id2entry_update(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	return bdb_id2entry_put(be, tid, e, 0);
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
	rc = db->get( db, tid, &key, &data, bdb->bi_db_opflags );

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
#ifdef BDB_HIER
	bdb_fix_dn(be, id, *e);
#endif
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
	/* Our entries are allocated in two blocks; the data comes from
	 * the db itself and the Entry structure and associated pointers
	 * are allocated in entry_decode. The db data pointer is saved
	 * in e_private. Since the Entry structure is allocated as a single
	 * block, e_attrs is always a fixed offset from e. The exception
	 * is when an entry has been modified, in which case we also need
	 * to free e_attrs.
	 */
	if( (void *) e->e_attrs != (void *) (e+1)) {
		attrs_free( e->e_attrs );
	}
#ifdef BDB_HIER
	/* We had to construct the dn and ndn as well, in a single block */
	free( e->e_dn );
#endif
	/* In tool mode the e_private buffer is realloc'd, leave it alone */
	if( e->e_private && !(slapMode & SLAP_TOOL_MODE) ) {
		free( e->e_private );
	}

	free( e );

	return 0;
}

int bdb_entry_release(
	BackendDB *be,
	Connection *c,
	Operation *o,
	Entry *e,
	int rw )
{
	return bdb_entry_return( be, e );
}
