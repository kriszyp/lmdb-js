/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
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

/*
 * This routine adds (or updates) an entry on disk.
 * The cache should be already be updated.
 */


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

int bdb_id2entry_rw(
	BackendDB *be,
	DB_TXN *tid,
	ID id,
	Entry **e,
	int rw,
	u_int32_t locker,
	DB_LOCK *lock )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval bv;
	int rc = 0, ret = 0;

	*e = NULL;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	DBTzero( &data );
	data.flags = DB_DBT_MALLOC;

	if ((*e = bdb_cache_find_entry_id(bdb->bi_dbenv, &bdb->bi_cache, id, rw, locker, lock)) != NULL) {
		return 0;
	}

	/* fetch it */
	rc = db->get( db, tid, &key, &data, bdb->bi_db_opflags | ( rw ? DB_RMW : 0 ));

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

	if ( rc == 0 ) {
#ifdef BDB_HIER
		bdb_fix_dn(be, id, *e);
#endif
		ret = bdb_cache_add_entry_rw( bdb->bi_dbenv,
				&bdb->bi_cache, *e, rw, locker, lock);
		while ( ret == 1 || ret == -1 ) {
			Entry *ee;
			int add_loop_cnt = 0;
			if ( (*e)->e_private != NULL ) {
				free ((*e)->e_private);
			}
			(*e)->e_private = NULL;
			if ( (ee = bdb_cache_find_entry_id
					(bdb->bi_dbenv, &bdb->bi_cache, id, rw, locker, lock) ) != NULL) {
				bdb_entry_return ( *e );
				*e = ee;
				return 0;
			}
			if ( ++add_loop_cnt == BDB_MAX_ADD_LOOP ) {
				bdb_entry_return ( *e );
				*e = NULL;
				return LDAP_BUSY;
			}
		}
		if ( ret != 0 ) {
			if ( (*e)->e_private != NULL )
				free ( (*e)->e_private );
			bdb_entry_return( *e );
			*e = NULL;
			ch_free( data.data );
		}
		rc = ret;
	}

	if (rc == 0) {
		bdb_cache_entry_commit(*e);
	}

	return rc;
}

int bdb_id2entry_delete(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key;
	int rc;

	bdb_cache_delete_entry(&bdb->bi_cache, e);

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	/* delete from database */
	rc = db->del( db, tid, &key, 0 );

	return rc;
}

int bdb_entry_return(
	Entry *e )
{
	/* Our entries are allocated in two blocks; the data comes from
	 * the db itself and the Entry structure and associated pointers
	 * are allocated in entry_decode. The db data pointer is saved
	 * in e_bv. Since the Entry structure is allocated as a single
	 * block, e_attrs is always a fixed offset from e. The exception
	 * is when an entry has been modified, in which case we also need
	 * to free e_attrs.
	 */
	if( !e->e_bv.bv_val ) {	/* A regular entry, from do_add */
		entry_free( e );
		return 0;
	}
	if( (void *) e->e_attrs != (void *) (e+1)) {
		attrs_free( e->e_attrs );
	}

#ifndef BDB_HIER
	/* See if the DNs were changed by modrdn */
	if( e->e_nname.bv_val < e->e_bv.bv_val || e->e_nname.bv_val >
		e->e_bv.bv_val + e->e_bv.bv_len ) {
		ch_free(e->e_name.bv_val);
		ch_free(e->e_nname.bv_val);
		e->e_name.bv_val = NULL;
		e->e_nname.bv_val = NULL;
	}
#else
	/* We had to construct the dn and ndn as well, in a single block */
	if( e->e_name.bv_val ) {
		free( e->e_name.bv_val );
	}
#endif
	/* In tool mode the e_bv buffer is realloc'd, leave it alone */
	if( !(slapMode & SLAP_TOOL_MODE) ) {
		free( e->e_bv.bv_val );
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
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
 
	/* slapMode : SLAP_SERVER_MODE, SLAP_TOOL_MODE,
			SLAP_TRUNCATE_MODE, SLAP_UNDEFINED_MODE */
 
	if ( slapMode == SLAP_SERVER_MODE ) {
		/* free entry and reader or writer lock */
		bdb_unlocked_cache_return_entry_rw( &bdb->bi_cache, e, rw );
	} else {
		if (e->e_private != NULL)
			free (e->e_private);
		e->e_private = NULL;
		bdb_entry_return ( e );
	}
 
	return 0;
}
