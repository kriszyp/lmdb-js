/* tools.c - tools for slap tools */
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

static DBC *cursor = NULL;
static DBT key, data;

int bdb_tool_entry_open(
	BackendDB *be, int mode )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	
	rc = bdb->bi_entries->bdi_db->cursor(
		bdb->bi_entries->bdi_db, NULL, &cursor, 0 );
	if( rc != 0 ) {
		return NOID;
	}

	/* initialize key and data thangs */
	DBTzero( &key );
	DBTzero( &data );
	key.flags = DB_DBT_REALLOC;
	data.flags = DB_DBT_REALLOC;

	return 0;
}

int bdb_tool_entry_close(
	BackendDB *be )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	if( key.data ) {
		ch_free( key.data );
		key.data = NULL;
	}
	if( data.data ) {
		ch_free( data.data );
		data.data = NULL;
	}

	if( cursor ) {
		cursor->c_close( cursor );
		cursor = NULL;
	}

	return 0;
}

ID bdb_tool_entry_next(
	BackendDB *be )
{
	int rc;
	ID id;

	assert( slapMode & SLAP_TOOL_MODE );
	assert( cursor != NULL );

	rc = cursor->c_get( cursor, &key, &data, DB_NEXT );

	if( rc != 0 ) {
		return NOID;
	}

	if( data.data == NULL ) {
		return NOID;
	}

	AC_MEMCPY( &id, key.data, key.size );
	return id;
}

Entry* bdb_tool_entry_get( BackendDB *be, ID id )
{
	int rc;
	Entry *e;
	struct berval bv;
	assert( slapMode & SLAP_TOOL_MODE );
	assert( data.data != NULL );

	DBT2bv( &data, &bv );

	rc = entry_decode( &bv, &e );

	if( rc == LDAP_SUCCESS ) {
		e->e_id = id;
	}

	return e;
}

ID bdb_tool_entry_put(
	BackendDB *be,
	Entry *e )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB_TXN *tid;
	DBT key, data;
	struct berval *bv;

	assert( slapMode & SLAP_TOOL_MODE );

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
	if( rc != LDAP_SUCCESS ) {
		return NOID;
	}

	DBTzero( &data );
	bv2DBT( bv, &data );

	Debug( LDAP_DEBUG_TRACE, "=> bdb_tool_entry_put( %ld, \"%s\" )\n",
		e->e_id, e->e_dn, 0 );

	rc = txn_begin( bdb->bi_dbenv, NULL, &tid, 0 );
	if( rc != 0 ) {
		ber_bvfree( bv );
		return NOID;
	}

	e->e_id = bdb_next_id( be, tid );
	if( e->e_id == NOID ) {
		goto done;
	}

	/* store it -- don't override */
	rc = bdb->bi_entries->bdi_db->put( bdb->bi_entries->bdi_db,
		tid, &key, &data, DB_NOOVERWRITE );
	if( rc != 0 ) {
		e->e_id = NOID;
		goto done;
	}

	/* add dn indices */
	rc = bdb_index_dn_add( be, tid, e->e_ndn, e->e_id );
	if( rc != 0 ) {
		e->e_id = NOID;
		goto done;
	}

#if 0
	rc = bdb_index_entry_add( be, tid, e, e->e_attrs );
	if( rc != 0 ) {
		e->e_id = NOID;
		goto done;
	}
#endif

done:
	if( e->e_id != NOID ) {
		rc = txn_commit( tid, 0 );
		if( rc != 0 ) {
			e->e_id = NOID;
		}

	} else {
		txn_abort( tid );
	}

	ber_bvfree( bv );
	return e->e_id;
}

#if 0
int bdb_tool_entry_reindex(
	BackendDB *be,
	ID id )
{
	struct bdb_dbinfo *bdi = (struct bdb_dbinfo *) be->be_private;
	int rc;
	Entry *e;
	DB_TXN *tid;

	Debug( LDAP_DEBUG_ARGS, "=> bdb_tool_entry_reindex( %ld )\n",
		(long) id, 0, 0 );

	rc = txn_begin( bdi->bdi_db_env, NULL, &tid, 0 );
 	
	e = bdb_tool_entry_get( be, tid, id );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_tool_entry_reindex:: could not locate id=%ld\n",
			(long) id, 0, 0 );
		txn_abort( bdi->bdi_db_env );
		return -1;
	}

	/*
	 * just (re)add them for now
	 * assume that some other routine (not yet implemented)
	 * will zap index databases
	 *
	 */

	Debug( LDAP_DEBUG_TRACE, "=> bdb_tool_entry_reindex( %ld, \"%s\" )\n",
		id, e->e_dn, 0 );

	rc = index_entry_add( be, e, e->e_attrs );

	entry_free( e );

	return rc;
}
#endif
