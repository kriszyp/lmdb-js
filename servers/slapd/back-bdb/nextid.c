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

	DBTzero( &key );
	key.data = (char *) &kid;
	key.size = sizeof( kid );

	DBTzero( &data );
	data.data = (char *) &id;
	data.ulen = sizeof( id );
	data.flags = DB_DBT_USERMEM;

	if( 0 ) {
retry:	if( tid != NULL ) {
			/* nested transaction, abort and return */
			(void) txn_abort( ltid );
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_next_id: aborted!\n",
				0, 0, 0 );
			return rc;
		}
		rc = txn_abort( ltid );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_next_id: txn_abort failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
			return rc;
		}
	}

	rc = txn_begin( bdb->bi_dbenv, tid, &ltid, 0 );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"=> bdb_next_id: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	/* get existing value for read/modify/write */
	rc = bdb->bi_nextid->bdi_db->get( bdb->bi_nextid->bdi_db,
		ltid, &key, &data, DB_RMW );

	switch(rc) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;

	case DB_NOTFOUND:
		id = 0;
		break;

	case 0:
		if ( data.size != sizeof(ID) ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_next_id: get size mismatch: expected %ld, got %ld\n",
				(long) sizeof( ID ), (long) data.size, 0 );
			rc = -1;
			goto done;
		}
		break;

	default:
		Debug( LDAP_DEBUG_ANY,
			"=> bdb_next_id: get failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}

	id++;

	/* put new value */
	rc = bdb->bi_nextid->bdi_db->put( bdb->bi_nextid->bdi_db,
		ltid, &key, &data, 0 );

	switch(rc) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;

	case 0:
		*out = id;
		rc = txn_commit( ltid, 0 );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_next_id: commit failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
		}
		break;

	default:
		Debug( LDAP_DEBUG_ANY,
			"=> bdb_next_id: put failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
done:	(void) txn_abort( ltid );
	}

	return rc;
}
