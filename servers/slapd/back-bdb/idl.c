/* idl.c - ldap id list handling routines */
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

#define BDB_IDL_SIZE	(1<<16)
#define BDB_IDL_MAX		(BDB_IDL_SIZE-16)
#define BDB_IDL_ALLOC	(BDB_IDL_MAX * sizeof(ID))

#define BDB_IS_ALLIDS(ids)	((ids)[0] == NOID)

#define IDL_CMP(x,y)	( x < y ? -1 : ( x > y ? 1 : 0 ) )

static int idl_search( ID *ids, ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first postion greater than id
	 */
	int base = 0;
	int cursor;
	int val;
	int n = ids[0];

	while( 0 < n ) {
		int pivot = n >> 1;
		cursor = base + pivot;
		val = IDL_CMP( id, ids[cursor + 1] );

		if( val < 0 ) {
			n = pivot;

		} else if ( val > 0 ) {
			base = cursor + 1;
			n -= pivot + 1;

		} else {
			return cursor + 1;
		}
	}
	
	if( val < 0 ) {
		return cursor + 1;
	} else {
		return cursor + 2;
	}
}

static int idl_insert( ID *ids, ID id )
{
	int x = idl_search( ids, id );

	if( ids[x] == id ) {
		/* duplicate */
		return -1;
	}

	if( x == 0 ) {
		/* append the id */
		ids[0]++;
		ids[ids[0]] = id;

	} else if ( ++ids[0] >= BDB_IDL_MAX ) {
		ids[0] = NOID;
	
	} else {
		/* insert id */
		AC_MEMCPY( &ids[x+1], &ids[x], (ids[0]-x) * sizeof(ID) );
		ids[0]++;
		ids[x] = id;
	}

	return 0;
}

static int idl_delete( ID *ids, ID id )
{
	int x = idl_search( ids, id );

	if( x == 0 || ids[x] != id ) {
		/* not found */
		return -1;

	} else if ( --ids[0] == 0 ) {
		if( x != 1 ) return -1;

	} else {
		AC_MEMCPY( &ids[x], &ids[x+1], (1+ids[0]-x) * sizeof(ID) );
	}

	return 0;
}

int
bdb_idl_insert_key(
    BackendDB	*be,
    DB			*db,
	DB_TXN		*tid,
    DBT			*key,
    ID			id )
{
	int	rc;
	ID ids[BDB_IDL_SIZE];
	DBT data;

	assert( id != NOID );

	data.data = ids;
	data.ulen = sizeof( ids );
	data.flags = DB_DBT_USERMEM;

	/* fetch the key and grab a write lock */
	rc = db->get( db, tid, key, &data, DB_RMW );

	if( rc == DB_NOTFOUND ) {
		ids[0] = 1;
		ids[1] = id;
		data.size = 2 * sizeof( ID );

	} else if ( rc != 0 ) {
		return rc;

	} else if ( data.size == 0 || data.size % sizeof( ID ) ) {
		/* size not multiple of ID size */
		return -1;
	
	} else if ( BDB_IS_ALLIDS(ids) ) {
		return 0;

	} else if ( data.size != (1 + ids[0]) * sizeof( ID ) ) {
		/* size mismatch */
		return -1;

	} else {
		rc = idl_insert( ids, id );

		if( rc != 0 ) return rc;

		data.size = (ids[0]+1) * sizeof( ID );
	}

	/* store the key */
	rc = db->put( db, tid, key, &data, 0 );

	return rc;
}

int
bdb_idl_delete_key(
    BackendDB	*be,
    DB			*db,
	DB_TXN		*tid,
    DBT			*key,
    ID			id )
{
	int	rc;
	ID ids[BDB_IDL_SIZE];
	DBT data;

	assert( id != NOID );

	data.data = ids;
	data.ulen = sizeof( ids );
	data.flags = DB_DBT_USERMEM;

	/* fetch the key and grab a write lock */
	rc = db->get( db, tid, key, &data, DB_RMW );

	if ( rc != 0 ) {
		return rc;

	} else if ( data.size == 0 || data.size % sizeof( ID ) ) {
		/* size not multiple of ID size */
		return -1;
	
	} else if ( BDB_IS_ALLIDS(ids) ) {
		return 0;

	} else if ( data.size != (1 + ids[0]) * sizeof( ID ) ) {
		/* size mismatch */
		return -1;

	} else {
		rc = idl_delete( ids, id );

		if( rc != 0 ) return rc;

		if( BDB_IS_ALLIDS(ids) ) {
			/* delete the key */
			rc = db->del( db, tid, key, 0 );
			return rc;
		}

		data.size = (ids[0]+1) * sizeof( ID );
	}

	/* store the key */
	rc = db->put( db, tid, key, &data, 0 );

	return rc;
}
