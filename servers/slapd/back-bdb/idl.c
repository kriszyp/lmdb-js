/* idl.c - ldap id list handling routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "idl.h"

#define IDL_MAX(x,y)	( x > y ? x : y )
#define IDL_MIN(x,y)	( x < y ? x : y )

#define IDL_CMP(x,y)	( x < y ? -1 : ( x > y ? 1 : 0 ) )

#define IDL_LRU_DELETE( bdb, e ) do { 					\
	if ( e->idl_lru_prev != NULL ) {				\
		e->idl_lru_prev->idl_lru_next = e->idl_lru_next; 	\
	} else {							\
		bdb->bi_idl_lru_head = e->idl_lru_next;			\
	}								\
	if ( e->idl_lru_next != NULL ) {				\
		e->idl_lru_next->idl_lru_prev = e->idl_lru_prev;	\
	} else {							\
		bdb->bi_idl_lru_tail = e->idl_lru_prev;			\
	}								\
} while ( 0 )

#define IDL_LRU_ADD( bdb, e ) do {					\
	e->idl_lru_next = bdb->bi_idl_lru_head;				\
	if ( e->idl_lru_next != NULL ) {				\
		e->idl_lru_next->idl_lru_prev = (e);			\
	}								\
	(bdb)->bi_idl_lru_head = (e);					\
	e->idl_lru_prev = NULL;						\
	if ( (bdb)->bi_idl_lru_tail == NULL ) {				\
		(bdb)->bi_idl_lru_tail = (e);				\
	}								\
} while ( 0 )

static int
bdb_idl_entry_cmp( const void *v_idl1, const void *v_idl2 )
{
	const bdb_idl_cache_entry_t *idl1 = v_idl1, *idl2 = v_idl2;
	int rc;

	if ((rc = SLAP_PTRCMP( idl1->db, idl2->db ))) return rc;
	if ((rc = idl1->kstr.bv_len - idl2->kstr.bv_len )) return rc;
	return ( memcmp ( idl1->kstr.bv_val, idl2->kstr.bv_val , idl1->kstr.bv_len ) );
}

#if IDL_DEBUG > 0
static void idl_check( ID *ids )
{
	if( BDB_IDL_IS_RANGE( ids ) ) {
		assert( BDB_IDL_RANGE_FIRST(ids) <= BDB_IDL_RANGE_LAST(ids) );
	} else {
		ID i;
		for( i=1; i < ids[0]; i++ ) {
			assert( ids[i+1] > ids[i] );
		}
	}
}

#if IDL_DEBUG > 1
static void idl_dump( ID *ids )
{
	if( BDB_IDL_IS_RANGE( ids ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, INFO, "IDL: range (%ld - %ld)\n",
			(long) BDB_IDL_RANGE_FIRST( ids ),
			(long) BDB_IDL_RANGE_LAST( ids ), 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"IDL: range ( %ld - %ld )\n",
			(long) BDB_IDL_RANGE_FIRST( ids ),
			(long) BDB_IDL_RANGE_LAST( ids ) );
#endif

	} else {
		ID i;
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, INFO, "IDL: size %ld", (long) ids[0], 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "IDL: size %ld", (long) ids[0], 0, 0 );
#endif

		for( i=1; i<=ids[0]; i++ ) {
			if( i % 16 == 1 ) {
				Debug( LDAP_DEBUG_ANY, "\n", 0, 0, 0 );
			}
#ifdef NEW_LOGGING
			LDAP_LOG( INDEX, INFO, "%02lx",(long)ids[i], 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "  %02lx", (long) ids[i], 0, 0 );
#endif
		}

		Debug( LDAP_DEBUG_ANY, "\n", 0, 0, 0 );
	}

	idl_check( ids );
}
#endif /* IDL_DEBUG > 1 */
#endif /* IDL_DEBUG > 0 */

unsigned bdb_idl_search( ID *ids, ID id )
{
#define IDL_BINARY_SEARCH 1
#ifdef IDL_BINARY_SEARCH
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first postion greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 0;
	int val = 0;
	unsigned n = ids[0];

#if IDL_DEBUG > 0
	idl_check( ids );
#endif

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
	
	if( val > 0 ) {
		return cursor + 2;
	} else {
		return cursor + 1;
	}

#else
	/* (reverse) linear search */
	int i;

#if IDL_DEBUG > 0
	idl_check( ids );
#endif

	for( i=ids[0]; i; i-- ) {
		if( id > ids[i] ) {
			break;
		}
	}

	return i+1;
#endif
}

int bdb_idl_insert( ID *ids, ID id )
{
	unsigned x;

#if IDL_DEBUG > 1
#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, DETAIL1, "insert: %04lx at %d\n", (long) id, x, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "insert: %04lx at %d\n", (long) id, x, 0 );
	idl_dump( ids );
#endif
#elif IDL_DEBUG > 0
	idl_check( ids );
#endif

	if (BDB_IDL_IS_RANGE( ids )) {
		/* if already in range, treat as a dup */
		if (id >= BDB_IDL_FIRST(ids) && id <= BDB_IDL_LAST(ids))
			return -1;
		if (id < BDB_IDL_FIRST(ids))
			ids[1] = id;
		else if (id > BDB_IDL_LAST(ids))
			ids[2] = id;
		return 0;
	}

	x = bdb_idl_search( ids, id );
	assert( x > 0 );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0] && ids[x] == id ) {
		/* duplicate */
		return -1;
	}

	if ( ++ids[0] >= BDB_IDL_DB_MAX ) {
		if( id < ids[1] ) {
			ids[1] = id;
			ids[2] = ids[ids[0]-1];
		} else if ( ids[ids[0]-1] < id ) {
			ids[2] = id;
		} else {
			ids[2] = ids[ids[0]-1];
		}
		ids[0] = NOID;
	
	} else {
		/* insert id */
		AC_MEMCPY( &ids[x+1], &ids[x], (ids[0]-x) * sizeof(ID) );
		ids[x] = id;
	}

#if IDL_DEBUG > 1
	idl_dump( ids );
#elif IDL_DEBUG > 0
	idl_check( ids );
#endif

	return 0;
}

static int bdb_idl_delete( ID *ids, ID id )
{
	unsigned x;

#if IDL_DEBUG > 1
#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, DETAIL1, "delete: %04lx at %d\n", (long) id, x, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "delete: %04lx at %d\n", (long) id, x, 0 );
	idl_dump( ids );
#endif
#elif IDL_DEBUG > 0
	idl_check( ids );
#endif

	if (BDB_IDL_IS_RANGE( ids )) {
		/* if in range, treat as a noop */
		if (id > BDB_IDL_FIRST(ids) && id < BDB_IDL_LAST(ids))
			return -1;
		if (id == BDB_IDL_FIRST(ids))
			ids[1] = id+1;
		else if (id == BDB_IDL_LAST(ids))
			ids[2] = id-1;
		/* range collapsed to a single item */
		if ( ids[1] == ids[2] )
			ids[0] = 1;
		return 0;
	}

	x = bdb_idl_search( ids, id );
	assert( x > 0 );

	if( x <= 0 ) {
		/* internal error */
		return -2;
	}

	if( x > ids[0] || ids[x] != id ) {
		/* not found */
		return -1;

	} else if ( --ids[0] == 0 ) {
		if( x != 1 ) {
			return -3;
		}

	} else {
		AC_MEMCPY( &ids[x], &ids[x+1], (1+ids[0]-x) * sizeof(ID) );
	}

#if IDL_DEBUG > 1
	idl_dump( ids );
#elif IDL_DEBUG > 0
	idl_check( ids );
#endif

	return 0;
}

static char *
bdb_show_key(
	DBT		*key,
	char		*buf )
{
	if ( key->size == sizeof( ID ) ) {
		unsigned char *c = key->data;
		sprintf( buf, "[%02x%02x%02x%02x]", c[0], c[1], c[2], c[3] );
		return buf;
	} else {
		return key->data;
	}
}

/* Find a db/key pair in the IDL cache. If ids is non-NULL,
 * copy the cached IDL into it, otherwise just return the status.
 */
int
bdb_idl_cache_get(
	struct bdb_info	*bdb,
	DB			*db,
	DBT			*key,
	ID			*ids )
{
	bdb_idl_cache_entry_t idl_tmp;
	bdb_idl_cache_entry_t *matched_idl_entry;

	DBT2bv( key, &idl_tmp.kstr );
	idl_tmp.db = db;
	ldap_pvt_thread_rdwr_rlock( &bdb->bi_idl_tree_rwlock );
	matched_idl_entry = avl_find( bdb->bi_idl_tree, &idl_tmp,
				      bdb_idl_entry_cmp );
	if ( matched_idl_entry != NULL ) {
		if ( matched_idl_entry->idl && ids )
			BDB_IDL_CPY( ids, matched_idl_entry->idl );
		ldap_pvt_thread_rdwr_runlock( &bdb->bi_idl_tree_rwlock );
		ldap_pvt_thread_mutex_lock( &bdb->bi_idl_tree_lrulock );
		IDL_LRU_DELETE( bdb, matched_idl_entry );
		IDL_LRU_ADD( bdb, matched_idl_entry );
		ldap_pvt_thread_mutex_unlock( &bdb->bi_idl_tree_lrulock );
		if ( matched_idl_entry->idl )
			return LDAP_SUCCESS;
		else
			return DB_NOTFOUND;
	}
	ldap_pvt_thread_rdwr_runlock( &bdb->bi_idl_tree_rwlock );

	return LDAP_NO_SUCH_OBJECT;
}

void
bdb_idl_cache_put(
	struct bdb_info	*bdb,
	DB			*db,
	DBT			*key,
	ID			*ids,
	int			rc )
{
	bdb_idl_cache_entry_t idl_tmp;
	bdb_idl_cache_entry_t *ee;

	DBT2bv( key, &idl_tmp.kstr );

	ee = (bdb_idl_cache_entry_t *) ch_malloc(
		sizeof( bdb_idl_cache_entry_t ) );
	ee->db = db;
	if ( rc == DB_NOTFOUND) {
		ee->idl = NULL;
	} else {
		ee->idl = (ID*) ch_malloc( BDB_IDL_SIZEOF ( ids ) );
		BDB_IDL_CPY( ee->idl, ids );
	}
	ee->idl_lru_prev = NULL;
	ee->idl_lru_next = NULL;
	ber_dupbv( &ee->kstr, &idl_tmp.kstr );
	ldap_pvt_thread_rdwr_wlock( &bdb->bi_idl_tree_rwlock );
	if ( avl_insert( &bdb->bi_idl_tree, (caddr_t) ee,
		bdb_idl_entry_cmp, avl_dup_error ))
	{
		ch_free( ee->kstr.bv_val );
		ch_free( ee->idl );
		ch_free( ee );
		ldap_pvt_thread_rdwr_wunlock( &bdb->bi_idl_tree_rwlock );
		return;
	}
	ldap_pvt_thread_mutex_lock( &bdb->bi_idl_tree_lrulock );
	IDL_LRU_ADD( bdb, ee );
	if ( ++bdb->bi_idl_cache_size > bdb->bi_idl_cache_max_size ) {
		int i = 0;
		while ( bdb->bi_idl_lru_tail != NULL && i < 10 ) {
			ee = bdb->bi_idl_lru_tail;
			if ( avl_delete( &bdb->bi_idl_tree, (caddr_t) ee,
				    bdb_idl_entry_cmp ) == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( INDEX, ERR, 
					"bdb_idl_cache_put: AVL delete failed\n", 
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "=> bdb_idl_cache_put: "
					"AVL delete failed\n",
					0, 0, 0 );
#endif
			}
			IDL_LRU_DELETE( bdb, ee );
			i++;
			--bdb->bi_idl_cache_size;
			ch_free( ee->kstr.bv_val );
			ch_free( ee->idl );
			ch_free( ee );
		}
	}

	ldap_pvt_thread_mutex_unlock( &bdb->bi_idl_tree_lrulock );
	ldap_pvt_thread_rdwr_wunlock( &bdb->bi_idl_tree_rwlock );
}

void
bdb_idl_cache_del(
	struct bdb_info	*bdb,
	DB			*db,
	DBT			*key )
{
	bdb_idl_cache_entry_t *matched_idl_entry, idl_tmp;
	DBT2bv( key, &idl_tmp.kstr );
	idl_tmp.db = db;
	ldap_pvt_thread_rdwr_wlock( &bdb->bi_idl_tree_rwlock );
	matched_idl_entry = avl_find( bdb->bi_idl_tree, &idl_tmp,
				      bdb_idl_entry_cmp );
	if ( matched_idl_entry != NULL ) {
		if ( avl_delete( &bdb->bi_idl_tree, (caddr_t) matched_idl_entry,
				    bdb_idl_entry_cmp ) == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( INDEX, ERR, 
				"bdb_idl_cache_del: AVL delete failed\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "=> bdb_idl_cache_del: "
				"AVL delete failed\n",
				0, 0, 0 );
#endif
		}
		--bdb->bi_idl_cache_size;
		ldap_pvt_thread_mutex_lock( &bdb->bi_idl_tree_lrulock );
		IDL_LRU_DELETE( bdb, matched_idl_entry );
		ldap_pvt_thread_mutex_unlock( &bdb->bi_idl_tree_lrulock );
		free( matched_idl_entry->kstr.bv_val );
		if ( matched_idl_entry->idl )
			free( matched_idl_entry->idl );
		free( matched_idl_entry );
	}
	ldap_pvt_thread_rdwr_wunlock( &bdb->bi_idl_tree_rwlock );
}

int
bdb_idl_fetch_key(
	BackendDB	*be,
	DB			*db,
	DB_TXN		*tid,
	DBT			*key,
	ID			*ids )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	DBT data;
	DBC *cursor;
	ID *i;
	void *ptr;
	size_t len;
	int rc2;
	int flags = bdb->bi_db_opflags | DB_MULTIPLE;

	/* If using BerkeleyDB 4.0, the buf must be large enough to
	 * grab the entire IDL in one get(), otherwise BDB will leak
	 * resources on subsequent get's.  We can safely call get()
	 * twice - once for the data, and once to get the DB_NOTFOUND
	 * result meaning there's no more data. See ITS#2040 for details.
	 * This bug is fixed in BDB 4.1 so a smaller buffer will work if
	 * stack space is too limited.
	 *
	 * configure now requires Berkeley DB 4.1.
	 */
#if (DB_VERSION_MAJOR == 4) && (DB_VERSION_MINOR == 0)
#	define BDB_ENOUGH 5
#else
#	define BDB_ENOUGH 1
#endif
	ID buf[BDB_IDL_DB_SIZE*BDB_ENOUGH];

	char keybuf[16];

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ARGS,
		"bdb_idl_fetch_key: %s\n", 
		bdb_show_key( key, keybuf ), 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS,
		"bdb_idl_fetch_key: %s\n", 
		bdb_show_key( key, keybuf ), 0, 0 );
#endif

	assert( ids != NULL );

	if ( bdb->bi_idl_cache_size ) {
		rc = bdb_idl_cache_get( bdb, db, key, ids );
		if ( rc != LDAP_NO_SUCH_OBJECT ) return rc;
	}

	DBTzero( &data );

	data.data = buf;
	data.ulen = sizeof(buf);
	data.flags = DB_DBT_USERMEM;

	if ( tid ) flags |= DB_RMW;

	rc = db->cursor( db, tid, &cursor, bdb->bi_db_opflags );
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_fetch_key: cursor failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_fetch_key: "
			"cursor failed: %s (%d)\n", db_strerror(rc), rc, 0 );
#endif
		return rc;
	}

	rc = cursor->c_get( cursor, key, &data, flags | DB_SET );
	if (rc == 0) {
		i = ids;
		while (rc == 0) {
			u_int8_t *j;

			DB_MULTIPLE_INIT( ptr, &data );
			while (ptr) {
				DB_MULTIPLE_NEXT(ptr, &data, j, len);
				if (j) {
					++i;
					AC_MEMCPY( i, j, sizeof(ID) );
				}
			}
			rc = cursor->c_get( cursor, key, &data, flags | DB_NEXT_DUP );
		}
		if ( rc == DB_NOTFOUND ) rc = 0;
		ids[0] = i - ids;
		/* On disk, a range is denoted by 0 in the first element */
		if (ids[1] == 0) {
			if (ids[0] != BDB_IDL_RANGE_SIZE) {
#ifdef NEW_LOGGING
				LDAP_LOG( INDEX, ERR, 
					"=> bdb_idl_fetch_key: range size mismatch: "
					"expected %ld, got %ld\n", 
					BDB_IDL_RANGE_SIZE, ids[0], 0 );
#else
				Debug( LDAP_DEBUG_ANY, "=> bdb_idl_fetch_key: "
					"range size mismatch: expected %d, got %ld\n",
					BDB_IDL_RANGE_SIZE, ids[0], 0 );
#endif
				cursor->c_close( cursor );
				return -1;
			}
			BDB_IDL_RANGE( ids, ids[2], ids[3] );
		}
		data.size = BDB_IDL_SIZEOF(ids);
	}

	rc2 = cursor->c_close( cursor );
	if (rc2) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_fetch_key: close failed: %s (%d)\n", 
			db_strerror(rc2), rc2, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_fetch_key: "
			"close failed: %s (%d)\n", db_strerror(rc2), rc2, 0 );
#endif
		return rc2;
	}

	if ( rc == DB_NOTFOUND ) {
		/* no-op */
	} else if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_fetch_key: get failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_fetch_key: "
			"get failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
		return rc;

	} else if ( data.size == 0 || data.size % sizeof( ID ) ) {
		/* size not multiple of ID size */
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_fetch_key: odd size: expected %ld multiple, got %ld\n", 
			(long) sizeof( ID ), (long) data.size, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_fetch_key: "
			"odd size: expected %ld multiple, got %ld\n",
			(long) sizeof( ID ), (long) data.size, 0 );
#endif
		return -1;

	} else if ( data.size != BDB_IDL_SIZEOF(ids) ) {
		/* size mismatch */
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_fetch_key: get size mismatch: expected %ld, got %ld\n", 
			(long) ((1 + ids[0]) * sizeof( ID )), (long) data.size, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_fetch_key: "
			"get size mismatch: expected %ld, got %ld\n",
			(long) ((1 + ids[0]) * sizeof( ID )), (long) data.size, 0 );
#endif
		return -1;
	}

	if ( bdb->bi_idl_cache_max_size ) {
		bdb_idl_cache_put( bdb, db, key, ids, rc );
	}

	return rc;
}


int
bdb_idl_insert_key(
	BackendDB	*be,
	DB			*db,
	DB_TXN		*tid,
	DBT			*key,
	ID			id )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int	rc;
	DBT data;
	ID lo, hi, tmp, idl[BDB_IDL_DB_SIZE];
	char *err;
	int wasrange = 0, isrange = 0;

	{
		char buf[16];
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ARGS,
			"bdb_idl_insert_key: %lx %s\n", 
			(long) id, bdb_show_key( key, buf ), 0 );
#else
		Debug( LDAP_DEBUG_ARGS,
			"bdb_idl_insert_key: %lx %s\n", 
			(long) id, bdb_show_key( key, buf ), 0 );
#endif
	}

	assert( id != NOID );

	BDB_IDL_ZERO( idl );
	rc = bdb_idl_fetch_key( be, db, tid, key, idl );
	if ( rc != DB_NOTFOUND ) {
		wasrange = BDB_IDL_IS_RANGE( idl );
		if ( wasrange ) {
			lo = idl[1];
			hi = idl[2];
		}
		rc = bdb_idl_insert( idl, id );

		/* Don't need to do anything */
		if ( rc == -1 ) return 0;

		isrange = BDB_IDL_IS_RANGE( idl );
	}

	DBTzero( &data );
	data.size = sizeof( ID );
	data.ulen = data.size;
	data.flags = DB_DBT_USERMEM;
	data.data = &tmp;

	if ( isrange ) {
		while ( !wasrange ) {
			/* Delete vector, rewrite as range */
			rc = db->del( db, tid, key, 0 );
			if ( rc != 0 ) {
				err = "del";
				break;
			}
			tmp = 0;
			rc = db->put( db, tid, key, &data, 0 );
			if ( rc != 0 ) {
				err = "put1";
				break;
			}
			tmp = idl[1];
			rc = db->put( db, tid, key, &data, 0 );
			if ( rc != 0 ) {
				err = "put2";
				break;
			}
			tmp = idl[2];
			rc = db->put( db, tid, key, &data, 0 );
			if ( rc != 0 ) {
				err = "put3";
				break;
			}
			break;
		}
		while( wasrange ) {
			DBC *cursor;
			/* Update range boundaries */
			rc = db->cursor( db, tid, &cursor, bdb->bi_db_opflags );
			if ( rc != 0 ) {
				err = "cursor";
				break;
			}
			data.data = &tmp;

			tmp = (id == idl[1]) ? lo : hi;
			rc = cursor->c_get( cursor, key, &data, DB_GET_BOTH );
			if ( rc != 0 ) {
				cursor->c_close( cursor );
				err = "c_get";
				break;
			}
			rc = cursor->c_del( cursor, 0 );
			if ( rc != 0 ) {
				cursor->c_close( cursor );
				err = "c_del";
				break;
			}
			tmp = id;
			rc = cursor->c_put( cursor, key, &data, DB_KEYFIRST );
			if ( rc != 0 ) {
				cursor->c_close( cursor );
				err = "c_put";
				break;
			}
			rc = cursor->c_close( cursor );
			if ( rc != 0 ) {
				err = "c_close";
				break;
			}
			break;
		}
	} else {
		tmp = id;
		rc = db->put( db, tid, key, &data, DB_NODUPDATA );
		if ( rc != 0 ) {
			err = "put4";
		}
	}
	if ( rc && rc != DB_KEYEXIST ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_insert_key: %s failed: %s (%d)\n", 
			err, db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_insert_key: "
			"%s failed: %s (%d)\n", err, db_strerror(rc), rc );
#endif
		return rc;
	}

	if ( bdb->bi_idl_cache_max_size ) {
		bdb_idl_cache_del( bdb, db, key );
		bdb_idl_cache_put( bdb, db, key, idl, 0 );
	}
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
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int	rc;
	DBT data;
	DBC *cursor;
	ID lo, hi, tmp, idl[BDB_IDL_DB_SIZE];
	int wasrange, isrange;
	char *err;

	{
		char buf[16];
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ARGS,
			"bdb_idl_delete_key: %lx %s\n", 
			(long) id, bdb_show_key( key, buf ), 0 );
#else
		Debug( LDAP_DEBUG_ARGS,
			"bdb_idl_delete_key: %lx %s\n", 
			(long) id, bdb_show_key( key, buf ), 0 );
#endif
	}
	assert( id != NOID );

	BDB_IDL_ZERO( idl );
	rc = bdb_idl_fetch_key( be, db, tid, key, idl );
	if ( rc != DB_NOTFOUND ) {
		wasrange = BDB_IDL_IS_RANGE( idl );
		if ( wasrange ) {
			lo = idl[1];
			hi = idl[2];
		}
		rc = bdb_idl_delete( idl, id );

		/* Don't need to do anything */
		if ( rc == -1 ) return 0;

		isrange = BDB_IDL_IS_RANGE( idl );
	}

	DBTzero( &data );
	data.data = &tmp;
	data.size = sizeof( id );
	data.ulen = data.size;
	data.flags = DB_DBT_USERMEM;

	rc = db->cursor( db, tid, &cursor, bdb->bi_db_opflags );
	if ( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_delete_key: cursor failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_delete_key: "
			"cursor failed: %s (%d)\n", db_strerror(rc), rc, 0 );
#endif
		return rc;
	}

	if ( wasrange && !isrange ) {
		rc = db->del( db, tid, key, 0 );
		if ( rc != 0 ) {
			err = "del";
		} else {
			tmp = idl[1];
			rc = db->put( db, tid, key, &data, 0 );
			if ( rc != 0 ) {
				err = "put";
			}
		}
	} else {
		tmp = id;
		rc = cursor->c_get( cursor, key, &data, DB_GET_BOTH );
		if ( rc != 0 ) {
			err = "c_get";
		} else {
			rc = cursor->c_del( cursor, 0 );
			if ( rc != 0 ) {
				err = "c_del";
			}
		}
	}
	if ( isrange && rc == 0 ) {
		tmp = ( id == lo ) ? idl[1] : idl[2];
		rc = cursor->c_put( cursor, key, &data, DB_KEYFIRST );
		if ( rc != 0 ) {
			err = "c_put";
		}
	}
	if ( rc && rc != DB_NOTFOUND ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			"bdb_idl_delete_key: %s failed: %s (%d)\n", 
			err, db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_idl_delete_key: "
			"%s failed: %s (%d)\n", err, db_strerror(rc), rc );
#endif
		cursor->c_close( cursor );
		return rc;
	}
	rc = cursor->c_close( cursor );
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, "bdb_idl_delete_key: c_close failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"=> bdb_idl_delete_key: c_close failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
		return rc;
	}
	if ( bdb->bi_idl_cache_max_size ) {
		bdb_idl_cache_del( bdb, db, key );
		bdb_idl_cache_put( bdb, db, key, idl, 0 );
	}

	return rc;
}


/*
 * idl_intersection - return a = a intersection b
 */
int
bdb_idl_intersection(
	ID *a,
	ID *b )
{
	ID ida, idb;
	ID idmax, idmin;
	ID cursora = 0, cursorb = 0, cursorc;
	int swap = 0;

	if ( BDB_IDL_IS_ZERO( a ) || BDB_IDL_IS_ZERO( b ) ) {
		a[0] = 0;
		return 0;
	}

	idmin = IDL_MAX( BDB_IDL_FIRST(a), BDB_IDL_FIRST(b) );
	idmax = IDL_MIN( BDB_IDL_LAST(a), BDB_IDL_LAST(b) );
	if ( idmin > idmax ) {
		a[0] = 0;
		return 0;
	} else if ( idmin == idmax ) {
		a[0] = 1;
		a[1] = idmin;
		return 0;
	}

	if ( BDB_IDL_IS_RANGE( a ) ) {
		if ( BDB_IDL_IS_RANGE(b) ) {
		/* If both are ranges, just shrink the boundaries */
			a[1] = idmin;
			a[2] = idmax;
			return 0;
		} else {
		/* Else swap so that b is the range, a is a list */
			ID *tmp = a;
			a = b;
			b = tmp;
			swap = 1;
		}
	}

	/* If a range completely covers the list, the result is
	 * just the list. If idmin to idmax is contiguous, just
	 * turn it into a range.
	 */
	if ( BDB_IDL_IS_RANGE( b )
		&& BDB_IDL_FIRST( b ) <= BDB_IDL_FIRST( a )
		&& BDB_IDL_LAST( b ) >= BDB_IDL_LAST( a ) ) {
		if (idmax - idmin + 1 == a[0])
		{
			a[0] = NOID;
			a[1] = idmin;
			a[2] = idmax;
		}
		goto done;
	}

	/* Fine, do the intersection one element at a time.
	 * First advance to idmin in both IDLs.
	 */
	cursora = cursorb = idmin;
	ida = bdb_idl_first( a, &cursora );
	idb = bdb_idl_first( b, &cursorb );
	cursorc = 0;

	while( ida <= idmax || idb <= idmax ) {
		if( ida == idb ) {
			a[++cursorc] = ida;
			ida = bdb_idl_next( a, &cursora );
			idb = bdb_idl_next( b, &cursorb );
		} else if ( ida < idb ) {
			ida = bdb_idl_next( a, &cursora );
		} else {
			idb = bdb_idl_next( b, &cursorb );
		}
	}
	a[0] = cursorc;
done:
	if (swap)
		BDB_IDL_CPY( b, a );

	return 0;
}


/*
 * idl_union - return a = a union b
 */
int
bdb_idl_union(
	ID	*a,
	ID	*b )
{
	ID ida, idb;
	ID cursora = 0, cursorb = 0, cursorc;

	if ( BDB_IDL_IS_ZERO( b ) ) {
		return 0;
	}

	if ( BDB_IDL_IS_ZERO( a ) ) {
		BDB_IDL_CPY( a, b );
		return 0;
	}

	if ( BDB_IDL_IS_RANGE( a ) || BDB_IDL_IS_RANGE(b) ) {
over:		ida = IDL_MIN( BDB_IDL_FIRST(a), BDB_IDL_FIRST(b) );
		idb = IDL_MAX( BDB_IDL_LAST(a), BDB_IDL_LAST(b) );
		a[0] = NOID;
		a[1] = ida;
		a[2] = idb;
		return 0;
	}

	ida = bdb_idl_first( a, &cursora );
	idb = bdb_idl_first( b, &cursorb );

	cursorc = b[0];

	/* The distinct elements of a are cat'd to b */
	while( ida != NOID || idb != NOID ) {
		if ( ida < idb ) {
			if( ++cursorc > BDB_IDL_UM_MAX ) {
				goto over;
			}
			b[cursorc] = ida;
			ida = bdb_idl_next( a, &cursora );

		} else {
			if ( ida == idb )
				ida = bdb_idl_next( a, &cursora );
			idb = bdb_idl_next( b, &cursorb );
		}
	}

	/* b is copied back to a in sorted order */
	a[0] = cursorc;
	cursora = 1;
	cursorb = 1;
	cursorc = b[0]+1;
	while (cursorb <= b[0] || cursorc <= a[0]) {
		if (cursorc > a[0])
			idb = NOID;
		else
			idb = b[cursorc];
		if (cursorb <= b[0] && b[cursorb] < idb)
			a[cursora++] = b[cursorb++];
		else {
			a[cursora++] = idb;
			cursorc++;
		}
	}

	return 0;
}


#if 0
/*
 * bdb_idl_notin - return a intersection ~b (or a minus b)
 */
int
bdb_idl_notin(
	ID	*a,
	ID	*b,
	ID *ids )
{
	ID ida, idb;
	ID cursora = 0, cursorb = 0;

	if( BDB_IDL_IS_ZERO( a ) ||
		BDB_IDL_IS_ZERO( b ) ||
		BDB_IDL_IS_RANGE( b ) )
	{
		BDB_IDL_CPY( ids, a );
		return 0;
	}

	if( BDB_IDL_IS_RANGE( a ) ) {
		BDB_IDL_CPY( ids, a );
		return 0;
	}

	ida = bdb_idl_first( a, &cursora ),
	idb = bdb_idl_first( b, &cursorb );

	ids[0] = 0;

	while( ida != NOID ) {
		if ( idb == NOID ) {
			/* we could shortcut this */
			ids[++ids[0]] = ida;
			ida = bdb_idl_next( a, &cursora );

		} else if ( ida < idb ) {
			ids[++ids[0]] = ida;
			ida = bdb_idl_next( a, &cursora );

		} else if ( ida > idb ) {
			idb = bdb_idl_next( b, &cursorb );

		} else {
			ida = bdb_idl_next( a, &cursora );
			idb = bdb_idl_next( b, &cursorb );
		}
	}

	return 0;
}
#endif

ID bdb_idl_first( ID *ids, ID *cursor )
{
	ID pos;

	if ( ids[0] == 0 ) {
		*cursor = NOID;
		return NOID;
	}

	if ( BDB_IDL_IS_RANGE( ids ) ) {
		if( *cursor < ids[1] ) {
			*cursor = ids[1];
		}
		return *cursor;
	}

	if ( *cursor == 0 )
		pos = 1;
	else
		pos = bdb_idl_search( ids, *cursor );

	if( pos > ids[0] ) {
		return NOID;
	}

	*cursor = pos;
	return ids[pos];
}

ID bdb_idl_next( ID *ids, ID *cursor )
{
	if ( BDB_IDL_IS_RANGE( ids ) ) {
		if( ids[2] < ++(*cursor) ) {
			return NOID;
		}
		return *cursor;
	}

	if ( ++(*cursor) <= ids[0] ) {
		return ids[*cursor];
	}

	return NOID;
}

