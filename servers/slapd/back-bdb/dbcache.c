/* dbcache.c - manage cache of open databases */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <sys/stat.h>

#include "slap.h"
#include "back-bdb.h"
#include "lutil_hash.h"

/* Pass-thru hash function. Since the indexer is already giving us hash
 * values as keys, we don't need BDB to re-hash them.
 */
static u_int32_t
bdb_db_hash(
	DB *db,
	const void *bytes,
	u_int32_t length
)
{
	u_int32_t ret = 0;
	unsigned char *dst = (unsigned char *)&ret;
	const unsigned char *src = (const unsigned char *)bytes;

	if ( length > sizeof(u_int32_t) )
		length = sizeof(u_int32_t);

	while ( length ) {
		*dst++ = *src++;
		length--;
	}
	return ret;
}

int
bdb_db_cache(
	Backend	*be,
	DB_TXN *tid,
	const char *name,
	DB **dbout )
{
	int i;
	int rc;
	int flags;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	struct bdb_db_info *db;
	char *file;
	DBT lockobj;
	DB_LOCK lock;
	u_int32_t locker = 0;

	*dbout = NULL;

	for( i=BDB_NDB; i < BDB_INDICES && bdb->bi_databases[i]; i++ ) {
		if( !strcmp( bdb->bi_databases[i]->bdi_name, name) ) {
			*dbout = bdb->bi_databases[i]->bdi_db;
			return 0;
		}
	}

	lockobj.data = "bdb_db_cache";
	lockobj.size = sizeof("bdb_db_cache");

	if (tid) {
		locker = TXN_ID( tid );
	} else {
#ifdef BDB_REUSE_LOCKERS
#define	op	NULL	/* implicit arg in LOCK_ID */
#endif
		rc = LOCK_ID( bdb->bi_dbenv, &locker );
		if (rc) return rc;
	}
	rc = LOCK_GET( bdb->bi_dbenv, locker, 0, &lockobj,
		DB_LOCK_WRITE, &lock );
	if (rc) return rc;

	/* check again! may have been added by another thread */
	for( i=BDB_NDB; i < BDB_INDICES && bdb->bi_databases[i]; i++ ) {
		if( !strcmp( bdb->bi_databases[i]->bdi_name, name) ) {
			*dbout = bdb->bi_databases[i]->bdi_db;
			LOCK_PUT( bdb->bi_dbenv, &lock);
			return 0;
		}
	}

	if( i >= BDB_INDICES ) {
		LOCK_PUT( bdb->bi_dbenv, &lock);
		return -1;
	}

	db = (struct bdb_db_info *) ch_calloc(1, sizeof(struct bdb_db_info));

	db->bdi_name = ch_strdup( name );

	rc = db_create( &db->bdi_db, bdb->bi_dbenv, 0 );
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( CACHE, ERR, 
			"bdb_db_cache: db_create(%s) failed: %s (%d)\n", 
			bdb->bi_dbenv_home, db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_ANY,
			"bdb_db_cache: db_create(%s) failed: %s (%d)\n",
			bdb->bi_dbenv_home, db_strerror(rc), rc );
#endif
		LOCK_PUT( bdb->bi_dbenv, &lock);
		return rc;
	}

	rc = db->bdi_db->set_pagesize( db->bdi_db, BDB_PAGESIZE );
	rc = db->bdi_db->set_h_hash( db->bdi_db, bdb_db_hash );
	rc = db->bdi_db->set_flags( db->bdi_db, DB_DUP | DB_DUPSORT );
	rc = db->bdi_db->set_dup_compare( db->bdi_db, bdb_bt_compare );

	file = ch_malloc( strlen( name ) + sizeof(BDB_SUFFIX) );
	sprintf( file, "%s" BDB_SUFFIX, name );

#ifdef HAVE_EBCDIC
	__atoe( file );
#endif
	flags = bdb->bi_db_opflags | DB_CREATE | DB_THREAD;
	if ( !tid ) flags |= DB_AUTO_COMMIT;
	rc = DB_OPEN( db->bdi_db, tid,
		file, NULL /* name */,
		DB_HASH, flags,
		bdb->bi_dbenv_mode );

	ch_free( file );

	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( CACHE, ERR, 
			"bdb_db_cache: db_open(%s) failed: %s (%d)\n", 
			name, db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_ANY,
			"bdb_db_cache: db_open(%s) failed: %s (%d)\n",
			name, db_strerror(rc), rc );
#endif
		LOCK_PUT( bdb->bi_dbenv, &lock);
		return rc;
	}

	bdb->bi_databases[i] = db;
	bdb->bi_ndatabases = i+1;

	*dbout = db->bdi_db;

	LOCK_PUT( bdb->bi_dbenv, &lock );
	return 0;
}
