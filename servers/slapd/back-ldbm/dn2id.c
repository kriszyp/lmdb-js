/* dn2id.c - routines to deal with the dn2id index */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
dn2id_add(
    Backend	*be,
    struct berval *dn,
    ID		id
)
{
	int		rc, flags;
	DBCache	*db;
	Datum		key, data;
	char		*buf;
	struct berval	ptr, pdn;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2id_add: (%s):%ld\n", dn->bv_val, id ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> dn2id_add( \"%s\", %ld )\n", dn->bv_val, id, 0 );
#endif

	assert( id != NOID );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "dn2id_add: couldn't open/create dn2id%s\n", LDBM_SUFFIX ));
#else
		Debug( LDAP_DEBUG_ANY, "Could not open/create dn2id%s\n",
		    LDBM_SUFFIX, 0, 0 );
#endif

		return( -1 );
	}

	ldbm_datum_init( key );
	key.dsize = dn->bv_len + 2;
	buf = ch_malloc( key.dsize );
	key.dptr = buf;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf + 1;
	ptr.bv_len = dn->bv_len;
	strcpy( ptr.bv_val, dn->bv_val );

	ldbm_datum_init( data );
	data.dptr = (char *) &id;
	data.dsize = sizeof(ID);

	flags = LDBM_INSERT;
	rc = ldbm_cache_store( db, key, data, flags );

	if ( rc != -1 && !be_issuffix( be, &ptr )) {
		buf[0] = DN_SUBTREE_PREFIX;
		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		rc = idl_insert_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		if ( rc != -1 ) {
			rc = dnParent( &ptr, &pdn );

			if( rc == LDAP_SUCCESS ) {
				pdn.bv_val[-1] = DN_ONE_PREFIX;
				key.dsize = pdn.bv_len + 2;
				key.dptr = pdn.bv_val - 1;
				ptr = pdn;
				ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
				rc = idl_insert_key( be, db, key, id );
				ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );
			}
		}
	}

	while ( rc != -1 && !be_issuffix( be, &ptr )) {
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		rc = idl_insert_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		if( rc != 0 ) break;
		rc = dnParent( &ptr, &pdn );
		key.dsize = pdn.bv_len + 2;
		key.dptr = pdn.bv_val - 1;
		ptr = pdn;
	}

	free( buf );
	ldbm_cache_close( be, db );

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2id_add: return %d\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE, "<= dn2id_add %d\n", rc, 0, 0 );
#endif

	return( rc );
}

int
dn2id(
    Backend	*be,
    struct berval *dn,
    ID          *idp
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	DBCache	*db;
	Datum		key, data;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2id: (%s)\n", dn->bv_val ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> dn2id( \"%s\" )\n", dn->bv_val, 0, 0 );
#endif

	assert( idp );

	/* first check the cache */
	if ( (*idp = cache_find_entry_ndn2id( be, &li->li_cache, dn )) != NOID ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
			   "dn2id: (%s)%ld in cache.\n", dn, *idp ));
#else
		Debug( LDAP_DEBUG_TRACE, "<= dn2id %ld (in cache)\n", *idp,
			0, 0 );
#endif

		return( 0 );
	}

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "dn2id: couldn't open dn2id%s\n", LDBM_SUFFIX ));
#else
		Debug( LDAP_DEBUG_ANY, "<= dn2id could not open dn2id%s\n",
			LDBM_SUFFIX, 0, 0 );
#endif
		/*
		 * return code !0 if ldbm cache open failed;
		 * callers should handle this
		 */
		*idp = NOID;
		return( -1 );
	}

	ldbm_datum_init( key );

	key.dsize = dn->bv_len + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_BASE_PREFIX, dn->bv_val );

	data = ldbm_cache_fetch( db, key );

	ldbm_cache_close( be, db );

	free( key.dptr );

	if ( data.dptr == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			   "dn2id: (%s) NOID\n", dn ));
#else
		Debug( LDAP_DEBUG_TRACE, "<= dn2id NOID\n", 0, 0, 0 );
#endif

		*idp = NOID;
		return( 0 );
	}

	AC_MEMCPY( (char *) idp, data.dptr, sizeof(ID) );

	assert( *idp != NOID );

	ldbm_datum_free( db->dbc_db, data );

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2id: %ld\n", *idp ));
#else
	Debug( LDAP_DEBUG_TRACE, "<= dn2id %ld\n", *idp, 0, 0 );
#endif

	return( 0 );
}

int
dn2idl(
    Backend	*be,
    struct berval	*dn,
    int		prefix,
    ID_BLOCK    **idlp
)
{
	DBCache	*db;
	Datum		key;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2idl: \"%c%s\"\n", prefix, dn->bv_val ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> dn2idl( \"%c%s\" )\n", prefix, dn->bv_val, 0 );
#endif

	assert( idlp != NULL );
	*idlp = NULL;

	if ( prefix == DN_SUBTREE_PREFIX && be_issuffix(be, dn) ) {
		*idlp = idl_allids( be );
		return 0;
	}

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "dn2idl: could not open dn2id%s\n", LDBM_SUFFIX ));
#else
		Debug( LDAP_DEBUG_ANY, "<= dn2idl could not open dn2id%s\n",
			LDBM_SUFFIX, 0, 0 );
#endif

		return -1;
	}

	ldbm_datum_init( key );

	key.dsize = dn->bv_len + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", prefix, dn->bv_val );

	*idlp = idl_fetch( be, db, key );

	ldbm_cache_close( be, db );

	free( key.dptr );

	return( 0 );
}


int
dn2id_delete(
    Backend	*be,
    struct berval *dn,
	ID id
)
{
	DBCache	*db;
	Datum		key;
	int		rc;
	char		*buf;
	struct berval	ptr, pdn;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2id_delete: (%s)%ld\n", dn->bv_val, id ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> dn2id_delete( \"%s\", %ld )\n", dn->bv_val, id, 0 );
#endif


	assert( id != NOID );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "dn2id_delete: couldn't open db2id%s\n", LDBM_SUFFIX ));
#else
		Debug( LDAP_DEBUG_ANY,
		    "<= dn2id_delete could not open dn2id%s\n", LDBM_SUFFIX,
		    0, 0 );
#endif

		return( -1 );
	}

	ldbm_datum_init( key );
	key.dsize = dn->bv_len + 2;
	buf = ch_malloc( key.dsize );
	key.dptr = buf;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf + 1;
	ptr.bv_len = dn->bv_len;
	strcpy( ptr.bv_val, dn->bv_val );

	rc = ldbm_cache_delete( db, key );
	
	if( !be_issuffix( be, &ptr )) {
		buf[0] = DN_SUBTREE_PREFIX;
		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		(void) idl_delete_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		rc = dnParent( &ptr, &pdn );

		if( rc == LDAP_SUCCESS ) {
			pdn.bv_val[-1] = DN_ONE_PREFIX;
			key.dsize = pdn.bv_len + 2;
			key.dptr = pdn.bv_val - 1;
			ptr = pdn;

			ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
			(void) idl_delete_key( be, db, key, id );
			ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );
		}
	}

	while ( rc != -1 && !be_issuffix( be, &ptr )) {
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		(void) idl_delete_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		rc = dnParent( &ptr, &pdn );
		key.dsize = pdn.bv_len + 2;
		key.dptr = pdn.bv_val - 1;
		ptr = pdn;
	}

	free( buf );

	ldbm_cache_close( be, db );

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2id_delete: return %d\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE, "<= dn2id_delete %d\n", rc, 0, 0 );
#endif

	return( rc );
}

/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry.
 */

Entry *
dn2entry_rw(
    Backend	*be,
    struct berval *dn,
    Entry	**matched,
    int		rw
)
{
	ID		id;
	Entry		*e = NULL;
	struct berval	pdn;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "dn2entry_rw: %s entry %s\n", rw ? "w" : "r",
		   dn->bv_val ));
#else
	Debug(LDAP_DEBUG_TRACE, "dn2entry_%s: dn: \"%s\"\n",
		rw ? "w" : "r", dn->bv_val, 0);
#endif


	if( matched != NULL ) {
		/* caller cares about match */
		*matched = NULL;
	}

	if ( dn2id( be, dn, &id ) ) {
		/* something bad happened to ldbm cache */
		return( NULL );

	} else if ( id != NOID ) {
		/* try to return the entry */
		if ((e = id2entry_rw( be, id, rw )) != NULL ) {
			return( e );
		}

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "dn2entry_rw: no entry for valid id (%ld), dn (%s)\n",
			   id, dn->bv_val ));
#else
		Debug(LDAP_DEBUG_ANY,
			"dn2entry_%s: no entry for valid id (%ld), dn \"%s\"\n",
			rw ? "w" : "r", id, dn->bv_val);
#endif

		/* must have been deleted from underneath us */
		/* treat as if NOID was found */
	}

	/* caller doesn't care about match */
	if( matched == NULL ) return NULL;

	/* entry does not exist - see how much of the dn does exist */
	if ( !be_issuffix( be, dn ) && dnParent( dn, &pdn ) == LDAP_SUCCESS
		&& pdn.bv_len ) {
		/* get entry with reader lock */
		if ( (e = dn2entry_r( be, &pdn, matched )) != NULL ) {
			*matched = e;
		}
	}

	return NULL;
}

