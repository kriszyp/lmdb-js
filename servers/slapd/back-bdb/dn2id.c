/* dn2id.c - routines to deal with the dn2id index */
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

int
bdb_index_dn_add(
    Backend	*be,
	DB_TXN *txn,
    const char	*dn,
    ID		id
)
{
	int		rc;
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_index_dn_add( \"%s\", %ld )\n", dn, id, 0 );
	assert( id != NOID );

	DBTzero( &key );
	key.size = strlen( dn ) + 2;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = DN_BASE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn, key.size - 1 );

	DBTzero( &data );
	data.data = (char *) &id;
	data.size = sizeof( id );

	/* store it -- don't override */
	rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
	if( rc != 0 ) {
		goto done;
	}

	{
		char *pdn = dn_parent( NULL, dn );
		((char *)(key.data))[0] = DN_ONE_PREFIX;

		if( pdn != NULL ) {
			key.size = strlen( pdn ) + 2;
			AC_MEMCPY( &((char*)key.data)[1],
				pdn, key.size - 1 );

			rc = bdb_idl_insert_key( be, db, txn, &key, id );
			free( pdn );

			if( rc != 0 ) {
				goto done;
			}
		}
	}

	if ( rc != -1 ) {
		char **subtree = dn_subtree( NULL, dn );

		if( subtree != NULL ) {
			int i;
			((char *)key.data)[0] = DN_SUBTREE_PREFIX;
			for( i=0; subtree[i] != NULL; i++ ) {
				key.size = strlen( subtree[i] ) + 2;
				AC_MEMCPY( &((char *)key.data)[1],
					subtree[i], key.size - 1 );

				rc = bdb_idl_insert_key( be, db, txn, &key, id );

				if( rc != 0 ) {
					goto done;
				}
			}

			charray_free( subtree );
		}
	}

done:
	ch_free( key.data );
	Debug( LDAP_DEBUG_TRACE, "<= bdb_index_dn_add %d\n", rc, 0, 0 );
	return( rc );
}

#if 0
ID
dn2id(
    Backend	*be,
    const char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	DBCache	*db;
	ID		id;
	Datum		key, data;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id( \"%s\" )\n", dn, 0, 0 );

	/* first check the cache */
	if ( (id = cache_find_entry_dn2id( be, &li->li_cache, dn )) != NOID ) {
		Debug( LDAP_DEBUG_TRACE, "<= dn2id %ld (in cache)\n", id,
			0, 0 );
		return( id );
	}

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= dn2id could not open dn2id%s\n",
			LDBM_SUFFIX, 0, 0 );
		return( NOID );
	}

	ldbm_datum_init( key );

	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_BASE_PREFIX, dn );

	data = ldbm_cache_fetch( db, key );

	ldbm_cache_close( be, db );

	free( key.dptr );

	if ( data.dptr == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= dn2id NOID\n", 0, 0, 0 );
		return( NOID );
	}

	AC_MEMCPY( (char *) &id, data.dptr, sizeof(ID) );

	assert( id != NOID );

	ldbm_datum_free( db->dbc_db, data );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id %ld\n", id, 0, 0 );
	return( id );
}

ID_BLOCK *
dn2idl(
    Backend	*be,
    const char	*dn,
	int		prefix
)
{
	DBCache	*db;
	Datum		key;
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> dn2idl( \"%c%s\" )\n", prefix, dn, 0 );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= dn2idl could not open dn2id%s\n",
			LDBM_SUFFIX, 0, 0 );
		return NULL;
	}

	ldbm_datum_init( key );

	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", prefix, dn );

	idl = idl_fetch( be, db, key );

	ldbm_cache_close( be, db );

	free( key.dptr );

	return( idl );
}


int
dn2id_delete(
    Backend	*be,
    const char	*dn,
	ID id
)
{
	DBCache	*db;
	Datum		key;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_delete( \"%s\", %ld )\n", dn, id, 0 );

	assert( id != NOID );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= dn2id_delete could not open dn2id%s\n", LDBM_SUFFIX,
		    0, 0 );
		return( -1 );
	}


	{
		char *pdn = dn_parent( NULL, dn );

		if( pdn != NULL ) {
			ldbm_datum_init( key );
			key.dsize = strlen( pdn ) + 2;
			key.dptr = ch_malloc( key.dsize );
			sprintf( key.dptr, "%c%s", DN_ONE_PREFIX, pdn );

			(void) idl_delete_key( be, db, key, id );

			free( key.dptr );
			free( pdn );
		}
	}

	{
		char **subtree = dn_subtree( NULL, dn );

		if( subtree != NULL ) {
			int i;
			for( i=0; subtree[i] != NULL; i++ ) {
				ldbm_datum_init( key );
				key.dsize = strlen( subtree[i] ) + 2;
				key.dptr = ch_malloc( key.dsize );
				sprintf( key.dptr, "%c%s",
					DN_SUBTREE_PREFIX, subtree[i] );

				(void) idl_delete_key( be, db, key, id );

				free( key.dptr );
			}

			charray_free( subtree );
		}
	}

	ldbm_datum_init( key );

	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_BASE_PREFIX, dn );

	rc = ldbm_cache_delete( db, key );

	free( key.dptr );

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id_delete %d\n", rc, 0, 0 );
	return( rc );
}

/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry.
 */

Entry *
dn2entry_rw(
    Backend	*be,
    const char	*dn,
    Entry	**matched,
    int         rw
)
{
	ID		id;
	Entry		*e = NULL;
	char		*pdn;

	Debug(LDAP_DEBUG_TRACE, "dn2entry_%s: dn: \"%s\"\n",
		rw ? "w" : "r", dn, 0);

	if( matched != NULL ) {
		/* caller cares about match */
		*matched = NULL;
	}

	if ( (id = dn2id( be, dn )) != NOID &&
		(e = id2entry_rw( be, id, rw )) != NULL )
	{
		return( e );
	}

	if ( id != NOID ) {
		Debug(LDAP_DEBUG_ANY,
			"dn2entry_%s: no entry for valid id (%ld), dn \"%s\"\n",
			rw ? "w" : "r", id, dn);
		/* must have been deleted from underneath us */
		/* treat as if NOID was found */
	}

	/* caller doesn't care about match */
	if( matched == NULL ) return NULL;

	/* entry does not exist - see how much of the dn does exist */
	/* dn_parent checks returns NULL if dn is suffix */
	if ( (pdn = dn_parent( be, dn )) != NULL ) {
		/* get entry with reader lock */
		if ( (e = dn2entry_r( be, pdn, matched )) != NULL ) {
			*matched = e;
		}
		free( pdn );
	}

	return NULL;
}

#endif