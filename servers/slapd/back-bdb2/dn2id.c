/* dn2id.c - routines to deal with the dn2id index */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

int
bdb2i_dn2id_add(
    BackendDB	*be,
    const char	*dn,
    ID		id
)
{
	int		rc, flags;
	struct dbcache	*db;
	Datum		key, data;
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_dn2id_add( \"%s\", %ld )\n", dn, id, 0 );

	if ( (db = bdb2i_cache_open( be, "dn2id", BDB2_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create dn2id%s\n",
		    BDB2_SUFFIX, 0, 0 );
		return( -1 );
	}

	ldbm_datum_init( key );
	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_BASE_PREFIX, dn );

	ldbm_datum_init( data );
	data.dptr = (char *) &id;
	data.dsize = sizeof(ID);

	flags = LDBM_INSERT;
	if ( li->li_dbcachewsync ) flags |= LDBM_SYNC;

	rc = bdb2i_cache_store( db, key, data, flags );

	free( key.dptr );

	if ( rc != -1 ) {
		char *pdn = dn_parent( NULL, dn );

		if( pdn != NULL ) {
			ldbm_datum_init( key );
			key.dsize = strlen( pdn ) + 2;
			key.dptr = ch_malloc( key.dsize );
			sprintf( key.dptr, "%c%s", DN_ONE_PREFIX, pdn );
			rc = bdb2i_idl_insert_key( be, db, key, id );
			free( key.dptr );
			free( pdn );
		}
	}

	if ( rc != -1 ) {
		char **subtree = dn_subtree( NULL, dn );

		if( subtree != NULL ) {
			int i;
			for( i=0; subtree[i] != NULL; i++ ) {
				ldbm_datum_init( key );
				key.dsize = strlen( subtree[i] ) + 2;
				key.dptr = ch_malloc( key.dsize );
				sprintf( key.dptr, "%c%s", DN_SUBTREE_PREFIX, subtree[i] );

				rc = bdb2i_idl_insert_key( be, db, key, id );

				free( key.dptr );
			}

			charray_free( subtree );
		}
	}

	bdb2i_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_dn2id_add %d\n", rc, 0, 0 );
	return( rc );
}

ID
bdb2i_dn2id(
    BackendDB	*be,
    const char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	ID		id;
	Datum		key, data;

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_dn2id( \"%s\" )\n", dn, 0, 0 );

	/* first check the cache */
	if ( (id = bdb2i_cache_find_entry_dn2id( be, &li->li_cache, dn )) != NOID ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_dn2id %ld (in cache)\n", id,
			0, 0 );
		return( id );
	}

	if ( (db = bdb2i_cache_open( be, "dn2id", BDB2_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= bdb2i_dn2id could not open dn2id%s\n",
			BDB2_SUFFIX, 0, 0 );
		return( NOID );
	}

	ldbm_datum_init( key );

	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_BASE_PREFIX, dn );

	data = bdb2i_cache_fetch( db, key );

	bdb2i_cache_close( be, db );

	free( key.dptr );

	if ( data.dptr == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_dn2id NOID\n", 0, 0, 0 );
		return( NOID );
	}

	(void) memcpy( (char *) &id, data.dptr, sizeof(ID) );

	ldbm_datum_free( db->dbc_db, data );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_dn2id %ld\n", id, 0, 0 );
	return( id );
}

ID_BLOCK *
bdb2i_dn2idl(
    BackendDB	*be,
    const char	*dn,
	int	prefix )
{
	struct dbcache	*db;
	Datum key;
	ID_BLOCK *idl;

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_dn2idl( \"%c%s\" )\n", prefix, dn, 0 );

	if ( (db = bdb2i_cache_open( be, "dn2id", BDB2_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_dn2idl could not open dn2id%s\n", BDB2_SUFFIX,
		    0, 0 );
		return( NULL );
	}

	ldbm_datum_init( key );

	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", prefix, dn );

	idl = bdb2i_idl_fetch( be, db, key );

	free( key.dptr );

	bdb2i_cache_close( be, db );

	return( idl );
}

int
bdb2i_dn2id_delete(
    BackendDB	*be,
    const char	*dn,
	ID id
)
{
	struct dbcache	*db;
	Datum		key;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_dn2id_delete( \"%s\", %ld )\n",
		dn, id, 0 );

	if ( (db = bdb2i_cache_open( be, "dn2id", BDB2_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_dn2id_delete could not open dn2id%s\n", BDB2_SUFFIX,
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
			(void) bdb2i_idl_delete_key( be, db, key, id );
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
				sprintf( key.dptr, "%c%s", DN_SUBTREE_PREFIX, subtree[i] );

				(void) bdb2i_idl_delete_key( be, db, key, id );

				free( key.dptr );
			}

			charray_free( subtree );
		}
	}

	ldbm_datum_init( key );

	key.dsize = strlen( dn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_BASE_PREFIX, dn );

	rc = bdb2i_cache_delete( db, key );

	free( key.dptr );

	bdb2i_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_dn2id_delete %d\n", rc, 0, 0 );
	return( rc );
}

/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry.
 */

Entry *
bdb2i_dn2entry_rw(
    BackendDB	*be,
    const char	*dn,
    Entry	**matched,
    int         rw
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	ID		id;
	Entry		*e = NULL;
	char		*pdn;

	Debug(LDAP_DEBUG_TRACE, "dn2entry_%s: dn: \"%s\"\n",
		rw ? "w" : "r", dn, 0);

	if( matched != NULL ) {
		/* caller cares about match */
		*matched = NULL;
	}

	if ( (id = bdb2i_dn2id( be, dn )) != NOID &&
		(e = bdb2i_id2entry_rw( be, id, rw )) != NULL )
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
		if ( (e = bdb2i_dn2entry_r( be, pdn, matched )) != NULL ) {
			*matched = e;
		}
		free( pdn );
	}

	return( NULL );
}


