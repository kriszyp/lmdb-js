/* dn2id.c - routines to deal with the dn2id index */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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
    const char	*dn,
    ID		id
)
{
	int		rc, flags;
	DBCache	*db;
	Datum		key, data;
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_add( \"%s\", %ld )\n", dn, id, 0 );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create dn2id%s\n",
		    LDBM_SUFFIX, 0, 0 );
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

	rc = ldbm_cache_store( db, key, data, flags );

	free( key.dptr );

	if ( rc != -1 ) {
		char *pdn = dn_parent( NULL, dn );

		if( pdn != NULL ) {
			ldbm_datum_init( key );
			key.dsize = strlen( pdn ) + 2;
			key.dptr = ch_malloc( key.dsize );
			sprintf( key.dptr, "%c%s", DN_ONE_PREFIX, pdn );
			rc = idl_insert_key( be, db, key, id );
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
				sprintf( key.dptr, "%c%s",
					DN_SUBTREE_PREFIX, subtree[i] );

				rc = idl_insert_key( be, db, key, id );

				free( key.dptr );

				if(rc == -1) break;
			}

			charray_free( subtree );
		}

	}

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id_add %d\n", rc, 0, 0 );
	return( rc );
}

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

	(void) memcpy( (char *) &id, data.dptr, sizeof(ID) );

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
    const char	*dn
)
{
	DBCache	*db;
	Datum		key;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_delete( \"%s\" )\n", dn, 0, 0 );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= dn2id_delete could not open dn2id%s\n", LDBM_SUFFIX,
		    0, 0 );
		return( -1 );
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

