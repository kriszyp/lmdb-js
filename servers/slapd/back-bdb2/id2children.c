/* id2children.c - routines to deal with the id2children index */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

int
bdb2i_id2children_add(
    BackendDB	*be,
    Entry	*p,
    Entry	*e
)
{
	struct dbcache	*db;
	Datum		key;
	char		buf[20];

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_id2children_add( %ld, %ld )\n",
	       p ? p->e_id : 0, e->e_id, 0 );

	if ( (db = bdb2i_cache_open( be, "id2children", BDB2_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_id2children_add -1 could not open \"id2children%s\"\n",
		    BDB2_SUFFIX, 0, 0 );
		return( -1 );
	}

	sprintf( buf, "%c%ld", EQ_PREFIX, p ? p->e_id : 0 );
	key.dptr = buf;
	key.dsize = strlen( buf ) + 1;

	if ( bdb2i_idl_insert_key( be, db, key, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2children_add -1 (idl_insert)\n",
		    0, 0, 0 );
		bdb2i_cache_close( be, db );
		return( -1 );
	}

	bdb2i_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2children_add 0\n", 0, 0, 0 );
	return( 0 );
}


int
bdb2i_id2children_remove(
    BackendDB	*be,
    Entry	*p,
    Entry	*e
)
{
	struct dbcache	*db;
	Datum		key;
	char		buf[20];

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_id2children_remove( %ld, %ld )\n",
		p ? p->e_id : 0, e->e_id, 0 );

	if ( (db = bdb2i_cache_open( be, "id2children", BDB2_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_id2children_remove -1 could not open \"id2children%s\"\n",
		    BDB2_SUFFIX, 0, 0 );
		return( -1 );
	}

	ldbm_datum_init( key );
	sprintf( buf, "%c%ld", EQ_PREFIX, p ? p->e_id : 0 );
	key.dptr = buf;
	key.dsize = strlen( buf ) + 1;

	if ( bdb2i_idl_delete_key( be, db, key, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2children_remove -1 (idl_delete)\n",
		    0, 0, 0 );
		bdb2i_cache_close( be, db );
		return( -1 );
	}

	bdb2i_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2children_remove 0\n", 0, 0, 0 );
	return( 0 );
}

int
bdb2i_has_children(
    BackendDB	*be,
    Entry	*p
)
{
	struct dbcache	*db;
	Datum		key;
	int		rc = 0;
	ID_BLOCK		*idl;
	char		buf[20];

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_has_children( %ld )\n", p->e_id , 0, 0 );

	if ( (db = bdb2i_cache_open( be, "id2children", BDB2_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_has_children -1 could not open \"id2children%s\"\n",
		    BDB2_SUFFIX, 0, 0 );
		return( 0 );
	}

	sprintf( buf, "%c%ld", EQ_PREFIX, p->e_id );
	key.dptr = buf;
	key.dsize = strlen( buf ) + 1;

	idl = bdb2i_idl_fetch( be, db, key );

	bdb2i_cache_close( be, db );

	if( idl != NULL ) {
		bdb2i_idl_free( idl );
		rc = 1;
	}

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_has_children( %ld ): %s\n",
					p->e_id, rc ? "yes" : "no", 0 );
	return( rc );
}
