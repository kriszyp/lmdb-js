/* id2children.c - routines to deal with the id2children index */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

int
id2children_add(
    Backend	*be,
    Entry	*p,
    Entry	*e
)
{
	struct dbcache	*db;
	Datum		key;
	int		len, rc;
	ID_BLOCK		*idl;
	char		buf[20];

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> id2children_add( %lu, %lu )\n",
	       p ? p->e_id : 0, e->e_id, 0 );

	if ( (db = ldbm_cache_open( be, "id2children", LDBM_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= id2children_add -1 could not open \"id2children%s\"\n",
		    LDBM_SUFFIX, 0, 0 );
		return( -1 );
	}

	sprintf( buf, "%c%ld", EQ_PREFIX, p ? p->e_id : 0 );
	key.dptr = buf;
	key.dsize = strlen( buf ) + 1;

	if ( idl_insert_key( be, db, key, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "<= id2children_add -1 (idl_insert)\n",
		    0, 0, 0 );
		ldbm_cache_close( be, db );
		return( -1 );
	}

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= id2children_add 0\n", 0, 0, 0 );
	return( 0 );
}


int
id2children_remove(
    Backend	*be,
    Entry	*p,
    Entry	*e
)
{
	struct dbcache	*db;
	Datum		key;
	int		len, rc;
	ID_BLOCK		*idl;
	char		buf[20];

	Debug( LDAP_DEBUG_TRACE, "=> id2children_remove( %lu, %lu )\n", p ? p->e_id
	    : 0, e->e_id, 0 );

	if ( (db = ldbm_cache_open( be, "id2children", LDBM_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= id2children_remove -1 could not open \"id2children%s\"\n",
		    LDBM_SUFFIX, 0, 0 );
		return( -1 );
	}

	ldbm_datum_init( key );
	sprintf( buf, "%c%ld", EQ_PREFIX, p ? p->e_id : 0 );
	key.dptr = buf;
	key.dsize = strlen( buf ) + 1;

	if ( idl_delete_key( be, db, key, e->e_id ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "<= id2children_remove -1 (idl_delete)\n",
		    0, 0, 0 );
		ldbm_cache_close( be, db );
		return( -1 );
	}

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= id2children_remove 0\n", 0, 0, 0 );
	return( 0 );
}

int
has_children(
    Backend	*be,
    Entry	*p
)
{
	struct dbcache	*db;
	Datum		key;
	int		rc;
	ID_BLOCK		*idl;
	char		buf[20];

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> has_children( %lu )\n", p->e_id , 0, 0 );

	if ( (db = ldbm_cache_open( be, "id2children", LDBM_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= has_children -1 could not open \"id2children%s\"\n",
		    LDBM_SUFFIX, 0, 0 );
		return( 0 );
	}

	sprintf( buf, "%c%ld", EQ_PREFIX, p->e_id );
	key.dptr = buf;
	key.dsize = strlen( buf ) + 1;

	idl = idl_fetch( be, db, key );

	ldbm_cache_close( be, db );
	rc = idl ? 1 : 0;
	idl_free( idl );

	Debug( LDAP_DEBUG_TRACE, "<= has_children %d\n", rc, 0, 0 );
	return( rc );
}
