/* id2children.c - routines to deal with the id2children index */
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

#ifndef DN_INDICES
int
id2children_add(
    Backend	*be,
    Entry	*p,
    Entry	*e
)
{
	DBCache	*db;
	Datum		key;
	char		buf[20];

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> id2children_add( %ld, %ld )\n",
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
	DBCache	*db;
	Datum		key;
	char		buf[20];

	Debug( LDAP_DEBUG_TRACE, "=> id2children_remove( %ld, %ld )\n", p ? p->e_id
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
#if 0
		Debug( LDAP_DEBUG_ANY,
			"<= id2children_remove: idl_delete_key failure\n",
		    0, 0, 0 );
		ldbm_cache_close( be, db );
		return( -1 );
#else
		Debug( LDAP_DEBUG_ANY,
			"<= id2children_remove: ignoring idl_delete_key failure\n",
		    0, 0, 0 );
#endif
	}

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= id2children_remove 0\n", 0, 0, 0 );
	return( 0 );
}
#endif

int
has_children(
    Backend	*be,
    Entry	*p
)
{
	DBCache	*db;
	Datum		key;
	int		rc = 0;
	ID_BLOCK		*idl;
#ifndef DN_INDICES
	char		buf[20];
#endif

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> has_children( %ld )\n", p->e_id , 0, 0 );

#ifndef DN_INDICES
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

#else
	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= has_children -1 could not open \"dn2id%s\"\n",
		    LDBM_SUFFIX, 0, 0 );
		return( 0 );
	}

	key.dsize = strlen( p->e_ndn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_ONE_PREFIX, p->e_ndn );
#endif

	idl = idl_fetch( be, db, key );

	ldbm_cache_close( be, db );

	if( idl != NULL ) {
		idl_free( idl );
		rc = 1;
	}

	Debug( LDAP_DEBUG_TRACE, "<= has_children( %ld ): %s\n",
		p->e_id, rc ? "yes" : "no", 0 );
	return( rc );
}
