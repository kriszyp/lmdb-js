/* id2children.c - routines to deal with the id2children index */
/* $OpenLDAP$ */
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

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> has_children( %ld )\n", p->e_id , 0, 0 );

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

	idl = idl_fetch( be, db, key );

	free( key.dptr );

	ldbm_cache_close( be, db );

	if( idl != NULL ) {
		idl_free( idl );
		rc = 1;
	}

	Debug( LDAP_DEBUG_TRACE, "<= has_children( %ld ): %s\n",
		p->e_id, rc ? "yes" : "no", 0 );
	return( rc );
}
