/* id2children.c - routines to deal with the id2children index */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

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

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_has_children( %ld )\n", p->e_id , 0, 0 );

	if ( (db = bdb2i_cache_open( be, "dn2id", BDB2_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_has_children: could not open \"dn2id" BDB2_SUFFIX "\"\n",
		    0, 0, 0 );
		return( 0 );
	}

	key.dsize = strlen( p->e_ndn ) + 2;
	key.dptr = ch_malloc( key.dsize );
	sprintf( key.dptr, "%c%s", DN_ONE_PREFIX, p->e_ndn );

	idl = bdb2i_idl_fetch( be, db, key );

	free( key.dptr );

	bdb2i_cache_close( be, db );

	if( idl != NULL ) {
		bdb2i_idl_free( idl );
		rc = 1;
	}

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_has_children( %ld ): %s\n",
					p->e_id, rc ? "yes" : "no", 0 );
	return( rc );
}
