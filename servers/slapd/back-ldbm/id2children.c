/* id2children.c - routines to deal with the id2children index */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "has_children: enter %ld\n", p->e_id ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> has_children( %ld )\n", p->e_id , 0, 0 );
#endif


	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX,
	    LDBM_WRCREAT )) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_ERR,
			   "has_children: could not open \"dn2id%s\"\n",
			   LDBM_SUFFIX ));
#else
		Debug( LDAP_DEBUG_ANY,
		    "<= has_children -1 could not open \"dn2id%s\"\n",
		    LDBM_SUFFIX, 0, 0 );
#endif

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

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "has_children: id (%ld) %s children.\n",
		   p->e_id, rc ? "has" : "doesn't have" ));
#else
	Debug( LDAP_DEBUG_TRACE, "<= has_children( %ld ): %s\n",
		p->e_id, rc ? "yes" : "no", 0 );
#endif

	return( rc );
}
