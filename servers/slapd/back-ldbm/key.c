/* index.c - routines for dealing with attribute indexes */
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

/* read a key */
int
key_read(
    Backend	*be,
	DBCache *db,
    struct berval *k,
	ID_BLOCK **idout
)
{
	Datum   	key;
	ID_BLOCK		*idl;

	Debug( LDAP_DEBUG_TRACE, "=> key_read\n", 0, 0, 0 );

	ldbm_datum_init( key );
	key.dptr = k->bv_val;
	key.dsize = k->bv_len;

	idl = idl_fetch( be, db, key );

	Debug( LDAP_DEBUG_TRACE, "<= index_read %ld candidates\n",
	       idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );

	*idout = idl;
	return LDAP_SUCCESS;
}

/* Add or remove stuff from index files */
int
key_change(
    Backend		*be,
    DBCache	*db,
    struct berval *k,
    ID			id,
    int			op
)
{
	int	rc;
	Datum   key;

	Debug( LDAP_DEBUG_TRACE, "=> key_change(%s,%lx)\n",
		op == SLAP_INDEX_ADD_OP ? "ADD":"DELETE", (long) id, 0 );

	ldbm_datum_init( key );
	key.dptr = k->bv_val;
	key.dsize = k->bv_len;

	if (op == SLAP_INDEX_ADD_OP) {
	    /* Add values */
	    rc = idl_insert_key( be, db, key, id );

	} else {
	    /* Delete values */
	    rc = idl_delete_key( be, db, key, id );
	}


	Debug( LDAP_DEBUG_TRACE, "<= key_change %d\n", rc, 0, 0 );

	ldap_pvt_thread_yield();

	return rc;
}
