/* index.c - routines for dealing with attribute indexes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
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
	Datum		key;
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
	Datum	key;

	Debug( LDAP_DEBUG_TRACE, "=> key_change(%s,%lx)\n",
		op == SLAP_INDEX_ADD_OP ? "ADD":"DELETE", (long) id, 0 );


	ldbm_datum_init( key );
	key.dptr = k->bv_val;
	key.dsize = k->bv_len;

	ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
	if (op == SLAP_INDEX_ADD_OP) {
	    /* Add values */
	    rc = idl_insert_key( be, db, key, id );

	} else {
	    /* Delete values */
	    rc = idl_delete_key( be, db, key, id );
	}
	ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );


	Debug( LDAP_DEBUG_TRACE, "<= key_change %d\n", rc, 0, 0 );


	ldap_pvt_thread_yield();

	return rc;
}
