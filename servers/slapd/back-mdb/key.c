/* index.c - routines for dealing with attribute indexes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2011 The OpenLDAP Foundation.
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
#include "back-mdb.h"
#include "idl.h"

/* read a key */
int
mdb_key_read(
	Backend	*be,
	MDB_txn *txn,
	MDB_dbi dbi,
	struct berval *k,
	ID *ids,
	MDB_cursor **saved_cursor,
	int get_flag
)
{
	int rc;
	MDB_val key;

	Debug( LDAP_DEBUG_TRACE, "=> key_read\n", 0, 0, 0 );

	key.mv_size = k->bv_len;
	key.mv_data = k->bv_val;

	rc = mdb_idl_fetch_key( be, txn, dbi, &key, ids, saved_cursor, get_flag );

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "<= mdb_index_read: failed (%d)\n",
			rc, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<= mdb_index_read %ld candidates\n",
			(long) MDB_IDL_N(ids), 0, 0 );
	}

	return rc;
}

/* Add or remove stuff from index files */
int
mdb_key_change(
	Backend *be,
	MDB_txn *txn,
	MDB_dbi dbi,
	struct berval *k,
	ID id,
	int op
)
{
	int	rc;
	MDB_val	key;

	Debug( LDAP_DEBUG_TRACE, "=> key_change(%s,%lx)\n",
		op == SLAP_INDEX_ADD_OP ? "ADD":"DELETE", (long) id, 0 );

	key.mv_size = k->bv_len;
	key.mv_data = k->bv_val;

	if (op == SLAP_INDEX_ADD_OP) {
		/* Add values */
		rc = mdb_idl_insert_key( be, txn, dbi, &key, id );
		if ( rc == MDB_KEYEXIST ) rc = 0;
	} else {
		/* Delete values */
		rc = mdb_idl_delete_key( be, txn, dbi, &key, id );
		if ( rc == MDB_NOTFOUND ) rc = 0;
	}

	Debug( LDAP_DEBUG_TRACE, "<= key_change %d\n", rc, 0, 0 );

	return rc;
}
