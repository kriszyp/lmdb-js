/* index.c - routines for dealing with attribute indexes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
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
#include "back-bdb.h"
#include "idl.h"

/* read a key */
int
bdb_key_read(
	Backend	*be,
	DB *db,
	DB_TXN *txn,
	struct berval *k,
	ID *ids
)
{
	int rc;
	DBT key;

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "key_read: enter\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> key_read\n", 0, 0, 0 );
#endif

	DBTzero( &key );
	bv2DBT(k,&key);
	key.ulen = key.size;
	key.flags = DB_DBT_USERMEM;

	rc = bdb_idl_fetch_key( be, db, txn, &key, ids );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, "bdb_key_read: failed (%d)\n", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "<= bdb_index_read: failed (%d)\n",
			rc, 0, 0 );
#endif
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, DETAIL1, 
			"bdb_key_read: %ld candidates\n", (long)BDB_IDL_N(ids), 0, 0);
#else
		Debug( LDAP_DEBUG_TRACE, "<= bdb_index_read %ld candidates\n",
			(long) BDB_IDL_N(ids), 0, 0 );
#endif
	}

	return rc;
}

/* Add or remove stuff from index files */
int
bdb_key_change(
	Backend *be,
	DB *db,
	DB_TXN *txn,
	struct berval *k,
	ID id,
	int op
)
{
	int	rc;
	DBT	key;

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "key_change: %s ID %lx\n",
		op == SLAP_INDEX_ADD_OP ? "Add" : "Delete", (long) id, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> key_change(%s,%lx)\n",
		op == SLAP_INDEX_ADD_OP ? "ADD":"DELETE", (long) id, 0 );
#endif

	DBTzero( &key );
	bv2DBT(k,&key);
	key.ulen = key.size;
	key.flags = DB_DBT_USERMEM;

	if (op == SLAP_INDEX_ADD_OP) {
		/* Add values */
		rc = bdb_idl_insert_key( be, db, txn, &key, id );
		if ( rc == DB_KEYEXIST ) rc = 0;
	} else {
		/* Delete values */
		rc = bdb_idl_delete_key( be, db, txn, &key, id );
		if ( rc == DB_NOTFOUND ) rc = 0;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, RESULTS, "key_change: return %d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= key_change %d\n", rc, 0, 0 );
#endif

	return rc;
}
