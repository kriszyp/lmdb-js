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
#include "back-bdb.h"

#ifdef BDB_FILTER_INDICES
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
	DBT		key;

#ifdef NEW_LOGGING
	LDAP_LOG(( "index", LDAP_LEVEL_ENTRY,
		"key_read: enter\n" ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> key_read\n", 0, 0, 0 );
#endif

	DBzero( &key );
	key.data = k->bv_val;
	key.size = k->bv_len;

	rc = bdb_idl_fetch_key( be, db, txn, key, ids );

	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "index", LDAP_LEVEL_ENTRY,
			"bdb_key_read: failed (%d)\n",
			rc ));
#else
		Debug( LDAP_DEBUG_TRACE, "<= bdb_index_read: failed (%d)\n",
			rc, 0, 0 );
#endif
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG(( "index", LDAP_LEVEL_ENTRY,
			"bdb_key_read: %ld candidates\n",
			idl ? ID_BLOCK_NIDS(idl) : 0 ));
#else
		Debug( LDAP_DEBUG_TRACE, "<= bdb_index_read %ld candidates\n",
	    	idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
#endif
	}

	return rc;
}
#endif

#ifdef BDB_INDEX
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
	LDAP_LOG(( "index", LDAP_LEVEL_ENTRY,
		"key_change: %s ID %lx\n",
		op == SLAP_INDEX_ADD_OP ? "Add" : "Delete", (long)id ));
#else
	Debug( LDAP_DEBUG_TRACE, "=> key_change(%s,%lx)\n",
		op == SLAP_INDEX_ADD_OP ? "ADD":"DELETE", (long) id, 0 );
#endif

	DBTzero( &key );
	key.data = k->bv_val;
	key.size = k->bv_len;

	if (op == SLAP_INDEX_ADD_OP) {
	    /* Add values */
	    rc = bdb_idl_insert_key( be, db, txn, &key, id );

	} else {
	    /* Delete values */
	    rc = bdb_idl_delete_key( be, db, txn, &key, id );
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "index", LDAP_LEVEL_ENTRY,
		"key_change: return %d\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE, "<= key_change %d\n", rc, 0, 0 );
#endif

	return rc;
}
#endif
