/* dn2entry.c - routines to deal with the dn2id / id2entry glue */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"


/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry.
 */

int
bdb_dn2entry_rw(
	BackendDB	*be,
	DB_TXN *tid,
	struct berval *dn,
	Entry **e,
	Entry **matched,
	int flags,
	int rw,
	u_int32_t locker,
	DB_LOCK *lock )
{
	int rc;
	ID		id, id2 = 0;

#ifdef NEW_LOGGING
	LDAP_LOG ( CACHE, ARGS, "bdb_dn2entry_rw(\"%s\")\n", dn->bv_val, 0, 0 );
#else
	Debug(LDAP_DEBUG_TRACE, "bdb_dn2entry_rw(\"%s\")\n",
		dn->bv_val, 0, 0 );
#endif

	*e = NULL;

	if( matched != NULL ) {
		*matched = NULL;
		rc = bdb_dn2id_matched( be, tid, dn, &id, &id2, flags );
	} else {
		rc = bdb_dn2id( be, tid, dn, &id, flags );
	}

	if( rc != 0 ) {
		return rc;
	}

	if( id2 == 0 ) {
		rc = bdb_id2entry_rw( be, tid, id, e, rw, locker, lock );
	} else {
		rc = bdb_id2entry_r( be, tid, id2, matched, locker, lock );
	}

	return rc;
}
