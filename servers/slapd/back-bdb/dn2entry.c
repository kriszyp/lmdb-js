/* dn2entry.c - routines to deal with the dn2id / id2entry glue */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
bdb_dn2entry(
	BackendDB	*be,
	DB_TXN *tid,
	const char *dn,
	Entry **e,
	Entry **matched,
	int flags )
{
	int rc;
	ID		id;
	char	*matchedDN = NULL;

	Debug(LDAP_DEBUG_TRACE, "bdb_dn2entry: dn: \"%s\"\n",
		dn, 0, 0 );

	*e = NULL;

	if( matched != NULL ) {
		*matched = NULL;
		rc = bdb_dn2id_matched( be, tid, dn, &id, &matchedDN );
	} else {
		rc = bdb_dn2id( be, tid, dn, &id );
	}

	if( rc != 0 ) {
		return rc;
	}

	if( matchedDN == NULL ) {
		rc = bdb_id2entry( be, tid, id, e );
	} else {
		ch_free( matchedDN );
		rc = bdb_id2entry( be, tid, id, matched );
	}

	return rc;
}
