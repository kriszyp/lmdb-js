/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

int bdb_id2entry_add(
	Backend *be,
	DB_TXN *tid,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DBT key, data;
	struct berval *bv;
	int rc;

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	DBTzero( &data );
	bv2DBT( bv, &data );

	rc = bdb->bi_id2entry->bdi_db->put( bdb->bi_id2entry->bdi_db,
		tid, &key, &data, DB_NOOVERWRITE );

	ber_bvfree( bv );
	return rc;
}
