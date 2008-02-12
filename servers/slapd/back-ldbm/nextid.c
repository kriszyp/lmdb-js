/* nextid.c - keep track of the next id to be given out */
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
#include <ac/param.h>

#include "slap.h"
#include "back-ldbm.h"

static int
next_id_read( Backend *be, ID *idp )
{
	Datum key, data;
	DBCache *db;

	*idp = NOID;

	if ( (db = ldbm_cache_open( be, "nextid", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create nextid" LDBM_SUFFIX "\n",
			0, 0, 0 );

		return( -1 );
	}

	ldbm_datum_init( key );
	key.dptr = (char *) idp;
	key.dsize = sizeof(ID);

	data = ldbm_cache_fetch( db, key );

	if( data.dptr != NULL ) {
		AC_MEMCPY( idp, data.dptr, sizeof( ID ) );
		ldbm_datum_free( db->dbc_db, data );

	} else {
		*idp = 1;
	}

	ldbm_cache_close( be, db );
	return( 0 );
}

int
next_id_write( Backend *be, ID id )
{
	Datum key, data;
	DBCache *db;
	ID noid = NOID;
	int flags, rc = 0;

	if ( (db = ldbm_cache_open( be, "nextid", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create nextid" LDBM_SUFFIX "\n",
		    0, 0, 0 );

		return( -1 );
	}

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.dptr = (char *) &noid;
	key.dsize = sizeof(ID);

	data.dptr = (char *) &id;
	data.dsize = sizeof(ID);

	flags = LDBM_REPLACE;
	if ( ldbm_cache_store( db, key, data, flags ) != 0 ) {
		rc = -1;
	}

	ldbm_cache_close( be, db );
	return( rc );
}

int
next_id_get( Backend *be, ID *idp )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int rc = 0;

	*idp = NOID;

	if ( li->li_nextid == NOID ) {
		if ( ( rc = next_id_read( be, idp ) ) ) {
			return( rc );
		}
		li->li_nextid = *idp;
	}

	*idp = li->li_nextid;

	return( rc );
}

int
next_id( Backend *be, ID *idp )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int rc = 0;

	if ( li->li_nextid == NOID ) {
		if ( ( rc = next_id_read( be, idp ) ) ) {
			return( rc );
		}
		li->li_nextid = *idp;
	}

	*idp = li->li_nextid++;
	if ( next_id_write( be, li->li_nextid ) ) {
		rc = -1;
	}

	return( rc );
}
