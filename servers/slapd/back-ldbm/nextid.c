/* nextid.c - keep track of the next id to be given out */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-ldbm.h"

static ID
next_id_read( Backend *be )
{
	ID id = NOID;
	Datum key, data;
	DBCache *db;

	if ( (db = ldbm_cache_open( be, "nextid", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create nextid" LDBM_SUFFIX "\n",
			0, 0, 0 );
		return( NOID );
	}

	ldbm_datum_init( key );
	key.dptr = (char *) &id;
	key.dsize = sizeof(ID);

	data = ldbm_cache_fetch( db, key );

	if( data.dptr != NULL ) {
		AC_MEMCPY( &id, data.dptr, sizeof( ID ) );
		ldbm_datum_free( db->dbc_db, data );

	} else {
		id = 1;
	}

	ldbm_cache_close( be, db );
	return id;
}

ID
next_id_write( Backend *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Datum key, data;
	DBCache *db;
	ID noid = NOID;
	int flags;

	if ( (db = ldbm_cache_open( be, "nextid", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create nextid" LDBM_SUFFIX "\n",
		    0, 0, 0 );
		return( NOID );
	}

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.dptr = (char *) &noid;
	key.dsize = sizeof(ID);

	data.dptr = (char *) &id;
	data.dsize = sizeof(ID);

	flags = LDBM_REPLACE;
	if ( ldbm_cache_store( db, key, data, flags ) != 0 ) {
		id = NOID;
	}

	ldbm_cache_close( be, db );
	return id;
}

ID
next_id_get( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID id = NOID;

	ldap_pvt_thread_mutex_lock( &li->li_nextid_mutex );

	if ( li->li_nextid == NOID ) {
		li->li_nextid = next_id_read( be );
	}

	id = li->li_nextid;

	ldap_pvt_thread_mutex_unlock( &li->li_nextid_mutex );
	return id;
}

ID
next_id( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID id = NOID;

	ldap_pvt_thread_mutex_lock( &li->li_nextid_mutex );

	if ( li->li_nextid == NOID ) {
		li->li_nextid = next_id_read( be );
	}

	if ( li->li_nextid != NOID ) {
		id = li->li_nextid++;

		(void) next_id_write( be, li->li_nextid );
	}

	ldap_pvt_thread_mutex_unlock( &li->li_nextid_mutex );
	return id;

}
