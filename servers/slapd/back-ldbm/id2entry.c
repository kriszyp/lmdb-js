/* id2entry.c - routines to deal with the id2entry index */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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

#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

/*
 * This routine adds (or updates) an entry on disk.
 * The cache should already be updated. 
 */

int
id2entry_add( Backend *be, Entry *e )
{
	DBCache	*db;
	Datum		key, data;
	int		len, rc, flags;
#ifndef WORDS_BIGENDIAN
	ID		id;
#endif

	ldbm_datum_init( key );
	ldbm_datum_init( data );

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "id2entry_add: (%s)%ld\n", e->e_dn, e->e_id, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> id2entry_add( %ld, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );
#endif


	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
		   "id2entry_add: could not open/create id2entry%s\n", 
		   LDBM_SUFFIX, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry%s\n",
		    LDBM_SUFFIX, 0, 0 );
#endif

		return( -1 );
	}

#ifdef WORDS_BIGENDIAN
	key.dptr = (char *) &e->e_id;
#else
	id = htonl(e->e_id);
	key.dptr = (char *) &id;
#endif
	key.dsize = sizeof(ID);

	ldap_pvt_thread_mutex_lock( &entry2str_mutex );
	data.dptr = entry2str( e, &len );
	data.dsize = len + 1;

	/* store it */
	flags = LDBM_REPLACE;
	rc = ldbm_cache_store( db, key, data, flags );

	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );

	ldbm_cache_close( be, db );

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "id2entry_add: return %d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= id2entry_add %d\n", rc, 0, 0 );
#endif


	return( rc );
}

int
id2entry_delete( Backend *be, Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	DBCache	*db;
	Datum		key;
	int		rc;
#ifndef WORDS_BIGENDIAN
	ID		id;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "id2entry_delete: (%s)%ld\n", e->e_dn, e->e_id, 0 );
#else
	Debug(LDAP_DEBUG_TRACE, "=> id2entry_delete( %ld, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );
#endif


#ifdef notdef
#ifdef LDAP_RDWR_DEBUG
	/* check for writer lock */
	assert(ldap_pvt_thread_rdwr_writers(&e->e_rdwr) == 1);
#endif
#endif

	ldbm_datum_init( key );

	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			   "id2entry_delete: could not open/create id2entry%s\n",
			   LDBM_SUFFIX, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry%s\n",
		    LDBM_SUFFIX, 0, 0 );
#endif

		return( -1 );
	}

	if ( cache_delete_entry( &li->li_cache, e ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			   "id2entry_delete: Could not delete (%s)%ld from cache\n",
			   e->e_dn, e->e_id, 0 );
#else
		Debug(LDAP_DEBUG_ANY, "could not delete %ld (%s) from cache\n",
		    e->e_id, e->e_dn, 0 );
#endif

	}

#ifdef WORDS_BIGENDIAN
	key.dptr = (char *) &e->e_id;
#else
	id = htonl(e->e_id);
	key.dptr = (char *) &id;
#endif
	key.dsize = sizeof(ID);

	rc = ldbm_cache_delete( db, key );

	ldbm_cache_close( be, db );

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, "id2entry_delete: return %d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= id2entry_delete %d\n", rc, 0, 0 );
#endif

	return( rc );
}

/* returns entry with reader/writer lock */
Entry *
id2entry_rw( Backend *be, ID id, int rw )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	DBCache	*db;
	Datum		key, data;
	Entry		*e;
#ifndef WORDS_BIGENDIAN
	ID		id2;
#endif

	ldbm_datum_init( key );
	ldbm_datum_init( data );

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, 
		   "id2entry_rw: %s (%ld)\n", rw ? "write" : "read", id, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> id2entry_%s( %ld )\n",
		rw ? "w" : "r", id, 0 );
#endif


	if ( (e = cache_find_entry_id( &li->li_cache, id, rw )) != NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, DETAIL1, 
			   "id2entry_rw: %s (%ld) 0x%lx (cache).\n",
			   rw ? "write" : "read", id, (unsigned long)e  );
#else
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) 0x%lx (cache)\n",
			rw ? "w" : "r", id, (unsigned long) e );
#endif

		return( e );
	}

	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			   "id2entry_rw: could not open id2entry%s\n", LDBM_SUFFIX, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "Could not open id2entry%s\n",
		    LDBM_SUFFIX, 0, 0 );
#endif

		return( NULL );
	}

#ifdef WORDS_BIGENDIAN
	key.dptr = (char *) &id;
#else
	id2 = htonl(id);
	key.dptr = (char *) &id2;
#endif
	key.dsize = sizeof(ID);

	data = ldbm_cache_fetch( db, key );

	if ( data.dptr == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			   "id2entry_rw: (%ld) not found\n", id, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) not found\n",
			rw ? "w" : "r", id, 0 );
#endif

		ldbm_cache_close( be, db );
		return( NULL );
	}

	e = str2entry( data.dptr );
	ldbm_datum_free( db->dbc_db, data );
	ldbm_cache_close( be, db );

	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			   "id2entry_rw: %s of %ld failed\n", rw ? "write" : "read", id, 0);
#else
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) (failed)\n",
			rw ? "w" : "r", id, 0 );
#endif

		return( NULL );
	}

	e->e_id = id;

	if ( slapMode == SLAP_SERVER_MODE
			&& cache_add_entry_rw( &li->li_cache, e, rw ) != 0 )
	{
		entry_free( e );

		/* XXX this is a kludge.
		 * maybe the entry got added underneath us
		 * There are many underlying race condtions in the cache/disk code.
		 */
		if ( (e = cache_find_entry_id( &li->li_cache, id, rw )) != NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( INDEX, DETAIL1, 
				   "id2entry_rw: %s of %ld 0x%lx (cache)\n",
				   rw ? "write" : "read", id, (unsigned long)e  );
#else
			Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) 0x%lx (cache)\n",
				rw ? "w" : "r", id, (unsigned long) e );
#endif

			return( e );
		}

#ifdef NEW_LOGGING
		LDAP_LOG( INDEX, ERR, 
			   "id2entry_rw: %s of %ld (cache add failed)\n",
			   rw ? "write" : "read", id, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) (cache add failed)\n",
			rw ? "w" : "r", id, 0 );
#endif

		return NULL;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( INDEX, ENTRY, 
		   "id2entry_rw: %s of %ld 0x%lx (disk)\n",
		   rw ? "write" : "read", id, (unsigned long)e  );
#else
	Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) 0x%lx (disk)\n",
		rw ? "w" : "r", id, (unsigned long) e );
#endif

	if ( slapMode == SLAP_SERVER_MODE ) {
		/* marks the entry as committed, so it will get added to the cache
		 * when the lock is released */
		cache_entry_commit( e );
	}

	return( e );
}
