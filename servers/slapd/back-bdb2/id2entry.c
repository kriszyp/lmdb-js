/* id2entry.c - routines to deal with the id2entry index */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

int
bdb2i_id2entry_add( BackendDB *be, Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key, data;
	int		len, rc, flags;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_id2entry_add( %lu, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

	if ( (db = bdb2i_cache_open( be, "id2entry", BDB2_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry%s\n",
		    BDB2_SUFFIX, 0, 0 );
		return( -1 );
	}

	key.dptr = (char *) &e->e_id;
	key.dsize = sizeof(ID);

	ldap_pvt_thread_mutex_lock( &entry2str_mutex );
	data.dptr = entry2str( e, &len, 1 );
	data.dsize = len + 1;

	/* store it */
	flags = LDBM_REPLACE;
	if ( li->li_dbcachewsync ) flags |= LDBM_SYNC;
	rc = bdb2i_cache_store( db, key, data, flags );

	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );

	bdb2i_cache_close( be, db );
	(void) bdb2i_cache_add_entry_lock( &li->li_cache, e, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2entry_add %d\n", rc, 0, 0 );

	/* XXX should entries be born locked, i.e. apply writer lock here? */
	return( rc );
}

int
bdb2i_id2entry_delete( BackendDB *be, Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key;
	int		rc;

	Debug(LDAP_DEBUG_TRACE, "=> bdb2i_id2entry_delete( %lu, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

#ifdef LDAP_DEBUG
	/* check for writer lock */
	assert(ldap_pvt_thread_rdwr_writers(&e->e_rdwr));
#endif

	ldbm_datum_init( key );

	if ( (db = bdb2i_cache_open( be, "id2entry", BDB2_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry%s\n",
		    BDB2_SUFFIX, 0, 0 );
		return( -1 );
	}

	if ( bdb2i_cache_delete_entry( &li->li_cache, e ) != 0 ) {
		Debug(LDAP_DEBUG_ANY, "could not delete %lu (%s) from cache\n",
		    e->e_id, e->e_dn, 0 );
	}

	key.dptr = (char *) &e->e_id;
	key.dsize = sizeof(ID);

	rc = bdb2i_cache_delete( db, key );

	bdb2i_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2entry_delete %d\n", rc, 0, 0 );
	return( rc );
}

/* XXX returns entry with reader/writer lock */
Entry *
bdb2i_id2entry( BackendDB *be, ID id, int rw )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key, data;
	Entry		*e;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_id2entry_%s( %ld )\n",
		rw ? "w" : "r", id, 0 );

	if ( (e = bdb2i_cache_find_entry_id( &li->li_cache, id, rw )) != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2entry_%s 0x%lx (cache)\n",
			rw ? "w" : "r", (unsigned long)e, 0 );
		return( e );
	}

	if ( (db = bdb2i_cache_open( be, "id2entry", BDB2_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open id2entry%s\n",
		    BDB2_SUFFIX, 0, 0 );
		return( NULL );
	}

	key.dptr = (char *) &id;
	key.dsize = sizeof(ID);

	data = bdb2i_cache_fetch( db, key );

	if ( data.dptr == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2entry_%s( %ld ) not found\n",
			rw ? "w" : "r", id, 0 );
		bdb2i_cache_close( be, db );
		return( NULL );
	}

	e = str2entry( data.dptr );

	ldbm_datum_free( db->dbc_db, data );
	bdb2i_cache_close( be, db );

	if ( e == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2entry_%s( %ld )  (failed)\n",
			rw ? "w" : "r", id, 0 );
		return( NULL );
	}

	/* acquire required reader/writer lock */
	if (entry_rdwr_lock(e, rw)) {
		/* XXX set DELETE flag?? */
		entry_free(e);
		return(NULL);
	}

	e->e_id = id;
	(void) bdb2i_cache_add_entry_lock( &li->li_cache, e, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_id2entry_%s( %ld ) (disk)\n",
		rw ? "w" : "r", id, 0 );
	return( e );
}

Entry *
bdb2i_id2entry_r( BackendDB *be, ID id )
{
	return( bdb2i_id2entry( be, id, 0 ) );
}

Entry *
bdb2i_id2entry_w( BackendDB *be, ID id )
{
	return( bdb2i_id2entry( be, id, 1 ) );
}

