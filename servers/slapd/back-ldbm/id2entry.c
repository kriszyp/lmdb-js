/* id2entry.c - routines to deal with the id2entry index */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"

extern struct dbcache	*ldbm_cache_open();
extern Datum		ldbm_cache_fetch();
extern char		*dn_parent();
extern Entry		*str2entry();
extern char		*entry2str();
extern pthread_mutex_t	entry2str_mutex;

int
id2entry_add( Backend *be, Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key, data;
	int		len, rc, flags;

#ifdef LDBM_USE_DB2
	memset( &key, 0, sizeof( key ) );
	memset( &data, 0, sizeof( data ) );
#endif

	Debug( LDAP_DEBUG_TRACE, "=> id2entry_add( %d, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry%s\n",
		    LDBM_SUFFIX, 0, 0 );
		return( -1 );
	}

	key.dptr = (char *) &e->e_id;
	key.dsize = sizeof(ID);

	pthread_mutex_lock( &entry2str_mutex );
	data.dptr = entry2str( e, &len, 1 );
	data.dsize = len + 1;

	/* store it */
	flags = LDBM_REPLACE;
	if ( li->li_flush_wrt ) flags |= LDBM_SYNC;
	rc = ldbm_cache_store( db, key, data, flags );

	pthread_mutex_unlock( &entry2str_mutex );

	ldbm_cache_close( be, db );
	(void) cache_add_entry_lock( &li->li_cache, e, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= id2entry_add %d\n", rc, 0, 0 );

	/* XXX should entries be born locked, i.e. apply writer lock here? */
	return( rc );
}

int
id2entry_delete( Backend *be, Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "=> id2entry_delete( %d, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

	/* XXX - check for writer lock - should also check no reader pending */
	assert(pthread_rdwr_wchk_np(&e->e_rdwr));

#ifdef LDBM_USE_DB2
	memset( &key, 0, sizeof( key ) );
#endif

	/* XXX - check for writer lock - should also check no reader pending */
	Debug (LDAP_DEBUG_TRACE,
		"rdwr_Xchk: readers_reading: %d writer_writing: %d\n",
		e->e_rdwr.readers_reading, e->e_rdwr.writer_writing, 0);
 
	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry%s\n",
		    LDBM_SUFFIX, 0, 0 );
		return( -1 );
	}

	if ( cache_delete_entry( &li->li_cache, e ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "could not delete %d (%s) from cache\n",
		    e->e_id, e->e_dn, 0 );
	}

	key.dptr = (char *) &e->e_id;
	key.dsize = sizeof(ID);

	rc = ldbm_cache_delete( db, key );

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= id2entry_delete %d\n", rc, 0, 0 );
	return( rc );
}

/* XXX returns entry with reader/writer lock */
Entry *
id2entry( Backend *be, ID id, int rw )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key, data;
	Entry		*e;

#ifdef LDBM_USE_DB2
	memset( &key, 0, sizeof( key ) );
	memset( &data, 0, sizeof( data ) );
#endif

	Debug( LDAP_DEBUG_TRACE, "=> id2entry_%s( %ld )\n",
		rw ? "w" : "r", id, 0 );

	if ( (e = cache_find_entry_id( &li->li_cache, id, rw )) != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s 0x%x (cache)\n",
			rw ? "w" : "r", e, 0 );
		return( e );
	}

	if ( (db = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, LDBM_WRCREAT ))
		== NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open id2entry%s\n",
		    LDBM_SUFFIX, 0, 0 );
		return( NULL );
	}

	key.dptr = (char *) &id;
	key.dsize = sizeof(ID);

	data = ldbm_cache_fetch( db, key );

	if ( data.dptr == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) not found\n",
			rw ? "w" : "r", id, 0 );
		ldbm_cache_close( be, db );
		return( NULL );
	}

	e = str2entry( data.dptr );

	ldbm_datum_free( db->dbc_db, data );
	ldbm_cache_close( be, db );

	if ( e == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld )  (failed)\n",
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
	(void) cache_add_entry_lock( &li->li_cache, e, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= id2entry_%s( %ld ) (disk)\n",
		rw ? "w" : "r", id, 0 );
	return( e );
}

Entry *
id2entry_r( Backend *be, ID id )
{
	return( id2entry( be, id, 0 ) );
}

Entry *
id2entry_2( Backend *be, ID id )
{
	return( id2entry( be, id, 1 ) );
}

