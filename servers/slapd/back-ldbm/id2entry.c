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
extern Entry		*cache_find_entry_id();
extern char		*entry2str();
extern pthread_mutex_t	entry2str_mutex;

int
id2entry_add( Backend *be, Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key, data;
	int		len, rc, flags;

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
	if ( li->li_flush_wrt ) flags != LDBM_SYNC;
	rc = ldbm_cache_store( db, key, data, flags );

	pthread_mutex_unlock( &entry2str_mutex );

	ldbm_cache_close( be, db );
	(void) cache_add_entry_lock( &li->li_cache, e, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= id2entry_add %d\n", rc, 0, 0 );
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

Entry *
id2entry( Backend *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key, data;
	Entry		*e;

	Debug( LDAP_DEBUG_TRACE, "=> id2entry( %ld )\n", id, 0, 0 );

	if ( (e = cache_find_entry_id( &li->li_cache, id )) != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= id2entry 0x%x (cache)\n", e, 0,
		    0 );
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
		Debug( LDAP_DEBUG_TRACE, "<= id2entry( %ld ) not found\n", id,
		    0, 0 );
		ldbm_cache_close( be, db );
		return( NULL );
	}

	if ( (e = str2entry( data.dptr )) != NULL ) {
		e->e_id = id;
		(void) cache_add_entry_lock( &li->li_cache, e, 0 );
	}

	ldbm_datum_free( db->dbc_db, data );
	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= id2entry( %ld ) 0x%x (disk)\n", id, e, 0 );
	return( e );
}
