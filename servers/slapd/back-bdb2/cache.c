/* cache.c - routines to maintain an in-core cache of entries */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#include "back-bdb2.h"

static int	cache_delete_entry_internal(struct cache *cache, Entry *e);
#ifdef LDAP_DEBUG
static void	lru_print(struct cache *cache);
#endif

/*
 * the cache has three entry points (ways to find things):
 *
 * 	by entry	e.g., if you already have an entry from the cache
 *			and want to delete it. (really by entry ptr)
 *	by dn		e.g., when looking for the base object of a search
 *	by id		e.g., for search candidates
 *
 * these correspond to three different avl trees that are maintained.
 */

static int
cache_entry_cmp( Entry *e1, Entry *e2 )
{
	return( e1 < e2 ? -1 : (e1 > e2 ? 1 : 0) );
}

static int
cache_entrydn_cmp( Entry *e1, Entry *e2 )
{
	/* compare their normalized UPPERCASED dn's */
	return( strcmp( e1->e_ndn, e2->e_ndn ) );
}

static int
cache_entryid_cmp( Entry *e1, Entry *e2 )
{
	return( e1->e_id < e2->e_id ? -1 : (e1->e_id > e2->e_id ? 1 : 0) );
}

void
bdb2i_cache_set_state( struct cache *cache, Entry *e, int state )
{
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	e->e_state = state;

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
}

#ifdef not_used
static void
cache_return_entry( struct cache *cache, Entry *e )
{
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( --e->e_refcnt == 0 && e->e_state == ENTRY_STATE_DELETED ) {
		entry_free( e );
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
}
#endif

static void
cache_return_entry_rw( struct cache *cache, Entry *e, int rw )
{
	Debug( LDAP_DEBUG_TRACE, "====> cache_return_entry_%s\n",
		rw ? "w" : "r", 0, 0);

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	entry_rdwr_unlock(e, rw);;

	if ( --e->e_refcnt == 0 && e->e_state == ENTRY_STATE_DELETED ) {
		entry_free( e );
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
}

void
bdb2i_cache_return_entry_r( struct cache *cache, Entry *e )
{
	cache_return_entry_rw(cache, e, 0);
}

void
bdb2i_cache_return_entry_w( struct cache *cache, Entry *e )
{
	cache_return_entry_rw(cache, e, 1);
}


#define LRU_DELETE( cache, e ) { \
	if ( e->e_lruprev != NULL ) { \
		e->e_lruprev->e_lrunext = e->e_lrunext; \
	} else { \
		cache->c_lruhead = e->e_lrunext; \
	} \
	if ( e->e_lrunext != NULL ) { \
		e->e_lrunext->e_lruprev = e->e_lruprev; \
	} else { \
		cache->c_lrutail = e->e_lruprev; \
	} \
}

#define LRU_ADD( cache, e ) { \
	e->e_lrunext = cache->c_lruhead; \
	if ( e->e_lrunext != NULL ) { \
		e->e_lrunext->e_lruprev = e; \
	} \
	cache->c_lruhead = e; \
	e->e_lruprev = NULL; \
	if ( cache->c_lrutail == NULL ) { \
		cache->c_lrutail = e; \
	} \
}

/*
 * cache_create_entry_lock - create an entry in the cache, and lock it.
 * returns:	0	entry has been created and locked
 *		1	entry already existed
 *		-1	something bad happened
 */
int
bdb2i_cache_add_entry_lock(
    struct cache	*cache,
    Entry		*e,
    int			state
)
{
	int	i, rc;
	Entry	*ee;

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		cache_entrydn_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_TRACE,
			"====> cache_add_entry lock: entry %20s id %lu already in dn cache\n",
		    e->e_dn, e->e_id, 0 );

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( 1 );
	}

	/* id tree */
	if ( avl_insert( &cache->c_idtree, (caddr_t) e,
		cache_entryid_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_ANY,
			"====> entry %20s id %lu already in id cache\n",
		    e->e_dn, e->e_id, 0 );

		/* delete from dn tree inserted above */
		if ( avl_delete( &cache->c_dntree, (caddr_t) e,
			cache_entrydn_cmp ) == NULL )
		{
			Debug( LDAP_DEBUG_ANY, "====> can't delete from dn cache\n",
			    0, 0, 0 );
		}

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( -1 );
	}

	e->e_state = state;
	e->e_refcnt = 1;

	/* lru */
	LRU_ADD( cache, e );
	if ( ++cache->c_cursize > cache->c_maxsize ) {
		/*
		 * find the lru entry not currently in use and delete it.
		 * in case a lot of entries are in use, only look at the
		 * first 10 on the tail of the list.
		 */
		i = 0;
		while ( cache->c_lrutail != NULL && cache->c_lrutail->e_refcnt
		    != 0 && i < 10 ) {
			/* move this in-use entry to the front of the q */
			ee = cache->c_lrutail;
			LRU_DELETE( cache, ee );
			LRU_ADD( cache, ee );
			i++;
		}

		/*
		 * found at least one to delete - try to get back under
		 * the max cache size.
		 */
		while ( cache->c_lrutail != NULL && cache->c_lrutail->e_refcnt
                    == 0 && cache->c_cursize > cache->c_maxsize ) {
			e = cache->c_lrutail;

		/* XXX check for writer lock - should also check no readers pending */
#ifdef LDAP_DEBUG
			assert(!ldap_pvt_thread_rdwr_active(&e->e_rdwr));
#endif

			/* delete from cache and lru q */
			rc = cache_delete_entry_internal( cache, e );

			entry_free( e );
		}
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
	return( 0 );
}

/*
 * cache_find_entry_dn2id - find an entry in the cache, given dn
 */

ID
bdb2i_cache_find_entry_dn2id(
	Backend		*be,
    struct cache	*cache,
    char		*dn
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	Entry		e, *ep;
	ID			id;

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	e.e_dn = dn;
	e.e_ndn = dn_normalize_case( ch_strdup( dn ) );

	if ( (ep = (Entry *) avl_find( cache->c_dntree, (caddr_t) &e,
		cache_entrydn_cmp )) != NULL )
	{
		/*
		 * ep now points to an unlocked entry
		 * we do not need to lock the entry if we only
		 * check the state, refcnt, LRU, and id.
		 */
		free(e.e_ndn);

		Debug(LDAP_DEBUG_TRACE, "====> cache_find_entry_dn2id: found dn: %s\n",
			dn, 0, 0);

		/*
		 * entry is deleted or not fully created yet
		 */
		if ( ep->e_state == ENTRY_STATE_DELETED ||
			ep->e_state == ENTRY_STATE_CREATING )
		{
			/* free cache mutex */
			ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
			return( NOID );
		}

		/* lru */
		LRU_DELETE( cache, ep );
		LRU_ADD( cache, ep );

		/* save id */
		id = ep->e_id;

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

		return( id );
	}

	free(e.e_ndn);

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

	return( NOID );
}

/*
 * cache_find_entry_id - find an entry in the cache, given id
 */

Entry *
bdb2i_cache_find_entry_id(
	struct cache	*cache,
	ID				id,
	int				rw
)
{
	Entry	e;
	Entry	*ep;

	e.e_id = id;

try_again:
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( (ep = (Entry *) avl_find( cache->c_idtree, (caddr_t) &e,
		cache_entryid_cmp )) != NULL )
	{
		Debug(LDAP_DEBUG_TRACE,
			"====> cache_find_entry_dn2id: found id: %ld rw: %d\n",
			id, rw, 0);

		/*
		 * entry is deleted or not fully created yet
		 */
		if ( ep->e_state == ENTRY_STATE_DELETED ||
			ep->e_state == ENTRY_STATE_CREATING )
		{
			/* free cache mutex */
			ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
			return( NULL );
		}

		/* acquire reader lock */
		if ( entry_rdwr_trylock(ep, rw) == LDAP_PVT_THREAD_EBUSY ) {
			/* could not acquire entry lock...
			 * owner cannot free as we have the cache locked.
			 * so, unlock the cache, yield, and try again.
			 */

			/* free cache mutex */
			ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
			ldap_pvt_thread_yield();
			goto try_again;
		}

		/* lru */
		LRU_DELETE( cache, ep );
		LRU_ADD( cache, ep );
                
		ep->e_refcnt++;

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

		return( ep );
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

	return( NULL );
}

/*
 * cache_delete_entry - delete the entry e from the cache.  the caller
 * should have obtained e (increasing its ref count) via a call to one
 * of the cache_find_* routines.  the caller should *not* call the
 * cache_return_entry() routine prior to calling cache_delete_entry().
 * it performs this function.
 *
 * returns:	0	e was deleted ok
 *		1	e was not in the cache
 *		-1	something bad happened
 */
int
bdb2i_cache_delete_entry(
    struct cache	*cache,
    Entry		*e
)
{
	int	rc;

	Debug( LDAP_DEBUG_TRACE, "====> cache_delete_entry:\n", 0, 0, 0 );

	/* XXX check for writer lock - should also check no readers pending */
#ifdef LDAP_DEBUG
	assert(ldap_pvt_thread_rdwr_writers(&e->e_rdwr));
#endif

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	rc = cache_delete_entry_internal( cache, e );

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
	return( rc );
}

static int
cache_delete_entry_internal(
    struct cache	*cache,
    Entry		*e
)
{
	int rc = 0; 	/* return code */

	/* dn tree */
	if ( avl_delete( &cache->c_dntree, (caddr_t) e, cache_entrydn_cmp )
		== NULL )
	{
		rc = -1;
	}

	/* id tree */
	if ( avl_delete( &cache->c_idtree, (caddr_t) e, cache_entryid_cmp )
		== NULL )
	{
		rc = -1;
	}

	if (rc != 0) {
		return rc;
	}

	/* lru */
	LRU_DELETE( cache, e );
	cache->c_cursize--;

	/*
	 * flag entry to be freed later by a call to cache_return_entry()
	 */
	e->e_state = ENTRY_STATE_DELETED;

	return( 0 );
}

#ifdef LDAP_DEBUG

static void
lru_print( struct cache *cache )
{
	Entry	*e;

	fprintf( stderr, "LRU queue (head to tail):\n" );
	for ( e = cache->c_lruhead; e != NULL; e = e->e_lrunext ) {
		fprintf( stderr, "\tdn %20s id %lu refcnt %d\n", e->e_dn,
		    e->e_id, e->e_refcnt );
	}
	fprintf( stderr, "LRU queue (tail to head):\n" );
	for ( e = cache->c_lrutail; e != NULL; e = e->e_lruprev ) {
		fprintf( stderr, "\tdn %20s id %lu refcnt %d\n", e->e_dn,
		    e->e_id, e->e_refcnt );
	}
}

#endif

