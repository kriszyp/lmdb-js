/* cache.c - routines to maintain an in-core cache of entries */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#include "back-ldbm.h"

/* LDBM backend specific entry info -- visible only to the cache */
struct ldbm_entry_info {
	ldap_pvt_thread_rdwr_t	lei_rdwr;	/* reader/writer lock */

	/*
	 * remaining fields require backend cache lock to access
	 * These items are specific to the LDBM backend and should
	 * be hidden.
	 */
	int		lei_state;	/* for the cache */

	int		lei_refcnt;	/* # threads ref'ing this entry */
	struct entry	*lei_lrunext;	/* for cache lru list */
	struct entry	*lei_lruprev;
};
#define LEI(e)	((struct ldbm_entry_info *) ((e)->e_private))

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
cache_set_state( struct cache *cache, Entry *e, int state )
{
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	LEI(e)->lei_state = state;

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
}

static int
cache_entry_rdwr_lock(Entry *e, int rw)
{
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%slock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);

	if (rw)
		return ldap_pvt_thread_rdwr_wlock(&LEI(e)->lei_rdwr);
	else
		return ldap_pvt_thread_rdwr_rlock(&LEI(e)->lei_rdwr);
}

static int
cache_entry_rdwr_trylock(Entry *e, int rw)
{
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%strylock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);

	if (rw)
		return ldap_pvt_thread_rdwr_wtrylock(&LEI(e)->lei_rdwr);
	else
		return ldap_pvt_thread_rdwr_rtrylock(&LEI(e)->lei_rdwr);
}

static int
cache_entry_rdwr_unlock(Entry *e, int rw)
{
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%sunlock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);

	if (rw)
		return ldap_pvt_thread_rdwr_wunlock(&LEI(e)->lei_rdwr);
	else
		return ldap_pvt_thread_rdwr_runlock(&LEI(e)->lei_rdwr);
}

static int
cache_entry_rdwr_init(Entry *e)
{
	return ldap_pvt_thread_rdwr_init( &LEI(e)->lei_rdwr );
}

static int
cache_entry_rdwr_destroy(Entry *e)
{
	return ldap_pvt_thread_rdwr_destroy( &LEI(e)->lei_rdwr );
}

static int
cache_entry_private_init( Entry*e )
{
	struct ldbm_entry_info *lei;

	if( e->e_private != NULL ) {
		return 1;
	}

	e->e_private = ch_calloc(1, sizeof(struct ldbm_entry_info));

	if( cache_entry_rdwr_init( e ) != 0 ) {
		free( LEI(e) );
		return 1;
	} 

	return 0;
}

static int
cache_entry_private_destroy( Entry*e )
{
	struct ldbm_entry_info *lei;

	if( e->e_private == NULL ) {
		return 1;
	}

	cache_entry_rdwr_destroy( e );

	free( e->e_private );
	e->e_private = NULL;
	return 0;
}

static void
cache_return_entry_rw( struct cache *cache, Entry *e, int rw )
{
	Debug( LDAP_DEBUG_TRACE, "====> cache_return_entry_%s\n",
		rw ? "w" : "r", 0, 0);

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	cache_entry_rdwr_unlock(e, rw);

	if ( --LEI(e)->lei_refcnt == 0 &&
		LEI(e)->lei_state == ENTRY_STATE_DELETED )
	{
		cache_entry_private_destroy( e );
		entry_free( e );
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
}

void
cache_return_entry_r( struct cache *cache, Entry *e )
{
	cache_return_entry_rw(cache, e, 0);
}

void
cache_return_entry_w( struct cache *cache, Entry *e )
{
	cache_return_entry_rw(cache, e, 1);
}


#define LRU_DELETE( cache, e ) { \
	if ( LEI(e)->lei_lruprev != NULL ) { \
		LEI(LEI(e)->lei_lruprev)->lei_lrunext = LEI(e)->lei_lrunext; \
	} else { \
		cache->c_lruhead = LEI(e)->lei_lrunext; \
	} \
	if ( LEI(e)->lei_lrunext != NULL ) { \
		LEI(LEI(e)->lei_lrunext)->lei_lruprev = LEI(e)->lei_lruprev; \
	} else { \
		cache->c_lrutail = LEI(e)->lei_lruprev; \
	} \
}

#define LRU_ADD( cache, e ) { \
	LEI(e)->lei_lrunext = cache->c_lruhead; \
	if ( LEI(e)->lei_lrunext != NULL ) { \
		LEI(LEI(e)->lei_lrunext)->lei_lruprev = e; \
	} \
	cache->c_lruhead = e; \
	LEI(e)->lei_lruprev = NULL; \
	if ( cache->c_lrutail == NULL ) { \
		cache->c_lrutail = e; \
	} \
}

/*
 * cache_add_entry_rw - create and lock an entry in the cache
 * returns:	0	entry has been created and locked
 *		1	entry already existed
 *		-1	something bad happened
 */
int
cache_add_entry_rw(
    struct cache	*cache,
    Entry		*e,
    int			state,
	int		rw
)
{
	int	i, rc;
	Entry	*ee;

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( e->e_private != NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"====> cache_add_entry: entry %20s id %lu already cached.\n",
		    e->e_dn, e->e_id, 0 );
		return( -1 );
	}

	if( cache_entry_private_init(e) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"====> cache_add_entry: entry %20s id %lu: private init failed!\n",
		    e->e_dn, e->e_id, 0 );
		return( -1 );
	}

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		cache_entrydn_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_TRACE,
			"====> cache_add_entry: entry %20s id %lu already in dn cache\n",
		    e->e_dn, e->e_id, 0 );

		cache_entry_private_destroy(e);

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

		cache_entry_private_destroy(e);

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( -1 );
	}

	cache_entry_rdwr_lock( e, rw );

	LEI(e)->lei_state = state;
	LEI(e)->lei_refcnt = 1;

	/* lru */
	LRU_ADD( cache, e );
	if ( ++cache->c_cursize > cache->c_maxsize ) {
		/*
		 * find the lru entry not currently in use and delete it.
		 * in case a lot of entries are in use, only look at the
		 * first 10 on the tail of the list.
		 */
		i = 0;
		while ( cache->c_lrutail != NULL &&
			LEI(cache->c_lrutail)->lei_refcnt != 0 &&
			i < 10 )
		{
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
		while ( cache->c_lrutail != NULL &&
			LEI(cache->c_lrutail)->lei_refcnt == 0 &&
			cache->c_cursize > cache->c_maxsize )
		{
			e = cache->c_lrutail;

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
 * cache_update_entry - update a LOCKED entry which has been deleted.
 * returns:	0	entry has been created and locked
 *		1	entry already existed
 *		-1	something bad happened
 */
int
cache_update_entry(
    struct cache	*cache,
    Entry		*e
)
{
	int	i, rc;
	Entry	*ee;

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( e->e_private == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"====> cache_update_entry: entry %20s id %lu no private data.\n",
		    e->e_dn, e->e_id, 0 );
		return( -1 );
	}

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		cache_entrydn_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_TRACE,
			"====> cache_add_entry: entry %20s id %lu already in dn cache\n",
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

	/* lru */
	LRU_ADD( cache, e );
	if ( ++cache->c_cursize > cache->c_maxsize ) {
		/*
		 * find the lru entry not currently in use and delete it.
		 * in case a lot of entries are in use, only look at the
		 * first 10 on the tail of the list.
		 */
		i = 0;
		while ( cache->c_lrutail != NULL &&
			LEI(cache->c_lrutail)->lei_refcnt != 0 &&
			i < 10 )
		{
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
		while ( cache->c_lrutail != NULL &&
			LEI(cache->c_lrutail)->lei_refcnt == 0 &&
			cache->c_cursize > cache->c_maxsize )
		{
			e = cache->c_lrutail;

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
cache_find_entry_dn2id(
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
		if ( LEI(ep)->lei_state == ENTRY_STATE_DELETED ||
			LEI(ep)->lei_state == ENTRY_STATE_CREATING )
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
cache_find_entry_id(
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
		if ( LEI(ep)->lei_state == ENTRY_STATE_DELETED ||
			LEI(ep)->lei_state == ENTRY_STATE_CREATING )
		{
			/* free cache mutex */
			ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
			return( NULL );
		}

		/* acquire reader lock */
		if ( cache_entry_rdwr_trylock(ep, rw) == LDAP_PVT_THREAD_EBUSY ) {
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
                
		LEI(ep)->lei_refcnt++;

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
cache_delete_entry(
    struct cache	*cache,
    Entry		*e
)
{
	int	rc;

	Debug( LDAP_DEBUG_TRACE, "====> cache_delete_entry:\n", 0, 0, 0 );

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
	LEI(e)->lei_state = ENTRY_STATE_DELETED;

	return( 0 );
}

#ifdef LDAP_DEBUG

static void
lru_print( struct cache *cache )
{
	Entry	*e;

	fprintf( stderr, "LRU queue (head to tail):\n" );
	for ( e = cache->c_lruhead; e != NULL; e = LEI(e)->lei_lrunext ) {
		fprintf( stderr, "\tdn %20s id %lu refcnt %d\n", e->e_dn,
		    e->e_id, LEI(e)->lei_refcnt );
	}
	fprintf( stderr, "LRU queue (tail to head):\n" );
	for ( e = cache->c_lrutail; e != NULL; e = LEI(e)->lei_lruprev ) {
		fprintf( stderr, "\tdn %20s id %lu refcnt %d\n", e->e_dn,
		    e->e_id, LEI(e)->lei_refcnt );
	}
}

#endif

