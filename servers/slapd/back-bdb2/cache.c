/* cache.c - routines to maintain an in-core cache of entries */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#include "back-bdb2.h"

/* LDBM backend specific entry info -- visible only to the cache */
struct ldbm_entry_info {
	/*
	 * These items are specific to the LDBM backend and should
	 * be hidden.
	 */
	int		lei_state;	/* for the cache */
#define CACHE_ENTRY_UNDEFINED	0
#define CACHE_ENTRY_CREATING	1
#define CACHE_ENTRY_READY		2
#define CACHE_ENTRY_DELETED		3

	int		lei_refcnt;	/* # threads ref'ing this entry */
	Entry	*lei_lrunext;	/* for cache lru list */
	Entry	*lei_lruprev;
};
#define LEI(e)	((struct ldbm_entry_info *) ((e)->e_private))

static int	cache_delete_entry_internal(struct cache *cache, Entry *e);
#ifdef LDAP_DEBUG
static void	lru_print(struct cache *cache);
#endif

static int
cache_entry_private_init( Entry*e )
{
	assert( e->e_private == NULL );

	if( e->e_private != NULL ) {
		/* this should never happen */
		return 1;
	}

	e->e_private = ch_calloc(1, sizeof(struct ldbm_entry_info));

	return 0;
}

static int
cache_entry_private_destroy( Entry*e )
{
	assert( e->e_private );

	free( e->e_private );
	e->e_private = NULL;
	return 0;
}

void
bdb2i_cache_return_entry_rw( struct cache *cache, Entry *e, int rw )
{
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	assert( e->e_private );

	LEI(e)->lei_refcnt--;

	if ( LEI(e)->lei_state == CACHE_ENTRY_CREATING ) {
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb2i_cache_return_entry_%s( %ld ): created (%d)\n",
			rw ? "w" : "r", e->e_id, LEI(e)->lei_refcnt );

		LEI(e)->lei_state = CACHE_ENTRY_READY;

	} else if ( LEI(e)->lei_state == CACHE_ENTRY_DELETED ) {
		if( LEI(e)->lei_refcnt > 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			"====> bdb2i_cache_return_entry_%s( %ld ): delete pending (%d)\n",
				rw ? "w" : "r", e->e_id, LEI(e)->lei_refcnt );

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"====> bdb2i_cache_return_entry_%s( %ld ): deleted (%d)\n",
				rw ? "w" : "r", e->e_id, LEI(e)->lei_refcnt );

			cache_entry_private_destroy( e );
			entry_free( e );
		}

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb2i_cache_return_entry_%s( %ld ): returned (%d)\n",
			rw ? "w" : "r", e->e_id, LEI(e)->lei_refcnt);
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
}

#define LRU_DELETE( cache, e ) { \
	if ( LEI(e)->lei_lruprev != NULL ) { \
		LEI(LEI(e)->lei_lruprev)->lei_lrunext = LEI(e)->lei_lrunext; \
	} else { \
		(cache)->c_lruhead = LEI(e)->lei_lrunext; \
	} \
	if ( LEI(e)->lei_lrunext != NULL ) { \
		LEI(LEI(e)->lei_lrunext)->lei_lruprev = LEI(e)->lei_lruprev; \
	} else { \
		(cache)->c_lrutail = LEI(e)->lei_lruprev; \
	} \
}

#define LRU_ADD( cache, e ) { \
	LEI(e)->lei_lrunext = (cache)->c_lruhead; \
	if ( LEI(e)->lei_lrunext != NULL ) { \
		LEI(LEI(e)->lei_lrunext)->lei_lruprev = (e); \
	} \
	(cache)->c_lruhead = (e); \
	LEI(e)->lei_lruprev = NULL; \
	if ( (cache)->c_lrutail == NULL ) { \
		(cache)->c_lrutail = (e); \
	} \
}

/*
 * bdb2i_cache_add_entry_rw - create and lock an entry in the cache
 * returns:	0	entry has been created and locked
 *		1	entry already existed
 *		-1	something bad happened
 */
int
bdb2i_cache_add_entry_rw(
    struct cache	*cache,
    Entry		*e,
	int		rw
)
{
	int	i;
	Entry	*ee;

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	assert( e->e_private == NULL );

	if( cache_entry_private_init(e) != 0 ) {
		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

		Debug( LDAP_DEBUG_ANY,
		"====> bdb2i_cache_add_entry( %ld ): \"%s\": private init failed!\n",
		    e->e_id, e->e_dn, 0 );

		return( -1 );
	}

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		(AVL_CMP) entry_dn_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_TRACE,
		"====> bdb2i_cache_add_entry( %ld ): \"%s\": already in dn cache\n",
		    e->e_id, e->e_dn, 0 );

		cache_entry_private_destroy(e);

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( 1 );
	}

	/* id tree */
	if ( avl_insert( &cache->c_idtree, (caddr_t) e,
		(AVL_CMP) entry_id_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_ANY,
		"====> bdb2i_cache_add_entry( %ld ): \"%s\": already in id cache\n",
		    e->e_id, e->e_dn, 0 );

		/* delete from dn tree inserted above */
		if ( avl_delete( &cache->c_dntree, (caddr_t) e,
			(AVL_CMP) entry_dn_cmp ) == NULL )
		{
			Debug( LDAP_DEBUG_ANY, "====> can't delete from dn cache\n",
			    0, 0, 0 );
		}

		cache_entry_private_destroy(e);

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( -1 );
	}

	/* put the entry into 'CREATING' state */
	/* will be marked after when entry is returned */
	LEI(e)->lei_state = CACHE_ENTRY_CREATING;
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
			cache_delete_entry_internal( cache, e );
			cache_entry_private_destroy( e );
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
bdb2i_cache_update_entry(
    struct cache	*cache,
    Entry		*e
)
{
	int	i;
	Entry	*ee;

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	assert( e->e_private );

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		(AVL_CMP) entry_dn_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_TRACE,
		"====> bdb2i_cache_add_entry( %ld ): \"%s\": already in dn cache\n",
		    e->e_id, e->e_dn, 0 );

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( 1 );
	}

	/* id tree */
	if ( avl_insert( &cache->c_idtree, (caddr_t) e,
		(AVL_CMP) entry_id_cmp, avl_dup_error ) != 0 )
	{
		Debug( LDAP_DEBUG_ANY,
		"====> bdb2i_cache_update_entry( %ld ): \"%s\": already in id cache\n",
		    e->e_id, e->e_dn, 0 );

		/* delete from dn tree inserted above */
		if ( avl_delete( &cache->c_dntree, (caddr_t) e,
			(AVL_CMP) entry_dn_cmp ) == NULL )
		{
			Debug( LDAP_DEBUG_ANY, "====> can't delete from dn cache\n",
			    0, 0, 0 );
		}

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
		return( -1 );
	}

	/* put the entry into 'CREATING' state */
	/* will be marked after when entry is returned */
	LEI(e)->lei_state = CACHE_ENTRY_CREATING;

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
			cache_delete_entry_internal( cache, e );
			cache_entry_private_destroy( e );
			entry_free( e );
		}
	}

	/* free cache mutex */
	ldap_pvt_thread_mutex_unlock( &cache->c_mutex );
	return( 0 );
}

/*
 * bdb2i_cache_find_entry_dn2id - find an entry in the cache, given dn
 */

ID
bdb2i_cache_find_entry_dn2id(
	BackendDB		*be,
    struct cache	*cache,
    const char		*dn
)
{
	Entry		e, *ep;
	ID			id;
	int		count = 0;

	e.e_dn = (char *) dn;
	e.e_ndn = ch_strdup( dn );
	(void) dn_normalize_case( e.e_ndn );

try_again:
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( (ep = (Entry *) avl_find( cache->c_dntree, (caddr_t) &e,
		(AVL_CMP) entry_dn_cmp )) != NULL )
	{
		int state;
		count++;

		/*
		 * ep now points to an unlocked entry
		 * we do not need to lock the entry if we only
		 * check the state, refcnt, LRU, and id.
		 */

		assert( ep->e_private );

		/* save id */
		id = ep->e_id;
		state = LEI(ep)->lei_state;

		/*
		 * entry is deleted or not fully created yet
		 */
		if ( state != CACHE_ENTRY_READY ) {
			assert(state != CACHE_ENTRY_UNDEFINED);

			/* free cache mutex */
			ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

			Debug(LDAP_DEBUG_TRACE,
			"====> bdb2i_cache_find_entry_dn2id(\"%s\"): %ld (not ready) %d\n",
				dn, id, state);

			ldap_pvt_thread_yield();
			goto try_again;
		}

		/* lru */
		LRU_DELETE( cache, ep );
		LRU_ADD( cache, ep );

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

		Debug(LDAP_DEBUG_TRACE,
			"====> bdb2i_cache_find_entry_dn2id(\"%s\"): %ld (%d tries)\n",
			dn, id, count);

	} else {
		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

		id = NOID;
	}

	free(e.e_ndn);

	return( id );
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
	int count=0;

	e.e_id = id;

try_again:
	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	if ( (ep = (Entry *) avl_find( cache->c_idtree, (caddr_t) &e,
		(AVL_CMP) entry_id_cmp )) != NULL )
	{
		int state;

		assert( ep->e_private );

		state = LEI(ep)->lei_state;

		/*
		 * entry is deleted or not fully created yet
		 */
		if ( state != CACHE_ENTRY_READY ) {
			ID ep_id = ep->e_id;

			assert(state != CACHE_ENTRY_UNDEFINED);

			/* free cache mutex */
			ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

			Debug(LDAP_DEBUG_TRACE,
				"====> bdb2i_cache_find_entry_id( %ld ): %ld (not ready) %d\n",
				id, ep_id, state);

			ldap_pvt_thread_yield();
			goto try_again;
		}

		/* lru */
		LRU_DELETE( cache, ep );
		LRU_ADD( cache, ep );
                
		LEI(ep)->lei_refcnt++;

		/* free cache mutex */
		ldap_pvt_thread_mutex_unlock( &cache->c_mutex );

		Debug(LDAP_DEBUG_TRACE,
			"====> bdb2i_cache_find_entry_id( %ld ) \"%s\" (found) (%d tries)\n",
			id, ep->e_dn, count);

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

	/* set cache mutex */
	ldap_pvt_thread_mutex_lock( &cache->c_mutex );

	assert( e->e_private );

	Debug( LDAP_DEBUG_TRACE, "====> bdb2i_cache_delete_entry( %ld )\n",
		e->e_id, 0, 0 );

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
	if ( avl_delete( &cache->c_dntree, (caddr_t) e, (AVL_CMP) entry_dn_cmp )
		== NULL )
	{
		rc = -1;
	}

	/* id tree */
	if ( avl_delete( &cache->c_idtree, (caddr_t) e, (AVL_CMP) entry_id_cmp )
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
	LEI(e)->lei_state = CACHE_ENTRY_DELETED;

	return( 0 );
}

#ifdef LDAP_DEBUG

static void
lru_print( struct cache *cache )
{
	Entry	*e;

	fprintf( stderr, "LRU queue (head to tail):\n" );
	for ( e = cache->c_lruhead; e != NULL; e = LEI(e)->lei_lrunext ) {
		fprintf( stderr, "\tdn \"%20s\" id %ld refcnt %d\n",
			e->e_dn, e->e_id, LEI(e)->lei_refcnt );
	}
	fprintf( stderr, "LRU queue (tail to head):\n" );
	for ( e = cache->c_lrutail; e != NULL; e = LEI(e)->lei_lruprev ) {
		fprintf( stderr, "\tdn \"%20s\" id %ld refcnt %d\n",
			e->e_dn, e->e_id, LEI(e)->lei_refcnt );
	}
}

#endif

