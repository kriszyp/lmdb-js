/* cache.c - routines to maintain an in-core cache of entries */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#include "back-bdb.h"

/* BDB backend specific entry info -- visible only to the cache */
typedef struct bdb_entry_info {
	ldap_pvt_thread_rdwr_t	bei_rdwr;	/* reader/writer lock */

	/*
	 * remaining fields require backend cache lock to access
	 * These items are specific to the BDB backend and should
	 * be hidden.
	 */
	int		bei_state;	/* for the cache */
#define	CACHE_ENTRY_UNDEFINED	0
#define CACHE_ENTRY_CREATING	1
#define CACHE_ENTRY_READY	2
#define CACHE_ENTRY_DELETED	3
#define CACHE_ENTRY_COMMITTED	4
	
	int		bei_refcnt;	/* # threads ref'ing this entry */
	Entry	*bei_lrunext;	/* for cache lru list */
	Entry	*bei_lruprev;
} EntryInfo;
#undef BEI
#define BEI(e)	((EntryInfo *) ((e)->e_private))

static int	bdb_cache_delete_entry_internal(Cache *cache, Entry *e);
#ifdef LDAP_DEBUG
static void	bdb_lru_print(Cache *cache);
#endif

static int
bdb_cache_entry_rdwr_lock(Entry *e, int rw)
{
#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, 
		"bdb_cache_entry_rdwr_lock: %s lock on ID %ld\n",
		rw ? "w" : "r", e->e_id, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%slock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);
#endif

	if (rw)
		return ldap_pvt_thread_rdwr_wlock(&BEI(e)->bei_rdwr);
	else
		return ldap_pvt_thread_rdwr_rlock(&BEI(e)->bei_rdwr);
}

static int
bdb_cache_entry_rdwr_trylock(Entry *e, int rw)
{
#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, 
		"bdb_cache_entry_rdwr_trylock: try %s lock on ID: %ld.\n",
		rw ? "w" : "r", e->e_id, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%strylock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);
#endif

	if (rw)
		return ldap_pvt_thread_rdwr_wtrylock(&BEI(e)->bei_rdwr);
	else
		return ldap_pvt_thread_rdwr_rtrylock(&BEI(e)->bei_rdwr);
}

static int
bdb_cache_entry_rdwr_unlock(Entry *e, int rw)
{
#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, 
		"bdb_cache_entry_rdwr_unlock: remove %s lock on ID %ld.\n",
		rw ? "w" : "r", e->e_id, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%sunlock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);
#endif

	if (rw)
		return ldap_pvt_thread_rdwr_wunlock(&BEI(e)->bei_rdwr);
	else
		return ldap_pvt_thread_rdwr_runlock(&BEI(e)->bei_rdwr);
}

static int
bdb_cache_entry_rdwr_init(Entry *e)
{
	return ldap_pvt_thread_rdwr_init( &BEI(e)->bei_rdwr );
}

static int
bdb_cache_entry_rdwr_destroy(Entry *e)
{
	return ldap_pvt_thread_rdwr_destroy( &BEI(e)->bei_rdwr );
}

static int
bdb_cache_entry_private_init( Entry *e )
{
	assert( e->e_private == NULL );

	if( e->e_private != NULL ) {
		/* this should never happen */
		return 1;
	}

	e->e_private = ch_calloc(1, sizeof(struct bdb_entry_info));

	if( bdb_cache_entry_rdwr_init( e ) != 0 ) {
		free( BEI(e) );
		e->e_private = NULL;
		return 1;
	} 

	return 0;
}

int
bdb_cache_entry_db_lock
( DB_ENV *env, u_int32_t locker, Entry *e, int rw, u_int32_t flags, DB_LOCK *lock )
{
	int       rc;
	DBT       lockobj;
	int       db_rw;

	if (rw)
		db_rw = DB_LOCK_WRITE;
	else
		db_rw = DB_LOCK_READ;

	lockobj.data = e->e_nname.bv_val;
	lockobj.size = e->e_nname.bv_len;
	rc = LOCK_GET(env, locker, flags | DB_LOCK_NOWAIT,
					&lockobj, db_rw, lock);
	return rc;
}

int
bdb_cache_entry_db_unlock
( DB_ENV *env, DB_LOCK *lock )
{
	int rc;

	rc = LOCK_PUT ( env, lock );
	return rc;
}

/*
 * marks an entry in CREATING state as committed, so it is really returned
 * to the cache. Otherwise an entry in CREATING state is removed.
 * Makes e_private be destroyed at the following cache_return_entry_w,
 * but lets the entry untouched (owned by someone else)
 */
void
bdb_cache_entry_commit( Entry *e )
{
	assert( e );
	assert( e->e_private );
	assert( BEI(e)->bei_state == CACHE_ENTRY_CREATING );
	/* assert( BEI(e)->bei_refcnt == 1 ); */

	BEI(e)->bei_state = CACHE_ENTRY_COMMITTED;
}

static int
bdb_cache_entry_private_destroy( Entry *e )
{
	assert( e->e_private );

	bdb_cache_entry_rdwr_destroy( e );

	free( e->e_private );
	e->e_private = NULL;
	return 0;
}

void
bdb_unlocked_cache_return_entry_rw( Cache *cache, Entry *e, int rw )
{

	ID id;
	int refcnt, freeit = 1;

	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );

	assert( e->e_private );

#if 0
	bdb_cache_entry_rdwr_unlock(e, rw);
#endif

	id = e->e_id;
	refcnt = --BEI(e)->bei_refcnt;

	/*
	 * if the entry is returned when in CREATING state, it is deleted
	 * but not freed because it may belong to someone else (do_add,
	 * for instance)
	 */
	if (  BEI(e)->bei_state == CACHE_ENTRY_CREATING ) {
		/* set lru mutex */
		ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
		bdb_cache_delete_entry_internal( cache, e );
		/* free lru mutex */
		ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );
		freeit = 0;
		/* now the entry is in DELETED state */
	}

	if ( BEI(e)->bei_state == CACHE_ENTRY_COMMITTED ) {
		BEI(e)->bei_state = CACHE_ENTRY_READY;

		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			   "bdb_unlocked_cache_return_entry_rw: return (%ld):%s, refcnt=%d\n",
			   id, rw ? "w" : "r", refcnt );
#else
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb_unlocked_cache_return_entry_%s( %ld ): created (%d)\n",
			rw ? "w" : "r", id, refcnt );
#endif


	} else if ( BEI(e)->bei_state == CACHE_ENTRY_DELETED ) {
		if( refcnt > 0 ) {
			/* free cache write lock */
			ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, DETAIL1, 
				   "bdb_unlocked_cache_return_entry_rw: %ld, delete pending (%d).\n",
				   id, refcnt, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"====> bdb_unlocked_cache_return_entry_%s( %ld ): delete pending (%d)\n",
				rw ? "w" : "r", id, refcnt );
#endif

		} else {
			bdb_cache_entry_private_destroy( e );
			if ( freeit ) {
				bdb_entry_return( e );
			}

			/* free cache write lock */
			ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, DETAIL1, 
				   "bdb_unlocked_cache_return_entry_rw: (%ld): deleted (%d)\n",
				   id, refcnt, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"====> bdb_unlocked_cache_return_entry_%s( %ld ): deleted (%d)\n",
				rw ? "w" : "r", id, refcnt );
#endif
		}

	} else {
		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			   "bdb_unlocked_cache_return_entry_rw: ID %ld:%s returned (%d)\n",
			   id, rw ? "w": "r", refcnt );
#else
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb_unlocked_cache_return_entry_%s( %ld ): returned (%d)\n",
			rw ? "w" : "r", id, refcnt);
#endif
	}
}

void
bdb_cache_return_entry_rw
( DB_ENV *env, Cache *cache, Entry *e, int rw, DB_LOCK *lock )
{
	ID id;
	int refcnt, freeit = 1;

	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );

	assert( e->e_private );

	bdb_cache_entry_db_unlock( env, lock );
#if 0
	bdb_cache_entry_rdwr_unlock(e, rw);
#endif

	id = e->e_id;
	refcnt = --BEI(e)->bei_refcnt;

	/*
	 * if the entry is returned when in CREATING state, it is deleted
	 * but not freed because it may belong to someone else (do_add,
	 * for instance)
	 */
	if (  BEI(e)->bei_state == CACHE_ENTRY_CREATING ) {
		/* set lru mutex */
		ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
		bdb_cache_delete_entry_internal( cache, e );
		/* free lru mutex */
		ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );
		freeit = 0;
		/* now the entry is in DELETED state */
	}

	if ( BEI(e)->bei_state == CACHE_ENTRY_COMMITTED ) {
		BEI(e)->bei_state = CACHE_ENTRY_READY;

		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			   "bdb_cache_return_entry_rw: return (%ld):%s, refcnt=%d\n",
			   id, rw ? "w" : "r", refcnt );
#else
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb_cache_return_entry_%s( %ld ): created (%d)\n",
			rw ? "w" : "r", id, refcnt );
#endif


	} else if ( BEI(e)->bei_state == CACHE_ENTRY_DELETED ) {
		if( refcnt > 0 ) {
			/* free cache write lock */
			ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, DETAIL1, 
				   "bdb_cache_return_entry_rw: %ld, delete pending (%d).\n",
				   id, refcnt, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"====> bdb_cache_return_entry_%s( %ld ): delete pending (%d)\n",
				rw ? "w" : "r", id, refcnt );
#endif

		} else {
			bdb_cache_entry_private_destroy( e );
			if ( freeit ) {
				bdb_entry_return( e );
			}

			/* free cache write lock */
			ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, DETAIL1, 
				   "bdb_cache_return_entry_rw: (%ld): deleted (%d)\n",
				   id, refcnt, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"====> bdb_cache_return_entry_%s( %ld ): deleted (%d)\n",
				rw ? "w" : "r", id, refcnt );
#endif
		}

	} else {
		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			   "bdb_cache_return_entry_rw: ID %ld:%s returned (%d)\n",
			   id, rw ? "w": "r", refcnt );
#else
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb_cache_return_entry_%s( %ld ): returned (%d)\n",
			rw ? "w" : "r", id, refcnt);
#endif
	}
}

#define LRU_DELETE( cache, e ) do { \
	if ( BEI(e)->bei_lruprev != NULL ) { \
		BEI(BEI(e)->bei_lruprev)->bei_lrunext = BEI(e)->bei_lrunext; \
	} else { \
		(cache)->c_lruhead = BEI(e)->bei_lrunext; \
	} \
	if ( BEI(e)->bei_lrunext != NULL ) { \
		BEI(BEI(e)->bei_lrunext)->bei_lruprev = BEI(e)->bei_lruprev; \
	} else { \
		(cache)->c_lrutail = BEI(e)->bei_lruprev; \
	} \
} while(0)

#define LRU_ADD( cache, e ) do { \
	BEI(e)->bei_lrunext = (cache)->c_lruhead; \
	if ( BEI(e)->bei_lrunext != NULL ) { \
		BEI(BEI(e)->bei_lrunext)->bei_lruprev = (e); \
	} \
	(cache)->c_lruhead = (e); \
	BEI(e)->bei_lruprev = NULL; \
	if ( (cache)->c_lrutail == NULL ) { \
		(cache)->c_lrutail = (e); \
	} \
} while(0)

/*
 * cache_add_entry_rw - create and lock an entry in the cache
 * returns:	0	entry has been created and locked
 *		1	entry already existed
 *		-1	something bad happened
 *             other    Berkeley DB locking error code
 */
int
bdb_cache_add_entry_rw(
    DB_ENV	*env,
    Cache	*cache,
    Entry	*e,
    int		rw,
    u_int32_t	locker,
    DB_LOCK	*lock
)
{
	int	i, rc;
	Entry	*ee;

#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, 
		"bdb_cache_add_entry_rw: add (%s):%s to cache\n",
		e->e_dn, rw ? "w" : "r", 0 );
#endif
	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );

	assert( e->e_private == NULL );

	if( bdb_cache_entry_private_init(e) != 0 ) {
		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, ERR, 
			"bdb_cache_add_entry_rw: add (%s):%ld private init failed!\n",
			e->e_dn, e->e_id, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"====> bdb_cache_add_entry( %ld ): \"%s\": private init failed!\n",
		    e->e_id, e->e_dn, 0 );
#endif


		return( -1 );
	}

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		(AVL_CMP) entry_dn_cmp, avl_dup_error ) != 0 )
	{
		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_add_entry: (%s):%ld already in cache.\n",
			e->e_dn, e->e_id, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb_cache_add_entry( %ld ): \"%s\": already in dn cache\n",
		    e->e_id, e->e_dn, 0 );
#endif

		bdb_cache_entry_private_destroy(e);

		return( 1 );
	}

	/* id tree */
	if ( avl_insert( &cache->c_idtree, (caddr_t) e,
		(AVL_CMP) entry_id_cmp, avl_dup_error ) != 0 )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_add_entry: (%s):%ls already in cache.\n",
			e->e_dn, e->e_id, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"====> bdb_cache_add_entry( %ld ): \"%s\": already in id cache\n",
		    e->e_id, e->e_dn, 0 );
#endif

		/* delete from dn tree inserted above */
		if ( avl_delete( &cache->c_dntree, (caddr_t) e,
			(AVL_CMP) entry_dn_cmp ) == NULL )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_add_entry: can't delete (%s) from cache.\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "====> can't delete from dn cache\n",
			    0, 0, 0 );
#endif
		}

		bdb_cache_entry_private_destroy(e);

		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
		return( -1 );
	}

	rc = bdb_cache_entry_db_lock( env, locker, e, rw, 0, lock );
	switch ( rc ) {
	case 0 :
		break;
	case DB_LOCK_DEADLOCK :
	case DB_LOCK_NOTGRANTED :
		/* undo avl changes immediately */
		if ( avl_delete( &cache->c_idtree, (caddr_t) e,
			(AVL_CMP) entry_id_cmp ) == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_add_entry: can't delete (%s) from cache.\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "====> can't delete from id cache\n", 0, 0, 0 );
#endif
		}
		if ( avl_delete( &cache->c_dntree, (caddr_t) e,
				(AVL_CMP) entry_dn_cmp ) == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_add_entry: can't delete (%s) from cache.\n", 
				e->e_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "====> can't delete from dn cache\n", 0, 0, 0 );
#endif
		}
		/* fall through */
	default :
		bdb_cache_entry_private_destroy(e);
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
		return rc;
	}

	/* put the entry into 'CREATING' state */
	/* will be marked after when entry is returned */
	BEI(e)->bei_state = CACHE_ENTRY_CREATING;
	BEI(e)->bei_refcnt = 1;

	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
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
			BEI(cache->c_lrutail)->bei_refcnt != 0 &&
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
			BEI(cache->c_lrutail)->bei_refcnt == 0 &&
			cache->c_cursize > cache->c_maxsize )
		{
			e = cache->c_lrutail;

			/* delete from cache and lru q */
			/* XXX do we need rc ? */
			rc = bdb_cache_delete_entry_internal( cache, e );
			bdb_cache_entry_private_destroy( e );
			bdb_entry_return( e );
		}
	}

	/* free lru mutex */
	ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );
	/* free cache write lock */
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
	return( 0 );
}

/*
 * cache_update_entry - update a LOCKED entry which has been deleted.
 * returns:	0	entry has been created and locked
 *		1	entry already existed
 *		-1	something bad happened
 */
int
bdb_cache_update_entry(
    Cache	*cache,
    Entry		*e
)
{
	int	i, rc;
	Entry	*ee;

	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );

	assert( e->e_private );

	if ( avl_insert( &cache->c_dntree, (caddr_t) e,
		(AVL_CMP) entry_dn_cmp, avl_dup_error ) != 0 )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_update_entry: (%s):%ld already in dn cache\n",
			e->e_dn, e->e_id, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"====> bdb_cache_update_entry( %ld ): \"%s\": already in dn cache\n",
		    e->e_id, e->e_dn, 0 );
#endif

		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
		return( 1 );
	}

	/* id tree */
	if ( avl_insert( &cache->c_idtree, (caddr_t) e,
		(AVL_CMP) entry_id_cmp, avl_dup_error ) != 0 )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_update_entry: (%s)%ld already in id cache\n",
			e->e_dn, e->e_id, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"====> bdb_cache_update_entry( %ld ): \"%s\": already in id cache\n",
		    e->e_id, e->e_dn, 0 );
#endif

		/* delete from dn tree inserted above */
		if ( avl_delete( &cache->c_dntree, (caddr_t) e,
			(AVL_CMP) entry_dn_cmp ) == NULL )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_update_entry: can't delete (%s)%ld from dn cache.\n",
				e->e_dn, e->e_id, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "====> can't delete from dn cache\n",
			    0, 0, 0 );
#endif
		}

		/* free cache write lock */
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
		return( -1 );
	}


	/* put the entry into 'CREATING' state */
	/* will be marked after when entry is returned */
	BEI(e)->bei_state = CACHE_ENTRY_CREATING;

	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
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
			BEI(cache->c_lrutail)->bei_refcnt != 0 &&
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
			BEI(cache->c_lrutail)->bei_refcnt == 0 &&
			cache->c_cursize > cache->c_maxsize )
		{
			e = cache->c_lrutail;

			/* delete from cache and lru q */
			/* XXX do we need rc ? */
			rc = bdb_cache_delete_entry_internal( cache, e );
			bdb_cache_entry_private_destroy( e );
			bdb_entry_return( e );
		}
	}

	/* free lru mutex */
	ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );
	/* free cache write lock */
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
	return( 0 );
}

ID
bdb_cache_find_entry_ndn2id(
	Backend		*be,
    Cache	*cache,
    struct berval	*ndn
)
{
	Entry		e, *ep;
	ID			id;
	int count = 0;

	/* this function is always called with normalized DN */
	e.e_nname = *ndn;

try_again:
	/* set cache read lock */
	ldap_pvt_thread_rdwr_rlock( &cache->c_rwlock );

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
		state = BEI(ep)->bei_state;

		/*
		 * entry is deleted or not fully created yet
		 */
		if ( state != CACHE_ENTRY_READY ) {
			assert(state != CACHE_ENTRY_UNDEFINED);

			/* free cache read lock */
			ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_find_entry_dn2id: (%s) %ld not ready: %d\n",
				ndn->bv_val, id, state );
#else
			Debug(LDAP_DEBUG_TRACE,
				"====> bdb_cache_find_entry_dn2id(\"%s\"): %ld (not ready) %d\n",
				ndn->bv_val, id, state);
#endif


			ldap_pvt_thread_yield();
			goto try_again;
		}

		/* free cache read lock */
		ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );

		/* set lru mutex */
		ldap_pvt_thread_mutex_lock( &cache->lru_mutex );

		/* lru */
		LRU_DELETE( cache, ep );
		LRU_ADD( cache, ep );
		
		/* free lru mutex */
		ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_find_entry_dn2id: (%s): %ld %d tries\n",
			ndn->bv_val, id, count );
#else
		Debug(LDAP_DEBUG_TRACE,
			"====> bdb_cache_find_entry_dn2id(\"%s\"): %ld (%d tries)\n",
			ndn->bv_val, id, count);
#endif

	} else {
		/* free cache read lock */
		ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );

		id = NOID;
	}

	return( id );
}

/*
 * cache_find_entry_id - find an entry in the cache, given id
 */

Entry *
bdb_cache_find_entry_id(
	DB_ENV	*env,
	Cache	*cache,
	ID				id,
	int				rw,
	u_int32_t	locker,
	DB_LOCK		*lock
)
{
	Entry	e;
	Entry	*ep;
	int	count = 0;
	int	rc;

	e.e_id = id;

try_again:
	/* set cache read lock */
	ldap_pvt_thread_rdwr_rlock( &cache->c_rwlock );

	if ( (ep = (Entry *) avl_find( cache->c_idtree, (caddr_t) &e,
		(AVL_CMP) entry_id_cmp )) != NULL )
	{
		int state;
		ID	ep_id;

		count++;

		assert( ep->e_private );

		ep_id = ep->e_id; 
		state = BEI(ep)->bei_state;

		/*
		 * entry is deleted or not fully created yet
		 */
		if ( state != CACHE_ENTRY_READY ) {

			assert(state != CACHE_ENTRY_UNDEFINED);

			/* free cache read lock */
			ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_find_entry_id: (%ld)->%ld not ready (%d).\n",
				id, ep_id, state );
				   
#else
			Debug(LDAP_DEBUG_TRACE,
				"====> bdb_cache_find_entry_id( %ld ): %ld (not ready) %d\n",
				id, ep_id, state);
#endif

			ldap_pvt_thread_yield();
			goto try_again;
		}

		/* acquire reader lock */
		rc = bdb_cache_entry_db_lock ( env, locker, ep, rw, 0, lock );

#if 0
		if ( bdb_cache_entry_rdwr_trylock(ep, rw) == LDAP_PVT_THREAD_EBUSY ) {
#endif

		if ( rc ) { /* will be changed to retry beyond threshold */
			/* could not acquire entry lock...
			 * owner cannot free as we have the cache locked.
			 * so, unlock the cache, yield, and try again.
			 */

			/* free cache read lock */
			ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );

#ifdef NEW_LOGGING
			LDAP_LOG( CACHE, INFO, 
				"bdb_cache_find_entry_id: %ld -> %ld (busy) %d.\n",
				id, ep_id, state );
#else
			Debug(LDAP_DEBUG_TRACE,
				"====> bdb_cache_find_entry_id( %ld ): %ld (busy) %d\n",
				id, ep_id, state);
			Debug(LDAP_DEBUG_TRACE,
				"locker = %d\n",
				locker, 0, 0);
#endif

			ldap_pvt_thread_yield();
			goto try_again;
		}

		/* free cache read lock */
		ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );
		/* set lru mutex */
		ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
		/* lru */
		LRU_DELETE( cache, ep );
		LRU_ADD( cache, ep );
		
		BEI(ep)->bei_refcnt++;

		/* free lru mutex */
		ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );

#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_find_entry_id: %ld -> %s  found %d tries.\n",
			ep_id, ep->e_dn, count );
#else
		Debug(LDAP_DEBUG_TRACE,
			"====> bdb_cache_find_entry_id( %ld ) \"%s\" (found) (%d tries)\n",
			ep_id, ep->e_dn, count);
#endif


		return( ep );
	}

	/* free cache read lock */
	ldap_pvt_thread_rdwr_runlock( &cache->c_rwlock );

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
bdb_cache_delete_entry(
    Cache	*cache,
    Entry		*e
)
{
	int	rc;

	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );

	assert( e->e_private );

#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, 
		"bdb_cache_delete_entry: delete %ld.\n", e->e_id, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "====> bdb_cache_delete_entry( %ld )\n",
		e->e_id, 0, 0 );
#endif

	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
	rc = bdb_cache_delete_entry_internal( cache, e );
	/* free lru mutex */
	ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );

	/* free cache write lock */
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
	return( rc );
}

static int
bdb_cache_delete_entry_internal(
    Cache	*cache,
    Entry		*e
)
{
	int rc = 0;	/* return code */

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
	BEI(e)->bei_state = CACHE_ENTRY_DELETED;

	return( 0 );
}

void
bdb_cache_release_all( Cache *cache )
{
	Entry *e;
	int rc;

	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );
	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &cache->lru_mutex );

#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, "bdb_cache_release_all: enter\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "====> bdb_cache_release_all\n", 0, 0, 0 );
#endif

	while ( (e = cache->c_lrutail) != NULL && BEI(e)->bei_refcnt == 0 ) {
#ifdef LDAP_RDWR_DEBUG
		assert(!ldap_pvt_thread_rdwr_active(&BEI(e)->bei_rdwr));
#endif

		/* delete from cache and lru q */
		/* XXX do we need rc ? */
		rc = bdb_cache_delete_entry_internal( cache, e );
		bdb_cache_entry_private_destroy( e );
		bdb_entry_return( e );
	}

	if ( cache->c_cursize ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, INFO,
		   "bdb_cache_release_all: Entry cache could not be emptied.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "Entry-cache could not be emptied\n", 0, 0, 0 );
#endif

	}

	/* free lru mutex */
	ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );
	/* free cache write lock */
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
}

#ifdef LDAP_DEBUG
static void
bdb_lru_print( Cache *cache )
{
	Entry	*e;

	fprintf( stderr, "LRU queue (head to tail):\n" );
	for ( e = cache->c_lruhead; e != NULL; e = BEI(e)->bei_lrunext ) {
		fprintf( stderr, "\tdn \"%20s\" id %ld refcnt %d\n",
			e->e_dn, e->e_id, BEI(e)->bei_refcnt );
	}
	fprintf( stderr, "LRU queue (tail to head):\n" );
	for ( e = cache->c_lrutail; e != NULL; e = BEI(e)->bei_lruprev ) {
		fprintf( stderr, "\tdn \"%20s\" id %ld refcnt %d\n",
			e->e_dn, e->e_id, BEI(e)->bei_refcnt );
	}
}
#endif

#ifdef BDB_REUSE_LOCKERS
void
bdb_locker_id_free( void *key, void *data )
{
	DB_ENV *env = key;
	int lockid = (int) data;

	XLOCK_ID_FREE( env, lockid );
}

int
bdb_locker_id( Operation *op, DB_ENV *env, int *locker )
{
	int i, rc, lockid;
	void *data;

	if ( !env || !op || !locker ) return -1;

	/* Shouldn't happen unless we're single-threaded */
	if ( !op->o_threadctx ) {
		*locker = 0;
		return 0;
	}

	if ( ldap_pvt_thread_pool_getkey( op->o_threadctx, env, &data, NULL ) ) {
		for ( i=0, rc=1; rc != 0 && i<4; i++ ) {
			rc = XLOCK_ID( env, &lockid );
			if (rc) ldap_pvt_thread_yield();
		}
		if ( rc != 0) {
			return rc;
		}
		data = (void *)lockid;
		if ( ( rc = ldap_pvt_thread_pool_setkey( op->o_threadctx, env,
			data, bdb_locker_id_free ) ) ) {
			XLOCK_ID_FREE( env, lockid );
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_BDB, ERR, "bdb_locker_id: err %s(%d)\n",
				db_strerror(rc), rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "bdb_locker_id: err %s(%d)\n",
				db_strerror(rc), rc, 0 );
#endif

			return rc;
		}
	} else {
		lockid = (int)data;
	}
	*locker = lockid;
	return 0;
}
#endif
