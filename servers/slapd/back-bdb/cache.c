/* cache.c - routines to maintain an in-core cache of entries */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
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

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#include "back-bdb.h"

static int	bdb_cache_delete_internal(Cache *cache, EntryInfo *e);
#ifdef LDAP_DEBUG
static void	bdb_lru_print(Cache *cache);
#endif

static EntryInfo *
bdb_cache_entryinfo_new( Cache *cache )
{
	EntryInfo *ei = NULL;

	if ( cache->c_eifree ) {
		ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );
		if ( cache->c_eifree ) {
			ei = cache->c_eifree;
			cache->c_eifree = ei->bei_lrunext;
		}
		ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
	}
	if ( ei ) {
		ei->bei_lrunext = NULL;
		ei->bei_state = 0;
	} else {
		ei = ch_calloc(1, sizeof(struct bdb_entry_info));
		ldap_pvt_thread_mutex_init( &ei->bei_kids_mutex );
	}

	return ei;
}

/* Atomically release and reacquire a lock */
int
bdb_cache_entry_db_relock(
	DB_ENV *env,
	u_int32_t locker,
	EntryInfo *ei,
	int rw,
	int tryOnly,
	DB_LOCK *lock )
{
#ifdef NO_THREADS
	return 0;
#else
	int	rc;
	DBT	lockobj;
	DB_LOCKREQ list[2];

	if ( !lock ) return 0;

	lockobj.data = &ei->bei_id;
	lockobj.size = sizeof(ei->bei_id) + 1;

	list[0].op = DB_LOCK_PUT;
	list[0].lock = *lock;
	list[1].op = DB_LOCK_GET;
	list[1].lock = *lock;
	list[1].mode = rw ? DB_LOCK_WRITE : DB_LOCK_READ;
	list[1].obj = &lockobj;
	rc = env->lock_vec(env, locker, tryOnly ? DB_LOCK_NOWAIT : 0,
		list, 2, NULL );

	if (rc) {
#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_entry_db_relock: entry %ld, rw %d, rc %d\n",
			ei->bei_id, rw, rc );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_cache_entry_db_relock: entry %ld, rw %d, rc %d\n",
			ei->bei_id, rw, rc );
#endif
	} else {
		*lock = list[1].lock;
	}
	return rc;
#endif
}

static int
bdb_cache_entry_db_lock( DB_ENV *env, u_int32_t locker, EntryInfo *ei,
	int rw, int tryOnly, DB_LOCK *lock )
{
#ifdef NO_THREADS
	return 0;
#else
	int       rc;
	DBT       lockobj;
	int       db_rw;

	if ( !lock ) return 0;

	if (rw)
		db_rw = DB_LOCK_WRITE;
	else
		db_rw = DB_LOCK_READ;

	lockobj.data = &ei->bei_id;
	lockobj.size = sizeof(ei->bei_id) + 1;

	rc = LOCK_GET(env, locker, tryOnly ? DB_LOCK_NOWAIT : 0,
					&lockobj, db_rw, lock);
	if (rc) {
#ifdef NEW_LOGGING
		LDAP_LOG( CACHE, DETAIL1, 
			"bdb_cache_entry_db_lock: entry %ld, rw %d, rc %d\n",
			ei->bei_id, rw, rc );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_cache_entry_db_lock: entry %ld, rw %d, rc %d\n",
			ei->bei_id, rw, rc );
#endif
	}
	return rc;
#endif /* NO_THREADS */
}

int
bdb_cache_entry_db_unlock ( DB_ENV *env, DB_LOCK *lock )
{
#ifdef NO_THREADS
	return 0;
#else
	int rc;

	if ( !lock ) return 0;

	rc = LOCK_PUT ( env, lock );
	return rc;
#endif
}

static int
bdb_cache_entryinfo_destroy( EntryInfo *e )
{
	ldap_pvt_thread_mutex_destroy( &e->bei_kids_mutex );
	free( e->bei_nrdn.bv_val );
#ifdef BDB_HIER
	free( e->bei_rdn.bv_val );
#endif
	free( e );
	return 0;
}

#define LRU_DELETE( cache, ei ) do { \
	if ( (ei)->bei_lruprev != NULL ) { \
		(ei)->bei_lruprev->bei_lrunext = (ei)->bei_lrunext; \
	} else { \
		(cache)->c_lruhead = (ei)->bei_lrunext; \
	} \
	if ( (ei)->bei_lrunext != NULL ) { \
		(ei)->bei_lrunext->bei_lruprev = (ei)->bei_lruprev; \
	} else { \
		(cache)->c_lrutail = (ei)->bei_lruprev; \
	} \
	(ei)->bei_lrunext = (ei)->bei_lruprev = NULL; \
} while(0)

#define LRU_ADD( cache, ei ) do { \
	(ei)->bei_lrunext = (cache)->c_lruhead; \
	if ( (ei)->bei_lrunext != NULL ) { \
		(ei)->bei_lrunext->bei_lruprev = (ei); \
	} \
	(cache)->c_lruhead = (ei); \
	(ei)->bei_lruprev = NULL; \
	if ( (cache)->c_lrutail == NULL ) { \
		(cache)->c_lrutail = (ei); \
	} \
} while(0)

/* Do a length-ordered sort on normalized RDNs */
static int
bdb_rdn_cmp( const void *v_e1, const void *v_e2 )
{
	const EntryInfo *e1 = v_e1, *e2 = v_e2;
	int rc = e1->bei_nrdn.bv_len - e2->bei_nrdn.bv_len;
	if (rc == 0) {
		rc = strncmp( e1->bei_nrdn.bv_val, e2->bei_nrdn.bv_val,
			e1->bei_nrdn.bv_len );
	}
	return rc;
}

static int
bdb_id_cmp( const void *v_e1, const void *v_e2 )
{
	const EntryInfo *e1 = v_e1, *e2 = v_e2;
	return e1->bei_id - e2->bei_id;
}

/* Create an entryinfo in the cache. Caller must release the locks later.
 */
static int
bdb_entryinfo_add_internal(
	struct bdb_info *bdb,
	EntryInfo *ei,
	EntryInfo **res )
{
	EntryInfo *ei2 = NULL;

	*res = NULL;

	ei2 = bdb_cache_entryinfo_new( &bdb->bi_cache );

	ldap_pvt_thread_rdwr_wlock( &bdb->bi_cache.c_rwlock );
	bdb_cache_entryinfo_lock( ei->bei_parent );

	ei2->bei_id = ei->bei_id;
	ei2->bei_parent = ei->bei_parent;
#ifdef BDB_HIER
	ei2->bei_rdn = ei->bei_rdn;
#endif

	/* Add to cache ID tree */
	if (avl_insert( &bdb->bi_cache.c_idtree, ei2, bdb_id_cmp, avl_dup_error )) {
		EntryInfo *eix;
		eix = avl_find( bdb->bi_cache.c_idtree, ei2, bdb_id_cmp );
		bdb_cache_entryinfo_destroy( ei2 );
		ei2 = eix;
#ifdef BDB_HIER
		/* It got freed above because its value was
		 * assigned to ei2.
		 */
		ei->bei_rdn.bv_val = NULL;
#endif
	} else {
		ber_dupbv( &ei2->bei_nrdn, &ei->bei_nrdn );
		avl_insert( &ei->bei_parent->bei_kids, ei2, bdb_rdn_cmp,
			avl_dup_error );
#ifdef BDB_HIER
		ei->bei_parent->bei_ckids++;
#endif
	}

	*res = ei2;
	return 0;
}

/* Find the EntryInfo for the requested DN. If the DN cannot be found, return
 * the info for its closest ancestor. *res should be NULL to process a
 * complete DN starting from the tree root. Otherwise *res must be the
 * immediate parent of the requested DN, and only the RDN will be searched.
 * The EntryInfo is locked upon return and must be unlocked by the caller.
 */
int
bdb_cache_find_ndn(
	Operation	*op,
	DB_TXN		*txn,
	struct berval	*ndn,
	EntryInfo	**res )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	EntryInfo	ei, *eip, *ei2;
	int rc = 0;
	char *ptr;

	/* this function is always called with normalized DN */
	if ( *res ) {
		/* we're doing a onelevel search for an RDN */
		ei.bei_nrdn.bv_val = ndn->bv_val;
		ei.bei_nrdn.bv_len = dn_rdnlen( op->o_bd, ndn );
		eip = *res;
	} else {
		/* we're searching a full DN from the root */
		ptr = ndn->bv_val + ndn->bv_len - op->o_bd->be_nsuffix[0].bv_len;
		ei.bei_nrdn.bv_val = ptr;
		ei.bei_nrdn.bv_len = op->o_bd->be_nsuffix[0].bv_len;
		/* Skip to next rdn if suffix is empty */
		if ( ei.bei_nrdn.bv_len == 0 ) {
			for (ptr = ei.bei_nrdn.bv_val - 2; ptr > ndn->bv_val
				&& !DN_SEPARATOR(*ptr); ptr--) /* empty */;
			if ( ptr >= ndn->bv_val ) {
				if (DN_SEPARATOR(*ptr)) ptr++;
				ei.bei_nrdn.bv_len = ei.bei_nrdn.bv_val - ptr;
				ei.bei_nrdn.bv_val = ptr;
			}
		}
		eip = &bdb->bi_cache.c_dntree;
	}
	
	for ( bdb_cache_entryinfo_lock( eip ); eip; ) {
		ei.bei_parent = eip;
		ei2 = (EntryInfo *)avl_find( eip->bei_kids, &ei, bdb_rdn_cmp );
		if ( !ei2 ) {
			int len = ei.bei_nrdn.bv_len;
				
			ei.bei_nrdn.bv_len = ndn->bv_len -
				(ei.bei_nrdn.bv_val - ndn->bv_val);
			bdb_cache_entryinfo_unlock( eip );

			rc = bdb_dn2id( op, txn, &ei.bei_nrdn, &ei );
			if (rc) {
				bdb_cache_entryinfo_lock( eip );
				*res = eip;
				return rc;
			}

			/* DN exists but needs to be added to cache */
			ei.bei_nrdn.bv_len = len;
			rc = bdb_entryinfo_add_internal( bdb, &ei, &ei2 );
			/* add_internal left eip and c_rwlock locked */
			ldap_pvt_thread_rdwr_wunlock( &bdb->bi_cache.c_rwlock );
			if ( rc ) {
				*res = eip;
				return rc;
			}
		} else if ( ei2->bei_state & CACHE_ENTRY_DELETED ) {
			/* In the midst of deleting? Give it a chance to
			 * complete.
			 */
			bdb_cache_entryinfo_unlock( eip );
			ldap_pvt_thread_yield();
			bdb_cache_entryinfo_lock( eip );
			*res = eip;
			return DB_NOTFOUND;
		}
		bdb_cache_entryinfo_unlock( eip );
		bdb_cache_entryinfo_lock( ei2 );

		eip = ei2;

		/* Advance to next lower RDN */
		for (ptr = ei.bei_nrdn.bv_val - 2; ptr > ndn->bv_val
			&& !DN_SEPARATOR(*ptr); ptr--) /* empty */;
		if ( ptr >= ndn->bv_val ) {
			if (DN_SEPARATOR(*ptr)) ptr++;
			ei.bei_nrdn.bv_len = ei.bei_nrdn.bv_val - ptr - 1;
			ei.bei_nrdn.bv_val = ptr;
		}
		if ( ptr < ndn->bv_val ) {
			*res = eip;
			break;
		}
	}

	return rc;
}

#ifdef BDB_HIER
/* Walk up the tree from a child node, looking for an ID that's already
 * been linked into the cache.
 */
static int
hdb_cache_find_parent(
	Operation *op,
	DB_TXN *txn,
	ID id,
	EntryInfo **res )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	EntryInfo ei, eip, *ei2 = NULL, *ein = NULL, *eir = NULL;
	char ndn[SLAP_LDAPDN_MAXLEN];
	ID parent;
	int rc;
	int addlru = 1;

	ei.bei_id = id;
	ei.bei_kids = NULL;

	for (;;) {
		rc = hdb_dn2id_parent( op, txn, &ei, &eip.bei_id );
		if ( rc ) break;

		/* Save the previous node, if any */
		ei2 = ein;

		/* Create a new node for the current ID */
		ein = bdb_cache_entryinfo_new( &bdb->bi_cache );
		ein->bei_id = ei.bei_id;
		ein->bei_kids = ei.bei_kids;
		ein->bei_nrdn = ei.bei_nrdn;
		ein->bei_rdn = ei.bei_rdn;
		
		/* This node is not fully connected yet */
		ein->bei_state = CACHE_ENTRY_NOT_LINKED;

		/* Insert this node into the ID tree */
		ldap_pvt_thread_rdwr_wlock( &bdb->bi_cache.c_rwlock );
		if ( avl_insert( &bdb->bi_cache.c_idtree, (caddr_t)ein,
			bdb_id_cmp, avl_dup_error ) ) {

			/* Someone else created this node just before us.
			 * Free our new copy and use the existing one.
			 */
			bdb_cache_entryinfo_destroy( ein );
			ein = (EntryInfo *)avl_find( bdb->bi_cache.c_idtree,
				(caddr_t) &ei, bdb_id_cmp );
			
			/* Link in any kids we've already processed */
			if ( ei2 ) {
				bdb_cache_entryinfo_lock( ein );
				avl_insert( &ein->bei_kids, (caddr_t)ei2,
					bdb_rdn_cmp, avl_dup_error );
				bdb_cache_entryinfo_unlock( ein );
			}

			if ( !eir ) {
				addlru = 0;
			}
		}

		/* If this is the first time, save this node
		 * to be returned later.
		 */
		if ( eir == NULL ) eir = ein;

		/* If there was a previous node, link it to this one */
		if ( ei2 ) ei2->bei_parent = ein;

		/* Look for this node's parent */
		if ( eip.bei_id ) {
			ei2 = (EntryInfo *) avl_find( bdb->bi_cache.c_idtree,
					(caddr_t) &eip, bdb_id_cmp );
		} else {
			ei2 = &bdb->bi_cache.c_dntree;
		}
		ldap_pvt_thread_rdwr_wunlock( &bdb->bi_cache.c_rwlock );

		/* Got the parent, link in and we're done. */
		if ( ei2 ) {
			bdb_cache_entryinfo_lock( ei2 );
			ein->bei_parent = ei2;
			avl_insert( &ei2->bei_kids, (caddr_t)ein, bdb_rdn_cmp,
				avl_dup_error);
			bdb_cache_entryinfo_unlock( ei2 );
			bdb_cache_entryinfo_lock( eir );

			/* Reset all the state info */
			for (ein = eir; ein != ei2; ein=ein->bei_parent)
				ein->bei_state &= ~CACHE_ENTRY_NOT_LINKED;
			*res = eir;
			break;
		}
		ei.bei_kids = NULL;
		ei.bei_id = eip.bei_id;
		avl_insert( &ei.bei_kids, (caddr_t)ein, bdb_rdn_cmp,
			avl_dup_error );
	}
	return rc;
}

/* Used by hdb_dn2idl when loading the EntryInfo for all the children
 * of a given node
 */
int hdb_cache_load(
	struct bdb_info *bdb,
	EntryInfo *ei,
	EntryInfo **res )
{
	EntryInfo *ei2;
	int rc;

	/* See if we already have this one */
	bdb_cache_entryinfo_lock( ei->bei_parent );
	ei2 = (EntryInfo *)avl_find( ei->bei_parent->bei_kids, ei, bdb_rdn_cmp );
	bdb_cache_entryinfo_unlock( ei->bei_parent );

	if ( !ei2 ) {
		/* Not found, add it */
		struct berval bv;

		/* bei_rdn was not malloc'd before, do it now */
		ber_dupbv( &bv, &ei->bei_rdn );
		ei->bei_rdn = bv;

		rc = bdb_entryinfo_add_internal( bdb, ei, res );
		bdb_cache_entryinfo_unlock( ei->bei_parent );
		ldap_pvt_thread_rdwr_wunlock( &bdb->bi_cache.c_rwlock );
	} else {
		/* Found, return it */
		*res = ei2;
		return 0;
	}
	return rc;
}
#endif

/* caller must have lru_mutex locked. mutex
 * will be unlocked on return.
 */
static void
bdb_cache_lru_add(
	struct bdb_info *bdb,
	u_int32_t	locker,
	EntryInfo *ei )
{
	DB_LOCK		lock, *lockp;

	if ( locker ) {
		lockp = &lock;
	} else {
		lockp = NULL;
	}

	/* See if we're above the cache size limit */
	if ( bdb->bi_cache.c_cursize > bdb->bi_cache.c_maxsize ) {
		EntryInfo *elru, *elprev;
		int i = 0;

		/* Look for an unused entry to remove */
		for (elru = bdb->bi_cache.c_lrutail; elru; elru = elprev, i++ ) {
			elprev = elru->bei_lruprev;

			/* Too many probes, not enough idle, give up */
			if (i > 10) break;

			/* If we can successfully writelock it, then
			 * the object is idle.
			 */
			if ( bdb_cache_entry_db_lock( bdb->bi_dbenv, bdb->bi_cache.c_locker, elru, 1, 1,
				lockp ) == 0 ) {
				/* If there's no entry, or this node is in
				 * the process of linking into the cache,
				 * skip it.
				 */
				if ( !elru->bei_e || (elru->bei_state & CACHE_ENTRY_NOT_LINKED) ) {
					bdb_cache_entry_db_unlock( bdb->bi_dbenv, lockp );
					continue;
				}
				LRU_DELETE( &bdb->bi_cache, elru );
				elru->bei_e->e_private = NULL;
				bdb_entry_return( elru->bei_e );
				elru->bei_e = NULL;
				bdb_cache_entry_db_unlock( bdb->bi_dbenv, lockp );
				--bdb->bi_cache.c_cursize;
				if (bdb->bi_cache.c_cursize < bdb->bi_cache.c_maxsize)
					break;
			}
		}
	}
	LRU_ADD( &bdb->bi_cache, ei );
	ldap_pvt_thread_mutex_unlock( &bdb->bi_cache.lru_mutex );
}

EntryInfo *
bdb_cache_find_info(
	struct bdb_info *bdb,
	ID id )
{
	EntryInfo ei, *ei2;

	ei.bei_id = id;

	ldap_pvt_thread_rdwr_rlock( &bdb->bi_cache.c_rwlock );
	ei2 = (EntryInfo *) avl_find( bdb->bi_cache.c_idtree,
					(caddr_t) &ei, bdb_id_cmp );
	ldap_pvt_thread_rdwr_runlock( &bdb->bi_cache.c_rwlock );
	return ei2;
}

/*
 * cache_find_id - find an entry in the cache, given id.
 * The entry is locked for Read upon return. Call with islocked TRUE if
 * the supplied *eip was already locked.
 */

int
bdb_cache_find_id(
	Operation *op,
	DB_TXN	*tid,
	ID				id,
	EntryInfo	**eip,
	int		islocked,
	u_int32_t	locker,
	DB_LOCK		*lock )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry	*ep = NULL;
	int	rc = 0;
	EntryInfo ei;

	ei.bei_id = id;

	/* If we weren't given any info, see if we have it already cached */
	if ( !*eip ) {
again:	ldap_pvt_thread_rdwr_rlock( &bdb->bi_cache.c_rwlock );
		*eip = (EntryInfo *) avl_find( bdb->bi_cache.c_idtree,
			(caddr_t) &ei, bdb_id_cmp );
		if ( *eip ) {
			/* If the lock attempt fails, the info is in use */
			if ( ldap_pvt_thread_mutex_trylock(
					&(*eip)->bei_kids_mutex )) {
				ldap_pvt_thread_rdwr_runlock( &bdb->bi_cache.c_rwlock );
				/* If this node is being deleted, treat
				 * as if the delete has already finished
				 */
				if ( (*eip)->bei_state & CACHE_ENTRY_DELETED ) {
					return DB_NOTFOUND;
				}
				/* otherwise, wait for the info to free up */
				ldap_pvt_thread_yield();
				goto again;
			}
			/* If this info isn't hooked up to its parent yet,
			 * unlock and wait for it to be fully initialized
			 */
			if ( (*eip)->bei_state & CACHE_ENTRY_NOT_LINKED ) {
				bdb_cache_entryinfo_unlock( *eip );
				ldap_pvt_thread_rdwr_runlock( &bdb->bi_cache.c_rwlock );
				ldap_pvt_thread_yield();
				goto again;
			}
			islocked = 1;
		}
		ldap_pvt_thread_rdwr_runlock( &bdb->bi_cache.c_rwlock );
	}

	/* See if the ID exists in the database; add it to the cache if so */
	if ( !*eip ) {
#ifndef BDB_HIER
		rc = bdb_id2entry( op->o_bd, tid, id, &ep );
		if ( rc == 0 ) {
			rc = bdb_cache_find_ndn( op, tid,
				&ep->e_nname, eip );
			if ( *eip ) islocked = 1;
			if ( rc ) {
				bdb_entry_return( ep );
				ep = NULL;
			}
		}
#else
		rc = hdb_cache_find_parent(op, tid, id, eip );
		if ( rc == 0 && *eip ) islocked = 1;
#endif
	}

	/* Ok, we found the info, do we have the entry? */
	if ( *eip && rc == 0 ) {
		if ( (*eip)->bei_state & CACHE_ENTRY_DELETED ) {
			rc = DB_NOTFOUND;
		} else {
			rc = bdb_cache_entry_db_lock( bdb->bi_dbenv, locker, *eip, 0, 0, lock );
			/* entry is protected now, we don't need to hold the entryinfo */
			if ( islocked ) {
				bdb_cache_entryinfo_unlock( *eip );
				islocked = 0;
			}
			if ( rc == 0 ) {
				if ( !(*eip)->bei_e ) {
					if (!ep) {
						rc = bdb_id2entry( op->o_bd, tid, id, &ep );
					}
					if ( rc == 0 ) {
						bdb_cache_entry_db_relock( bdb->bi_dbenv, locker,
							*eip, 1, 0, lock );
						/* Make sure no other modifier beat us to it */
						if ( (*eip)->bei_e ) {
							bdb_entry_return( ep );
							ep = NULL;
#ifdef BDB_HIER
							/* Check for subtree renames */
							rc = bdb_fix_dn( (*eip)->bei_e, 1 );
							if ( rc ) rc = bdb_fix_dn( (*eip)->bei_e, 2 );
#endif
						} else {
							ep->e_private = *eip;
#ifdef BDB_HIER
							bdb_fix_dn( ep, 0 );
#endif
							(*eip)->bei_e = ep;
						}
						bdb_cache_entry_db_relock( bdb->bi_dbenv, locker,
							*eip, 0, 0, lock );
					}
#ifdef BDB_HIER
				} else {
					/* Check for subtree renames
					 */
					rc = bdb_fix_dn( (*eip)->bei_e, 1 );
					if ( rc ) {
						bdb_cache_entry_db_relock( bdb->bi_dbenv,
							locker, *eip, 1, 0, lock );
						/* check again in case other modifier did it already */
						if ( bdb_fix_dn( (*eip)->bei_e, 1 ) )
							rc = bdb_fix_dn( (*eip)->bei_e, 2 );
						bdb_cache_entry_db_relock( bdb->bi_dbenv,
							locker, *eip, 0, 0, lock );
					}
#endif
				}

			}
		}
	}
	if ( rc == 0 ) {
		/* set lru mutex */
		ldap_pvt_thread_mutex_lock( &bdb->bi_cache.lru_mutex );
		/* if entry is on LRU list, remove from old spot */
		if ( (*eip)->bei_lrunext || (*eip)->bei_lruprev ) {
			LRU_DELETE( &bdb->bi_cache, *eip );
		} else {
		/* if entry is new, bump cache size */
			bdb->bi_cache.c_cursize++;
		}
		/* lru_mutex is unlocked for us */
		bdb_cache_lru_add( bdb, locker, *eip );
	}

	if ( islocked ) {
		bdb_cache_entryinfo_unlock( *eip );
	}
	return rc;
}

int
bdb_cache_children(
	Operation *op,
	DB_TXN *txn,
	Entry *e )
{
	int rc;

	if ( BEI(e)->bei_kids ) {
		return 0;
	}
	if ( BEI(e)->bei_state & CACHE_ENTRY_NO_KIDS ) {
		return DB_NOTFOUND;
	}
	rc = bdb_dn2id_children( op, txn, e );
	if ( rc == DB_NOTFOUND ) {
		BEI(e)->bei_state |= CACHE_ENTRY_NO_KIDS | CACHE_ENTRY_NO_GRANDKIDS;
	}
	return rc;
}

/* Update the cache after a successful database Add. */
int
bdb_cache_add(
	struct bdb_info *bdb,
	EntryInfo *eip,
	Entry *e,
	struct berval *nrdn,
	u_int32_t locker )
{
	EntryInfo *new, ei;
	struct berval rdn = e->e_name;
	DB_LOCK lock;
	int rc;

	ei.bei_id = e->e_id;
	ei.bei_parent = eip;
	ei.bei_nrdn = *nrdn;
	ei.bei_lockpad = 0;

	/* Lock this entry so that bdb_add can run to completion.
	 * It can only fail if BDB has run out of lock resources.
	 */
	rc = bdb_cache_entry_db_lock( bdb->bi_dbenv, locker, &ei, 1, 0, &lock );
	if ( rc ) {
		bdb_cache_entryinfo_unlock( eip );
		return rc;
	}

#ifdef BDB_HIER
	if ( nrdn->bv_len != e->e_nname.bv_len ) {
		char *ptr = strchr( rdn.bv_val, ',' );
		rdn.bv_len = ptr - rdn.bv_val;
	}
	ber_dupbv( &ei.bei_rdn, &rdn );
	if ( eip->bei_dkids ) eip->bei_dkids++;
#endif

	rc = bdb_entryinfo_add_internal( bdb, &ei, &new );
	/* bdb_csn_commit can cause this when adding the database root entry */
	if ( new->bei_e ) {
		new->bei_e->e_private = NULL;
		bdb_entry_return( new->bei_e );
	}
	new->bei_e = e;
	e->e_private = new;
	new->bei_state = CACHE_ENTRY_NO_KIDS | CACHE_ENTRY_NO_GRANDKIDS;
	eip->bei_state &= ~CACHE_ENTRY_NO_KIDS;
	if (eip->bei_parent) {
		eip->bei_parent->bei_state &= ~CACHE_ENTRY_NO_GRANDKIDS;
	}

	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &bdb->bi_cache.lru_mutex );
	++bdb->bi_cache.c_cursize;
	/* lru_mutex is unlocked for us */
	bdb_cache_lru_add( bdb, locker, new );

	bdb_cache_entryinfo_unlock( eip );
	ldap_pvt_thread_rdwr_wunlock( &bdb->bi_cache.c_rwlock );
	return rc;
}

int
bdb_cache_modify(
	Entry *e,
	Attribute *newAttrs,
	DB_ENV *env,
	u_int32_t locker,
	DB_LOCK *lock )
{
	EntryInfo *ei = BEI(e);
	int rc;
	/* Get write lock on data */
	rc = bdb_cache_entry_db_relock( env, locker, ei, 1, 0, lock );

	/* If we've done repeated mods on a cached entry, then e_attrs
	 * is no longer contiguous with the entry, and must be freed.
	 */
	if ( ! rc ) {
		if ( (void *)e->e_attrs != (void *)(e+1) ) {
			attrs_free( e->e_attrs ); 
		}
		e->e_attrs = newAttrs;
	}
	return rc;
}

/*
 * Change the rdn in the entryinfo. Also move to a new parent if needed.
 */
int
bdb_cache_modrdn(
	Entry *e,
	struct berval *nrdn,
	Entry *new,
	EntryInfo *ein,
	DB_ENV *env,
	u_int32_t locker,
	DB_LOCK *lock )
{
	EntryInfo *ei = BEI(e), *pei;
	struct berval rdn;
	int rc;

	/* Get write lock on data */
	rc =  bdb_cache_entry_db_relock( env, locker, ei, 1, 0, lock );
	if ( rc ) return rc;

	/* If we've done repeated mods on a cached entry, then e_attrs
	 * is no longer contiguous with the entry, and must be freed.
	 */
	if ( (void *)e->e_attrs != (void *)(e+1) ) {
		attrs_free( e->e_attrs );
	}
	e->e_attrs = new->e_attrs;
	if( e->e_nname.bv_val < e->e_bv.bv_val ||
		e->e_nname.bv_val > e->e_bv.bv_val + e->e_bv.bv_len )
	{
		ch_free(e->e_name.bv_val);
		ch_free(e->e_nname.bv_val);
	}
	e->e_name = new->e_name;
	e->e_nname = new->e_nname;

	/* Lock the parent's kids AVL tree */
	pei = ei->bei_parent;
	bdb_cache_entryinfo_lock( pei );
	avl_delete( &pei->bei_kids, (caddr_t) ei, bdb_rdn_cmp );
	free( ei->bei_nrdn.bv_val );
	ber_dupbv( &ei->bei_nrdn, nrdn );
#ifdef BDB_HIER
	free( ei->bei_rdn.bv_val );

	rdn = e->e_name;
	if ( nrdn->bv_len != e->e_nname.bv_len ) {
		char *ptr = strchr(rdn.bv_val, ',');
		rdn.bv_len = ptr - rdn.bv_val;
	}
	ber_dupbv( &ei->bei_rdn, &rdn );
#endif

	if (!ein) {
		ein = ei->bei_parent;
	} else {
		ei->bei_parent = ein;
		bdb_cache_entryinfo_unlock( pei );
		bdb_cache_entryinfo_lock( ein );
	}
#ifdef BDB_HIER
	{
		int max = ei->bei_modrdns;
		/* Record the generation number of this change */
		for ( pei = ein; pei->bei_parent; pei = pei->bei_parent ) {
			if ( pei->bei_modrdns > max ) max = pei->bei_modrdns;
		}
		ei->bei_modrdns = max + 1;
	}
#endif
	avl_insert( &ein->bei_kids, ei, bdb_rdn_cmp, avl_dup_error );
	bdb_cache_entryinfo_unlock( ein );
	return rc;
}
/*
 * cache_delete - delete the entry e from the cache. 
 *
 * returns:	0	e was deleted ok
 *		1	e was not in the cache
 *		-1	something bad happened
 */
int
bdb_cache_delete(
    Cache	*cache,
    Entry		*e,
    DB_ENV	*env,
    u_int32_t	locker,
    DB_LOCK	*lock )
{
	EntryInfo *ei = BEI(e);
	int	rc;

	assert( e->e_private );

	/* Set this early, warn off any queriers */
	ei->bei_state |= CACHE_ENTRY_DELETED;

	/* Lock the entry's info */
	bdb_cache_entryinfo_lock( ei );

	/* Get write lock on the data */
	rc = bdb_cache_entry_db_relock( env, locker, ei, 1, 0, lock );
	if ( rc ) {
		/* couldn't lock, undo and give up */
		ei->bei_state ^= CACHE_ENTRY_DELETED;
		bdb_cache_entryinfo_unlock( ei );
		return rc;
	}

	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );

	/* Lock the parent's kids tree */
	bdb_cache_entryinfo_lock( ei->bei_parent );

#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, 
		"bdb_cache_delete: delete %ld.\n", e->e_id, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "====> bdb_cache_delete( %ld )\n",
		e->e_id, 0, 0 );
#endif

	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &cache->lru_mutex );
	rc = bdb_cache_delete_internal( cache, e->e_private );
	/* free lru mutex */
	ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );

	/* free cache write lock */
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
	bdb_cache_entryinfo_unlock( ei->bei_parent );

	/* Leave entry info locked */

	return( rc );
}

void
bdb_cache_delete_cleanup(
	Cache *cache,
	Entry *e )
{
	EntryInfo *ei = BEI(e);

	ei->bei_e = NULL;
	e->e_private = NULL;
	bdb_entry_return( e );

	free( ei->bei_nrdn.bv_val );
	ei->bei_nrdn.bv_val = NULL;
#ifdef BDB_HIER
	free( ei->bei_rdn.bv_val );
	ei->bei_rdn.bv_val = NULL;
	ei->bei_modrdns = 0;
	ei->bei_ckids = 0;
	ei->bei_dkids = 0;
#endif
	ei->bei_parent = NULL;
	ei->bei_kids = NULL;
	ei->bei_lruprev = NULL;

	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );
	ei->bei_lrunext = cache->c_eifree;
	cache->c_eifree = ei;
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
	bdb_cache_entryinfo_unlock( ei );
}

static int
bdb_cache_delete_internal(
    Cache	*cache,
    EntryInfo		*e )
{
	int rc = 0;	/* return code */

#ifdef BDB_HIER
	e->bei_parent->bei_ckids--;
	if ( e->bei_parent->bei_dkids ) e->bei_parent->bei_dkids--;
#endif
	/* dn tree */
	if ( avl_delete( &e->bei_parent->bei_kids, (caddr_t) e, bdb_rdn_cmp )
		== NULL )
	{
		rc = -1;
	}

	/* id tree */
	if ( avl_delete( &cache->c_idtree, (caddr_t) e, bdb_id_cmp ) == NULL ) {
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
	e->bei_state |= CACHE_ENTRY_DELETED;

	return( 0 );
}

static void
bdb_entryinfo_release( void *data )
{
	EntryInfo *ei = (EntryInfo *)data;
	if ( ei->bei_kids ) {
		avl_free( ei->bei_kids, NULL );
	}
	if ( ei->bei_e ) {
		ei->bei_e->e_private = NULL;
		bdb_entry_return( ei->bei_e );
	}
	bdb_cache_entryinfo_destroy( ei );
}

void
bdb_cache_release_all( Cache *cache )
{
	/* set cache write lock */
	ldap_pvt_thread_rdwr_wlock( &cache->c_rwlock );
	/* set lru mutex */
	ldap_pvt_thread_mutex_lock( &cache->lru_mutex );

#ifdef NEW_LOGGING
	LDAP_LOG( CACHE, ENTRY, "bdb_cache_release_all: enter\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "====> bdb_cache_release_all\n", 0, 0, 0 );
#endif

	avl_free( cache->c_dntree.bei_kids, NULL );
	avl_free( cache->c_idtree, bdb_entryinfo_release );
	cache->c_lruhead = NULL;
	cache->c_lrutail = NULL;

	/* free lru mutex */
	ldap_pvt_thread_mutex_unlock( &cache->lru_mutex );
	/* free cache write lock */
	ldap_pvt_thread_rdwr_wunlock( &cache->c_rwlock );
}

#ifdef LDAP_DEBUG
static void
bdb_lru_print( Cache *cache )
{
	EntryInfo	*e;

	fprintf( stderr, "LRU queue (head to tail):\n" );
	for ( e = cache->c_lruhead; e != NULL; e = e->bei_lrunext ) {
		fprintf( stderr, "\trdn \"%20s\" id %ld\n",
			e->bei_nrdn.bv_val, e->bei_id );
	}
	fprintf( stderr, "LRU queue (tail to head):\n" );
	for ( e = cache->c_lrutail; e != NULL; e = e->bei_lruprev ) {
		fprintf( stderr, "\trdn \"%20s\" id %ld\n",
			e->bei_nrdn.bv_val, e->bei_id );
	}
}
#endif

#ifdef BDB_REUSE_LOCKERS
static void
bdb_locker_id_free( void *key, void *data )
{
	DB_ENV *env = key;
	int lockid = (int) data;
	int rc;

	rc = XLOCK_ID_FREE( env, lockid );
	if ( rc == EINVAL ) {
		DB_LOCKREQ lr;
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_BDB, ERR,
			"bdb_locker_id_free: %d err %s(%d)\n",
			lockid, db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_ANY,
			"bdb_locker_id_free: %d err %s(%d)\n",
			lockid, db_strerror(rc), rc );
#endif
		memset( &lr, 0, sizeof(lr) );

		/* release all locks held by this locker. */
		lr.op = DB_LOCK_PUT_ALL;
		env->lock_vec( env, lockid, 0, &lr, 1, NULL );
		XLOCK_ID_FREE( env, lockid );
	}
}

int
bdb_locker_id( Operation *op, DB_ENV *env, int *locker )
{
	int i, rc, lockid;
	void *data;
	void *ctx;

	if ( !env || !locker ) return -1;

	/* If no op was provided, try to find the ctx anyway... */
	if ( op ) {
		ctx = op->o_threadctx;
	} else {
		ctx = ldap_pvt_thread_pool_context();
	}

	/* Shouldn't happen unless we're single-threaded */
	if ( !ctx ) {
		*locker = 0;
		return 0;
	}

	if ( ldap_pvt_thread_pool_getkey( ctx, env, &data, NULL ) ) {
		for ( i=0, rc=1; rc != 0 && i<4; i++ ) {
			rc = XLOCK_ID( env, &lockid );
			if (rc) ldap_pvt_thread_yield();
		}
		if ( rc != 0) {
			return rc;
		}
		data = (void *)lockid;
		if ( ( rc = ldap_pvt_thread_pool_setkey( ctx, env,
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

void
bdb_cache_delete_entry(
	struct bdb_info *bdb,
	EntryInfo *ei,
	u_int32_t locker,
	DB_LOCK *lock )
{
	ldap_pvt_thread_rdwr_wlock( &bdb->bi_cache.c_rwlock );
	if ( bdb_cache_entry_db_lock( bdb->bi_dbenv, bdb->bi_cache.c_locker, ei, 1, 1, lock ) == 0 )
	{
		if ( ei->bei_e && !(ei->bei_state & CACHE_ENTRY_NOT_LINKED )) {
			LRU_DELETE( &bdb->bi_cache, ei );
			ei->bei_e->e_private = NULL;
			bdb_entry_return( ei->bei_e );
			ei->bei_e = NULL;
			--bdb->bi_cache.c_cursize;
		}
		bdb_cache_entry_db_unlock( bdb->bi_dbenv, lock );
	}
	ldap_pvt_thread_rdwr_wunlock( &bdb->bi_cache.c_rwlock );
}
