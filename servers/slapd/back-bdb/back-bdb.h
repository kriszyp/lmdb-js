/* back-bdb.h - bdb back-end header file */
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

#ifndef _BACK_BDB_H_
#define _BACK_BDB_H_

#include <portable.h>
#include "slap.h"
#include <db.h>

LDAP_BEGIN_DECL

#define BDB_SUBENTRIES 1

#define DN_BASE_PREFIX		SLAP_INDEX_EQUALITY_PREFIX
#define DN_ONE_PREFIX	 	'%'
#define DN_SUBTREE_PREFIX 	'@'

#define DBTzero(t)			(memset((t), 0, sizeof(DBT)))
#define DBT2bv(t,bv)		((bv)->bv_val = (t)->data, \
								(bv)->bv_len = (t)->size)
#define bv2DBT(bv,t)		((t)->data = (bv)->bv_val, \
								(t)->size = (bv)->bv_len )

#define BDB_TXN_RETRIES		16

#define BDB_MAX_ADD_LOOP	30

#define	BDB_ALIASES	1

#ifdef BDB_SUBDIRS
#define BDB_TMP_SUBDIR	"tmp"
#define BDB_LG_SUBDIR	"log"
#define BDB_DATA_SUBDIR	"data"
#endif

#define BDB_SUFFIX		".bdb"
#define BDB_ID2ENTRY	0
#define BDB_DN2ID		1
#define BDB_NDB			2

/* The bdb on-disk entry format is pretty space-inefficient. Average
 * sized user entries are 3-4K each. You need at least two entries to
 * fit into a single database page, more is better. 64K is BDB's
 * upper bound. Smaller pages are better for concurrency.
 */
#ifndef BDB_ID2ENTRY_PAGESIZE
#define	BDB_ID2ENTRY_PAGESIZE	16384
#endif

#ifndef BDB_PAGESIZE
#define	BDB_PAGESIZE	4096	/* BDB's original default */
#endif

#define DEFAULT_CACHE_SIZE     1000

/* The default search IDL stack cache depth */
#define DEFAULT_SEARCH_STACK_DEPTH	16

/* The minimum we can function with */
#define MINIMUM_SEARCH_STACK_DEPTH	8

/* for the IDL cache */
#define SLAP_IDL_CACHE	1

#ifdef SLAP_IDL_CACHE
typedef struct bdb_idl_cache_entry_s {
	struct berval kstr;
	ldap_pvt_thread_rdwr_t idl_entry_rwlock;
	ID      *idl;
	DB      *db;
	struct bdb_idl_cache_entry_s* idl_lru_prev;
	struct bdb_idl_cache_entry_s* idl_lru_next;
} bdb_idl_cache_entry_t;
#endif

/* BDB backend specific entry info */
typedef struct bdb_entry_info {
	struct bdb_entry_info *bei_parent;
	ID bei_id;

	int bei_state;
#define	CACHE_ENTRY_DELETED	1
#define	CACHE_ENTRY_NO_KIDS	2
#define	CACHE_ENTRY_NOT_LINKED	4
#define CACHE_ENTRY_NO_GRANDKIDS	8

	/*
	 * remaining fields require backend cache lock to access
	 */
	struct berval bei_nrdn;
#ifdef BDB_HIER
	struct berval bei_rdn;
	int	bei_modrdns;	/* track renames */
	int	bei_ckids;	/* number of kids cached */
	int	bei_dkids;	/* number of kids on-disk, plus 1 */
#endif
	Entry	*bei_e;
	Avlnode	*bei_kids;
	ldap_pvt_thread_mutex_t	bei_kids_mutex;
	
	struct bdb_entry_info	*bei_lrunext;	/* for cache lru list */
	struct bdb_entry_info	*bei_lruprev;
} EntryInfo;
#undef BEI
#define BEI(e)	((EntryInfo *) ((e)->e_private))

/* for the in-core cache of entries */
typedef struct bdb_cache {
	int             c_maxsize;
	int             c_cursize;
	EntryInfo	c_dntree;
	EntryInfo	*c_eifree;	/* free list */
	Avlnode         *c_idtree;
	EntryInfo	*c_lruhead;	/* lru - add accessed entries here */
	EntryInfo	*c_lrutail;	/* lru - rem lru entries from here */
	ldap_pvt_thread_rdwr_t c_rwlock;
	ldap_pvt_thread_mutex_t lru_mutex;
} Cache;
 
#define CACHE_READ_LOCK                0
#define CACHE_WRITE_LOCK       1
 
#define BDB_INDICES		128

struct bdb_db_info {
	char		*bdi_name;
	DB			*bdi_db;
};

struct bdb_info {
	DB_ENV		*bi_dbenv;

	/* DB_ENV parameters */
	/* The DB_ENV can be tuned via DB_CONFIG */
	char		*bi_dbenv_home;
	u_int32_t	bi_dbenv_xflags; /* extra flags */
	int			bi_dbenv_mode;

	int			bi_ndatabases;
	struct bdb_db_info **bi_databases;
	ldap_pvt_thread_mutex_t	bi_database_mutex;
	int		bi_db_opflags;	/* db-specific flags */

	slap_mask_t	bi_defaultmask;
	Cache		bi_cache;
	Avlnode		*bi_attrs;
	void		*bi_search_stack;
	int		bi_search_stack_depth;

	int			bi_txn_cp;
	u_int32_t	bi_txn_cp_min;
	u_int32_t	bi_txn_cp_kbyte;

	int			bi_lock_detect;
	long		bi_shm_key;

	ID			bi_lastid;
	ldap_pvt_thread_mutex_t	bi_lastid_mutex;
	LDAP_LIST_HEAD(pl, slap_op) bi_psearch_list;
	ldap_pvt_thread_rdwr_t bi_pslist_rwlock;
	LDAP_LIST_HEAD(se, slap_session_entry) bi_session_list;
#ifdef SLAP_IDL_CACHE
	int		bi_idl_cache_max_size;
	int		bi_idl_cache_size;
	Avlnode		*bi_idl_tree;
	bdb_idl_cache_entry_t	*bi_idl_lru_head;
	bdb_idl_cache_entry_t	*bi_idl_lru_tail;
	ldap_pvt_thread_rdwr_t bi_idl_tree_rwlock;
	ldap_pvt_thread_mutex_t bi_idl_tree_lrulock;
#endif
};

#define bi_id2entry	bi_databases[BDB_ID2ENTRY]
#define bi_dn2id	bi_databases[BDB_DN2ID]

struct bdb_op_info {
	BackendDB*	boi_bdb;
	DB_TXN*		boi_txn;
	DB_LOCK		boi_lock;	/* used when no txn */
	u_int32_t	boi_err;
	u_int32_t	boi_locker;
	int		boi_acl_cache;
};

#define	DB_OPEN(db, file, name, type, flags, mode) \
	(db)->open(db, file, name, type, flags, mode)

#if DB_VERSION_MAJOR < 4
#define LOCK_DETECT(env,f,t,a)		lock_detect(env, f, t, a)
#define LOCK_GET(env,i,f,o,m,l)		lock_get(env, i, f, o, m, l)
#define LOCK_PUT(env,l)			lock_put(env, l)
#define TXN_CHECKPOINT(env,k,m,f)	txn_checkpoint(env, k, m, f)
#define TXN_BEGIN(env,p,t,f)		txn_begin((env), p, t, f)
#define TXN_PREPARE(txn,gid)		txn_prepare((txn), (gid))
#define TXN_COMMIT(txn,f)			txn_commit((txn), (f))
#define	TXN_ABORT(txn)				txn_abort((txn))
#define TXN_ID(txn)					txn_id(txn)
#define XLOCK_ID(env, locker)		lock_id(env, locker)
#define XLOCK_ID_FREE(env, locker)	lock_id_free(env, locker)
#else
#define LOCK_DETECT(env,f,t,a)		(env)->lock_detect(env, f, t, a)
#define LOCK_GET(env,i,f,o,m,l)		(env)->lock_get(env, i, f, o, m, l)
#define LOCK_PUT(env,l)			(env)->lock_put(env, l)
#define TXN_CHECKPOINT(env,k,m,f)	(env)->txn_checkpoint(env, k, m, f)
#define TXN_BEGIN(env,p,t,f)		(env)->txn_begin((env), p, t, f)
#define TXN_PREPARE(txn,g)			(txn)->prepare((txn), (g))
#define TXN_COMMIT(txn,f)			(txn)->commit((txn), (f))
#define TXN_ABORT(txn)				(txn)->abort((txn))
#define TXN_ID(txn)					(txn)->id(txn)
#define XLOCK_ID(env, locker)		(env)->lock_id(env, locker)
#define XLOCK_ID_FREE(env, locker)	(env)->lock_id_free(env, locker)

/* BDB 4.1.17 adds txn arg to db->open */
#if DB_VERSION_MINOR > 1 || DB_VERSION_PATCH >= 17
#undef DB_OPEN
#define	DB_OPEN(db, file, name, type, flags, mode) \
	(db)->open(db, NULL, file, name, type, (flags)|DB_AUTO_COMMIT, mode)
#endif

#endif

#define BDB_REUSE_LOCKERS

#define BDB_CSN_COMMIT	0
#define BDB_CSN_ABORT	1
#define BDB_CSN_RETRY	2

LDAP_END_DECL

#include "proto-bdb.h"

#endif /* _BACK_BDB_H_ */
