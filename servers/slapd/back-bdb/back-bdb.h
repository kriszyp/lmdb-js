/* back-bdb.h - bdb back-end header file */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _BACK_BDB_H_
#define _BACK_BDB_H_

#include <portable.h>
#include <db.h>

#include "slap.h"

LDAP_BEGIN_DECL

#define BDB_IDL_MULTI		1
/* #define BDB_HIER		1 */

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

#ifdef BDB_SUBDIRS
#define BDB_TMP_SUBDIR	LDAP_DIRSEP "tmp"
#define BDB_LG_SUBDIR	LDAP_DIRSEP "log"
#define BDB_DATA_SUBDIR	LDAP_DIRSEP "data"
#endif

#define BDB_SUFFIX		".bdb"
#define BDB_ID2ENTRY	0
#ifdef BDB_HIER
#define BDB_ID2PARENT		1
#else
#define BDB_DN2ID		1
#endif
#define BDB_NDB			2

/* The bdb on-disk entry format is pretty space-inefficient. Average
 * sized user entries are 3-4K each. You need at least two entries to
 * fit into a single database page, more is better. 64K is BDB's
 * upper bound. The same issues arise with IDLs in the index databases,
 * but it's nearly impossible to avoid overflows there.
 *
 * When using BDB_IDL_MULTI, the IDL size is no longer an issue. Smaller
 * pages are better for concurrency.
 */
#ifndef BDB_ID2ENTRY_PAGESIZE
#define	BDB_ID2ENTRY_PAGESIZE	16384
#endif

#ifndef BDB_PAGESIZE
#ifdef BDB_IDL_MULTI
#define	BDB_PAGESIZE	4096	/* BDB's original default */
#else
#define	BDB_PAGESIZE	16384
#endif
#endif

#define DEFAULT_CACHE_SIZE     1000

/* for the in-core cache of entries */
typedef struct bdb_cache {
        int             c_maxsize;
        int             c_cursize;
        Avlnode         *c_dntree;
        Avlnode         *c_idtree;
        Entry           *c_lruhead;     /* lru - add accessed entries here */
        Entry           *c_lrutail;     /* lru - rem lru entries from here */
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
#ifdef BDB_HIER
	Avlnode		*bi_tree;
	ldap_pvt_thread_rdwr_t	bi_tree_rdwr;
	void		*bi_troot;
	int		bi_nrdns;
#endif

	int			bi_txn_cp;
	u_int32_t	bi_txn_cp_min;
	u_int32_t	bi_txn_cp_kbyte;

#ifndef NO_THREADS
	int			bi_lock_detect;
	int			bi_lock_detect_seconds;
	ldap_pvt_thread_t	bi_lock_detect_tid;
#endif

	ID			bi_lastid;
	ldap_pvt_thread_mutex_t	bi_lastid_mutex;
};

#define bi_id2entry	bi_databases[BDB_ID2ENTRY]
#ifdef BDB_HIER
#define bi_id2parent	bi_databases[BDB_ID2PARENT]
#else
#define bi_dn2id	bi_databases[BDB_DN2ID]
#endif

struct bdb_op_info {
	BackendDB*	boi_bdb;
	DB_TXN*		boi_txn;
	int			boi_err;
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

#define BDB_REUSE_LOCKERS

#ifdef BDB_REUSE_LOCKERS
#define	LOCK_ID_FREE(env, locker)
#define	LOCK_ID(env, locker)	bdb_locker_id(op, env, locker)
#else
#define	LOCK_ID_FREE(env, locker)	XLOCK_ID_FREE(env, locker)
#define	LOCK_ID(env, locker)		XLOCK_ID(env, locker)
#endif

#endif

LDAP_END_DECL

#include "proto-bdb.h"

#endif /* _BACK_BDB_H_ */
