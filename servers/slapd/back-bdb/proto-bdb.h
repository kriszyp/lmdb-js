/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
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

#ifndef _PROTO_BDB_H
#define _PROTO_BDB_H

LDAP_BEGIN_DECL

#ifdef BDB_HIER
#define	BDB_SYMBOL(x)	LDAP_CONCAT(hdb_,x)
#else
#define BDB_SYMBOL(x)	LDAP_CONCAT(bdb_,x)
#endif

/*
 * attr.c
 */

#define bdb_attr_mask				BDB_SYMBOL(attr_mask)
#define bdb_attr_index_config		BDB_SYMBOL(attr_index_config)
#define bdb_attr_index_destroy		BDB_SYMBOL(attr_index_destroy)

void bdb_attr_mask( struct bdb_info *bdb,
	AttributeDescription *desc,
	slap_mask_t *indexmask );

int bdb_attr_index_config LDAP_P(( struct bdb_info *bdb,
	const char *fname, int lineno,
	int argc, char **argv ));

void bdb_attr_index_destroy LDAP_P(( Avlnode *tree ));

/*
 * ctxcsn.c
 */
#define bdb_csn_commit				BDB_SYMBOL(csn_commit)
#define bdb_get_commit_csn			BDB_SYMBOL(get_commit_csn)

int bdb_csn_commit LDAP_P(( Operation *op, SlapReply *rs, DB_TXN *tid,
						EntryInfo *ei, EntryInfo **suffix_ei, Entry **ctxcsn_e,
						int *ctxcsn_added, u_int32_t locker ));

int bdb_get_commit_csn LDAP_P(( Operation *op, SlapReply *rs,
						struct berval **search_context_csn,
						u_int32_t locker, DB_LOCK *ctxcsn_lock ));

/*
 * dbcache.c
 */
#define bdb_db_cache				BDB_SYMBOL(db_cache)

int
bdb_db_cache(
    Backend	*be,
    const char *name,
	DB **db );

/*
 * dn2entry.c
 */
#define bdb_dn2entry				BDB_SYMBOL(dn2entry)

int bdb_dn2entry LDAP_P(( Operation *op, DB_TXN *tid,
	struct berval *dn, EntryInfo **e, int matched,
	u_int32_t locker, DB_LOCK *lock ));

/*
 * dn2id.c
 */
#define bdb_dn2id					BDB_SYMBOL(dn2id)
#define bdb_dn2id_add				BDB_SYMBOL(dn2id_add)
#define bdb_dn2id_delete			BDB_SYMBOL(dn2id_delete)
#define bdb_dn2id_children			BDB_SYMBOL(dn2id_children)
#define bdb_dn2idl					BDB_SYMBOL(dn2idl)

int bdb_dn2id(
	Operation *op,
	DB_TXN *tid,
	struct berval *dn,
	EntryInfo *ei );

int bdb_dn2id_add(
	Operation *op,
	DB_TXN *tid,
	EntryInfo *eip,
	Entry *e );

int bdb_dn2id_delete(
	Operation *op,
	DB_TXN *tid,
	EntryInfo *eip,
	Entry *e );

int bdb_dn2id_children(
	Operation *op,
	DB_TXN *tid,
	Entry *e );

int bdb_dn2idl(
	Operation *op,
	Entry *e,
	ID *ids,
	ID *stack );

#ifdef BDB_HIER
#define bdb_dn2id_parent			BDB_SYMBOL(dn2id_parent)
#define bdb_dup_compare				BDB_SYMBOL(dup_compare)
#define bdb_fix_dn					BDB_SYMBOL(fix_dn)

int bdb_dn2id_parent(
	Operation *op,
	DB_TXN *txn,
	EntryInfo *ei,
	ID *idp );

int bdb_dup_compare(
	DB *db,
	const DBT *usrkey,
	const DBT *curkey );

int bdb_fix_dn( Entry *e, int checkit );
#endif


/*
 * error.c
 */
#define bdb_errcall					BDB_SYMBOL(errcall)

void bdb_errcall( const char *pfx, char * msg );

#ifdef HAVE_EBCDIC
#define ebcdic_dberror				BDB_SYMBOL(ebcdic_dberror)

char *ebcdic_dberror( int rc );
#define db_strerror(x)	ebcdic_dberror(x)
#endif

/*
 * filterentry.c
 */
#define bdb_filter_candidates		BDB_SYMBOL(filter_candidates)

int bdb_filter_candidates(
	Operation *op,
	Filter	*f,
	ID *ids,
	ID *tmp,
	ID *stack );

/*
 * id2entry.c
 */
#define bdb_id2entry				BDB_SYMBOL(id2entry)
#define bdb_id2entry_add			BDB_SYMBOL(id2entry_add)
#define bdb_id2entry_update			BDB_SYMBOL(id2entry_update)
#define bdb_id2entry_delete			BDB_SYMBOL(id2entry_delete)

int bdb_id2entry_add(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e );

int bdb_id2entry_update(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e );

int bdb_id2entry_delete(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e);

int bdb_id2entry(
	BackendDB *be,
	DB_TXN *tid,
	ID id,
	Entry **e);

#define bdb_entry_free				BDB_SYMBOL(entry_free)
#define bdb_entry_return			BDB_SYMBOL(entry_return)
#define bdb_entry_release			BDB_SYMBOL(entry_release)
#define bdb_entry_get				BDB_SYMBOL(entry_get)

void bdb_entry_free ( Entry *e );
int bdb_entry_return( Entry *e );
BI_entry_release_rw bdb_entry_release;
BI_entry_get_rw bdb_entry_get;


/*
 * idl.c
 */
#ifdef SLAP_IDL_CACHE

#define bdb_idl_cache_get			BDB_SYMBOL(idl_cache_get)
#define bdb_idl_cache_put			BDB_SYMBOL(idl_cache_put)
#define bdb_idl_cache_del			BDB_SYMBOL(idl_cache_del)

int bdb_idl_cache_get(
	struct bdb_info *bdb,
	DB *db,
	DBT *key,
	ID *ids );

void
bdb_idl_cache_put(
	struct bdb_info	*bdb,
	DB		*db,
	DBT		*key,
	ID		*ids,
	int		rc );

void
bdb_idl_cache_del(
	struct bdb_info	*bdb,
	DB		*db,
	DBT		*key );
#endif

#define bdb_idl_first				BDB_SYMBOL(idl_first)
#define bdb_idl_next				BDB_SYMBOL(idl_next)
#define bdb_idl_search				BDB_SYMBOL(idl_search)
#define bdb_idl_insert				BDB_SYMBOL(idl_insert)
#define bdb_idl_intersection		BDB_SYMBOL(idl_intersection)
#define bdb_idl_union				BDB_SYMBOL(idl_union)

#define bdb_idl_fetch_key			BDB_SYMBOL(idl_fetch_key)
#define bdb_idl_insert_key			BDB_SYMBOL(idl_insert_key)
#define bdb_idl_delete_key			BDB_SYMBOL(idl_delete_key)

unsigned bdb_idl_search( ID *ids, ID id );

int bdb_idl_fetch_key(
	BackendDB *be,
	DB *db,
	DB_TXN *txn,
	DBT *key,
	ID *ids );

int bdb_idl_insert( ID *ids, ID id );

int bdb_idl_insert_key(
	BackendDB *be,
	DB *db,
	DB_TXN *txn,
	DBT *key,
	ID id );

int bdb_idl_delete_key(
	BackendDB *be,
	DB *db,
	DB_TXN *txn,
	DBT *key,
	ID id );

int
bdb_idl_intersection(
	ID *a,
	ID *b );

int
bdb_idl_union(
	ID *a,
	ID *b );

ID bdb_idl_first( ID *ids, ID *cursor );
ID bdb_idl_next( ID *ids, ID *cursor );


#define bdb_bt_compare				BDB_SYMBOL(bt_compare)

int bdb_bt_compare(
	DB *db,
	const DBT *a,
	const DBT *b );


/*
 * index.c
 */
#define bdb_index_is_indexed		BDB_SYMBOL(index_is_indexed)
#define bdb_index_param				BDB_SYMBOL(index_param)
#define bdb_index_values			BDB_SYMBOL(index_values)
#define bdb_index_entry				BDB_SYMBOL(index_entry)

extern int
bdb_index_is_indexed LDAP_P((
	Backend *be,
	AttributeDescription *desc ));

extern int
bdb_index_param LDAP_P((
	Backend *be,
	AttributeDescription *desc,
	int ftype,
	DB **db,
	slap_mask_t *mask,
	struct berval *prefix ));

extern int
bdb_index_values LDAP_P((
	Operation *op,
	DB_TXN *txn,
	AttributeDescription *desc,
	BerVarray vals,
	ID id,
	int opid ));

int bdb_index_entry LDAP_P(( Operation *op, DB_TXN *t, int r, Entry *e ));

#define bdb_index_entry_add(op,t,e) \
	bdb_index_entry((op),(t),SLAP_INDEX_ADD_OP,(e))
#define bdb_index_entry_del(op,t,e) \
	bdb_index_entry((op),(t),SLAP_INDEX_DELETE_OP,(e))

/*
 * init.c
 */
#define bdb_uuid					BDB_SYMBOL(uuid)

extern struct berval bdb_uuid;

/*
 * key.c
 */
#define bdb_key_read				BDB_SYMBOL(key_read)
#define bdb_key_change				BDB_SYMBOL(key_change)

extern int
bdb_key_read(
    Backend	*be,
	DB *db,
	DB_TXN *txn,
    struct berval *k,
	ID *ids );

extern int
bdb_key_change(
    Backend	 *be,
    DB *db,
	DB_TXN *txn,
    struct berval *k,
    ID id,
    int	op );
	
/*
 * nextid.c
 */
#define bdb_next_id					BDB_SYMBOL(next_id)
#define bdb_last_id					BDB_SYMBOL(last_id)

int bdb_next_id( BackendDB *be, DB_TXN *tid, ID *id );
int bdb_last_id( BackendDB *be, DB_TXN *tid );

/*
 * modify.c
 */
#define bdb_modify_internal			BDB_SYMBOL(modify_internal)

int bdb_modify_internal(
	Operation *op,
	DB_TXN *tid,
	Modifications *modlist,
	Entry *e,
	const char **text,
	char *textbuf,
	size_t textlen );


/*
 * cache.c
 */
#define bdb_cache_entry_db_unlock	BDB_SYMBOL(cache_entry_db_unlock)

#define	bdb_cache_entryinfo_lock(e) \
	ldap_pvt_thread_mutex_lock( &(e)->bei_kids_mutex )
#define	bdb_cache_entryinfo_unlock(e) \
	ldap_pvt_thread_mutex_unlock( &(e)->bei_kids_mutex )

/* What a mess. Hopefully the current cache scheme will stabilize
 * and we can trim out all of this stuff.
 */
#if 0
void bdb_cache_return_entry_rw( DB_ENV *env, Cache *cache, Entry *e,
	int rw, DB_LOCK *lock );
#else
#define bdb_cache_return_entry_rw( env, cache, e, rw, lock ) \
	bdb_cache_entry_db_unlock( env, lock )
#define	bdb_cache_return_entry( env, lock ) \
	bdb_cache_entry_db_unlock( env, lock )
#endif
#define bdb_cache_return_entry_r(env, c, e, l) \
	bdb_cache_return_entry_rw((env), (c), (e), 0, (l))
#define bdb_cache_return_entry_w(env, c, e, l) \
	bdb_cache_return_entry_rw((env), (c), (e), 1, (l))
#if 0
void bdb_unlocked_cache_return_entry_rw( Cache *cache, Entry *e, int rw );
#else
#define	bdb_unlocked_cache_return_entry_rw( a, b, c )
#endif
#define bdb_unlocked_cache_return_entry_r( c, e ) \
	bdb_unlocked_cache_return_entry_rw((c), (e), 0)
#define bdb_unlocked_cache_return_entry_w( c, e ) \
	bdb_unlocked_cache_return_entry_rw((c), (e), 1)

#define bdb_cache_add				BDB_SYMBOL(cache_add)
#define bdb_cache_children			BDB_SYMBOL(cache_children)
#define bdb_cache_delete			BDB_SYMBOL(cache_delete)
#define bdb_cache_delete_cleanup		BDB_SYMBOL(cache_delete_cleanup)
#define bdb_cache_find_id			BDB_SYMBOL(cache_find_id)
#define bdb_cache_find_info			BDB_SYMBOL(cache_find_info)
#define bdb_cache_find_ndn			BDB_SYMBOL(cache_find_ndn)
#define bdb_cache_modify			BDB_SYMBOL(cache_modify)
#define bdb_cache_modrdn			BDB_SYMBOL(cache_modrdn)
#define bdb_cache_release_all		BDB_SYMBOL(cache_release_all)
#define bdb_cache_delete_entry		BDB_SYMBOL(cache_delete_entry)

int bdb_cache_children(
	Operation *op,
	DB_TXN *txn,
	Entry *e
);
int bdb_cache_add(
	struct bdb_info *bdb,
	EntryInfo *pei,
	Entry   *e,
	struct berval *nrdn,
	u_int32_t locker
);
int bdb_cache_modrdn(
	Entry	*e,
	struct berval *nrdn,
	Entry	*new,
	EntryInfo *ein,
	DB_ENV *env,
	u_int32_t locker,
	DB_LOCK *lock
);
int bdb_cache_modify(
	Entry *e,
	Attribute *newAttrs,
	DB_ENV *env,
	u_int32_t locker,
	DB_LOCK *lock
);
int bdb_cache_find_ndn(
	Operation *op,
	DB_TXN	*txn,
	struct berval   *ndn,
	EntryInfo	**res
);
EntryInfo * bdb_cache_find_info(
	struct bdb_info *bdb,
	ID id
);
int bdb_cache_find_id(
	Operation *op,
	DB_TXN	*tid,
	ID		id,
	EntryInfo **eip,
	int	islocked,
	u_int32_t	locker,
	DB_LOCK		*lock
);
int bdb_cache_delete(
	Cache	*cache,
	Entry	*e,
	DB_ENV	*env,
	u_int32_t locker,
	DB_LOCK	*lock
);
void bdb_cache_delete_cleanup(
	Cache	*cache,
	Entry	*e
);
void bdb_cache_release_all( Cache *cache );
void bdb_cache_delete_entry(
	struct bdb_info *bdb,
	EntryInfo *ei,
	u_int32_t locker,
	DB_LOCK *lock
);

#ifdef BDB_HIER
int hdb_cache_load(
	struct bdb_info *bdb,
	EntryInfo *ei,
	EntryInfo **res
);
#endif

#define bdb_cache_entry_db_relock		BDB_SYMBOL(cache_entry_db_relock)
int bdb_cache_entry_db_relock(
	DB_ENV *env,
	u_int32_t locker,
	EntryInfo *ei,
	int rw,
	int tryOnly,
	DB_LOCK *lock );

int bdb_cache_entry_db_unlock(
	DB_ENV *env,
	DB_LOCK *lock );

#ifdef BDB_REUSE_LOCKERS

#define bdb_locker_id				BDB_SYMBOL(locker_id)
int bdb_locker_id( Operation *op, DB_ENV *env, int *locker );

#define	LOCK_ID_FREE(env, locker)
#define	LOCK_ID(env, locker)	bdb_locker_id(op, env, locker)

#else

#define	LOCK_ID_FREE(env, locker)	XLOCK_ID_FREE(env, locker)
#define	LOCK_ID(env, locker)		XLOCK_ID(env, locker)

#endif

/*
 * search.c
 */

#define bdb_abandon					BDB_SYMBOL(abandon)
#define bdb_cancel					BDB_SYMBOL(cancel)
#define bdb_do_search				BDB_SYMBOL(do_search)

BI_op_abandon bdb_abandon;
BI_op_cancel bdb_cancel;

int bdb_do_search(
	Operation       *op,
	SlapReply	*rs,
	Operation       *ps_op,
	Entry           *entry,
	int             psearch_type
);
#define	bdb_psearch(op, rs, sop, e, ps_type)	bdb_do_search(op, rs, sop, e, ps_type)

/*
 * trans.c
 */
#define bdb_trans_backoff			BDB_SYMBOL(trans_backoff)

void
bdb_trans_backoff( int num_retries );

LDAP_END_DECL

#endif /* _PROTO_BDB_H */
