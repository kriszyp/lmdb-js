/* $OpenLDAP$ */
/*
 * Copyright 2000-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _PROTO_BDB_H
#define _PROTO_BDB_H

LDAP_BEGIN_DECL

/*
 * alias.c
 */
Entry *bdb_deref_internal_r LDAP_P((
	BackendDB *be,
	Entry *e,
	struct berval *dn,
	int *err,
	Entry **matched,
	const char **text ));

#define deref_entry_r( be, e, err, matched, text ) \
	bdb_deref_internal_r( be, e, NULL, err, matched, text )
#define deref_dn_r( be, dn, err, matched, text ) \
	bdb_deref_internal_r( be, NULL, dn, err, matched, text)

/*
 * attr.c
 */

void bdb_attr_mask( struct bdb_info *bdb,
	AttributeDescription *desc,
	slap_mask_t *indexmask );

int bdb_attr_index_config LDAP_P(( struct bdb_info *bdb,
	const char *fname, int lineno,
	int argc, char **argv ));

void bdb_attr_index_destroy LDAP_P(( Avlnode *tree ));

/*
 * dbcache.c
 */
int
bdb_db_cache(
    Backend	*be,
    DB_TXN *tid,
    const char *name,
	DB **db );

/*
 * dn2entry.c
 */
int bdb_dn2entry LDAP_P(( BackendDB *be, DB_TXN *tid,
	struct berval *dn, EntryInfo **e, int matched,
	u_int32_t locker, DB_LOCK *lock, void *ctx));

/*
 * dn2id.c
 */
int bdb_dn2id(
	BackendDB *be,
	DB_TXN *tid,
	struct berval *dn,
	EntryInfo *ei,
	void *ctx );

int bdb_dn2id_add(
	BackendDB *be,
	DB_TXN *tid,
	EntryInfo *eip,
	Entry *e,
	void *ctx );

int bdb_dn2id_delete(
	BackendDB *be,
	DB_TXN *tid,
	EntryInfo *eip,
	Entry *e,
	void *ctx );

int bdb_dn2id_children(
	Operation *op,
	DB_TXN *tid,
	Entry *e );

int
bdb_dn2idl(
	BackendDB	*be,
	struct berval	*dn,
	int prefix,
	ID *ids );

/*
 * entry.c
 */
int bdb_entry_return( Entry *e );
BI_entry_release_rw bdb_entry_release;
BI_entry_get_rw bdb_entry_get;

/*
 * error.c
 */
void bdb_errcall( const char *pfx, char * msg );

/*
 * filterentry.c
 */
int bdb_filter_candidates(
	Operation *op,
	Filter	*f,
	ID *ids,
	ID *tmp,
	ID *stack );

/*
 * id2entry.c
 */
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

void bdb_entry_free ( Entry *e );

/*
 * idl.c
 */
#ifdef SLAP_IDL_CACHE
int bdb_idl_entry_cmp( const void*, const void* );
#endif

unsigned bdb_idl_search( ID *ids, ID id );

int bdb_bt_compare(
	DB *db,
	const DBT *a,
	const DBT *b );

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

#if 0
int
bdb_idl_notin(
    ID 	*a,
    ID 	*b,
	ID	*ids );
#endif

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


/*
 * index.c
 */
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

#define bdb_index_entry_add(be,t,e) \
	bdb_index_entry((be),(t),SLAP_INDEX_ADD_OP,(e))
#define bdb_index_entry_del(be,t,e) \
	bdb_index_entry((be),(t),SLAP_INDEX_DELETE_OP,(e))

/*
 * init.c
 */
extern struct berval bdb_uuid;

/*
 * key.c
 */
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
int bdb_next_id( BackendDB *be, DB_TXN *tid, ID *id );
int bdb_last_id( BackendDB *be, DB_TXN *tid );

/*
 * modify.c
 */
int bdb_modify_internal(
	Operation *op,
	DB_TXN *tid,
	Modifications *modlist,
	Entry *e,
	const char **text,
	char *textbuf,
	size_t textlen );

/*
 * passwd.c
 */
BI_op_extended bdb_exop_passwd;


/*
 * cache.c
 */

#define	bdb_cache_entryinfo_lock(e) \
	ldap_pvt_thread_mutex_lock( &(e)->bei_kids_mutex )
#define	bdb_cache_entryinfo_unlock(e) \
	ldap_pvt_thread_mutex_unlock( &(e)->bei_kids_mutex )

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
int bdb_cache_update_entry(
       Cache   *cache,
       Entry   *e
);
int bdb_cache_find_entry_ndn2id(
	Backend *be,
	DB_TXN	*txn,
	struct berval   *ndn,
	EntryInfo	**res,
	u_int32_t	locker,
	void	*ctx
);
int bdb_cache_find_entry_id(
	Backend *be,
	DB_TXN	*tid,
	ID		id,
	EntryInfo **eip,
	int	islocked,
	u_int32_t	locker,
	DB_LOCK		*lock,
	void	*ctx
);
int bdb_cache_delete_entry(
	Cache	*cache,
	Entry	*e,
	DB_ENV	*env,
	u_int32_t locker,
	DB_LOCK	*lock
);
void bdb_cache_release_all( Cache *cache );

/*
 * lcup.c
 */

BI_op_abandon bdb_abandon;

BI_op_cancel bdb_cancel;

#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
int bdb_do_search(
	Operation       *op,
	SlapReply	*rs,
	Operation       *ps_op,
	Entry           *entry,
	int             psearch_type
);
#define	bdb_psearch(op, rs, sop, e, ps_type)	bdb_do_search(op, rs, sop, e, ps_type)
#endif

/*
 * search.c
 */

#ifdef LDAP_CLIENT_UPDATE
int
bdb_build_lcup_update_ctrl(
	Operation       *op,
	SlapReply	*rs,
	Entry           *e,
	int             entry_count,
	LDAPControl     **ctrls,
	int             num_ctrls,
	struct berval   *latest_entrycsn_bv,
	int             isdeleted       );

int
bdb_build_lcup_done_ctrl(
	Operation       *op,
	SlapReply	*rs,
	LDAPControl     **ctrls,
	int             num_ctrls,
	struct berval   *latest_entrycsn_bv     );
#endif

#ifdef LDAP_SYNC
int
bdb_build_sync_state_ctrl(
	Operation       *op,
	SlapReply	*rs,
	Entry           *e,
	int             entry_sync_state,
	LDAPControl     **ctrls,
	int             num_ctrls,
	int             send_cookie,
	struct berval   *latest_entrycsn_bv     );

int
bdb_build_sync_done_ctrl(
	Operation       *op,
	SlapReply	*rs,
	LDAPControl     **ctrls,
	int             num_ctrls,
	int             send_cookie,
	struct berval   *latest_entrycsn_bv     );

int
bdb_send_ldap_intermediate(
	Operation   *op,
	SlapReply	*rs,
	int         state,
	struct berval *cookie );
#endif

#ifdef BDB_REUSE_LOCKERS

int bdb_locker_id( Operation *op, DB_ENV *env, int *locker );

#endif

#ifdef HAVE_EBCDIC
char *ebcdic_dberror( int rc );

#define db_strerror(x)	ebcdic_dberror(x)
#endif

LDAP_END_DECL

#endif /* _PROTO_BDB_H */
