#ifndef _PROTO_BACK_BDB2
#define _PROTO_BACK_BDB2

#include <ldap_cdefs.h>

#include "external.h"

LDAP_BEGIN_DECL

/*
 * alias.c
 */
Entry *bdb2i_derefAlias_r LDAP_P((
	BackendDB   *be,
	Connection	*conn,
	Operation	*op,
	Entry       *e ));
char *bdb2i_derefDN LDAP_P((
	BackendDB   *be,
	Connection  *conn,
	Operation   *op,
	char        *dn ));

/*
 * attr.c
 */

void bdb2i_attr_masks LDAP_P(( struct ldbminfo *li, char *type, int *indexmask,
 int *syntaxmask ));
void bdb2i_attr_index_config LDAP_P(( struct ldbminfo *li, char *fname,
 int lineno, int argc, char **argv, int init ));

/*
 * cache.c
 */

int bdb2i_cache_add_entry_rw LDAP_P(( struct cache *cache, Entry *e, int rw ));
int bdb2i_cache_update_entry LDAP_P(( struct cache *cache, Entry *e ));
void bdb2i_cache_return_entry_rw LDAP_P(( struct cache *cache, Entry *e,
 int rw ));
#define bdb2i_cache_return_entry_r(c, e) bdb2i_cache_return_entry_rw((c), (e), 0)
#define bdb2i_cache_return_entry_w(c, e) bdb2i_cache_return_entry_rw((c), (e), 1)

ID bdb2i_cache_find_entry_dn2id LDAP_P(( BackendDB *be, struct cache *cache,
 char *dn ));
Entry * bdb2i_cache_find_entry_id LDAP_P(( struct cache *cache, ID id, int rw ));
int bdb2i_cache_delete_entry LDAP_P(( struct cache *cache, Entry *e ));

/*
 * dbcache.c
 */

struct dbcache * bdb2i_cache_open LDAP_P(( BackendDB *be, char *name, char *suffix,
 int flags ));
void bdb2i_cache_close LDAP_P(( BackendDB *be, struct dbcache *db ));
void bdb2i_cache_really_close LDAP_P(( BackendDB *be, struct dbcache *db ));
void bdb2i_cache_flush_all LDAP_P(( BackendDB *be ));
Datum bdb2i_cache_fetch LDAP_P(( struct dbcache *db, Datum key ));
int bdb2i_cache_store LDAP_P(( struct dbcache *db, Datum key, Datum data, int flags ));
int bdb2i_cache_delete LDAP_P(( struct dbcache *db, Datum key ));

/*
 * dn2id.c
 */

int bdb2i_dn2id_add LDAP_P(( BackendDB *be, char *dn, ID id ));
ID bdb2i_dn2id LDAP_P(( BackendDB *be, char *dn ));
int bdb2i_dn2id_delete LDAP_P(( BackendDB *be, char *dn ));

Entry * bdb2i_dn2entry_rw LDAP_P(( BackendDB *be, char *dn, char **matched,
 int rw ));
#define bdb2i_dn2entry_r(be, dn, m) bdb2i_dn2entry_rw((be), (dn), (m), 0)
#define bdb2i_dn2entry_w(be, dn, m) bdb2i_dn2entry_rw((be), (dn), (m), 1)

/*
 * filterindex.c
 */

ID_BLOCK * bdb2i_filter_candidates LDAP_P(( BackendDB *be, Filter *f ));

/*
 * id2children.c
 */

int bdb2i_id2children_add LDAP_P(( BackendDB *be, Entry *p, Entry *e ));
int bdb2i_id2children_remove LDAP_P(( BackendDB *be, Entry *p, Entry *e ));
int bdb2i_has_children LDAP_P(( BackendDB *be, Entry *p ));

/*
 * id2entry.c
 */

int bdb2i_id2entry_add LDAP_P(( BackendDB *be, Entry *e ));
int bdb2i_id2entry_delete LDAP_P(( BackendDB *be, Entry *e ));

Entry * bdb2i_id2entry_rw LDAP_P(( BackendDB *be, ID id, int rw )); 
#define bdb2i_id2entry_r(be, id)  bdb2i_id2entry_rw((be), (id), 0)
#define bdb2i_id2entry_w(be, id)  bdb2i_id2entry_rw((be), (id), 1)

/*
 * idl.c
 */

ID_BLOCK * bdb2i_idl_alloc LDAP_P(( int nids ));
ID_BLOCK * bdb2i_idl_allids LDAP_P(( BackendDB *be ));
void bdb2i_idl_free LDAP_P(( ID_BLOCK *idl ));
ID_BLOCK * bdb2i_idl_fetch LDAP_P(( BackendDB *be, struct dbcache *db, Datum key ));
int bdb2i_idl_insert_key LDAP_P(( BackendDB *be, struct dbcache *db, Datum key, ID id ));
int bdb2i_idl_insert LDAP_P(( ID_BLOCK **idl, ID id, int maxids ));
int bdb2i_idl_delete_key LDAP_P(( BackendDB *be, struct dbcache *db, Datum key, ID id ));
ID_BLOCK * bdb2i_idl_intersection LDAP_P(( BackendDB *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * bdb2i_idl_union LDAP_P(( BackendDB *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * bdb2i_idl_notin LDAP_P(( BackendDB *be, ID_BLOCK *a, ID_BLOCK *b ));
ID bdb2i_idl_firstid LDAP_P(( ID_BLOCK *idl ));
ID bdb2i_idl_nextid LDAP_P(( ID_BLOCK *idl, ID id ));

/*
 * index.c
 */

int bdb2i_index_add_entry LDAP_P(( BackendDB *be, Entry *e ));
int bdb2i_index_add_mods LDAP_P(( BackendDB *be, LDAPModList *ml, ID id ));
ID_BLOCK * bdb2i_index_read LDAP_P(( BackendDB *be, char *type, int indextype, char *val ));
int bdb2i_index_add_values LDAP_P(( BackendDB *be, char *type, struct berval **vals, ID  id ));

/*
 * kerberos.c
 */

#ifdef HAVE_KERBEROS
/* bdb2i_krbv4_ldap_auth LDAP_P(( BackendDB *be, struct berval *cred, AUTH_DAT *ad )); */
#endif

/*
 * nextid.c
 */

ID bdb2i_next_id LDAP_P(( BackendDB *be ));
void bdb2i_next_id_return LDAP_P(( BackendDB *be, ID id ));
ID bdb2i_next_id_get LDAP_P(( BackendDB *be ));
int bdb2i_next_id_save LDAP_P(( BackendDB *be ));

/*
 *  startup.c
 */

int bdb2i_back_startup     LDAP_P(( BackendInfo *bi ));
int bdb2i_back_shutdown    LDAP_P(( BackendInfo *bi ));
int bdb2i_back_db_startup  LDAP_P(( BackendDB *be ));
int bdb2i_back_db_shutdown LDAP_P(( BackendDB *be ));

/*
 *  timing.c
 */

void bdb2i_uncond_start_timing LDAP_P(( struct timeval *time1 ));
#define bdb2i_start_timing(bi,time1)  if ( with_timing( bi )) bdb2i_uncond_start_timing( (time1) )
void bdb2i_uncond_stop_timing LDAP_P(( struct timeval time1,
  char *func, Connection *conn, Operation *op, int level ));
#define bdb2i_stop_timing(bi,time1,func,conn,op)  if ( with_timing( bi )) bdb2i_uncond_stop_timing( (time1), (func), (conn), (op), LDAP_DEBUG_ANY )

/*
 * porter.c
 */

int bdb2i_enter_backend_rw  LDAP_P(( DB_ENV *dbEnv, DB_LOCK *lock, int writer ));
#define bdb2i_enter_backend_r(dbEnv,lock)  bdb2i_enter_backend_rw( (dbEnv), (lock), 0 )
#define bdb2i_enter_backend_w(dbEnv,lock)  bdb2i_enter_backend_rw( (dbEnv), (lock), 1 )
int bdb2i_leave_backend_rw LDAP_P(( DB_ENV *dbEnv, DB_LOCK lock, int writer ));
#define bdb2i_leave_backend_r(dbEnv,lock)  bdb2i_leave_backend_rw( (dbEnv), (lock), 0 )
#define bdb2i_leave_backend_w(dbEnv,lock)  bdb2i_leave_backend_rw( (dbEnv), (lock), 1 )

/*
 *  txn.c
 */

int bdb2i_txn_head_init  LDAP_P(( BDB2_TXN_HEAD *head ));
void bdb2i_txn_attr_config LDAP_P((
 struct ldbminfo  *li,
 char *attr,
 int open ));
int bdb2i_txn_open_files LDAP_P(( BackendDB *be ));
void bdb2i_txn_close_files LDAP_P(( BackendDB *be ));
BDB2_TXN_FILES *bdb2i_get_db_file_cache LDAP_P((
 struct ldbminfo *li,
 char *name ));
int bdb2i_check_additional_attr_index LDAP_P(( struct ldbminfo *li ));
void bdb2i_check_default_attr_index_add LDAP_P((
 struct ldbminfo *li,
 Entry *e ));
void bdb2i_check_default_attr_index_mod LDAP_P((
 struct ldbminfo *li,
 LDAPModList *modlist ));
ID bdb2i_get_nextid  LDAP_P(( BackendDB *be ));
int bdb2i_put_nextid LDAP_P(( BackendDB *be, ID id ));
int bdb2i_db_store   LDAP_P(( LDBM ldbm, Datum key, Datum data, int flags ));
int bdb2i_db_delete  LDAP_P(( LDBM ldbm, Datum key ));
Datum bdb2i_db_fetch LDAP_P(( LDBM ldbm, Datum key ));
Datum bdb2i_db_firstkey LDAP_P(( LDBM ldbm, DBC **dbch ));
Datum bdb2i_db_nextkey  LDAP_P(( LDBM ldbm, Datum key, DBC *dbcp ));
int bdb2i_start_transction   LDAP_P(( DB_TXNMGR *txmgr ));
int bdb2i_finish_transaction LDAP_P(( ));
int bdb2i_set_txn_checkpoint LDAP_P(( DB_TXNMGR *txmgr, int forced ));


LDAP_END_DECL
#endif
