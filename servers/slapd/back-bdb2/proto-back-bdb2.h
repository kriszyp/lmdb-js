/* $OpenLDAP$ */
#ifndef _PROTO_BACK_BDB2
#define _PROTO_BACK_BDB2

#include <ldap_cdefs.h>

#include <ac/time.h>		/* Needed in add.c compare.c struct timeval */

#include "external.h"

LDAP_BEGIN_DECL

/*
 * add.c
 */
int bdb2i_release_add_lock LDAP_P(());

/*
 * alias.c
 */

Entry * bdb2i_deref_r LDAP_P((
	Backend *be,
	Entry *e,
	char *dn,
	int *err,
	Entry **matched,
	char **text ));

#define deref_entry_r( be, e, err, matched, text ) \
	bdb2i_deref_r( be, e, NULL, err, matched, text )
#define deref_dn_r( be, dn, err, matched, text ) \
	bdb2i_deref_r( be, NULL, dn, err, matched, text )

/*
 * attr.c
 */

void bdb2i_attr_masks LDAP_P(( struct ldbminfo *li, char *type, int *indexmask,
 int *syntaxmask ));
void bdb2i_attr_index_config LDAP_P(( struct ldbminfo *li,
 const char *fname,
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
 const char *dn ));
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

int bdb2i_dn2id_add LDAP_P(( BackendDB *be, const char *dn, ID id ));
ID bdb2i_dn2id LDAP_P(( BackendDB *be, const char *dn ));
int bdb2i_dn2id_delete LDAP_P(( BackendDB *be, const char *dn, ID id ));

ID_BLOCK *
bdb2i_dn2idl LDAP_P((
    BackendDB	*be,
    const char	*dn,
	int	prefix ));

Entry * bdb2i_dn2entry_rw LDAP_P((
	BackendDB *be,
	const char *dn,
	Entry **matched,
	int rw ));

#define bdb2i_dn2entry_r(be, dn, m) bdb2i_dn2entry_rw((be), (dn), (m), 0)
#define bdb2i_dn2entry_w(be, dn, m) bdb2i_dn2entry_rw((be), (dn), (m), 1)

/*
 * entry.c
 */
int bdb2_back_entry_release_rw LDAP_P(( BackendDB *be, Entry *e, int rw ));

/*
 * filterindex.c
 */

ID_BLOCK * bdb2i_filter_candidates LDAP_P(( BackendDB *be, Filter *f ));

/*
 * id2children.c
 */

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

ID_BLOCK * bdb2i_idl_alloc LDAP_P(( unsigned int nids ));
ID_BLOCK * bdb2i_idl_allids LDAP_P(( BackendDB *be ));
void bdb2i_idl_free LDAP_P(( ID_BLOCK *idl ));
ID_BLOCK * bdb2i_idl_fetch LDAP_P(( BackendDB *be, struct dbcache *db, Datum key ));
int bdb2i_idl_insert_key LDAP_P(( BackendDB *be, struct dbcache *db, Datum key, ID id ));
int bdb2i_idl_insert LDAP_P(( ID_BLOCK **idl, ID id, unsigned int maxids ));
int bdb2i_idl_delete_key LDAP_P(( BackendDB *be, struct dbcache *db, Datum key, ID id ));
ID_BLOCK * bdb2i_idl_intersection LDAP_P(( BackendDB *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * bdb2i_idl_union LDAP_P(( BackendDB *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * bdb2i_idl_notin LDAP_P(( BackendDB *be, ID_BLOCK *a, ID_BLOCK *b ));
ID bdb2i_idl_firstid LDAP_P(( ID_BLOCK *idl, ID *cursor ));
ID bdb2i_idl_nextid LDAP_P(( ID_BLOCK *idl, ID *cursor ));

/*
 * index.c
 */

int bdb2i_index_add_entry LDAP_P(( BackendDB *be, Entry *e ));
int bdb2i_index_add_mods LDAP_P(( BackendDB *be, Modifications *ml, ID id ));
ID_BLOCK * bdb2i_index_read LDAP_P(( BackendDB *be, char *type, int indextype, char *val ));
int bdb2i_index_add_values LDAP_P(( BackendDB *be, char *type, struct berval **vals, ID  id ));

/*
 * kerberos.c
 */

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
/* bdb2i_krbv4_ldap_auth LDAP_P(( BackendDB *be, struct berval *cred, AUTH_DAT *ad )); */
#endif

/*
 * modify.c
 * These prototypes are placed here because they are used by modify and
 * modify rdn which are implemented in different files. 
 *
 * We need bdb2i_back_modify_internal here because of LDAP modrdn & modify use 
 * it. If we do not add this, there would be a bunch of code replication 
 * here and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 *
 */

int bdb2i_add_values LDAP_P(( Entry *e, LDAPMod *mod, char *dn ));
int bdb2i_delete_values LDAP_P(( Entry *e, LDAPMod *mod, char *dn ));
int bdb2i_replace_values LDAP_P(( Entry *e, LDAPMod *mod, char *dn ));
int bdb2i_back_modify_internal LDAP_P((Backend *be, Connection *conn, Operation *op,
			         char *dn, Modifications *mods, Entry *e));
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

int bdb2i_enter_backend_rw  LDAP_P(( DB_LOCK *lock, int writer ));
#define bdb2i_enter_backend_r(lock)  bdb2i_enter_backend_rw((lock), 0 )
#define bdb2i_enter_backend_w(lock)  bdb2i_enter_backend_rw((lock), 1 )
int bdb2i_leave_backend_rw LDAP_P(( DB_LOCK lock, int writer ));
#define bdb2i_leave_backend_r(lock)  bdb2i_leave_backend_rw((lock), 0 )
#define bdb2i_leave_backend_w(lock)  bdb2i_leave_backend_rw((lock), 1 )

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
 Modifications *modlist ));
ID bdb2i_get_nextid  LDAP_P(( BackendDB *be ));
int bdb2i_put_nextid LDAP_P(( BackendDB *be, ID id ));
LDBM bdb2i_db_open LDAP_P(( char *name, int type, int rw, int mode,
 int dbcachesize ));
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
