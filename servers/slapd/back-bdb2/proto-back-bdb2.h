#ifndef _PROTO_BACK_BDB2
#define _PROTO_BACK_BDB2

#include <ldap_cdefs.h>

#include "external.h"

LDAP_BEGIN_DECL

/*
 * alias.c
 */
Entry *bdb2i_derefAlias_r LDAP_P((
	Backend     *be,
	Connection	*conn,
	Operation	*op,
	Entry       *e ));
char *bdb2i_derefDN LDAP_P((
	Backend     *be,
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

void bdb2i_cache_set_state LDAP_P(( struct cache *cache, Entry *e, int state ));
void bdb2i_cache_return_entry_r LDAP_P(( struct cache *cache, Entry *e ));
void bdb2i_cache_return_entry_w LDAP_P(( struct cache *cache, Entry *e ));
int bdb2i_cache_add_entry_lock LDAP_P(( struct cache *cache, Entry *e,
 int state ));
ID bdb2i_cache_find_entry_dn2id LDAP_P(( Backend *be, struct cache *cache,
 char *dn ));
Entry * bdb2i_cache_find_entry_id LDAP_P(( struct cache *cache, ID id, int rw ));
int bdb2i_cache_delete_entry LDAP_P(( struct cache *cache, Entry *e ));

/*
 * dbcache.c
 */

struct dbcache * bdb2i_cache_open LDAP_P(( Backend *be, char *name, char *suffix,
 int flags ));
void bdb2i_cache_close LDAP_P(( Backend *be, struct dbcache *db ));
void bdb2i_cache_really_close LDAP_P(( Backend *be, struct dbcache *db ));
void bdb2i_cache_flush_all LDAP_P(( Backend *be ));
Datum bdb2i_cache_fetch LDAP_P(( struct dbcache *db, Datum key ));
int bdb2i_cache_store LDAP_P(( struct dbcache *db, Datum key, Datum data, int flags ));
int bdb2i_cache_delete LDAP_P(( struct dbcache *db, Datum key ));

/*
 * dn2id.c
 */

int bdb2i_dn2id_add LDAP_P(( Backend *be, char *dn, ID id ));
ID bdb2i_dn2id LDAP_P(( Backend *be, char *dn ));
int bdb2i_dn2id_delete LDAP_P(( Backend *be, char *dn ));
Entry * bdb2i_dn2entry_r LDAP_P(( Backend *be, char *dn, char **matched ));
Entry * bdb2i_dn2entry_w LDAP_P(( Backend *be, char *dn, char **matched ));

/*
 * filterindex.c
 */

ID_BLOCK * bdb2i_filter_candidates LDAP_P(( Backend *be, Filter *f ));

/*
 * id2children.c
 */

int bdb2i_id2children_add LDAP_P(( Backend *be, Entry *p, Entry *e ));
int bdb2i_id2children_remove LDAP_P(( Backend *be, Entry *p, Entry *e ));
int bdb2i_has_children LDAP_P(( Backend *be, Entry *p ));

/*
 * id2entry.c
 */

int bdb2i_id2entry_add LDAP_P(( Backend *be, Entry *e ));
int bdb2i_id2entry_delete LDAP_P(( Backend *be, Entry *e ));
Entry * bdb2i_id2entry LDAP_P(( Backend *be, ID id, int rw )); 
Entry * bdb2i_id2entry_r LDAP_P(( Backend *be, ID id ));
Entry * bdb2i_id2entry_w LDAP_P(( Backend *be, ID id ));

/*
 * idl.c
 */

ID_BLOCK * bdb2i_idl_alloc LDAP_P(( int nids ));
ID_BLOCK * bdb2i_idl_allids LDAP_P(( Backend *be ));
void bdb2i_idl_free LDAP_P(( ID_BLOCK *idl ));
ID_BLOCK * bdb2i_idl_fetch LDAP_P(( Backend *be, struct dbcache *db, Datum key ));
int bdb2i_idl_insert_key LDAP_P(( Backend *be, struct dbcache *db, Datum key, ID id ));
int bdb2i_idl_insert LDAP_P(( ID_BLOCK **idl, ID id, int maxids ));
int bdb2i_idl_delete_key LDAP_P(( Backend *be, struct dbcache *db, Datum key, ID id ));
ID_BLOCK * bdb2i_idl_intersection LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * bdb2i_idl_union LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * bdb2i_idl_notin LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID bdb2i_idl_firstid LDAP_P(( ID_BLOCK *idl ));
ID bdb2i_idl_nextid LDAP_P(( ID_BLOCK *idl, ID id ));

/*
 * index.c
 */

int bdb2i_index_add_entry LDAP_P(( Backend *be, Entry *e ));
int bdb2i_index_add_mods LDAP_P(( Backend *be, LDAPModList *ml, ID id ));
ID_BLOCK * bdb2i_index_read LDAP_P(( Backend *be, char *type, int indextype, char *val ));
int bdb2i_index_add_values LDAP_P(( Backend *be, char *type, struct berval **vals, ID  id ));

/*
 * kerberos.c
 */

#ifdef HAVE_KERBEROS
/* bdb2i_krbv4_ldap_auth LDAP_P(( Backend *be, struct berval *cred, AUTH_DAT *ad )); */
#endif

/*
 * nextid.c
 */

ID bdb2i_next_id LDAP_P(( Backend *be ));
void bdb2i_next_id_return LDAP_P(( Backend *be, ID id ));
ID bdb2i_next_id_get LDAP_P(( Backend *be ));
int bdb2i_next_id_save LDAP_P(( Backend *be ));

/*
 *  timing.c
 */

char *bdb2i_elapsed LDAP_P(( struct timeval firsttime,
 struct timeval secondtime ));

/*
 * porter.c
 */

int bdb2i_enter_backend_r  LDAP_P(( DB_ENV *dbEnv, DB_LOCK *lock ));
int bdb2i_enter_backend_w  LDAP_P(( DB_ENV *dbEnv, DB_LOCK *lock ));
int bdb2i_leave_backend    LDAP_P(( DB_ENV *dbEnv, DB_LOCK lock ));

/*
 *  txn.c
 */

void bdb2i_txn_head_init  LDAP_P(( BDB2_TXN_HEAD *head ));
void bdb2i_txn_attr_config LDAP_P((
 struct ldbminfo  *li,
 char *attr,
 int open ));
void bdb2i_txn_open_files LDAP_P(( struct ldbminfo *li ));
void bdb2i_txn_close_files LDAP_P(( BDB2_TXN_HEAD *head ));
BDB2_TXN_FILES *bdb2i_get_db_file_cache LDAP_P((
 struct ldbminfo *li,
 char *name ));
void bdb2i_check_additional_attr_index LDAP_P(( struct ldbminfo *li ));
void bdb2i_check_default_attr_index_add LDAP_P((
 struct ldbminfo *li,
 Entry *e ));
void bdb2i_check_default_attr_index_mod LDAP_P((
 struct ldbminfo *li,
 LDAPModList *modlist ));



LDAP_END_DECL
#endif
