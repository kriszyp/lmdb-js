#ifndef _PROTO_BACK_LDBM
#define _PROTO_BACK_LDBM

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/*
 * alias.c
 */
#ifdef SLAPD_ALIAS_DEREF
Entry *derefAlias_r LDAP_P((
	Backend     *be,
	Connection	*conn,
	Operation	*op,
	Entry       *e ));
char *derefDN LDAP_P((
	Backend     *be,
	Connection  *conn,
	Operation   *op,
	char        *dn ));
#endif

/*
 * attr.c
 */

void attr_masks LDAP_P(( struct ldbminfo *li, char *type, int *indexmask,
 int *syntaxmask ));
void attr_index_config LDAP_P(( struct ldbminfo *li, char *fname, int lineno,
 int argc, char **argv, int init ));

/*
 * cache.c
 */

void cache_set_state LDAP_P(( struct cache *cache, Entry *e, int state ));
void cache_return_entry_r LDAP_P(( struct cache *cache, Entry *e ));
void cache_return_entry_w LDAP_P(( struct cache *cache, Entry *e ));
int cache_add_entry_lock LDAP_P(( struct cache *cache, Entry *e, int state ));
ID cache_find_entry_dn2id LDAP_P(( Backend *be, struct cache *cache, char *dn ));
Entry * cache_find_entry_id LDAP_P(( struct cache *cache, ID id, int rw ));
int cache_delete_entry LDAP_P(( struct cache *cache, Entry *e ));

/*
 * dbcache.c
 */

struct dbcache * ldbm_cache_open LDAP_P(( Backend *be, char *name, char *suffix,
 int flags ));
void ldbm_cache_close LDAP_P(( Backend *be, struct dbcache *db ));
void ldbm_cache_really_close LDAP_P(( Backend *be, struct dbcache *db ));
void ldbm_cache_flush_all LDAP_P(( Backend *be ));
Datum ldbm_cache_fetch LDAP_P(( struct dbcache *db, Datum key ));
int ldbm_cache_store LDAP_P(( struct dbcache *db, Datum key, Datum data, int flags ));
int ldbm_cache_delete LDAP_P(( struct dbcache *db, Datum key ));

/*
 * dn2id.c
 */

int dn2id_add LDAP_P(( Backend *be, char *dn, ID id ));
ID dn2id LDAP_P(( Backend *be, char *dn ));
int dn2id_delete LDAP_P(( Backend *be, char *dn ));
Entry * dn2entry_r LDAP_P(( Backend *be, char *dn, char **matched ));
Entry * dn2entry_w LDAP_P(( Backend *be, char *dn, char **matched ));

/*
 * filterindex.c
 */

ID_BLOCK * filter_candidates LDAP_P(( Backend *be, Filter *f ));

/*
 * id2children.c
 */

int id2children_add LDAP_P(( Backend *be, Entry *p, Entry *e ));
int id2children_remove LDAP_P(( Backend *be, Entry *p, Entry *e ));
int has_children LDAP_P(( Backend *be, Entry *p ));

/*
 * id2entry.c
 */

int id2entry_add LDAP_P(( Backend *be, Entry *e ));
int id2entry_delete LDAP_P(( Backend *be, Entry *e ));
Entry * id2entry LDAP_P(( Backend *be, ID id, int rw )); 
Entry * id2entry_r LDAP_P(( Backend *be, ID id ));
Entry * id2entry_w LDAP_P(( Backend *be, ID id ));

/*
 * idl.c
 */

ID_BLOCK * idl_alloc LDAP_P(( int nids ));
ID_BLOCK * idl_allids LDAP_P(( Backend *be ));
void idl_free LDAP_P(( ID_BLOCK *idl ));
ID_BLOCK * idl_fetch LDAP_P(( Backend *be, struct dbcache *db, Datum key ));
int idl_insert_key LDAP_P(( Backend *be, struct dbcache *db, Datum key, ID id ));
int idl_insert LDAP_P(( ID_BLOCK **idl, ID id, int maxids ));
int idl_delete_key LDAP_P(( Backend *be, struct dbcache *db, Datum key, ID id ));
ID_BLOCK * idl_intersection LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * idl_union LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * idl_notin LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID idl_firstid LDAP_P(( ID_BLOCK *idl ));
ID idl_nextid LDAP_P(( ID_BLOCK *idl, ID id ));

/*
 * index.c
 */

int index_add_entry LDAP_P(( Backend *be, Entry *e ));
int index_add_mods LDAP_P(( Backend *be, LDAPMod *mods, ID id ));
ID_BLOCK * index_read LDAP_P(( Backend *be, char *type, int indextype, char *val ));
int index_add_values LDAP_P(( Backend *be, char *type, struct berval **vals, ID  id ));

/*
 * kerberos.c
 */

#ifdef HAVE_KERBEROS
/* krbv4_ldap_auth LDAP_P(( Backend *be, struct berval *cred, AUTH_DAT *ad )); */
#endif

/*
 * nextid.c
 */

ID next_id LDAP_P(( Backend *be ));
void next_id_return LDAP_P(( Backend *be, ID id ));
ID next_id_get LDAP_P(( Backend *be ));
int next_id_save LDAP_P(( Backend *be ));

LDAP_END_DECL
#endif
