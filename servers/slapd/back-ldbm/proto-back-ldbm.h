#ifndef _PROTO_BACK_LDBM
#define _PROTO_BACK_LDBM

/*
 * attr.c
 */

void attr_masks( struct ldbminfo *li, char *type, int *indexmask,
 int *syntaxmask );
void attr_index_config( struct ldbminfo *li, char *fname, int lineno,
 int argc, char **argv, int init );

/*
 * cache.c
 */

void cache_set_state( struct cache *cache, Entry *e, int state );
void cache_return_entry( struct cache *cache, Entry *e );
int cache_add_entry_lock( struct cache *cache, Entry *e, int state );
Entry * cache_find_entry_dn( struct cache *cache, char *dn );
Entry * cache_find_entry_id( struct cache *cache, ID id );
int cache_delete_entry( struct cache *cache, Entry *e );

/*
 * dbcache.c
 */

struct dbcache * ldbm_cache_open( Backend *be, char *name, char *suffix,
 int flags );
void ldbm_cache_close( Backend *be, struct dbcache *db );
void ldbm_cache_flush_all( Backend *be );
Datum ldbm_cache_fetch( struct dbcache *db, Datum key );
int ldbm_cache_store( struct dbcache *db, Datum key, Datum data, int flags );
int ldbm_cache_delete( struct dbcache *db, Datum key );

/*
 * dn2id.c
 */

int dn2id_add( Backend *be, char *dn, ID id );
ID dn2id( Backend *be, char *dn );
int dn2id_delete( Backend *be, char *dn );
Entry * dn2entry( Backend *be, char *dn, char **matched );

/*
 * filterindex.c
 */

IDList * filter_candidates( Backend *be, Filter *f );

/*
 * id2children.c
 */

int id2children_add( Backend *be, Entry *p, Entry *e );
int has_children( Backend *be, Entry *p );

/*
 * id2entry.c
 */

int id2entry_add( Backend *be, Entry *e );
int id2entry_delete( Backend *be, Entry *e );
Entry * id2entry( Backend *be, ID id );

/*
 * idl.c
 */

IDList * idl_alloc( int nids );
IDList * idl_allids( Backend *be );
void idl_free( IDList *idl );
IDList * idl_fetch( Backend *be, struct dbcache *db, Datum key );
int idl_insert_key( Backend *be, struct dbcache *db, Datum key, ID id );
int idl_insert( IDList **idl, ID id, int maxids );
IDList * idl_intersection( Backend *be, IDList *a, IDList *b );
IDList * idl_union( Backend *be, IDList *a, IDList *b );
IDList * idl_notin( Backend *be, IDList *a, IDList *b );
ID idl_firstid( IDList *idl );
ID idl_nextid( IDList *idl, ID id );

/*
 * index.c
 */

int index_add_entry( Backend *be, Entry *e );
int index_add_mods( Backend *be, LDAPMod *mods, ID id );
IDList * index_read( Backend *be, char *type, int indextype, char *val );
int index_add_values( Backend *be, char *type, struct berval **vals, ID  id );

/*
 * kerberos.c
 */

#ifdef KERBEROS
/* krbv4_ldap_auth( Backend *be, struct berval *cred, AUTH_DAT *ad ); */
#endif

/*
 * nextid.c
 */

ID next_id( Backend *be );
void next_id_return( Backend *be, ID id );
ID next_id_get( Backend *be );

#endif
