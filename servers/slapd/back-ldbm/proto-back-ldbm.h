#ifndef _PROTO_BACK_LDBM
#define _PROTO_BACK_LDBM

#include <ldap_cdefs.h>

#include "external.h"

LDAP_BEGIN_DECL

/*
 * alias.c
 */
Entry *deref_internal_r LDAP_P((
	Backend *be,
	Entry *e,
	char *dn,
	int *err,
	Entry **matched,
	char **text ));

#define deref_entry_r( be, e, err, matched, text ) \
	deref_internal_r( be, e, NULL, err, matched, text )
#define deref_dn_r( be, dn, err, matched, text ) \
	deref_internal_r( be, NULL, dn, err, matched, text)

/*
 * attr.c
 */

void attr_masks LDAP_P(( struct ldbminfo *li, char *type, int *indexmask,
 int *syntaxmask ));
void attr_index_config LDAP_P(( struct ldbminfo *li, char *fname, int lineno,
 int argc, char **argv, int init ));
#ifdef SLAP_CLEANUP
void attr_index_destroy LDAP_P(( Avlnode *tree ));
#endif

/*
 * cache.c
 */

int cache_add_entry_rw LDAP_P(( struct cache *cache, Entry *e, int rw ));
int cache_update_entry LDAP_P(( struct cache *cache, Entry *e ));
void cache_return_entry_rw LDAP_P(( struct cache *cache, Entry *e, int rw ));
#define cache_return_entry_r(c, e) cache_return_entry_rw((c), (e), 0)
#define cache_return_entry_w(c, e) cache_return_entry_rw((c), (e), 1)

ID cache_find_entry_dn2id LDAP_P(( Backend *be, struct cache *cache, char *dn ));
Entry * cache_find_entry_id LDAP_P(( struct cache *cache, ID id, int rw ));
int cache_delete_entry LDAP_P(( struct cache *cache, Entry *e ));
#ifdef SLAP_CLEANUP
void cache_release_all LDAP_P(( struct cache *cache ));
#endif

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

Entry * dn2entry_rw LDAP_P(( Backend *be, char *dn, Entry **matched, int rw ));
#define dn2entry_r(be, dn, m) dn2entry_rw((be), (dn), (m), 0)
#define dn2entry_w(be, dn, m) dn2entry_rw((be), (dn), (m), 1)

/*
 * entry.c
 */
int ldbm_back_entry_release_rw LDAP_P(( Backend *be, Entry *e, int rw ));

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

Entry * id2entry_rw LDAP_P(( Backend *be, ID id, int rw )); 
#define id2entry_r(be, id)	id2entry_rw((be), (id), 0)
#define id2entry_w(be, id)	id2entry_rw((be), (id), 1)

/*
 * idl.c
 */

ID_BLOCK * idl_alloc LDAP_P(( unsigned int nids ));
ID_BLOCK * idl_allids LDAP_P(( Backend *be ));
void idl_free LDAP_P(( ID_BLOCK *idl ));
ID_BLOCK * idl_fetch LDAP_P(( Backend *be, struct dbcache *db, Datum key ));
int idl_insert_key LDAP_P(( Backend *be, struct dbcache *db, Datum key, ID id ));
int idl_insert LDAP_P(( ID_BLOCK **idl, ID id, unsigned int maxids ));
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
int index_add_mods LDAP_P(( Backend *be, LDAPModList *ml, ID id ));
ID_BLOCK * index_read LDAP_P(( Backend *be, char *type, int indextype, char *val ));
/* Possible operations supported (op) by index_change_values() */
#define __INDEX_ADD_OP		0x0001
#define __INDEX_DELETE_OP	0x0002
int index_change_values LDAP_P(( Backend *be,
				 char *type,
				 struct berval **vals,
				 ID  id,
				 unsigned int op ));


/*
 * kerberos.c
 */

#ifdef HAVE_KERBEROS
/* krbv4_ldap_auth LDAP_P(( Backend *be, struct berval *cred, AUTH_DAT *ad )); */
#endif
 
/*
 * modify.c
 * These prototypes are placed here because they are used by modify and
 * modify rdn which are implemented in different files. 
 *
 * We need ldbm_internal_modify here because of LDAP modrdn & modify use 
 * it. If we do not add this, there would be a bunch of code replication 
 * here and there and of course the likelihood of bugs increases.
 * Juan C. Gomez (gomez@engr.sgi.com) 05/18/99
 * 
 */

int add_values LDAP_P(( Entry *e, LDAPMod *mod, char *dn ));
int delete_values LDAP_P(( Entry *e, LDAPMod *mod, char *dn ));
int replace_values LDAP_P(( Entry *e, LDAPMod *mod, char *dn ));
int ldbm_modify_internal LDAP_P((Backend *be, Connection *conn, Operation *op,
			         char *dn, LDAPModList *mods, Entry *e));

/*
 * nextid.c
 */

ID next_id LDAP_P(( Backend *be ));
void next_id_return LDAP_P(( Backend *be, ID id ));
ID next_id_get LDAP_P(( Backend *be ));
int next_id_save LDAP_P(( Backend *be ));

LDAP_END_DECL
#endif
