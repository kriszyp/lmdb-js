/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

#ifndef _PROTO_BACK_LDBM
#define _PROTO_BACK_LDBM

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/*
 * alias.c
 */
Entry *deref_internal_r LDAP_P((
	Backend *be,
	Entry *e,
	struct berval *dn,
	int *err,
	Entry **matched,
	const char **text ));

#define deref_entry_r( be, e, err, matched, text ) \
	deref_internal_r( be, e, NULL, err, matched, text )
#define deref_dn_r( be, dn, err, matched, text ) \
	deref_internal_r( be, NULL, dn, err, matched, text)

/*
 * attr.c
 */

void attr_mask LDAP_P(( struct ldbminfo *li,
	AttributeDescription *desc,
	slap_mask_t *indexmask ));

int attr_index_config LDAP_P(( struct ldbminfo *li,
	const char *fname, int lineno,
	int argc, char **argv ));
void attr_index_destroy LDAP_P(( Avlnode *tree ));

/*
 * cache.c
 */

int cache_add_entry_rw LDAP_P(( Cache *cache, Entry *e, int rw ));
int cache_update_entry LDAP_P(( Cache *cache, Entry *e ));
void cache_return_entry_rw LDAP_P(( Cache *cache, Entry *e, int rw ));
#define cache_return_entry_r(c, e) cache_return_entry_rw((c), (e), 0)
#define cache_return_entry_w(c, e) cache_return_entry_rw((c), (e), 1)
void cache_entry_commit LDAP_P(( Entry *e ));

ID cache_find_entry_ndn2id LDAP_P(( Backend *be, Cache *cache, struct berval *ndn ));
Entry * cache_find_entry_id LDAP_P(( Cache *cache, ID id, int rw ));
int cache_delete_entry LDAP_P(( Cache *cache, Entry *e ));
void cache_release_all LDAP_P(( Cache *cache ));

/*
 * dbcache.c
 */

DBCache * ldbm_cache_open LDAP_P(( Backend *be,
	const char *name, const char *suffix, int flags ));
void ldbm_cache_close LDAP_P(( Backend *be, DBCache *db ));
void ldbm_cache_really_close LDAP_P(( Backend *be, DBCache *db ));
void ldbm_cache_flush_all LDAP_P(( Backend *be ));
void ldbm_cache_sync LDAP_P(( Backend *be ));
#if 0 /* replaced by macro */
Datum ldbm_cache_fetch LDAP_P(( DBCache *db, Datum key ));
#else /* 1 */
#define ldbm_cache_fetch( db, key )	ldbm_fetch( (db)->dbc_db, (key) )
#endif /* 1 */
int ldbm_cache_store LDAP_P(( DBCache *db, Datum key, Datum data, int flags ));
int ldbm_cache_delete LDAP_P(( DBCache *db, Datum key ));
void *ldbm_cache_sync_daemon LDAP_P(( void *ctx, void *arg ));

/*
 * dn2id.c
 */

int dn2id_add LDAP_P(( Backend *be, struct berval *dn, ID id ));
int dn2id LDAP_P(( Backend *be, struct berval *dn, ID *idp ));
int dn2idl LDAP_P(( Backend *be, struct berval *dn, int prefix, ID_BLOCK **idlp ));
int dn2id_delete LDAP_P(( Backend *be, struct berval *dn, ID id ));

Entry * dn2entry_rw LDAP_P(( Backend *be, struct berval *dn, Entry **matched, int rw ));
#define dn2entry_r(be, dn, m) dn2entry_rw((be), (dn), (m), 0)
#define dn2entry_w(be, dn, m) dn2entry_rw((be), (dn), (m), 1)

/*
 * entry.c
 */
BI_entry_release_rw ldbm_back_entry_release_rw;
BI_entry_get_rw ldbm_back_entry_get;

/*
 * filterindex.c
 */

ID_BLOCK * filter_candidates LDAP_P(( Operation *op, Filter *f ));

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
ID_BLOCK * idl_fetch LDAP_P(( Backend *be, DBCache *db, Datum key ));
int idl_insert_key LDAP_P(( Backend *be, DBCache *db, Datum key, ID id ));
int idl_insert LDAP_P(( ID_BLOCK **idl, ID id, unsigned int maxids ));
int idl_delete_key LDAP_P(( Backend *be, DBCache *db, Datum key, ID id ));
ID_BLOCK * idl_intersection LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * idl_union LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID_BLOCK * idl_notin LDAP_P(( Backend *be, ID_BLOCK *a, ID_BLOCK *b ));
ID idl_firstid LDAP_P(( ID_BLOCK *idl, ID *cursor ));
ID idl_nextid LDAP_P(( ID_BLOCK *idl, ID *cursor ));

/*
 * index.c
 */
extern int
index_is_indexed LDAP_P((
	Backend *be,
	AttributeDescription *desc ));

extern int
index_param LDAP_P((
	Backend *be,
	AttributeDescription *desc,
	int ftype,
	char **dbname,
	slap_mask_t *mask,
	struct berval *prefix ));

extern int
index_values LDAP_P((
	Operation *op,
	AttributeDescription *desc,
	BerVarray vals,
	ID id,
	int opid ));

int index_entry LDAP_P(( Operation *op, int r, Entry *e ));
#define index_entry_add(be,e) index_entry((be),SLAP_INDEX_ADD_OP,(e))
#define index_entry_del(be,e) index_entry((be),SLAP_INDEX_DELETE_OP,(e))


/*
 * key.c
 */
extern int
key_change LDAP_P((
    Backend		*be,
    DBCache	*db,
    struct berval *k,
    ID			id,
    int			op ));
extern int
key_read LDAP_P((
    Backend	*be,
	DBCache *db,
    struct berval *k,
	ID_BLOCK **idout ));

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

/* returns LDAP error code indicating error OR SLAPD_ABANDON */
int ldbm_modify_internal LDAP_P(( Operation *op,
	Modifications *mods, Entry *e,
	const char **text, char *textbuf, size_t textlen ));

/*
 * nextid.c
 */

int next_id LDAP_P(( Backend *be, ID *idp ));
int next_id_get LDAP_P(( Backend *be, ID *idp ));
int next_id_write LDAP_P(( Backend *be, ID id ));

/*
 * former external.h
 */

extern BI_init			ldbm_back_initialize;

extern BI_open			ldbm_back_open;
extern BI_close			ldbm_back_close;
extern BI_destroy		ldbm_back_destroy;

extern BI_db_init		ldbm_back_db_init;
extern BI_db_open		ldbm_back_db_open;
extern BI_db_close		ldbm_back_db_close;
extern BI_db_destroy		ldbm_back_db_destroy;
extern BI_db_config		ldbm_back_db_config;

extern BI_op_extended		ldbm_back_extended;
extern BI_op_bind		ldbm_back_bind;
extern BI_op_search		ldbm_back_search;
extern BI_op_compare		ldbm_back_compare;
extern BI_op_modify		ldbm_back_modify;
extern BI_op_modrdn		ldbm_back_modrdn;
extern BI_op_add		ldbm_back_add;
extern BI_op_delete		ldbm_back_delete;

extern BI_operational		ldbm_back_operational;
extern BI_has_subordinates	ldbm_back_hasSubordinates;

/* hooks for slap tools */
extern BI_tool_entry_open	ldbm_tool_entry_open;
extern BI_tool_entry_close	ldbm_tool_entry_close;
extern BI_tool_entry_first	ldbm_tool_entry_first;
extern BI_tool_entry_next	ldbm_tool_entry_next;
extern BI_tool_entry_get	ldbm_tool_entry_get;
extern BI_tool_entry_put	ldbm_tool_entry_put;

extern BI_tool_entry_reindex	ldbm_tool_entry_reindex;
extern BI_tool_sync		ldbm_tool_sync;

extern BI_chk_referrals		ldbm_back_referrals;

LDAP_END_DECL

#endif /* _PROTO_BACK_LDBM */
