/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
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
	const char *dn,
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
 * attribute.c
 */

BI_acl_attribute bdb_attribute;

/*
 * dbcache.c
 */
int
bdb_db_cache(
    Backend	*be,
    const char *name,
	DB **db );

/*
 * dn2entry.c
 */
int bdb_dn2entry LDAP_P(( BackendDB *be, DB_TXN *tid,
	struct berval *dn, Entry **e, Entry **matched, int flags ));

/*
 * dn2id.c
 */
int bdb_dn2id(
	BackendDB *be,
	DB_TXN *tid,
	struct berval *dn,
	ID *id );

int bdb_dn2id_matched(
	BackendDB *be,
	DB_TXN *tid,
	struct berval *dn,
	ID *id,
	char **matchedDN );

int bdb_dn2id_add(
	BackendDB *be,
	DB_TXN *tid,
	char *pdn,
	Entry *e );

int bdb_dn2id_delete(
	BackendDB *be,
	DB_TXN *tid,
	char *pdn,
	Entry *e );

int bdb_dn2id_children(
	BackendDB *be,
	DB_TXN *tid,
	struct berval *dn );

int
bdb_dn2idl(
	BackendDB	*be,
	struct berval	*dn,
	int prefix,
	ID *ids );

/*
 * entry.c
 */
int bdb_entry_return( BackendDB *be, Entry *e );
BI_entry_release_rw bdb_entry_release;

/*
 * error.c
 */
void bdb_errcall( const char *pfx, char * msg );

/*
 * filterentry.c
 */
int bdb_filter_candidates(
	Backend	*be,
	Filter	*f,
	ID *ids,
	ID *tmp );

/*
 * group.c
 */

BI_acl_group bdb_group;

/*
 * id2entry
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
	ID id );

int bdb_id2entry(
	BackendDB *be,
	DB_TXN *tid,
	ID id,
	Entry **e );

/*
 * idl.c
 */
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
bdb_index_param LDAP_P((
	Backend *be,
	AttributeDescription *desc,
	int ftype,
	DB **db,
	slap_mask_t *mask,
	struct berval *prefix ));

extern int
bdb_index_values LDAP_P((
	Backend *be,
	DB_TXN *txn,
	AttributeDescription *desc,
	struct berval **vals,
	ID id,
	int op ));

int bdb_index_entry LDAP_P(( Backend *be, DB_TXN *t,
	int r, Entry *e, Attribute *ap ));

#define bdb_index_entry_add(be,t,e,ap) \
	bdb_index_entry((be),(t),SLAP_INDEX_ADD_OP,(e),(ap))
#define bdb_index_entry_del(be,t,e,ap) \
	bdb_index_entry((be),(t),SLAP_INDEX_DELETE_OP,(e),(ap))

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
	BackendDB *be,
	Connection *conn,
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
 * tools.c
 */
BI_tool_entry_open	bdb_tool_entry_open;
BI_tool_entry_close	bdb_tool_entry_close;
BI_tool_entry_next	bdb_tool_entry_next;
BI_tool_entry_get	bdb_tool_entry_get;
BI_tool_entry_put	bdb_tool_entry_put;
BI_tool_entry_reindex	bdb_tool_entry_reindex;


LDAP_END_DECL

#endif /* _PROTO_BDB_H */
