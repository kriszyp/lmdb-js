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

void bdb_attr_mask LDAP_P(( struct bdb_info *bdb,
	const char *desc,
	slap_mask_t *indexmask ));

int bdb_attr_index_config LDAP_P(( struct bdb_info *bdb,
	const char *fname, int lineno,
	int argc, char **argv ));

void bdb_attr_index_destroy LDAP_P(( Avlnode *tree ));

/*
 * dn2entry.c
 */
int bdb_dn2entry LDAP_P(( BackendDB *be, DB_TXN *tid,
	const char *dn, Entry **e, Entry **matched, int flags ));

/*
 * dn2id.c
 */
int bdb_dn2id(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn,
	ID *id );

int bdb_dn2id_matched(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn,
	ID *id,
	char **matchedDN );

int bdb_dn2id_add(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn,
	ID id );

int bdb_dn2id_delete(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn,
	ID id );

int bdb_dn2id_children(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn );

int
bdb_dn2idl(
	BackendDB	*be,
	const char	*dn,
	int prefix,
	ID *ids );

/*
 * entry.c
 */
int bdb_entry_return( BackendDB *be, Entry *e );

/*
 * error.c
 */
void bdb_errcall( const char *pfx, char * msg );

/*
 * filterentry.c
 */
int bdb_filter_candidates(
	Backend	*be,
	ID *range,
	Filter	*f,
	ID *ids );

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
bdb_idl_notin(
    ID 	*a,
    ID 	*b,
	ID	*ids );

int
bdb_idl_intersection(
	ID *a,
	ID *b,
	ID *ids );

int
bdb_idl_union(
	ID *a,
	ID *b,
	ID *ids );

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
	char **dbname,
	slap_mask_t *mask,
	struct berval **prefix ));

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
    struct berval *k,
	ID *ids );
	
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
int
bdb_exop_passwd(
	Backend		*be,
	Connection		*conn,
	Operation		*op,
	const char		*reqoid,
	struct berval	*reqdata,
	char			**rspoid,
	struct berval	**rspdata,
	LDAPControl		*** rspctrls,
	const char		**text,
	struct berval	*** refs );

/*
 * tools.c
 */
int bdb_tool_entry_open( BackendDB *be, int mode );
int bdb_tool_entry_close( BackendDB *be );
ID bdb_tool_entry_next( BackendDB *be );
Entry* bdb_tool_entry_get( BackendDB *be, ID id );
ID bdb_tool_entry_put( BackendDB *be, Entry *e );
int bdb_tool_entry_reindex( BackendDB *be, ID id );


LDAP_END_DECL

#endif /* _PROTO_BDB_H */
