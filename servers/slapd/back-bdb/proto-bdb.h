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
 * dn2entry.c
 */
int bdb_dn2entry LDAP_P(( BackendDB *be, DB_TXN *tid,
	const char *dn, Entry **e, Entry **matched, int flags ));

#define dn2entry_r(be, tid, dn, p, m) \
	bdb_dn2entry((be), (tid), (dn), (p), (m), 0 )

#define dn2entry_w(be, tid, dn, p, m) \
	bdb_dn2entry((be), (tid), (dn), (p), (m), DB_RMW )

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

/*
 * entry.c
 */
int bdb_entry_return( BackendDB *be, Entry *e );

/*
 * error.c
 */
void bdb_errcall( const char *pfx, char * msg );

/*
 * id2entry
 */
int bdb_id2entry_add(
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
int bdb_idl_search( ID *ids, ID id );

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

/*
 * nextid.c
 */
int bdb_next_id( BackendDB *be, DB_TXN *tid, ID *id );

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
