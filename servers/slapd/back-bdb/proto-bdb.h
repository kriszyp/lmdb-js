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
	Backend *be,
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
 * dn2id.c
 */
int bdb_index_dn_add(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn,
	ID id );

Entry * bdb_dn2entry_rw LDAP_P(( Backend *be, DB_TXN *tid,
	const char *dn, Entry **matched, int rw ));

#define dn2entry_r(be, tid, dn, m) bdb_dn2entry_rw((be), (tid), (dn), (m), 0)
#define dn2entry_w(be, tid, dn, m) bdb_dn2entry_rw((be), (tid), (dn), (m), 1)

/*
 * error.c
 */
void bdb_errcall( const char *pfx, char * msg );

/*
 * idl.c
 */
int bdb_idl_insert_key(
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


LDAP_END_DECL

#endif /* _PROTO_BDB_H */
