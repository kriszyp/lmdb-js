/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _PROTO_BDB_H
#define _PROTO_BDB_H

LDAP_BEGIN_DECL

/*
 * error.c
 */
void bdb_errcall( const char *pfx, char * msg );

/*
 * dn.c
 */
int bdb_index_dn_add(
	BackendDB *be,
	DB_TXN *tid,
	const char *dn,
	ID id );

/*
 * nextid.c
 */
int bdb_next_id( BackendDB *be, DB_TXN *tid, ID *id );

LDAP_END_DECL

#endif /* _PROTO_BDB_H */
