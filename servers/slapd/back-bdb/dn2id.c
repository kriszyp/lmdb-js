/* dn2id.c - routines to deal with the dn2id index */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "idl.h"
#include "lutil.h"

#ifndef BDB_HIER
int
bdb_dn2id_add(
	BackendDB	*be,
	DB_TXN *txn,
	EntryInfo *eip,
	Entry		*e,
	void *ctx )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	int		rc;
	DBT		key, data;
	char		*buf;
	struct berval	ptr, pdn;

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, ARGS, "bdb_dn2id_add( \"%s\", 0x%08lx )\n",
		e->e_ndn, (long) e->e_id, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_add( \"%s\", 0x%08lx )\n",
		e->e_ndn, (long) e->e_id, 0 );
#endif
	assert( e->e_id != NOID );

	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	key.ulen = key.size;
	key.flags = DB_DBT_USERMEM;
	buf = sl_malloc( key.size, ctx );
	key.data = buf;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf + 1;
	ptr.bv_len = e->e_nname.bv_len;
	AC_MEMCPY( ptr.bv_val, e->e_nname.bv_val, e->e_nname.bv_len );
	ptr.bv_val[ptr.bv_len] = '\0';

	DBTzero( &data );
	data.data = (char *) &e->e_id;
	data.size = sizeof( e->e_id );

	/* store it -- don't override */
	rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( INDEX, ERR, "bdb_dn2id_add: put failed: %s %d\n",
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_dn2id_add: put failed: %s %d\n",
			db_strerror(rc), rc, 0 );
#endif
		goto done;
	}

#ifndef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( be, &ptr )) {
#endif
		buf[0] = DN_SUBTREE_PREFIX;
		rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
		if( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( INDEX, ERR, 
				"=> bdb_dn2id_add: subtree (%s) put failed: %d\n",
				ptr.bv_val, rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
			"=> bdb_dn2id_add: subtree (%s) put failed: %d\n",
			ptr.bv_val, rc, 0 );
#endif
			goto done;
		}
		
#ifdef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( be, &ptr )) {
#endif
		dnParent( &ptr, &pdn );
	
		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		pdn.bv_val[-1] = DN_ONE_PREFIX;
		key.data = pdn.bv_val-1;
		ptr = pdn;

		rc = bdb_idl_insert_key( be, db, txn, &key, e->e_id );

		if( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( INDEX, ERR, 
				"=> bdb_dn2id_add: parent (%s) insert failed: %d\n",
				ptr.bv_val, rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_add: parent (%s) insert failed: %d\n",
					ptr.bv_val, rc, 0 );
#endif
			goto done;
		}
#ifndef BDB_MULTIPLE_SUFFIXES
	}

	while( !be_issuffix( be, &ptr )) {
#else
	for (;;) {
#endif
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		rc = bdb_idl_insert_key( be, db, txn, &key, e->e_id );

		if( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( INDEX, ERR, 
				"=> bdb_dn2id_add: subtree (%s) insert failed: %d\n",
				ptr.bv_val, rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_add: subtree (%s) insert failed: %d\n",
					ptr.bv_val, rc, 0 );
#endif
			break;
		}
#ifdef BDB_MULTIPLE_SUFFIXES
		if( be_issuffix( be, &ptr )) break;
#endif
		dnParent( &ptr, &pdn );

		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		key.data = pdn.bv_val - 1;
		ptr = pdn;
	}
#ifdef BDB_MULTIPLE_SUFFIXES
	}
#endif

done:
	sl_free( buf, ctx );
#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, RESULTS, "<= bdb_dn2id_add: %d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_add: %d\n", rc, 0, 0 );
#endif
	return rc;
}

int
bdb_dn2id_delete(
	BackendDB	*be,
	DB_TXN *txn,
	EntryInfo	*eip,
	Entry		*e,
	void *ctx )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	int		rc;
	DBT		key;
	char		*buf;
	struct berval	pdn, ptr;

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, ARGS, 
		"=> bdb_dn2id_delete ( \"%s\", 0x%08lx )\n", e->e_ndn, e->e_id, 0);
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_delete( \"%s\", 0x%08lx )\n",
		e->e_ndn, e->e_id, 0 );
#endif

	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	buf = sl_malloc( key.size, ctx );
	key.data = buf;
	key.flags = DB_DBT_USERMEM;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf+1;
	ptr.bv_len = e->e_nname.bv_len;
	AC_MEMCPY( ptr.bv_val, e->e_nname.bv_val, e->e_nname.bv_len );
	ptr.bv_val[ptr.bv_len] = '\0';

	/* delete it */
	rc = db->del( db, txn, &key, 0 );
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( INDEX, ERR, 
			"=> bdb_dn2id_delete: delete failed: %s %d\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "=> bdb_dn2id_delete: delete failed: %s %d\n",
			db_strerror(rc), rc, 0 );
#endif
		goto done;
	}

#ifndef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( be, &ptr )) {
#endif
		buf[0] = DN_SUBTREE_PREFIX;
		rc = db->del( db, txn, &key, 0 );
		if( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( INDEX, ERR, 
				"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n", 
				ptr.bv_val, rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
			"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n",
			ptr.bv_val, rc, 0 );
#endif
			goto done;
		}

#ifdef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( be, &ptr )) {
#endif
		dnParent( &ptr, &pdn );

		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		pdn.bv_val[-1] = DN_ONE_PREFIX;
		key.data = pdn.bv_val - 1;
		ptr = pdn;

		rc = bdb_idl_delete_key( be, db, txn, &key, e->e_id );

		if( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( INDEX, ERR, 
				"=> bdb_dn2id_delete: parent (%s) delete failed: %d\n", 
				ptr.bv_val, rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_delete: parent (%s) delete failed: %d\n",
				ptr.bv_val, rc, 0 );
#endif
			goto done;
		}
#ifndef BDB_MULTIPLE_SUFFIXES
	}

	while( !be_issuffix( be, &ptr )) {
#else
	for (;;) {
#endif
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		rc = bdb_idl_delete_key( be, db, txn, &key, e->e_id );
		if( rc != 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( INDEX, ERR, 
				"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n", 
				ptr.bv_val, rc, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n",
				ptr.bv_val, rc, 0 );
#endif
			goto done;
		}
#ifdef BDB_MULTIPLE_SUFFIXES
		if( be_issuffix( be, &ptr )) break;
#endif
		dnParent( &ptr, &pdn );

		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		key.data = pdn.bv_val - 1;
		ptr = pdn;
	}
#ifdef BDB_MULTIPLE_SUFFIXES
	}
#endif

done:
	sl_free( buf, ctx );
#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, RESULTS, "<= bdb_dn2id_delete %d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_delete %d\n", rc, 0, 0 );
#endif
	return rc;
}

int
bdb_dn2id(
	BackendDB	*be,
	DB_TXN *txn,
	struct berval	*dn,
	EntryInfo *ei,
	void *ctx )
{
	int		rc;
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, ARGS, "=> bdb_dn2id( \"%s\" )\n", dn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id( \"%s\" )\n", dn->bv_val, 0, 0 );
#endif

	DBTzero( &key );
	key.size = dn->bv_len + 2;
	key.data = sl_malloc( key.size, ctx );
	((char *)key.data)[0] = DN_BASE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn->bv_val, key.size - 1 );

	/* store the ID */
	DBTzero( &data );
	data.data = &ei->bei_id;
	data.ulen = sizeof(ID);
	data.flags = DB_DBT_USERMEM;

	/* fetch it */
	rc = db->get( db, txn, &key, &data, bdb->bi_db_opflags );

	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( INDEX, ERR, "<= bdb_dn2id: get failed %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id: get failed: %s (%d)\n",
			db_strerror( rc ), rc, 0 );
#endif
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( INDEX, RESULTS, 
			"<= bdb_dn2id: got id=0x%08lx\n", ei->bei_id, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id: got id=0x%08lx\n",
			ei->bei_id, 0, 0 );
#endif
	}

	sl_free( key.data, ctx );
	return rc;
}

int
bdb_dn2id_children(
	Operation *op,
	DB_TXN *txn,
	Entry *e )
{
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	ID		id;
	int		rc;

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, ARGS, 
		"=> bdb_dn2id_children( %s )\n", e->e_nname.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_children( %s )\n",
		e->e_nname.bv_val, 0, 0 );
#endif
	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	key.data = sl_malloc( key.size, op->o_tmpmemctx );
	((char *)key.data)[0] = DN_ONE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], e->e_nname.bv_val, key.size - 1 );

#ifdef SLAP_IDL_CACHE
	if ( bdb->bi_idl_cache_size ) {
		rc = bdb_idl_cache_get( bdb, db, &key, NULL );
		if ( rc != LDAP_NO_SUCH_OBJECT ) {
			sl_free( key.data, o->o_tmpmemctx );
			return rc;
		}
	}
#endif
	/* we actually could do a empty get... */
	DBTzero( &data );
	data.data = &id;
	data.ulen = sizeof(id);
	data.flags = DB_DBT_USERMEM;
	data.doff = 0;
	data.dlen = sizeof(id);

	rc = db->get( db, txn, &key, &data, bdb->bi_db_opflags );
	sl_free( key.data, op->o_tmpmemctx );

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, DETAIL1, 
		"<= bdb_dn2id_children( %s ): %s (%d)\n", 
		e->e_nname.bv_val, rc == 0 ? "" : ( rc == DB_NOTFOUND ? "no " :
		db_strerror(rc)), rc );
#else
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_children( %s ): %s (%d)\n",
		e->e_nname.bv_val,
		rc == 0 ? "" : ( rc == DB_NOTFOUND ? "no " :
			db_strerror(rc) ), rc );
#endif

	return rc;
}

int
bdb_dn2idl(
	BackendDB	*be,
	struct berval	*dn,
	int prefix,
	ID *ids )
{
	int		rc;
	DBT		key;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, ARGS, 
		"=> bdb_dn2ididl( \"%s\" )\n", dn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2idl( \"%s\" )\n", dn->bv_val, 0, 0 );
#endif

#ifndef	BDB_MULTIPLE_SUFFIXES
	if (prefix == DN_SUBTREE_PREFIX && be_issuffix(be, dn))
	{
		BDB_IDL_ALL(bdb, ids);
		return 0;
	}
#endif

	DBTzero( &key );
	key.size = dn->bv_len + 2;
	key.ulen = key.size;
	key.flags = DB_DBT_USERMEM;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = prefix;
	AC_MEMCPY( &((char *)key.data)[1], dn->bv_val, key.size - 1 );

	rc = bdb_idl_fetch_key( be, db, NULL, &key, ids );

	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( INDEX, ERR, 
			"<= bdb_dn2ididl: get failed: %s (%d)\n", db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_dn2idl: get failed: %s (%d)\n",
			db_strerror( rc ), rc, 0 );
#endif

	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( INDEX, RESULTS, 
			"<= bdb_dn2ididl: id=%ld first=%ld last=%ld\n", 
			(long) ids[0], (long) BDB_IDL_FIRST( ids ), 
			(long) BDB_IDL_LAST( ids ) );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_dn2idl: id=%ld first=%ld last=%ld\n",
			(long) ids[0],
			(long) BDB_IDL_FIRST( ids ), (long) BDB_IDL_LAST( ids ) );
#endif
	}

	ch_free( key.data );
	return rc;
}
#else	/* BDB_HIER */

/* Experimental management routines for a hierarchically structured database.
 *
 * Unsupported! Use at your own risk!
 *
 * Instead of a ldbm-style dn2id database, we use a hierarchical one. Each
 * entry in this database is a struct diskNode, keyed by entryID and with
 * the data containing the RDN and entryID of the node's children. We use
 * a B-Tree with sorted duplicates to store all the children of a node under
 * the same key. Also, the first item under the key contains an empty rdn
 * and the ID of the node's parent, to allow bottom-up tree traversal as
 * well as top-down.
 *
 * The diskNode is a variable length structure. This definition is not
 * directly usable for in-memory manipulation.
 */
typedef struct diskNode {
	ID entryID;
	short nrdnlen;
	char nrdn[1];
	char rdn[1];
} diskNode;

/* Sort function for the sorted duplicate data items of a dn2id key.
 * Sorts based on normalized RDN, in lexical order.
 */
int
bdb_hdb_compare(
	DB *db, 
	const DBT *usrkey,
	const DBT *curkey
)
{
	diskNode *usr = usrkey->data;
	diskNode *cur = curkey->data;
	short curlen;
	char *ptr = (char *)&cur->nrdnlen;
	int rc;

	curlen = ptr[0] << 8 | ptr[1];

	rc = strncmp( usr->nrdn, cur->nrdn, usr->nrdnlen );
	if ( rc == 0 ) rc = usrlen - curlen;
	return rc;
}

/* This function constructs a full DN for a given entry.
 */
int bdb_fix_dn(
	BackendDB *be,
	Entry *e
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	EntryInfo *ei;
	int rlen = 0, nrlen = 0;
	char *ptr, *nptr;
	
	for ( ei = BEI(e); ei; ei=ei->bei_parent ) {
		rlen += ei->bei_rdn.bv_len + 1;
		nrlen += ei->bei_nrdn.bv_len + 1;
	}
	e->e_name.bv_len = rlen - 1;
	e->e_nname.bv_len = nrlen - 1;
	e->e_name.bv_val = ch_malloc(rlen + nrlen);
	e->e_nname.bv_val = e->e_name.bv_val + rlen;
	ptr = e->e_name.bv_val;
	nptr = e->e_nname.bv_val;
	for ( ei = BEI(e); ei; ei=ei->bei_parent ) {
		ptr = lutil_strcopy(ptr, ei->bei_rdn.bv_val);
		nptr = lutil_strcopy(nptr, ei->bei_nrdn.bv_val);
		if ( ei->bei_parent ) {
			*ptr++ = ',';
			*nptr++ = ',';
		}
	}
	*ptr = '\0';
	*nptr = '\0';

	return 0;
}

/* We add two elements to the DN2ID database - a data item under the parent's
 * entryID containing the child's RDN and entryID, and an item under the
 * child's entryID containing the parent's entryID.
 */
int
bdb_dn2id_add(
	BackendDB	*be,
	DB_TXN *txn,
	EntryInfo	*eip,
	Entry		*e,
	void *ctx )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	int		rc, rlen, nrlen;
	diskNode *d;
	char *ptr;

	nrlen = dn_rdnlen( be, &e->e_nname );
	if (nrlen) {
		rlen = dn_rdnlen( be, &e->e_name );
	} else {
		rlen = 0;
	}

	d = sl_malloc(sizeof(diskNode) + rlen + nrlen, ctx);
	d->entryID = e->e_id;
	d->nrdnlen = nrlen;
	ptr = lutil_strncopy( d->nrdn, e->e_nname.bv_val, nrlen );
	*ptr++ = '\0';
	ptr = lutil_strncopy( ptr, e->e_name.bv_val, rlen );
	*ptr = '\0';

	DBTzero(&key);
	DBTzero(&data);
	key.data = &eip->bei_id;
	key.size = sizeof(ID);
	key.flags = DB_DBT_USERMEM;

#ifdef SLAP_IDL_CACHE
	if ( bdb->bi_idl_cache_size ) {
		bdb_idl_cache_del( bdb, db, &key );
	}
#endif
	data.data = d;
	data.size = sizeof(diskNode) + rlen + nrlen + 2;
	data.flags = DB_DBT_USERMEM;

	rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );

	if (rc == 0) {
		key.data = &e->e_id;
		d->entryID = eip->bei_id;
		d->nrdnlen = 0;
		d->nrdn[0] = '\0';
		d->rdn[0] = '\0';
		data.size = sizeof(diskNode);

		rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
	}

	sl_free( d, ctx );

	return rc;
}

int
bdb_dn2id_delete(
	BackendDB	*be,
	DB_TXN *txn,
	EntryInfo	*eip,
	Entry	*e,
	void	*ctx )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	DBC	*cursor;
	diskNode *d;
	int rc, nrlen;

	DBTzero(&key);
	key.size = sizeof(ID);
	key.ulen = key.size;
	key.data = &eip->bei_id;
	key.flags = DB_DBT_USERMEM;

	DBTzero(&data);
	data.size = sizeof(diskNode) + BEI(e)->nrdn.bv_len;
	d = sl_malloc( data.size, ctx );
	d->entryID = e->e_id;
	d->nrdnlen = BEI(e)->nrdn.bv_len;
	strcpy( d->nrdn, BEI(e)->nrdn.bv_val );
	data.data = d;
	data.ulen = data.size;
	data.dlen = data.size;
	data.flags = DB_DBT_USERMEM | DB_DBT_PARTIAL;

#ifdef SLAP_IDL_CACHE
	if ( bdb->bi_idl_cache_size ) {
		bdb_idl_cache_del( bdb, db, &key );
	}
#endif
	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	rc = cursor->c_get( cursor, &key, &data, DB_GET_BOTH | DB_RMW );
	if ( rc == 0 )
		rc = cursor->c_del( cursor, 0 );
	cursor->c_close( cursor );

	key.data = &e->e_id;
	rc = db->del( db, txn, &key, 0);
	sl_free( d, ctx );

	return rc;
}

int
bdb_dn2id(
	BackendDB	*be,
	DB_TXN *txn,
	struct berval	*in,
	EntryInfo	*ei,
	void *ctx )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	DBC	*cursor;
	int		rc = 0, nrlen;
	char	*ptr;

	nrlen = dn_rdnlen( be, &in );

	DBTzero(&key);
	key.size = sizeof(ID);
	key.data = &eip->bei_id;
	key.flags = DB_DBT_USERMEM;

	DBTzero(&data);
	data.size = sizeof(diskNode) + nrlen;
	d = sl_malloc( data.size * 3, ctx );
	d->nrdnlen = nrlen;
	ptr = lutil_strncopy( d->nrdn, BEI(e)->nrdn.bv_val, nrlen );
	*ptr = '\0';
	data.data = d;
	data.ulen = data.size * 3;
	data.flags = DB_DBT_USERMEM;

	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	rc = cursor->c_get( cursor, &key, &data, DB_GET_BOTH );
	cursor->c_close( cursor );
	if ( rc ) return rc;

	AC_MEMCPY( &ei->bei_id, &d->entryID, sizeof(ID) );
	ei->rdn.bv_len = data.size - sizeof(diskNode) - nrlen;
	ptr = d->nrdn + nrlen + 1;
	strcpy( ei->rdn.bv_val, ptr );

	return rc;
}

int
bdb_dn2id_children(
	Operation *op,
	DB_TXN *txn,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	DBC		*cursor;
	int		rc;
	ID		id;
	diskNode d;

	DBTzero(&key);
	key.size = sizeof(ID);
	key.data = &e->e_id;
	key.flags = DB_DBT_USERMEM;

#ifdef SLAP_IDL_CACHE
	if ( bdb->bi_idl_cache_size ) {
		rc = bdb_idl_cache_get( bdb, db, &key, NULL );
		if ( rc != LDAP_NO_SUCH_OBJECT ) {
			sl_free( key.data, o->o_tmpmemctx );
			return rc;
		}
	}
#endif
	DBTzero(&data);
	data.ulen = sizeof(d);
	data.flags = DB_DBT_USERMEM | DB_DBT_PARTIAL;
	data.dlen = sizeof(d);

	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	rc = cursor->c_get( cursor, &key, &data, DB_FIRST );
	if ( rc == 0 ) {
		rc = cursor->c_get( cursor, &key, &data, DB_NEXT_DUP );
	}
	cursor->c_close( cursor );
	return rc;
}

int
bdb_dn2idl(
	BackendDB	*be,
	struct berval	*dn,
	int prefix,
	ID *ids )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int		rc;
	ID		id;
	idNode		*n;

	if (prefix == DN_SUBTREE_PREFIX && be_issuffix(be, dn)) {
		BDB_IDL_ALL(bdb, ids);
		return 0;
	}

	rc = bdb_dn2id(be, NULL, dn, &id, 0);
	if (rc) return rc;

	ldap_pvt_thread_rdwr_rlock(&bdb->bi_tree_rdwr);
	n = bdb_find_id_node(id, bdb->bi_tree);
	ldap_pvt_thread_rdwr_runlock(&bdb->bi_tree_rdwr);

	ids[0] = 0;
	ldap_pvt_thread_rdwr_rlock(&n->i_kids_rdwr);
	if (prefix == DN_ONE_PREFIX) {
		rc = avl_apply(n->i_kids, insert_one, ids, -1, AVL_INORDER);
	} else {
		ids[0] = 1;
		ids[1] = id;
		if (n->i_kids)
			rc = avl_apply(n->i_kids, insert_sub, ids, -1, AVL_INORDER);
	}
	ldap_pvt_thread_rdwr_runlock(&n->i_kids_rdwr);
	return rc;
}
#endif	/* BDB_HIER */
