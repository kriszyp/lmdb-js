/* dn2id.c - routines to deal with the dn2id index */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "idl.h"
#include "lutil.h"

#ifndef BDB_HIER
int
bdb_dn2id_add(
	Operation *op,
	DB_TXN *txn,
	EntryInfo *eip,
	Entry		*e )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	int		rc;
	DBT		key, data;
	ID		nid;
	char		*buf;
	struct berval	ptr, pdn;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_add( \"%s\", 0x%08lx )\n",
		e->e_ndn, (long) e->e_id, 0 );
	assert( e->e_id != NOID );

	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	key.ulen = key.size;
	key.flags = DB_DBT_USERMEM;
	buf = op->o_tmpalloc( key.size, op->o_tmpmemctx );
	key.data = buf;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf + 1;
	ptr.bv_len = e->e_nname.bv_len;
	AC_MEMCPY( ptr.bv_val, e->e_nname.bv_val, e->e_nname.bv_len );
	ptr.bv_val[ptr.bv_len] = '\0';

	DBTzero( &data );
	data.data = &nid;
	data.size = sizeof( nid );
	BDB_ID2DISK( e->e_id, &nid );

	/* store it -- don't override */
	rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY, "=> bdb_dn2id_add: put failed: %s %d\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}

#ifndef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( op->o_bd, &ptr ))
#endif
	{
		buf[0] = DN_SUBTREE_PREFIX;
		rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			"=> bdb_dn2id_add: subtree (%s) put failed: %d\n",
			ptr.bv_val, rc, 0 );
			goto done;
		}
		
#ifdef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( op->o_bd, &ptr ))
#endif
	{
		dnParent( &ptr, &pdn );
	
		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		pdn.bv_val[-1] = DN_ONE_PREFIX;
		key.data = pdn.bv_val-1;
		ptr = pdn;

		rc = bdb_idl_insert_key( op->o_bd, db, txn, &key, e->e_id );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_add: parent (%s) insert failed: %d\n",
					ptr.bv_val, rc, 0 );
			goto done;
		}
	}

#ifndef BDB_MULTIPLE_SUFFIXES
	while( !be_issuffix( op->o_bd, &ptr ))
#else
	for (;;)
#endif
	{
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		rc = bdb_idl_insert_key( op->o_bd, db, txn, &key, e->e_id );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_add: subtree (%s) insert failed: %d\n",
					ptr.bv_val, rc, 0 );
			break;
		}
#ifdef BDB_MULTIPLE_SUFFIXES
		if( be_issuffix( op->o_bd, &ptr )) break;
#endif
		dnParent( &ptr, &pdn );

		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		key.data = pdn.bv_val - 1;
		ptr = pdn;
	}
	}

done:
	op->o_tmpfree( buf, op->o_tmpmemctx );
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_add: %d\n", rc, 0, 0 );
	return rc;
}

int
bdb_dn2id_delete(
	Operation *op,
	DB_TXN *txn,
	EntryInfo	*eip,
	Entry		*e )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	int		rc;
	DBT		key;
	char		*buf;
	struct berval	pdn, ptr;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_delete( \"%s\", 0x%08lx )\n",
		e->e_ndn, e->e_id, 0 );

	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	buf = op->o_tmpalloc( key.size, op->o_tmpmemctx );
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
		Debug( LDAP_DEBUG_ANY, "=> bdb_dn2id_delete: delete failed: %s %d\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}

#ifndef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( op->o_bd, &ptr ))
#endif
	{
		buf[0] = DN_SUBTREE_PREFIX;
		rc = db->del( db, txn, &key, 0 );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n",
			ptr.bv_val, rc, 0 );
			goto done;
		}

#ifdef BDB_MULTIPLE_SUFFIXES
	if( !be_issuffix( op->o_bd, &ptr ))
#endif
	{
		dnParent( &ptr, &pdn );

		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		pdn.bv_val[-1] = DN_ONE_PREFIX;
		key.data = pdn.bv_val - 1;
		ptr = pdn;

		rc = bdb_idl_delete_key( op->o_bd, db, txn, &key, e->e_id );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_delete: parent (%s) delete failed: %d\n",
				ptr.bv_val, rc, 0 );
			goto done;
		}
	}

#ifndef BDB_MULTIPLE_SUFFIXES
	while( !be_issuffix( op->o_bd, &ptr ))
#else
	for (;;)
#endif
	{
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		rc = bdb_idl_delete_key( op->o_bd, db, txn, &key, e->e_id );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n",
				ptr.bv_val, rc, 0 );
			goto done;
		}
#ifdef BDB_MULTIPLE_SUFFIXES
		if( be_issuffix( op->o_bd, &ptr )) break;
#endif
		dnParent( &ptr, &pdn );

		key.size = pdn.bv_len + 2;
		key.ulen = key.size;
		key.data = pdn.bv_val - 1;
		ptr = pdn;
	}
	}

done:
	op->o_tmpfree( buf, op->o_tmpmemctx );
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_delete %d\n", rc, 0, 0 );
	return rc;
}

int
bdb_dn2id(
	Operation *op,
	DB_TXN *txn,
	struct berval	*dn,
	EntryInfo *ei )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	int		rc;
	DBT		key, data;
	ID		nid;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id(\"%s\")\n", dn->bv_val, 0, 0 );
	DBTzero( &key );
	key.size = dn->bv_len + 2;
	key.data = op->o_tmpalloc( key.size, op->o_tmpmemctx );
	((char *)key.data)[0] = DN_BASE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn->bv_val, key.size - 1 );

	/* store the ID */
	DBTzero( &data );
	data.data = &nid;
	data.ulen = sizeof(ID);
	data.flags = DB_DBT_USERMEM;

	/* fetch it */
	rc = db->get( db, txn, &key, &data, bdb->bi_db_opflags );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id: get failed: %s (%d)\n",
			db_strerror( rc ), rc, 0 );
	} else {
		BDB_DISK2ID( &nid, &ei->bei_id );
		Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id: got id=0x%08lx\n",
			ei->bei_id, 0, 0 );
	}

	op->o_tmpfree( key.data, op->o_tmpmemctx );
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

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_children(\"%s\")\n",
		e->e_nname.bv_val, 0, 0 );
	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	key.data = op->o_tmpalloc( key.size, op->o_tmpmemctx );
	((char *)key.data)[0] = DN_ONE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], e->e_nname.bv_val, key.size - 1 );

	if ( bdb->bi_idl_cache_size ) {
		rc = bdb_idl_cache_get( bdb, db, &key, NULL );
		if ( rc != LDAP_NO_SUCH_OBJECT ) {
			op->o_tmpfree( key.data, op->o_tmpmemctx );
			return rc;
		}
	}
	/* we actually could do a empty get... */
	DBTzero( &data );
	data.data = &id;
	data.ulen = sizeof(id);
	data.flags = DB_DBT_USERMEM;
	data.doff = 0;
	data.dlen = sizeof(id);

	rc = db->get( db, txn, &key, &data, bdb->bi_db_opflags );
	op->o_tmpfree( key.data, op->o_tmpmemctx );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_children(\"%s\"): %s (%d)\n",
		e->e_nname.bv_val,
		rc == 0 ? "" : ( rc == DB_NOTFOUND ? "no " :
			db_strerror(rc) ), rc );

	return rc;
}

int
bdb_dn2idl(
	Operation *op,
	Entry *e,
	ID *ids,
	ID *stack )
{
	int		rc;
	DBT		key;
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	int prefix = ( op->ors_scope == LDAP_SCOPE_ONELEVEL )
		? DN_ONE_PREFIX : DN_SUBTREE_PREFIX;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2idl(\"%s\")\n",
		e->e_nname.bv_val, 0, 0 );

#ifndef	BDB_MULTIPLE_SUFFIXES
	if ( prefix == DN_SUBTREE_PREFIX && BEI(e)->bei_parent->bei_id == 0 ) {
		BDB_IDL_ALL(bdb, ids);
		return 0;
	}
#endif

	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	key.ulen = key.size;
	key.flags = DB_DBT_USERMEM;
	key.data = op->o_tmpalloc( key.size, op->o_tmpmemctx );
	((char *)key.data)[0] = prefix;
	AC_MEMCPY( &((char *)key.data)[1], e->e_nname.bv_val, key.size - 1 );

	rc = bdb_idl_fetch_key( op->o_bd, db, NULL, &key, ids, NULL, 0 );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_dn2idl: get failed: %s (%d)\n",
			db_strerror( rc ), rc, 0 );

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"<= bdb_dn2idl: id=%ld first=%ld last=%ld\n",
			(long) ids[0],
			(long) BDB_IDL_FIRST( ids ), (long) BDB_IDL_LAST( ids ) );
	}

	op->o_tmpfree( key.data, op->o_tmpmemctx );
	return rc;
}

#else	/* BDB_HIER */
/* Experimental management routines for a hierarchically structured database.
 *
 * Unsupported! Use at your own risk!
 * -- Howard Chu, Symas Corp. 2003.
 *
 * Instead of a ldbm-style dn2id database, we use a hierarchical one. Each
 * entry in this database is a struct diskNode, keyed by entryID and with
 * the data containing the RDN and entryID of the node's children. We use
 * a B-Tree with sorted duplicates to store all the children of a node under
 * the same key. Also, the first item under the key contains the entry's own
 * rdn and the ID of the node's parent, to allow bottom-up tree traversal as
 * well as top-down. To keep this info first in the list, the nrdnlen is set
 * to the negative of its value.
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
 * Sorts based on normalized RDN, in length order.
 */
int
hdb_dup_compare(
	DB *db, 
	const DBT *usrkey,
	const DBT *curkey )
{
	signed char *u = (signed char *)&(((diskNode *)(usrkey->data))->nrdnlen);
	signed char *c = (signed char *)&(((diskNode *)(curkey->data))->nrdnlen);
	int rc, i;

	/* data is not aligned, cannot compare directly */
#ifdef WORDS_BIGENDIAN
	for( i = 0; i < (int)sizeof(short); i++)
#else
	for( i = sizeof(short)-1; i >= 0; i--)
#endif
	{
		rc = u[i] - c[i];
		if( rc ) return rc;
	}
	return strcmp( u+sizeof(short), c+sizeof(short) );
}

/* This function constructs a full DN for a given entry.
 */
int hdb_fix_dn(
	Entry *e,
	int checkit )
{
	EntryInfo *ei;
	int rlen = 0, nrlen = 0;
	char *ptr, *nptr;
	int max = 0;

	/* count length of all DN components */
	for ( ei = BEI(e); ei && ei->bei_id; ei=ei->bei_parent ) {
		rlen += ei->bei_rdn.bv_len + 1;
		nrlen += ei->bei_nrdn.bv_len + 1;
		if (ei->bei_modrdns > max) max = ei->bei_modrdns;
	}

	/* See if the entry DN was invalidated by a subtree rename */
	if ( checkit ) {
		if ( BEI(e)->bei_modrdns >= max ) {
			return 0;
		}
		/* We found a mismatch, tell the caller to lock it */
		if ( checkit == 1 ) {
			return 1;
		}
		/* checkit == 2. do the fix. */
		free( e->e_name.bv_val );
		free( e->e_nname.bv_val );
	}

	e->e_name.bv_len = rlen - 1;
	e->e_nname.bv_len = nrlen - 1;
	e->e_name.bv_val = ch_malloc(rlen);
	e->e_nname.bv_val = ch_malloc(nrlen);
	ptr = e->e_name.bv_val;
	nptr = e->e_nname.bv_val;
	for ( ei = BEI(e); ei && ei->bei_id; ei=ei->bei_parent ) {
		ptr = lutil_strcopy(ptr, ei->bei_rdn.bv_val);
		nptr = lutil_strcopy(nptr, ei->bei_nrdn.bv_val);
		if ( ei->bei_parent ) {
			*ptr++ = ',';
			*nptr++ = ',';
		}
	}
	BEI(e)->bei_modrdns = max;
	ptr[-1] = '\0';
	nptr[-1] = '\0';

	return 0;
}

/* We add two elements to the DN2ID database - a data item under the parent's
 * entryID containing the child's RDN and entryID, and an item under the
 * child's entryID containing the parent's entryID.
 */
int
hdb_dn2id_add(
	Operation	*op,
	DB_TXN *txn,
	EntryInfo	*eip,
	Entry		*e )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	int		rc, rlen, nrlen;
	diskNode *d;
	char *ptr;

	nrlen = dn_rdnlen( op->o_bd, &e->e_nname );
	if (nrlen) {
		rlen = dn_rdnlen( op->o_bd, &e->e_name );
	} else {
		nrlen = e->e_nname.bv_len;
		rlen = e->e_name.bv_len;
	}

	d = op->o_tmpalloc(sizeof(diskNode) + rlen + nrlen, op->o_tmpmemctx);
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

	/* Need to make dummy root node once. Subsequent attempts
	 * will fail harmlessly.
	 */
	if ( eip->bei_id == 0 ) {
		diskNode dummy = {0};
		data.data = &dummy;
		data.size = sizeof(diskNode);
		data.flags = DB_DBT_USERMEM;

		db->put( db, txn, &key, &data, DB_NODUPDATA );
	}

	if ( bdb->bi_idl_cache_size ) {
		bdb_idl_cache_del( bdb, db, &key );
	}
	data.data = d;
	data.size = sizeof(diskNode) + rlen + nrlen;
	data.flags = DB_DBT_USERMEM;

	rc = db->put( db, txn, &key, &data, DB_NODUPDATA );

	if (rc == 0) {
		key.data = &e->e_id;
		d->entryID = eip->bei_id;
		d->nrdnlen = 0 - nrlen;

		rc = db->put( db, txn, &key, &data, DB_NODUPDATA );
	}

	op->o_tmpfree( d, op->o_tmpmemctx );

	return rc;
}

int
hdb_dn2id_delete(
	Operation	*op,
	DB_TXN *txn,
	EntryInfo	*eip,
	Entry	*e )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
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
	data.size = sizeof(diskNode) + BEI(e)->bei_nrdn.bv_len;
	data.ulen = data.size;
	data.dlen = data.size;
	data.flags = DB_DBT_USERMEM | DB_DBT_PARTIAL;

	if ( bdb->bi_idl_cache_size ) {
		bdb_idl_cache_del( bdb, db, &key );
	}
	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	d = op->o_tmpalloc( data.size, op->o_tmpmemctx );
	d->entryID = e->e_id;
	d->nrdnlen = BEI(e)->bei_nrdn.bv_len;
	strcpy( d->nrdn, BEI(e)->bei_nrdn.bv_val );
	data.data = d;

	/* Delete our ID from the parent's list */
	rc = cursor->c_get( cursor, &key, &data, DB_GET_BOTH | DB_RMW );
	if ( rc == 0 )
		rc = cursor->c_del( cursor, 0 );

	/* Delete our ID from the tree. With sorted duplicates, this
	 * will leave any child nodes still hanging around. This is OK
	 * for modrdn, which will add our info back in later.
	 */
	if ( rc == 0 ) {
		key.data = &e->e_id;
		rc = cursor->c_get( cursor, &key, &data, DB_SET | DB_RMW );
		if ( rc == 0 )
			rc = cursor->c_del( cursor, 0 );
	}
	cursor->c_close( cursor );
	op->o_tmpfree( d, op->o_tmpmemctx );

	return rc;
}


int
hdb_dn2id(
	Operation	*op,
	DB_TXN *txn,
	struct berval	*in,
	EntryInfo	*ei )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	DBC	*cursor;
	int		rc = 0, nrlen;
	diskNode *d;
	char	*ptr;
	ID idp = ei->bei_parent->bei_id;

	nrlen = dn_rdnlen( op->o_bd, in );
	if (!nrlen) nrlen = in->bv_len;

	DBTzero(&key);
	key.size = sizeof(ID);
	key.data = &idp;
	key.ulen = sizeof(ID);
	key.flags = DB_DBT_USERMEM;

	DBTzero(&data);
	data.size = sizeof(diskNode) + nrlen;
	data.ulen = data.size * 3;
	data.flags = DB_DBT_USERMEM;

	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	d = op->o_tmpalloc( data.size * 3, op->o_tmpmemctx );
	d->nrdnlen = nrlen;
	ptr = lutil_strncopy( d->nrdn, in->bv_val, nrlen );
	*ptr = '\0';
	data.data = d;

	rc = cursor->c_get( cursor, &key, &data, DB_GET_BOTH );
	if ( rc == 0 ) {
		ei->bei_id = d->entryID;
		ei->bei_rdn.bv_len = data.size - sizeof(diskNode) - nrlen;
		ptr = d->nrdn + nrlen + 1;
		ber_str2bv( ptr, ei->bei_rdn.bv_len, 1, &ei->bei_rdn );
		if ( !ei->bei_parent->bei_dkids ) {
			db_recno_t dkids;
			/* How many children does the parent have? */
			/* FIXME: do we need to lock the parent
			 * entryinfo? Seems safe...
			 */
			cursor->c_count( cursor, &dkids, 0 );
			ei->bei_parent->bei_dkids = dkids;
		}
	}
	cursor->c_close( cursor );
	op->o_tmpfree( d, op->o_tmpmemctx );

	return rc;
}

int
hdb_dn2id_parent(
	Operation *op,
	DB_TXN *txn,
	EntryInfo *ei,
	ID *idp )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	DBT		key, data;
	DBC	*cursor;
	int		rc = 0;
	diskNode *d;
	char	*ptr;
	unsigned char *pt2;

	DBTzero(&key);
	key.size = sizeof(ID);
	key.data = &ei->bei_id;
	key.ulen = sizeof(ID);
	key.flags = DB_DBT_USERMEM;

	DBTzero(&data);
	data.flags = DB_DBT_USERMEM;

	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	data.ulen = sizeof(diskNode) + (SLAP_LDAPDN_MAXLEN * 2);
	d = op->o_tmpalloc( data.ulen, op->o_tmpmemctx );
	data.data = d;

	rc = cursor->c_get( cursor, &key, &data, DB_SET );
	if ( rc == 0 ) {
		if (d->nrdnlen >= 0) {
			rc = LDAP_OTHER;
		} else {
			db_recno_t dkids;
			*idp = d->entryID;
			ei->bei_nrdn.bv_len = 0 - d->nrdnlen;
			ber_str2bv( d->nrdn, ei->bei_nrdn.bv_len, 1, &ei->bei_nrdn );
			ei->bei_rdn.bv_len = data.size - sizeof(diskNode) -
				ei->bei_nrdn.bv_len;
			ptr = d->nrdn + ei->bei_nrdn.bv_len + 1;
			ber_str2bv( ptr, ei->bei_rdn.bv_len, 1, &ei->bei_rdn );
			/* How many children does this node have? */
			cursor->c_count( cursor, &dkids, 0 );
			ei->bei_dkids = dkids;
		}
	}
	cursor->c_close( cursor );
	op->o_tmpfree( d, op->o_tmpmemctx );
	return rc;
}

int
hdb_dn2id_children(
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

	if ( bdb->bi_idl_cache_size ) {
		rc = bdb_idl_cache_get( bdb, db, &key, NULL );
		if ( rc != LDAP_NO_SUCH_OBJECT ) {
			return rc;
		}
	}
	DBTzero(&data);
	data.data = &d;
	data.ulen = sizeof(d);
	data.flags = DB_DBT_USERMEM | DB_DBT_PARTIAL;
	data.dlen = sizeof(d);

	rc = db->cursor( db, txn, &cursor, bdb->bi_db_opflags );
	if ( rc ) return rc;

	rc = cursor->c_get( cursor, &key, &data, DB_SET );
	if ( rc == 0 ) {
		db_recno_t dkids;
		rc = cursor->c_count( cursor, &dkids, 0 );
		if ( rc == 0 ) {
			BEI(e)->bei_dkids = dkids;
			if ( dkids < 2 ) rc = DB_NOTFOUND;
		}
	}
	cursor->c_close( cursor );
	return rc;
}

/* bdb_dn2idl:
 * We can't just use bdb_idl_fetch_key because
 * 1 - our data items are longer than just an entry ID
 * 2 - our data items are sorted alphabetically by nrdn, not by ID.
 *
 * We descend the tree recursively, so we define this cookie
 * to hold our necessary state information. The bdb_dn2idl_internal
 * function uses this cookie when calling itself.
 */

struct dn2id_cookie {
	struct bdb_info *bdb;
	DB *db;
	int prefix;
	int rc;
	EntryInfo *ei;
	ID id;
	ID dbuf;
	ID *ids;
	void *ptr;
	ID tmp[BDB_IDL_DB_SIZE];
	ID *buf;
	DBT key;
	DBT data;
	DBC *dbc;
	Operation *op;
};

static int
apply_func(
	void *data,
	void *arg )
{
	EntryInfo *ei = data;
	ID *idl = arg;

	bdb_idl_insert( idl, ei->bei_id );
	return 0;
}

static int
hdb_dn2idl_internal(
	struct dn2id_cookie *cx
)
{
	if ( cx->bdb->bi_idl_cache_size ) {
		cx->rc = bdb_idl_cache_get(cx->bdb, cx->db, &cx->key, cx->tmp);
		if ( cx->rc == DB_NOTFOUND ) {
			return cx->rc;
		}
		if ( cx->rc == LDAP_SUCCESS ) {
			goto gotit;
		}
	}
	BDB_IDL_ZERO( cx->tmp );

	if ( !cx->ei ) {
		cx->ei = bdb_cache_find_info( cx->bdb, cx->id );
		if ( !cx->ei ) {
			cx->rc = DB_NOTFOUND;
			goto saveit;
		}
	}

	bdb_cache_entryinfo_lock( cx->ei );

	/* If number of kids in the cache differs from on-disk, load
	 * up all the kids from the database
	 */
	if ( cx->ei->bei_ckids+1 != cx->ei->bei_dkids ) {
		EntryInfo ei;
		db_recno_t dkids = cx->ei->bei_dkids;
		ei.bei_parent = cx->ei;

		bdb_cache_entryinfo_unlock( cx->ei );

		cx->rc = cx->db->cursor( cx->db, NULL, &cx->dbc,
			cx->bdb->bi_db_opflags );
		if ( cx->rc ) return cx->rc;

		cx->data.data = &cx->dbuf;
		cx->data.ulen = sizeof(ID);
		cx->data.dlen = sizeof(ID);
		cx->data.flags = DB_DBT_USERMEM | DB_DBT_PARTIAL;

		/* The first item holds the parent ID. Ignore it. */
		cx->rc = cx->dbc->c_get( cx->dbc, &cx->key, &cx->data, DB_SET );
		if ( cx->rc ) {
			cx->dbc->c_close( cx->dbc );
			if ( cx->rc == DB_NOTFOUND ) goto saveit;
			return cx->rc;
		}

		/* If the on-disk count is zero we've never checked it.
		 * Count it now.
		 */
		if ( !dkids ) {
			cx->dbc->c_count( cx->dbc, &dkids, 0 );
			cx->ei->bei_dkids = dkids;
		}

		cx->data.data = cx->buf;
		cx->data.ulen = BDB_IDL_UM_SIZE * sizeof(ID);
		cx->data.flags = DB_DBT_USERMEM;

		/* Fetch the rest of the IDs in a loop... */
		while ( (cx->rc = cx->dbc->c_get( cx->dbc, &cx->key, &cx->data,
			DB_MULTIPLE | DB_NEXT_DUP )) == 0 ) {
			u_int8_t *j;
			size_t len;
			DB_MULTIPLE_INIT( cx->ptr, &cx->data );
			while (cx->ptr) {
				DB_MULTIPLE_NEXT( cx->ptr, &cx->data, j, len );
				if (j) {
					EntryInfo *ei2;
					diskNode *d = (diskNode *)j;
					short nrlen;

					AC_MEMCPY( &ei.bei_id, &d->entryID, sizeof(ID) );
					AC_MEMCPY( &nrlen, &d->nrdnlen, sizeof(d->nrdnlen) );
					ei.bei_nrdn.bv_len = nrlen;
					/* nrdn/rdn are set in-place.
					 * hdb_cache_load will copy them as needed
					 */
					ei.bei_nrdn.bv_val = d->nrdn;
					ei.bei_rdn.bv_len = len - sizeof(diskNode)
						- ei.bei_nrdn.bv_len;
					ei.bei_rdn.bv_val = d->nrdn + ei.bei_nrdn.bv_len + 1;
					bdb_idl_insert( cx->tmp, ei.bei_id );
					hdb_cache_load( cx->bdb, &ei, &ei2 );
				}
			}
		}
		cx->rc = cx->dbc->c_close( cx->dbc );
	} else {
		/* The in-memory cache is in sync with the on-disk data.
		 * do we have any kids?
		 */
		cx->rc = 0;
		if ( cx->ei->bei_ckids > 0 ) {
			/* Walk the kids tree; order is irrelevant since bdb_idl_insert
			 * will insert in sorted order.
			 */
			avl_apply( cx->ei->bei_kids, apply_func,
				cx->tmp, -1, AVL_POSTORDER );
		}
		bdb_cache_entryinfo_unlock( cx->ei );
	}

saveit:
	if ( cx->bdb->bi_idl_cache_max_size ) {
		bdb_idl_cache_put( cx->bdb, cx->db, &cx->key, cx->tmp, cx->rc );
	}
	;
gotit:
	if ( !BDB_IDL_IS_ZERO( cx->tmp )) {
		if ( cx->prefix == DN_SUBTREE_PREFIX ) {
			if (cx->ei->bei_state & CACHE_ENTRY_NO_GRANDKIDS) {
				bdb_idl_union( cx->ids, cx->tmp );
			} else {
				ID *save, idcurs;
				EntryInfo *ei = cx->ei;
				int nokids = 1;
				save = cx->op->o_tmpalloc( BDB_IDL_SIZEOF( cx->tmp ),
					cx->op->o_tmpmemctx );
				BDB_IDL_CPY( save, cx->tmp );
				bdb_idl_union( cx->ids, cx->tmp );

				idcurs = 0;
				for ( cx->id = bdb_idl_first( save, &idcurs );
					cx->id != NOID;
					cx->id = bdb_idl_next( save, &idcurs )) {
					cx->ei = NULL;
					hdb_dn2idl_internal( cx );
					if ( !BDB_IDL_IS_ZERO( cx->tmp ))
						nokids = 0;
				}
				cx->op->o_tmpfree( save, cx->op->o_tmpmemctx );
				if ( nokids ) ei->bei_state |= CACHE_ENTRY_NO_GRANDKIDS;
			}
			/* Make sure caller knows it had kids! */
			cx->tmp[0]=1;

			cx->rc = 0;
		} else {
			BDB_IDL_CPY( cx->ids, cx->tmp );
		}
	}
	return cx->rc;
}

int
hdb_dn2idl(
	Operation	*op,
	Entry		*e,
	ID *ids,
	ID *stack )
{
	struct bdb_info *bdb = (struct bdb_info *)op->o_bd->be_private;
	struct dn2id_cookie cx;

	Debug( LDAP_DEBUG_TRACE, "=> hdb_dn2idl(\"%s\")\n",
		e->e_nname.bv_val, 0, 0 );

#ifndef BDB_MULTIPLE_SUFFIXES
	if ( op->ors_scope != LDAP_SCOPE_ONELEVEL && 
		BEI(e)->bei_parent->bei_id == 0 )
	{
		BDB_IDL_ALL( bdb, ids );
		return 0;
	}
#endif

	cx.id = e->e_id;
	cx.ei = e->e_id ? BEI(e) : &bdb->bi_cache.c_dntree;
	cx.bdb = bdb;
	cx.db = cx.bdb->bi_dn2id->bdi_db;
	cx.prefix = op->ors_scope == LDAP_SCOPE_ONELEVEL
		? DN_ONE_PREFIX : DN_SUBTREE_PREFIX;
	cx.ids = ids;
	cx.buf = stack;
	cx.op = op;

	BDB_IDL_ZERO( ids );
	if ( cx.prefix == DN_SUBTREE_PREFIX ) {
		bdb_idl_insert( ids, cx.id );
	}

	DBTzero(&cx.key);
	cx.key.data = &cx.id;
	cx.key.ulen = sizeof(ID);
	cx.key.size = sizeof(ID);
	cx.key.flags = DB_DBT_USERMEM;

	DBTzero(&cx.data);

	return hdb_dn2idl_internal(&cx);
}
#endif	/* BDB_HIER */
