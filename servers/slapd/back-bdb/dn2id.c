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
	struct berval	*pbv,
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
	char	*pdnc,
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
	int		rc;

#ifdef NEW_LOGGING
	LDAP_LOG ( INDEX, ARGS, 
		"=> bdb_dn2id_children( %s )\n", e->e_nname.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_children( %s )\n",
		e->e_nname.bv_val, 0, 0 );
#endif

	if ( BEI(e)->bei_kids ) {
		rc = 0;
	}
	if ( BEI(e)->bei_state & CACHE_ENTRY_NO_KIDS ) {
		rc = DB_NOTFOUND;
	} else {

	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	ID		id;

	DBTzero( &key );
	key.size = e->e_nname.bv_len + 2;
	key.data = sl_malloc( key.size, op->o_tmpmemctx );
	((char *)key.data)[0] = DN_ONE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], e->e_nname.bv_val, key.size - 1 );

	/* we actually could do a empty get... */
	DBTzero( &data );
	data.data = &id;
	data.ulen = sizeof(id);
	data.flags = DB_DBT_USERMEM;
	data.doff = 0;
	data.dlen = sizeof(id);

	rc = db->get( db, txn, &key, &data, bdb->bi_db_opflags );
	sl_free( key.data, op->o_tmpmemctx );

	if ( rc == DB_NOTFOUND ) {
		BEI(e)->bei_state |= CACHE_ENTRY_NO_KIDS;
	}

	}

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

/* Experimental management routines for a hierarchically structured backend.
 *
 * Unsupported! Use at your own risk!
 *
 * Instead of a dn2id database, we use an id2parent database. Each entry in
 * this database is a struct diskNode, containing the ID of the node's parent
 * and the RDN of the node.
 */
typedef struct diskNode {
	ID parent;
	struct berval rdn;
	struct berval nrdn;
} diskNode;

/* In bdb_db_open() we call bdb_build_tree() which reads the entire id2parent
 * database into memory (into an AVL tree). Next we iterate through each node
 * of this tree, connecting each child to its parent. The nodes in this AVL
 * tree are a struct idNode. The immediate (Onelevel) children of a node are
 * referenced in the i_kids AVL tree. With this arrangement, there is no need
 * to maintain the DN_ONE_PREFIX or DN_SUBTREE_PREFIX database keys. Note that
 * the DN of an entry is constructed by walking up the list of i_parent
 * pointers, so no full DN is stored on disk anywhere. This makes modrdn
 * extremely efficient, even when operating on a populated subtree.
 *
 * The idNode tree is searched directly from the root when performing id to
 * entry lookups. The tree is traversed using the i_kids subtrees when
 * performing dn to id lookups.
 */
typedef struct idNode {
	ID i_id;
	struct idNode *i_parent;
	diskNode *i_rdn;
	Avlnode *i_kids;
	ldap_pvt_thread_rdwr_t i_kids_rdwr;
} idNode;


/* The main AVL tree is sorted in ID order. The i_kids AVL trees are
 * sorted in lexical order. These are the various helper routines used
 * for the searches and sorts.
 */
static int
node_find_cmp(
	const void *id,
	const void *node
)
{
	return *(const ID *)id - ((const idNode *)node)->i_id;
}

static int
node_frdn_cmp(
	const void *v_nrdn,
	const void *v_n
)
{
	const struct berval *nrdn = v_nrdn;
	const idNode *n = v_n;
	return ber_bvcmp(nrdn, &n->i_rdn->nrdn);
}

static int
node_add_cmp(
	const void *v_a,
	const void *v_b
)
{
	const idNode *a = v_a, *b = v_b;
	return a->i_id - b->i_id;
}

static int
node_rdn_cmp(
	const void *v_a,
	const void *v_b
)
{
	const idNode *a = v_a, *b = v_b;
	/* should be slightly better without ordering drawbacks */
	return ber_bvcmp(&a->i_rdn->nrdn, &b->i_rdn->nrdn);
}

idNode * bdb_find_id_node(
	ID id,
	Avlnode *tree
)
{
	return avl_find(tree, &id, node_find_cmp);
}

idNode * bdb_find_rdn_node(
	struct berval *nrdn,
	Avlnode *tree
)
{
	return avl_find(tree, nrdn, node_frdn_cmp);
}

/* This function links a node into its parent's i_kids tree. */
static int bdb_insert_kid(
	void *v_a,
	void *v_tree
)
{
	idNode *a = v_a;
	Avlnode *tree = v_tree;
	int rc;

	if (a->i_rdn->parent == 0)
		return 0;
	a->i_parent = bdb_find_id_node(a->i_rdn->parent, tree);
	if (!a->i_parent)
		return -1;
	ldap_pvt_thread_rdwr_wlock(&a->i_parent->i_kids_rdwr);
	rc = avl_insert( &a->i_parent->i_kids, (caddr_t) a,
	                 node_rdn_cmp, avl_dup_error );
	ldap_pvt_thread_rdwr_wunlock(&a->i_parent->i_kids_rdwr);
	return rc;
}

/* This function adds a node into the main AVL tree */
idNode *bdb_add_node(
	ID id,
	char *d,
	struct bdb_info *bdb
)
{
	idNode *node;

	node = (idNode *)ch_malloc(sizeof(idNode));
	node->i_id = id;
	node->i_parent = NULL;
	node->i_kids = NULL;
	node->i_rdn = (diskNode *)d;
	node->i_rdn->rdn.bv_val += (long)d;
	node->i_rdn->nrdn.bv_val += (long)d;
	ldap_pvt_thread_rdwr_init(&node->i_kids_rdwr);
	avl_insert( &bdb->bi_tree, (caddr_t) node, node_add_cmp, avl_dup_error );
	if (id == 1)
		bdb->bi_troot = node;
	return node;
}

/* This function initializes the trees at startup time. */
int bdb_build_tree(
	Backend *be
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	DBC *cursor;
	DBT key, data;
	ID id;
	idNode *node;

	bdb->bi_tree = NULL;

	rc = bdb->bi_id2parent->bdi_db->cursor(
		bdb->bi_id2parent->bdi_db, NULL, &cursor,
		bdb->bi_db_opflags );
	if( rc != 0 ) {
		return NOID;
	}

	DBTzero( &key );
	DBTzero( &data );
	key.data = (char *)&id;
	key.ulen = sizeof( id );
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;

	while (cursor->c_get( cursor, &key, &data, DB_NEXT ) == 0) {
		bdb_add_node( id, data.data, bdb );
	}
	cursor->c_close( cursor );

	rc = avl_apply(bdb->bi_tree, bdb_insert_kid, bdb->bi_tree,
		-1, AVL_INORDER );

	return rc;
}

/* This function constructs a full DN for a given id. We really should
 * be passing idNodes directly, to save some effort...
 */
int bdb_fix_dn(
	BackendDB *be,
	ID id,
	Entry *e
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	idNode *n, *o;
	int rlen, nrlen;
	char *ptr, *nptr;
	
	ldap_pvt_thread_rdwr_rlock(&bdb->bi_tree_rdwr);
	o = bdb_find_id_node(id, bdb->bi_tree);
	rlen = be->be_suffix[0].bv_len + 1;
	nrlen = be->be_nsuffix[0].bv_len + 1;
	for (n = o; n && n->i_parent; n=n->i_parent) {
		rlen += n->i_rdn->rdn.bv_len + 1;
		nrlen += n->i_rdn->nrdn.bv_len + 1;
	}
	e->e_name.bv_len = rlen - 1;
	e->e_nname.bv_len = nrlen - 1;
	e->e_name.bv_val = ch_malloc(rlen + nrlen);
	e->e_nname.bv_val = e->e_name.bv_val + rlen;
	ptr = e->e_name.bv_val;
	nptr = e->e_nname.bv_val;
	for (n = o; n && n->i_parent; n=n->i_parent) {
		ptr = lutil_strcopy(ptr, n->i_rdn->rdn.bv_val);
		*ptr++ = ',';
		nptr = lutil_strcopy(nptr, n->i_rdn->nrdn.bv_val);
		*nptr++ = ',';
	}
	ldap_pvt_thread_rdwr_runlock(&bdb->bi_tree_rdwr);

	strcpy(ptr, be->be_suffix[0].bv_val);
	strcpy(nptr, be->be_nsuffix[0].bv_val);

	return 0;
}

int
bdb_dn2id_add(
	BackendDB	*be,
	DB_TXN *txn,
	struct berval	*pdn,
	Entry		*e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int		rc, rlen, nrlen;
	DBT		key, data;
	DB *db = bdb->bi_id2parent->bdi_db;
	diskNode *d;
	idNode *n;

	nrlen = dn_rdnlen( be, &e->e_nname );
	if (nrlen) {
		rlen = dn_rdnlen( be, &e->e_name );
	} else {
		rlen = 0;
	}

	d = ch_malloc(sizeof(diskNode) + rlen + nrlen + 2);
	d->rdn.bv_len = rlen;
	d->nrdn.bv_len = nrlen;
	d->rdn.bv_val = (char *)(d+1);
	d->nrdn.bv_val = d->rdn.bv_val + rlen + 1;
	strncpy(d->rdn.bv_val, e->e_dn, rlen);
	d->rdn.bv_val[rlen] = '\0';
	strncpy(d->nrdn.bv_val, e->e_ndn, nrlen);
	d->nrdn.bv_val[nrlen] = '\0';
	d->rdn.bv_val -= (long)d;
	d->nrdn.bv_val -= (long)d;

	if (pdn->bv_len) {
		bdb_dn2id(be, txn, pdn, &d->parent, 0);
	} else {
		d->parent = 0;
	}

	DBTzero(&key);
	DBTzero(&data);
	key.data = &e->e_id;
	key.size = sizeof(ID);
	key.flags = DB_DBT_USERMEM;

	data.data = d;
	data.size = sizeof(diskNode) + rlen + nrlen + 2;
	data.flags = DB_DBT_USERMEM;

	rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );

	if (rc == 0) {
		ldap_pvt_thread_rdwr_wlock(&bdb->bi_tree_rdwr);
		n = bdb_add_node( e->e_id, data.data, bdb);
		ldap_pvt_thread_rdwr_wunlock(&bdb->bi_tree_rdwr);

		if (d->parent) {
			ldap_pvt_thread_rdwr_rlock(&bdb->bi_tree_rdwr);
			bdb_insert_kid(n, bdb->bi_tree);
			ldap_pvt_thread_rdwr_runlock(&bdb->bi_tree_rdwr);
		}
	} else {
		free(d);
	}
	return rc;
}

int
bdb_dn2id_delete(
	BackendDB	*be,
	DB_TXN *txn,
	char	*pdn,
	Entry	*e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc;
	DBT		key;
	DB *db = bdb->bi_id2parent->bdi_db;
	idNode *n;

	DBTzero(&key);
	key.size = sizeof(e->e_id);
	key.data = &e->e_id;

	rc = db->del( db, txn, &key, 0);

	ldap_pvt_thread_rdwr_wlock(&bdb->bi_tree_rdwr);
	n = avl_delete(&bdb->bi_tree, &e->e_id, node_find_cmp);
	if (n) {
		if (n->i_parent) {
			ldap_pvt_thread_rdwr_wlock(&n->i_parent->i_kids_rdwr);
			avl_delete(&n->i_parent->i_kids, &n->i_rdn->nrdn, node_frdn_cmp);
			ldap_pvt_thread_rdwr_wunlock(&n->i_parent->i_kids_rdwr);
		}
		free(n->i_rdn);
		ldap_pvt_thread_rdwr_destroy(&n->i_kids_rdwr);
		free(n);
	}
	if (e->e_id == 1)
		bdb->bi_troot = NULL;
	ldap_pvt_thread_rdwr_wunlock(&bdb->bi_tree_rdwr);

	return rc;
}

int
bdb_dn2id_matched(
	BackendDB	*be,
	DB_TXN *txn,
	struct berval	*in,
	ID *id,
	ID *id2,
	int flags )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	struct berval	rdn;
	char		*p1, *p2;
	idNode *n, *p;
	int		rc = 0;

	if (!bdb->bi_troot)
		return DB_NOTFOUND;

	p = bdb->bi_troot;
	if (be_issuffix(be, in)) {
		*id = p->i_id;
		return 0;
	}

	p1 = in->bv_val + in->bv_len - be->be_nsuffix[0].bv_len - 1;

	n = p;
	ldap_pvt_thread_rdwr_rlock(&bdb->bi_tree_rdwr);
	for (;;) {
		for (p2 = p1-1; (p2 >= in->bv_val) && !DN_SEPARATOR(*p2); p2--);
		rdn.bv_val = p2+1;
		rdn.bv_len = p1-rdn.bv_val;
		p1 = p2;

		ldap_pvt_thread_rdwr_rlock(&p->i_kids_rdwr);
		n = bdb_find_rdn_node(&rdn, p->i_kids);
		ldap_pvt_thread_rdwr_runlock(&p->i_kids_rdwr);
		if (!n || p2 < in->bv_val) break;
		p = n;
	}
	ldap_pvt_thread_rdwr_runlock(&bdb->bi_tree_rdwr);

	if (n) {
		*id = n->i_id;
	} else if (id2) {
		*id2 = p->i_id;
	} else {
		rc = DB_NOTFOUND;
	}

	return rc;
}

int
bdb_dn2id(
	BackendDB	*be,
	DB_TXN *txn,
	struct berval	*dn,
	ID *id,
	int flags )
{
	return bdb_dn2id_matched(be, txn, dn, id, NULL, flags);
}

int
bdb_dn2id_children(
	BackendDB	*be,
	DB_TXN *txn,
	struct berval	*dn,
	int flags )
{
	int		rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	ID		id;
	idNode *n;

	rc = bdb_dn2id(be, txn, dn, &id, flags);
	if (rc != 0)
		return rc;

	ldap_pvt_thread_rdwr_rlock(&bdb->bi_tree_rdwr);
	n = bdb_find_id_node(id, bdb->bi_tree);
	ldap_pvt_thread_rdwr_runlock(&bdb->bi_tree_rdwr);

	if (!n->i_kids)
		return DB_NOTFOUND;
	else
		return 0;
}

/* Since we don't store IDLs for onelevel or subtree, we have to construct
 * them on the fly... Perhaps the i_kids tree ought to just be an IDL?
 */
static int
insert_one(
	void *v_n,
	void *v_ids
)
{
	idNode *n = v_n;
	ID *ids = v_ids;
	return bdb_idl_insert(ids, n->i_id);
}

static int
insert_sub(
	void *v_n,
	void *v_ids
)
{
	idNode *n = v_n;
	ID *ids = v_ids;
	int rc;

	rc = bdb_idl_insert(ids, n->i_id);
	if (rc == 0) {
		ldap_pvt_thread_rdwr_rlock(&n->i_kids_rdwr);
		rc = avl_apply(n->i_kids, insert_sub, ids, -1, AVL_INORDER);
		ldap_pvt_thread_rdwr_runlock(&n->i_kids_rdwr);
	}
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
