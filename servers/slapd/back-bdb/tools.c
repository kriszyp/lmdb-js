/* tools.c - tools for slap tools */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2005 The OpenLDAP Foundation.
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

#define AVL_INTERNAL
#include "back-bdb.h"
#include "idl.h"

static DBC *cursor = NULL;
static DBT key, data;

typedef struct dn_id {
	ID id;
	struct berval dn;
} dn_id;

#define	HOLE_SIZE	4096
static dn_id hbuf[HOLE_SIZE], *holes = hbuf;
static unsigned nhmax = HOLE_SIZE;
static unsigned nholes;

static int index_nattrs;

#define bdb_tool_idl_cmp		BDB_SYMBOL(tool_idl_cmp)
#define bdb_tool_idl_flush_one		BDB_SYMBOL(tool_idl_flush_one)
#define bdb_tool_idl_flush		BDB_SYMBOL(tool_idl_flush)

static int bdb_tool_idl_flush( BackendDB *be );

#define	IDBLOCK	1024

static ID *bdb_tool_idls;
static int bdb_tool_idl_next;

int bdb_tool_entry_open(
	BackendDB *be, int mode )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	/* initialize key and data thangs */
	DBTzero( &key );
	DBTzero( &data );
	key.flags = DB_DBT_REALLOC;
	data.flags = DB_DBT_REALLOC;

	if (cursor == NULL) {
		int rc = bdb->bi_id2entry->bdi_db->cursor(
			bdb->bi_id2entry->bdi_db, NULL, &cursor,
			bdb->bi_db_opflags );
		if( rc != 0 ) {
			return -1;
		}
	}

	/* Get a block of memory for the IDL cache */
	if ( !(slapMode & SLAP_TOOL_READONLY ) && bdb->bi_idl_cache_max_size )
		bdb_tool_idls = ch_malloc( bdb->bi_idl_cache_max_size *
			sizeof( ID ) * IDBLOCK );

	return 0;
}

int bdb_tool_entry_close(
	BackendDB *be )
{
	assert( be != NULL );

	if( key.data ) {
		ch_free( key.data );
		key.data = NULL;
	}
	if( data.data ) {
		ch_free( data.data );
		data.data = NULL;
	}

	if( cursor ) {
		cursor->c_close( cursor );
		cursor = NULL;
	}

	bdb_tool_idl_flush( be );

	free( bdb_tool_idls );
	bdb_tool_idls = NULL;
	bdb_tool_idl_next = 0;

	if( nholes ) {
		unsigned i;
		fprintf( stderr, "Error, entries missing!\n");
		for (i=0; i<nholes; i++) {
			fprintf(stderr, "  entry %ld: %s\n",
				holes[i].id, holes[i].dn.bv_val);
		}
		return -1;
	}
			
	return 0;
}

ID bdb_tool_entry_next(
	BackendDB *be )
{
	int rc;
	ID id;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );
	assert( bdb != NULL );
	
	rc = cursor->c_get( cursor, &key, &data, DB_NEXT );

	if( rc != 0 ) {
		/* If we're doing linear indexing and there are more attrs to
		 * index, and we're at the end of the database, start over.
		 */
		if ( index_nattrs && rc == DB_NOTFOUND ) {
			/* optional - do a checkpoint here? */
			bdb_attr_info_free( bdb->bi_attrs[0] );
			bdb->bi_attrs[0] = bdb->bi_attrs[index_nattrs];
			index_nattrs--;
			rc = cursor->c_get( cursor, &key, &data, DB_FIRST );
			if ( rc ) {
				return NOID;
			}
		} else {
			return NOID;
		}
	}

	if( data.data == NULL ) {
		return NOID;
	}

	BDB_DISK2ID( key.data, &id );
	return id;
}

ID bdb_tool_dn2id_get(
	Backend *be,
	struct berval *dn
)
{
	Operation op = {0};
	Opheader ohdr = {0};
	EntryInfo *ei = NULL;
	int rc;

	if ( BER_BVISEMPTY(dn) )
		return 0;

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	rc = bdb_cache_find_ndn( &op, NULL, dn, &ei );
	if ( ei ) bdb_cache_entryinfo_unlock( ei );
	if ( rc == DB_NOTFOUND )
		return NOID;
	
	return ei->bei_id;
}

int bdb_tool_id2entry_get(
	Backend *be,
	ID id,
	Entry **e
)
{
	int rc = bdb_id2entry( be, NULL, 0, id, e );

	if ( rc == DB_NOTFOUND && id == 0 ) {
		Entry *dummy = ch_calloc( 1, sizeof(Entry) );
		struct berval gluebv = BER_BVC("glue");
		dummy->e_name.bv_val = ch_strdup( "" );
		dummy->e_nname.bv_val = ch_strdup( "" );
		attr_merge_one( dummy, slap_schema.si_ad_objectClass, &gluebv, NULL );
		attr_merge_one( dummy, slap_schema.si_ad_structuralObjectClass,
			&gluebv, NULL );
		*e = dummy;
		rc = LDAP_SUCCESS;
	}
	return rc;
}

Entry* bdb_tool_entry_get( BackendDB *be, ID id )
{
	int rc;
	Entry *e = NULL;
	struct berval bv;

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );
	assert( data.data != NULL );

	DBT2bv( &data, &bv );

#ifdef SLAP_ZONE_ALLOC
	/* FIXME: will add ctx later */
	rc = entry_decode( &bv, &e, NULL );
#else
	rc = entry_decode( &bv, &e );
#endif

	if( rc == LDAP_SUCCESS ) {
		e->e_id = id;
	}
#ifdef BDB_HIER
	if ( slapMode & SLAP_TOOL_READONLY ) {
		EntryInfo *ei = NULL;
		Operation op = {0};
		Opheader ohdr = {0};

		op.o_hdr = &ohdr;
		op.o_bd = be;
		op.o_tmpmemctx = NULL;
		op.o_tmpmfuncs = &ch_mfuncs;

		rc = bdb_cache_find_parent( &op, NULL, cursor->locker, id, &ei );
		if ( rc == LDAP_SUCCESS ) {
			bdb_cache_entryinfo_unlock( ei );
			e->e_private = ei;
			ei->bei_e = e;
			bdb_fix_dn( e, 0 );
			ei->bei_e = NULL;
			e->e_private = NULL;
		}
	}
#endif
	return e;
}

static int bdb_tool_next_id(
	Operation *op,
	DB_TXN *tid,
	Entry *e,
	struct berval *text,
	int hole )
{
	struct berval dn = e->e_name;
	struct berval ndn = e->e_nname;
	struct berval pdn, npdn;
	EntryInfo *ei = NULL, eidummy;
	int rc;

	if (ndn.bv_len == 0) {
		e->e_id = 0;
		return 0;
	}

	rc = bdb_cache_find_ndn( op, tid, &ndn, &ei );
	if ( ei ) bdb_cache_entryinfo_unlock( ei );
	if ( rc == DB_NOTFOUND ) {
		if ( !be_issuffix( op->o_bd, &ndn ) ) {
			ID eid = e->e_id;
			dnParent( &dn, &pdn );
			dnParent( &ndn, &npdn );
			e->e_name = pdn;
			e->e_nname = npdn;
			rc = bdb_tool_next_id( op, tid, e, text, 1 );
			e->e_name = dn;
			e->e_nname = ndn;
			if ( rc ) {
				return rc;
			}
			/* If parent didn't exist, it was created just now
			 * and its ID is now in e->e_id. Make sure the current
			 * entry gets added under the new parent ID.
			 */
			if ( eid != e->e_id ) {
				eidummy.bei_id = e->e_id;
				ei = &eidummy;
			}
		}
		rc = bdb_next_id( op->o_bd, tid, &e->e_id );
		if ( rc ) {
			snprintf( text->bv_val, text->bv_len,
				"next_id failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> bdb_tool_next_id: %s\n", text->bv_val, 0, 0 );
			return rc;
		}
		rc = bdb_dn2id_add( op, tid, ei, e );
		if ( rc ) {
			snprintf( text->bv_val, text->bv_len, 
				"dn2id_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> bdb_tool_next_id: %s\n", text->bv_val, 0, 0 );
		} else if ( hole ) {
			if ( nholes == nhmax - 1 ) {
				if ( holes == hbuf ) {
					holes = ch_malloc( nhmax * sizeof(dn_id) * 2 );
					AC_MEMCPY( holes, hbuf, sizeof(hbuf) );
				} else {
					holes = ch_realloc( holes, nhmax * sizeof(dn_id) * 2 );
				}
				nhmax *= 2;
			}
			ber_dupbv( &holes[nholes].dn, &ndn );
			holes[nholes++].id = e->e_id;
		}
	} else if ( !hole ) {
		unsigned i;

		e->e_id = ei->bei_id;

		for ( i=0; i<nholes; i++) {
			if ( holes[i].id == e->e_id ) {
				int j;
				free(holes[i].dn.bv_val);
				for (j=i;j<nholes;j++) holes[j] = holes[j+1];
				holes[j].id = 0;
				nholes--;
				break;
			} else if ( holes[i].id > e->e_id ) {
				break;
			}
		}
	}
	return rc;
}

ID bdb_tool_entry_put(
	BackendDB *be,
	Entry *e,
	struct berval *text )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB_TXN *tid = NULL;
	Operation op = {0};
	Opheader ohdr = {0};

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );

	assert( text != NULL );
	assert( text->bv_val != NULL );
	assert( text->bv_val[0] == '\0' );	/* overconservative? */

	Debug( LDAP_DEBUG_TRACE, "=> " LDAP_XSTRING(bdb_tool_entry_put)
		"( %ld, \"%s\" )\n", (long) e->e_id, e->e_dn, 0 );

	if (! (slapMode & SLAP_TOOL_QUICK)) {
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &tid, 
		bdb->bi_db_opflags );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
			"txn_begin failed: %s (%d)",
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_put) ": %s\n",
			 text->bv_val, 0, 0 );
		return NOID;
	}
	}

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	/* add dn2id indices */
	rc = bdb_tool_next_id( &op, tid, e, text, 0 );
	if( rc != 0 ) {
		goto done;
	}

	/* id2entry index */
	rc = bdb_id2entry_add( be, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"id2entry_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_put) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

	if ( !bdb->bi_linear_index )
		rc = bdb_index_entry_add( &op, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"index_entry_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_put) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

done:
	if( rc == 0 ) {
		if ( !( slapMode & SLAP_TOOL_QUICK )) {
		rc = TXN_COMMIT( tid, 0 );
		if( rc != 0 ) {
			snprintf( text->bv_val, text->bv_len,
					"txn_commit failed: %s (%d)",
					db_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(bdb_tool_entry_put) ": %s\n",
				text->bv_val, 0, 0 );
			e->e_id = NOID;
		}
		}

	} else {
		if ( !( slapMode & SLAP_TOOL_QUICK )) {
		TXN_ABORT( tid );
		snprintf( text->bv_val, text->bv_len,
			"txn_aborted! %s (%d)",
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_put) ": %s\n",
			text->bv_val, 0, 0 );
		}
		e->e_id = NOID;
	}

	return e->e_id;
}

int bdb_tool_entry_reindex(
	BackendDB *be,
	ID id )
{
	struct bdb_info *bi = (struct bdb_info *) be->be_private;
	int rc;
	Entry *e;
	DB_TXN *tid = NULL;
	Operation op = {0};
	Opheader ohdr = {0};

	Debug( LDAP_DEBUG_ARGS,
		"=> " LDAP_XSTRING(bdb_tool_entry_reindex) "( %ld )\n",
		(long) id, 0, 0 );

	/* No indexes configured, nothing to do. Could return an
	 * error here to shortcut things.
	 */
	if (!bi->bi_attrs) {
		return 0;
	}

	/* Get the first attribute to index */
	if (bi->bi_linear_index && !index_nattrs) {
		index_nattrs = bi->bi_nattrs - 1;
		bi->bi_nattrs = 1;
	}

	e = bdb_tool_entry_get( be, id );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			LDAP_XSTRING(bdb_tool_entry_reindex)
			": could not locate id=%ld\n",
			(long) id, 0, 0 );
		return -1;
	}

	if (! (slapMode & SLAP_TOOL_QUICK)) {
	rc = TXN_BEGIN( bi->bi_dbenv, NULL, &tid, bi->bi_db_opflags );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_reindex) ": "
			"txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}
	}
 	
	/*
	 * just (re)add them for now
	 * assume that some other routine (not yet implemented)
	 * will zap index databases
	 *
	 */

	Debug( LDAP_DEBUG_TRACE,
		"=> " LDAP_XSTRING(bdb_tool_entry_reindex) "( %ld, \"%s\" )\n",
		(long) id, e->e_dn, 0 );

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	rc = bdb_index_entry_add( &op, tid, e );

done:
	if( rc == 0 ) {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		rc = TXN_COMMIT( tid, 0 );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(bdb_tool_entry_reindex)
				": txn_commit failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
			e->e_id = NOID;
		}
		}

	} else {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		TXN_ABORT( tid );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_reindex)
			": txn_aborted! %s (%d)\n",
			db_strerror(rc), rc, 0 );
		}
		e->e_id = NOID;
	}
	bdb_entry_release( &op, e, 0 );

	return rc;
}

ID bdb_tool_entry_modify(
	BackendDB *be,
	Entry *e,
	struct berval *text )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB_TXN *tid = NULL;
	Operation op = {0};
	Opheader ohdr = {0};

	assert( be != NULL );
	assert( slapMode & SLAP_TOOL_MODE );

	assert( text != NULL );
	assert( text->bv_val != NULL );
	assert( text->bv_val[0] == '\0' );	/* overconservative? */

	assert ( e->e_id != NOID );

	Debug( LDAP_DEBUG_TRACE,
		"=> " LDAP_XSTRING(bdb_tool_entry_modify) "( %ld, \"%s\" )\n",
		(long) e->e_id, e->e_dn, 0 );

	if (! (slapMode & SLAP_TOOL_QUICK)) {
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &tid, 
		bdb->bi_db_opflags );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
			"txn_begin failed: %s (%d)",
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_modify) ": %s\n",
			 text->bv_val, 0, 0 );
		return NOID;
	}
	}

	op.o_hdr = &ohdr;
	op.o_bd = be;
	op.o_tmpmemctx = NULL;
	op.o_tmpmfuncs = &ch_mfuncs;

	/* id2entry index */
	rc = bdb_id2entry_update( be, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"id2entry_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_modify) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

#if 0
	/* FIXME: this is bogus, we don't have the old values to delete
	 * from the index because the given entry has already been modified.
	 */
	rc = bdb_index_entry_del( &op, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"index_entry_del failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_modify) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}
#endif

	rc = bdb_index_entry_add( &op, tid, e );
	if( rc != 0 ) {
		snprintf( text->bv_val, text->bv_len,
				"index_entry_add failed: %s (%d)",
				db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_modify) ": %s\n",
			text->bv_val, 0, 0 );
		goto done;
	}

done:
	if( rc == 0 ) {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		rc = TXN_COMMIT( tid, 0 );
		if( rc != 0 ) {
			snprintf( text->bv_val, text->bv_len,
					"txn_commit failed: %s (%d)",
					db_strerror(rc), rc );
			Debug( LDAP_DEBUG_ANY,
				"=> " LDAP_XSTRING(bdb_tool_entry_modify) ": "
				"%s\n", text->bv_val, 0, 0 );
			e->e_id = NOID;
		}
		}

	} else {
		if (! (slapMode & SLAP_TOOL_QUICK)) {
		TXN_ABORT( tid );
		snprintf( text->bv_val, text->bv_len,
			"txn_aborted! %s (%d)",
			db_strerror(rc), rc );
		Debug( LDAP_DEBUG_ANY,
			"=> " LDAP_XSTRING(bdb_tool_entry_modify) ": %s\n",
			text->bv_val, 0, 0 );
		}
		e->e_id = NOID;
	}

	return e->e_id;
}


typedef struct bdb_tool_idl_cache {
	struct berval kstr;
	ID first, last;
	int idls[BDB_IDL_DB_SIZE / IDBLOCK];
	int idn, count;
} bdb_tool_idl_cache;

static int
bdb_tool_idl_cmp( const void *v1, const void *v2 )
{
	const bdb_tool_idl_cache *c1 = v1, *c2 = v2;
	int rc;

	if (( rc = c1->kstr.bv_len - c2->kstr.bv_len )) return rc;
	return memcmp( c1->kstr.bv_val, c2->kstr.bv_val, c1->kstr.bv_len );
}

static int
bdb_tool_idl_flush_one( void *v1, void *arg )
{
	bdb_tool_idl_cache *ic = v1;
	DB *db = arg;
	DBC *curs;
	DBT key, data;
	int i, rc;
	ID id, nid;

	if ( !ic->count ) {
		ch_free( ic );
		return 0;
	}

	rc = db->cursor( db, NULL, &curs, 0 );
	if ( rc )
		return -1;

	DBTzero( &key );
	DBTzero( &data );

	bv2DBT( &ic->kstr, &key );

	data.size = data.ulen = sizeof( ID );
	data.flags = DB_DBT_USERMEM;
	data.data = &nid;

	rc = curs->c_get( curs, &key, &data, DB_SET );
	/* If key already exists and we're writing a range... */
	if ( rc == 0 && ic->count > BDB_IDL_DB_SIZE ) {
		/* If it's not currently a range, must delete old info */
		if ( nid ) {
			/* Skip lo */
			while ( curs->c_get( curs, &key, &data, DB_NEXT_DUP ) == 0 )
				curs->c_del( curs, 0 );

			nid = 0;
			/* Store range marker */
			curs->c_put( curs, &key, &data, DB_KEYFIRST );
		} else {
			
			/* Skip lo */
			rc = curs->c_get( curs, &key, &data, DB_NEXT_DUP );

			/* Get hi */
			rc = curs->c_get( curs, &key, &data, DB_NEXT_DUP );

			/* Delete hi */
			curs->c_del( curs, 0 );
		}
		BDB_ID2DISK( ic->last, &nid );
		curs->c_put( curs, &key, &data, DB_KEYLAST );
		rc = 0;
	} else if ( rc && rc != DB_NOTFOUND ) {
		rc = -1;
	} else if ( ic->count > BDB_IDL_DB_SIZE ) {
		/* range, didn't exist before */
		nid = 0;
		rc = curs->c_put( curs, &key, &data, DB_KEYLAST );
		if ( rc == 0 ) {
			BDB_ID2DISK( ic->first, &nid );
			rc = curs->c_put( curs, &key, &data, DB_KEYLAST );
			if ( rc == 0 ) {
				BDB_ID2DISK( ic->last, &nid );
				rc = curs->c_put( curs, &key, &data, DB_KEYLAST );
			}
		}
		if ( rc ) {
			rc = -1;
		}
	} else {
		int n;

		/* Just a normal write */
		rc = 0;
		for ( n=0; n<=ic->idn; n++ ) {
			ID *ids = bdb_tool_idls + ic->idls[n];
			int end;
			if ( n < ic->idn ) {
				end = IDBLOCK;
			} else {
				end = ic->count & (IDBLOCK-1);
				if ( !end )
					end = IDBLOCK;
			}
			for ( i=0; i<end; i++ ) {
				if ( !ids[i] ) continue;
				BDB_ID2DISK( ids[i], &nid );
				rc = curs->c_put( curs, &key, &data, DB_NODUPDATA );
				if ( rc ) {
					if ( rc == DB_KEYEXIST ) {
						rc = 0;
						continue;
					}
					rc = -1;
					break;
				}
			}
			if ( rc ) {
				rc = -1;
				break;
			}
		}
	}
	ch_free( ic );
	curs->c_close( curs );
	return rc;
}

static int
bdb_tool_idl_flush( BackendDB *be )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db;
	Avlnode *root;
	int i, rc = 0;

	for ( i=BDB_NDB; i < bdb->bi_ndatabases; i++ ) {
		db = bdb->bi_databases[i]->bdi_db;
		if ( !db->app_private ) continue;
		rc = avl_apply( db->app_private, bdb_tool_idl_flush_one, db, -1,
			AVL_INORDER );
		avl_free( db->app_private, NULL );
		db->app_private = NULL;
		if ( rc == -1 )
			break;
		rc = 0;
	}
	if ( !rc ) {
		bdb->bi_idl_cache_size = 0;
		bdb_tool_idl_next = 0;
	}
	return rc;
}

int bdb_tool_idl_add(
	BackendDB *be,
	DB *db,
	DB_TXN *txn,
	DBT *key,
	ID id )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	bdb_tool_idl_cache *ic, itmp;
	ID *ids;
	Avlnode *root;
	int rc;

	if ( !bdb->bi_idl_cache_max_size )
		return bdb_idl_insert_key( be, db, txn, key, id );

	DBT2bv( key, &itmp.kstr );

retry:
	root = db->app_private;

	ic = avl_find( root, &itmp, bdb_tool_idl_cmp );

	/* No entry yet, create one */
	if ( !ic ) {
		DBC *curs;
		DBT data;
		ID nid;
		int rc;

		ic = ch_malloc( sizeof( bdb_tool_idl_cache ) + itmp.kstr.bv_len );
		ic->kstr.bv_len = itmp.kstr.bv_len;
		ic->kstr.bv_val = (char *)(ic+1);
		AC_MEMCPY( ic->kstr.bv_val, itmp.kstr.bv_val, ic->kstr.bv_len );
		ic->idn = -1;
		ic->last = 0;
		ic->count = 0;
		avl_insert( &root, ic, bdb_tool_idl_cmp, avl_dup_error );
		db->app_private = root;

		/* load existing key count here */
		rc = db->cursor( db, NULL, &curs, 0 );
		if ( rc ) return rc;

		data.ulen = sizeof( ID );
		data.flags = DB_DBT_USERMEM;
		data.data = &nid;
		rc = curs->c_get( curs, key, &data, DB_SET );
		if ( rc == 0 ) {
			if ( nid == 0 ) {
				ic->count = BDB_IDL_DB_SIZE+1;
			} else {
				db_recno_t count;

				curs->c_count( curs, &count, 0 );
				ic->count = count;
				BDB_DISK2ID( &nid, &ic->first );
			}
		}
		curs->c_close( curs );
	}
	/* are we a range already? */
	if ( ic->count > BDB_IDL_DB_SIZE ) {
		ic->last = id;
		return 0;
	/* Are we at the limit, and converting to a range? */
	} else if ( ic->count == BDB_IDL_DB_SIZE ) {
		ic->last = id;
		ic->count++;
		ic->idn = -1;
		return 0;
	}
	/* No free block, create that too */
	if ( ic->idn == -1 || ( ic->count & (IDBLOCK-1)) == 0) {
		bdb->bi_idl_cache_size++;
		if ( bdb->bi_idl_cache_size > bdb->bi_idl_cache_max_size ) {
			rc = bdb_tool_idl_flush( be );
			if ( rc )
				return rc;
			goto retry;
		}
		ic->idls[++ic->idn] = bdb_tool_idl_next;
		ids = bdb_tool_idls + bdb_tool_idl_next;
		bdb_tool_idl_next += IDBLOCK;

		memset( ids, 0, IDBLOCK * sizeof( ID ));
		if ( !ic->count )
			ic->first = id;
	}
	ids = bdb_tool_idls + ic->idls[ic->idn];
	ids[ ic->count & (IDBLOCK-1) ] = id;
	ic->count++;

	return 0;
}
