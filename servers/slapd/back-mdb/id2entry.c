/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2011 The OpenLDAP Foundation.
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
#include <ac/errno.h>

#include "back-mdb.h"

static int mdb_id2entry_put(
	Operation *op,
	MDB_txn *tid,
	Entry *e,
	int flag )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	MDB_dbi dbi = mdb->mi_id2entry;
	MDB_val key, data;
	struct berval bv;
	int rc;
	struct berval odn, ondn;

	/* We only store rdns, and they go in the dn2id database. */

	odn = e->e_name; ondn = e->e_nname;

	e->e_name = slap_empty_bv;
	e->e_nname = slap_empty_bv;

	key.mv_data = &e->e_id;
	key.mv_size = sizeof(ID);

	rc = entry_encode( e, &bv );
	e->e_name = odn; e->e_nname = ondn;
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	data.mv_size = bv.bv_len;
	data.mv_data = bv.bv_val;

	rc = mdb_put( tid, dbi, &key, &data, flag );

	op->o_tmpfree( bv.bv_val, op->o_tmpmemctx );
	return rc;
}

/*
 * This routine adds (or updates) an entry on disk.
 * The cache should be already be updated.
 */


int mdb_id2entry_add(
	Operation *op,
	MDB_txn *tid,
	Entry *e )
{
	return mdb_id2entry_put(op, tid, e, MDB_NOOVERWRITE);
}

int mdb_id2entry_update(
	Operation *op,
	MDB_txn *tid,
	Entry *e )
{
	return mdb_id2entry_put(op, tid, e, 0);
}

int mdb_id2entry(
	Operation *op,
	MDB_txn *tid,
	ID id,
	Entry **e )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	MDB_dbi dbi = mdb->mi_id2entry;
	MDB_val key, data;
	EntryHeader eh;
	int rc = 0;

	*e = NULL;

	key.mv_data = &id;
	key.mv_size = sizeof(ID);

	/* fetch it */
	rc = mdb_get( tid, dbi, &key, &data );
	if ( rc == MDB_NOTFOUND ) {
		/* Looking for root entry on an empty-dn suffix? */
		if ( !id && BER_BVISEMPTY( &op->o_bd->be_nsuffix[0] )) {
			struct berval gluebv = BER_BVC("glue");
			Entry *r = entry_alloc();

			r->e_id = 0;
			attr_merge_one( r, slap_schema.si_ad_objectClass, &gluebv, NULL );
			attr_merge_one( r, slap_schema.si_ad_structuralObjectClass, &gluebv, NULL );
			r->e_ocflags = SLAP_OC_GLUE|SLAP_OC__END;
			*e = r;
			return MDB_SUCCESS;
		}
	}
	if ( rc ) return rc;

	eh.bv.bv_val = data.mv_data;
	eh.bv.bv_len = data.mv_size;
	rc = entry_header( &eh );
	if ( rc ) return rc;

	if ( eh.nvals ) {
		eh.bv.bv_len = eh.nvals * sizeof( struct berval );
		eh.bv.bv_val = ch_malloc( eh.bv.bv_len );
		rc = entry_decode(&eh, e);
	} else {
		*e = entry_alloc();
	}

	if( rc == 0 ) {
		(*e)->e_id = id;
		(*e)->e_name.bv_val = NULL;
		(*e)->e_nname.bv_val = NULL;
	} else {
		ch_free( eh.bv.bv_val );
	}

	return rc;
}

int mdb_id2entry_delete(
	BackendDB *be,
	MDB_txn *tid,
	Entry *e )
{
	struct mdb_info *mdb = (struct mdb_info *) be->be_private;
	MDB_dbi dbi = mdb->mi_id2entry;
	MDB_val key;
	int rc;

	key.mv_data = &e->e_id;
	key.mv_size = sizeof(ID);

	/* delete from database */
	rc = mdb_del( tid, dbi, &key, NULL );

	return rc;
}

int mdb_entry_return(
	Entry *e
)
{
	entry_free( e );
	return 0;
}

int mdb_entry_release(
	Operation *op,
	Entry *e,
	int rw )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	struct mdb_op_info *moi = NULL;
	int rc;
 
	/* slapMode : SLAP_SERVER_MODE, SLAP_TOOL_MODE,
			SLAP_TRUNCATE_MODE, SLAP_UNDEFINED_MODE */
 
	mdb_entry_return ( e );
	if ( slapMode == SLAP_SERVER_MODE ) {
		OpExtra *oex;
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == mdb ) {
				moi = (mdb_op_info *)oex;
				/* If it was setup by entry_get we should probably free it */
				if ( moi->moi_flag & MOI_FREEIT ) {
					moi->moi_ref--;
					if ( moi->moi_ref < 1 ) {
						mdb_txn_reset( moi->moi_txn );
						moi->moi_ref = 0;
						LDAP_SLIST_REMOVE( &op->o_extra, &moi->moi_oe, OpExtra, oe_next );
						op->o_tmpfree( moi, op->o_tmpmemctx );
					}
				}
				break;
			}
		}
	}
 
	return 0;
}

/* return LDAP_SUCCESS IFF we can retrieve the specified entry.
 */
int mdb_entry_get(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **ent )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	struct mdb_op_info *moi = NULL;
	MDB_txn *txn = NULL;
	Entry *e = NULL;
	int	rc;
	const char *at_name = at ? at->ad_cname.bv_val : "(null)";

	Debug( LDAP_DEBUG_ARGS,
		"=> mdb_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> mdb_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);

	rc = mdb_opinfo_get( op, mdb, rw == 0, &moi );
	if ( rc )
		return LDAP_OTHER;
	txn = moi->moi_txn;

	/* can we find entry */
	rc = mdb_dn2entry( op, txn, ndn, &e, 0 );
	switch( rc ) {
	case MDB_NOTFOUND:
	case 0:
		break;
	default:
		return (rc != LDAP_BUSY) ? LDAP_OTHER : LDAP_BUSY;
	}
	if (e == NULL) {
		Debug( LDAP_DEBUG_ACL,
			"=> mdb_entry_get: cannot find entry: \"%s\"\n",
				ndn->bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_OBJECT;
		goto return_results;
	}
	
	Debug( LDAP_DEBUG_ACL,
		"=> mdb_entry_get: found entry: \"%s\"\n",
		ndn->bv_val, 0, 0 ); 

	if ( oc && !is_entry_objectclass( e, oc, 0 )) {
		Debug( LDAP_DEBUG_ACL,
			"<= mdb_entry_get: failed to find objectClass %s\n",
			oc->soc_cname.bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

	/* NOTE: attr_find() or attrs_find()? */
	if ( at && attr_find( e->e_attrs, at ) == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"<= mdb_entry_get: failed to find attribute %s\n",
			at->ad_cname.bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

return_results:
	if( rc != LDAP_SUCCESS ) {
		/* free entry */
		if ( e )
			mdb_entry_return( e );

		if (moi->moi_ref == 1) {
			LDAP_SLIST_REMOVE( &op->o_extra, &moi->moi_oe, OpExtra, oe_next );
			mdb_txn_reset( txn );
			op->o_tmpfree( moi, op->o_tmpmemctx );
		}
	} else {
		*ent = e;
	}

	Debug( LDAP_DEBUG_TRACE,
		"mdb_entry_get: rc=%d\n",
		rc, 0, 0 ); 
	return(rc);
}

static void
mdb_reader_free( void *key, void *data )
{
	MDB_txn *txn = data;

	if ( txn ) mdb_txn_abort( txn );
}

/* free up any keys used by the main thread */
void
mdb_reader_flush( MDB_env *env )
{
	void *data;
	void *ctx = ldap_pvt_thread_pool_context();

	if ( !ldap_pvt_thread_pool_getkey( ctx, env, &data, NULL ) ) {
		ldap_pvt_thread_pool_setkey( ctx, env, NULL, 0, NULL, NULL );
		mdb_reader_free( env, data );
	}
}

int
mdb_opinfo_get( Operation *op, struct mdb_info *mdb, int rdonly, mdb_op_info **moip )
{
	int rc, renew = 0;
	void *data;
	void *ctx;
	mdb_op_info *moi = NULL;
	OpExtra *oex;

	assert( op != NULL );

	if ( !mdb || !moip ) return -1;

	/* If no op was provided, try to find the ctx anyway... */
	if ( op ) {
		ctx = op->o_threadctx;
	} else {
		ctx = ldap_pvt_thread_pool_context();
	}

	if ( op ) {
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == mdb ) break;
		}
		moi = (mdb_op_info *)oex;
	}

	if ( !moi ) {
		moi = *moip;

		if ( !moi ) {
			if ( op ) {
				moi = op->o_tmpalloc(sizeof(struct mdb_op_info),op->o_tmpmemctx);
			} else {
				moi = ch_malloc(sizeof(mdb_op_info));
			}
			moi->moi_flag = MOI_FREEIT;
			*moip = moi;
		}
		LDAP_SLIST_INSERT_HEAD( &op->o_extra, &moi->moi_oe, oe_next );
		moi->moi_oe.oe_key = mdb;
		moi->moi_ref = 0;
		moi->moi_txn = NULL;
	}

	if ( !rdonly ) {
		/* This op started as a reader, but now wants to write. */
		if ( moi->moi_flag & MOI_READER ) {
			moi = *moip;
			LDAP_SLIST_INSERT_HEAD( &op->o_extra, &moi->moi_oe, oe_next );
		} else {
		/* This op is continuing an existing write txn */
			*moip = moi;
		}
		moi->moi_ref++;
		if ( !moi->moi_txn ) {
			rc = mdb_txn_begin( mdb->mi_dbenv, 0, &moi->moi_txn );
			if (rc) {
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: err %s(%d)\n",
					mdb_strerror(rc), rc, 0 );
			}
			return rc;
		}
		return 0;
	}

	/* OK, this is a reader */
	if ( !moi->moi_txn ) {
		if ( !ctx ) {
			/* Shouldn't happen unless we're single-threaded */
			rc = mdb_txn_begin( mdb->mi_dbenv, MDB_RDONLY, &moi->moi_txn );
			if (rc) {
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: err %s(%d)\n",
					mdb_strerror(rc), rc, 0 );
			}
			return rc;
		}
		if ( ldap_pvt_thread_pool_getkey( ctx, mdb->mi_dbenv, &data, NULL ) ) {
			rc = mdb_txn_begin( mdb->mi_dbenv, MDB_RDONLY, &moi->moi_txn );
			if (rc) {
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: err %s(%d)\n",
					mdb_strerror(rc), rc, 0 );
				return rc;
			}
			data = moi->moi_txn;
			if ( ( rc = ldap_pvt_thread_pool_setkey( ctx, mdb->mi_dbenv,
				data, mdb_reader_free, NULL, NULL ) ) ) {
				mdb_txn_abort( moi->moi_txn );
				moi->moi_txn = NULL;
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: thread_pool_setkey failed err (%d)\n",
					rc, 0, 0 );
				return rc;
			}
		} else {
			moi->moi_txn = data;
			renew = 1;
		}
		moi->moi_flag |= MOI_READER;
	}
	if ( moi->moi_ref < 1 ) {
		moi->moi_ref = 0;
	}
	if ( renew ) {
		mdb_txn_renew( moi->moi_txn );
	}
	moi->moi_ref++;
	if ( *moip != moi )
		*moip = moi;

	return 0;
}
