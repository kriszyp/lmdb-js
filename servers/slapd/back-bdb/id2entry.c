/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
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
#include "external.h"

static int bdb_id2entry_put(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e,
	int flag )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval bv;
	int rc;
#ifdef BDB_HIER
	struct berval odn, ondn;

	/* We only store rdns, and they go in the dn2id database. */

	odn = e->e_name; ondn = e->e_nname;

	e->e_name = slap_empty_bv;
	e->e_nname = slap_empty_bv;
#endif
	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
#ifdef BDB_HIER
	e->e_name = odn; e->e_nname = ondn;
#endif
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	DBTzero( &data );
	bv2DBT( &bv, &data );

	rc = db->put( db, tid, &key, &data, flag );

	free( bv.bv_val );
	return rc;
}

/*
 * This routine adds (or updates) an entry on disk.
 * The cache should be already be updated.
 */


int bdb_id2entry_add(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	return bdb_id2entry_put(be, tid, e, DB_NOOVERWRITE);
}

int bdb_id2entry_update(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	return bdb_id2entry_put(be, tid, e, 0);
}

int bdb_id2entry(
	BackendDB *be,
	DB_TXN *tid,
	ID id,
	Entry **e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval bv;
	int rc = 0, ret = 0;

	*e = NULL;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	DBTzero( &data );
	data.flags = DB_DBT_MALLOC;

	/* fetch it */
	rc = db->get( db, tid, &key, &data, bdb->bi_db_opflags );

	if( rc != 0 ) {
		return rc;
	}

	DBT2bv( &data, &bv );

	rc = entry_decode( &bv, e );

	if( rc == 0 ) {
		(*e)->e_id = id;
	} else {
		/* only free on error. On success, the entry was
		 * decoded in place.
		 */
		ch_free( data.data );
	}

	return rc;
}

int bdb_id2entry_delete(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key;
	int rc;

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	/* delete from database */
	rc = db->del( db, tid, &key, 0 );

	return rc;
}

int bdb_entry_return(
	Entry *e )
{
	/* Our entries are allocated in two blocks; the data comes from
	 * the db itself and the Entry structure and associated pointers
	 * are allocated in entry_decode. The db data pointer is saved
	 * in e_bv. Since the Entry structure is allocated as a single
	 * block, e_attrs is always a fixed offset from e. The exception
	 * is when an entry has been modified, in which case we also need
	 * to free e_attrs.
	 */
	if( !e->e_bv.bv_val ) {	/* A regular entry, from do_add */
		entry_free( e );
		return 0;
	}
	if( (void *) e->e_attrs != (void *) (e+1)) {
		attrs_free( e->e_attrs );
	}

	/* See if the DNs were changed by modrdn */
	if( e->e_nname.bv_val < e->e_bv.bv_val || e->e_nname.bv_val >
		e->e_bv.bv_val + e->e_bv.bv_len ) {
		ch_free(e->e_name.bv_val);
		ch_free(e->e_nname.bv_val);
		e->e_name.bv_val = NULL;
		e->e_nname.bv_val = NULL;
	}
#ifndef BDB_HIER
	/* In tool mode the e_bv buffer is realloc'd, leave it alone */
	if( !(slapMode & SLAP_TOOL_MODE) ) {
		free( e->e_bv.bv_val );
	}
#else
	free( e->e_bv.bv_val );
#endif
	free( e );

	return 0;
}

int bdb_entry_release(
	Operation *o,
	Entry *e,
	int rw )
{
	struct bdb_info *bdb = (struct bdb_info *) o->o_bd->be_private;
	struct bdb_op_info *boi = NULL;
 
	/* slapMode : SLAP_SERVER_MODE, SLAP_TOOL_MODE,
			SLAP_TRUNCATE_MODE, SLAP_UNDEFINED_MODE */
 
	if ( slapMode == SLAP_SERVER_MODE ) {
		/* free entry and reader or writer lock */
		if ( o ) {
			boi = (struct bdb_op_info *)o->o_private;
		}
		/* lock is freed with txn */
		if ( !boi || boi->boi_txn ) {
			bdb_unlocked_cache_return_entry_rw( &bdb->bi_cache, e, rw );
		} else {
			bdb_cache_return_entry_rw( bdb->bi_dbenv, &bdb->bi_cache, e, rw, &boi->boi_lock );
			o->o_tmpfree( boi, o->o_tmpmemctx );
			o->o_private = NULL;
		}
	} else {
		if (e->e_private != NULL)
			BEI(e)->bei_e = NULL;
		e->e_private = NULL;
		bdb_entry_return ( e );
	}
 
	return 0;
}

/* return LDAP_SUCCESS IFF we can retrieve the specified entry.
 */
int bdb_entry_get(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **ent )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	struct bdb_op_info *boi = NULL;
	DB_TXN *txn = NULL;
	Entry *e = NULL;
	EntryInfo *ei;
	int	rc;
	const char *at_name = at ? at->ad_cname.bv_val : "(null)";

	u_int32_t	locker = 0;
	DB_LOCK		lock;
	int		free_lock_id = 0;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_BDB, ARGS, 
		"bdb_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 );
	LDAP_LOG( BACK_BDB, ARGS, 
		"bdb_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);
#else
	Debug( LDAP_DEBUG_ARGS,
		"=> bdb_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> bdb_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);
#endif

	if( op ) boi = (struct bdb_op_info *) op->o_private;
	if( boi != NULL && op->o_bd == boi->boi_bdb ) {
		txn = boi->boi_txn;
		locker = boi->boi_locker;
	}

	if ( txn != NULL ) {
		locker = TXN_ID ( txn );
	} else if ( !locker ) {
		rc = LOCK_ID ( bdb->bi_dbenv, &locker );
		free_lock_id = 1;
		switch(rc) {
		case 0:
			break;
		default:
			return LDAP_OTHER;
		}
	}

dn2entry_retry:
	/* can we find entry */
	rc = bdb_dn2entry( op, txn, ndn, &ei, 0, locker, &lock );
	switch( rc ) {
	case DB_NOTFOUND:
	case 0:
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		/* the txn must abort and retry */
		if ( txn ) {
			boi->boi_err = rc;
			return LDAP_BUSY;
		}
		ldap_pvt_thread_yield();
		goto dn2entry_retry;
	default:
		if ( boi ) boi->boi_err = rc;
		if ( free_lock_id ) {
			LOCK_ID_FREE( bdb->bi_dbenv, locker );
		}
		return (rc != LDAP_BUSY) ? LDAP_OTHER : LDAP_BUSY;
	}
	if (ei) e = ei->bei_e;
	if (e == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_BDB, INFO, 
			"bdb_entry_get: cannot find entry (%s)\n", 
			ndn->bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"=> bdb_entry_get: cannot find entry: \"%s\"\n",
				ndn->bv_val, 0, 0 ); 
#endif
		if ( free_lock_id ) {
			LOCK_ID_FREE( bdb->bi_dbenv, locker );
		}
		return LDAP_NO_SUCH_OBJECT; 
	}
	
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_BDB, DETAIL1, "bdb_entry_get: found entry (%s)\n",
		ndn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ACL,
		"=> bdb_entry_get: found entry: \"%s\"\n",
		ndn->bv_val, 0, 0 ); 
#endif

#ifdef BDB_ALIASES
	/* find attribute values */
	if( is_entry_alias( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_BDB, INFO, 
			"bdb_entry_get: entry (%s) is an alias\n", e->e_name.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= bdb_entry_get: entry is an alias\n", 0, 0, 0 );
#endif
		rc = LDAP_ALIAS_PROBLEM;
		goto return_results;
	}
#endif

	if( is_entry_referral( e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_BDB, INFO, 
			"bdb_entry_get: entry (%s) is a referral.\n", e->e_name.bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ACL,
			"<= bdb_entry_get: entry is a referral\n", 0, 0, 0 );
#endif
		rc = LDAP_REFERRAL;
		goto return_results;
	}

	if ( oc && !is_entry_objectclass( e, oc, 0 )) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_BDB, INFO, 
			"bdb_entry_get: failed to find objectClass.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ACL,
			"<= bdb_entry_get: failed to find objectClass\n",
			0, 0, 0 ); 
#endif
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

return_results:
	if( rc != LDAP_SUCCESS ) {
		/* free entry */
		bdb_cache_return_entry_rw(bdb->bi_dbenv, &bdb->bi_cache, e, rw, &lock);
	} else {
		*ent = e;
		/* big drag. we need a place to store a read lock so we can
		 * release it later??
		 */
		if ( op && !boi ) {
			boi = op->o_tmpcalloc(1,sizeof(struct bdb_op_info),op->o_tmpmemctx);
			boi->boi_lock = lock;
			op->o_private = boi;
		}
	}

	if ( free_lock_id ) {
		LOCK_ID_FREE( bdb->bi_dbenv, locker );
	}

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_BDB, ENTRY, "bdb_entry_get: rc=%d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"bdb_entry_get: rc=%d\n",
		rc, 0, 0 ); 
#endif
	return(rc);
}
