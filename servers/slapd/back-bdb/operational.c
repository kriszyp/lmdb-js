/* operational.c - bdb backend operational attributes function */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb.h"
#include "proto-bdb.h"

/*
 * sets *hasSubordinates to LDAP_COMPARE_TRUE/LDAP_COMPARE_FALSE
 * if the entry has children or not.
 */
int
bdb_hasSubordinates(
	BackendDB	*be,
	Connection	*conn, 
	Operation	*op,
	Entry		*e,
	int		*hasSubordinates )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int		rc;
	DB_TXN		*ltid = NULL;
	struct bdb_op_info opinfo;
	
	assert( e );
	assert( hasSubordinates );

	if( 0 ) {
retry:	/* transaction retry */
#if 0
		if( e != NULL ) {
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
		}
#endif
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"=> bdb_hasSubordinates: retrying...\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "==> bdb_hasSubordinates: retrying...\n", 
				0, 0, 0 );
#endif
		rc = TXN_ABORT( ltid );
		ltid = NULL;
		op->o_private = NULL;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			goto return_results;
		}
		ldap_pvt_thread_yield();
	}

	/* begin transaction */
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, bdb->bi_db_opflags );
	if ( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"=> bdb_hasSubordinates: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_hasSubordinates: txn_begin failed: %s (%d)\n",
			db_strerror( rc ), rc, 0 );
#endif
		rc = LDAP_OTHER;
		return rc;
	}

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	rc = bdb_dn2id_children( be, ltid, &e->e_nname, 0 );
	
	switch( rc ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;

	case 0:
		*hasSubordinates = LDAP_COMPARE_TRUE;
		break;

	case DB_NOTFOUND:
		*hasSubordinates = LDAP_COMPARE_FALSE;
		rc = LDAP_SUCCESS;
		break;

	default:
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"=> bdb_hasSubordinates: has_children failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#else
		Debug(LDAP_DEBUG_ARGS, 
			"<=- bdb_hasSubordinates: has_children failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#endif
		rc = LDAP_OTHER;
	}

return_results:
	if ( rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

	if ( ltid != NULL ) {
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	return rc;
}

/*
 * sets the supported operational attributes (if required)
 */
int
bdb_operational(
	BackendDB	*be,
	Connection	*conn, 
	Operation	*op,
	Entry		*e,
	AttributeName		*attrs,
	int		opattrs,
	Attribute	**a )
{
	Attribute	**aa = a;
	int		rc = 0;
	
	assert( e );

	if ( opattrs || ad_inlist( slap_schema.si_ad_hasSubordinates, attrs ) ) {
		int	hasSubordinates;

		rc = bdb_hasSubordinates( be, conn, op, e, &hasSubordinates );
		if ( rc == LDAP_SUCCESS ) {
			*aa = slap_operational_hasSubordinate( hasSubordinates == LDAP_COMPARE_TRUE );
			if ( *aa != NULL ) {
				aa = &(*aa)->a_next;
			}
		}
	}

	return rc;
}

