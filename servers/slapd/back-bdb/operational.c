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
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	Attribute	**aa = a;
	int		rc;
	DB_TXN		*ltid = NULL;
        struct bdb_op_info opinfo;
	
	assert( e );

	if ( !opattrs && !ad_inlist( slap_schema.si_ad_hasSubordinates, attrs ) ) {
		return 0;
	}


	if( 0 ) {
retry:	/* transaction retry */
		if( e != NULL ) {
			bdb_cache_return_entry_w(&bdb->bi_cache, e);
		}
		Debug( LDAP_DEBUG_TRACE, "==> bdb_delete: retrying...\n", 
				0, 0, 0 );
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
		Debug( LDAP_DEBUG_TRACE,
			"bdb_operational: txn_begin failed: %s (%d)\n",
			db_strerror( rc ), rc, 0 );
		rc = LDAP_OTHER;
		return rc;
	}

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	rc = bdb_dn2id_children( be, ltid, &e->e_nname );
	
	switch( rc ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;

	case 0:
	case DB_NOTFOUND:
		*aa = slap_operational_hasSubordinate( rc == 0 );
		if ( *aa != NULL ) {
			aa = &(*aa)->a_next;
		}
		break;

	default:
		Debug(LDAP_DEBUG_ARGS, 
			"<=- bdb_operational: has_children failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
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

