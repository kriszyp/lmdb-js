/* delete.c - ldbm backend delete routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_delete(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	const char	*dn,
	const char	*ndn
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	Entry	*matched;
	char	*pdn = NULL;
	Entry	*e, *p = NULL;
	int	rc;
	const char *text;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	DB_TXN		*ltid = NULL;
	struct bdb_op_info opinfo;

	Debug( LDAP_DEBUG_ARGS, "==> bdb_delete: %s\n", dn, 0, 0 );

	if (0) {
retry:	/* transaction retry */
		Debug( LDAP_DEBUG_TRACE, "==> bdb_delete: retrying...\n", 0, 0, 0 );
		rc = txn_abort( ltid );
		ltid = NULL;
		op->o_private = NULL;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}
	}

	/* begin transaction */
	rc = txn_begin( bdb->bi_dbenv, NULL, &ltid, 0 );
	text = NULL;
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	/* get entry for read/modify/write */
	rc = bdb_dn2entry( be, ltid, ndn, &e, &matched, DB_RMW );

	switch( rc ) {
	case 0:
	case DB_NOTFOUND:
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	default:
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		Debug( LDAP_DEBUG_ARGS,
			"<=- bdb_delete: no such object %s\n",
			dn, 0, 0);

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_entry_return( be, matched );
			matched = NULL;

		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		rc = -1;
		goto done;
	}

	pdn = dn_parent( be, ndn );

	if( pdn != NULL && *pdn != '\0' ) {
		/* get parent */
		rc = bdb_dn2entry( be, ltid, pdn, &p, NULL, 0 );

		ch_free( pdn );

		switch( rc ) {
		case 0:
		case DB_NOTFOUND:
			break;
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}

		if( p == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: parent does not exist\n",
				0, 0, 0);
			rc = LDAP_OTHER;
			text = "could not locate parent of entry";
			goto return_results;
		}

		/* check parent for "children" acl */
		rc = access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE );

		bdb_entry_return( be, p );
		p = NULL;

		if ( !rc  ) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: no access to parent\n",
				0, 0, 0 );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

	} else {
		ch_free( pdn );

		/* no parent, must be root to delete */
		if( ! be_isroot( be, op->o_ndn ) ) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: no parent and not root\n",
				0, 0, 0);
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: entry is referral\n",
			0, 0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		rc = 1;
		goto done;
	}

	rc = bdb_dn2id_children( be, ltid, e->e_ndn );
	if( rc != DB_NOTFOUND ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case 0:
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: non-leaf %s\n",
				dn, 0, 0);
			rc = LDAP_NOT_ALLOWED_ON_NONLEAF;
			text = "subtree delete not supported";
			break;
		default:
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: has_children failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
			rc = LDAP_OTHER;
			text = "internal error";
		}
		goto return_results;
	}

	/* delete from dn2id */
	rc = bdb_dn2id_delete( be, ltid, e->e_ndn, e->e_id );
	if ( rc != 0 ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rc = LDAP_OTHER;
		}
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb_delete: dn2id failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		text = "DN index delete failed";
		goto return_results;
	}

	/* delete from id2entry */
	if ( bdb_id2entry_delete( be, ltid, e->e_id ) != 0 ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rc = LDAP_OTHER;
		}
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb_delete: id2entry failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		text = "entry delete failed";
		goto return_results;
	}

	rc = txn_commit( ltid, 0 );
	ltid = NULL;
	op->o_private = NULL;

	if( rc == 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_add: txn_commit failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "commit failed";

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_add: added id=%08x dn=\"%s\"\n",
			e->e_id, e->e_dn, 0 );
		rc = LDAP_SUCCESS;
		text = NULL;
	}

return_results:
	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, text, NULL, NULL );

	if(rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		txn_checkpoint( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	/* free entry */
	if( e != NULL ) {
		bdb_entry_return( be, e );
	}

	if( ltid != NULL ) {
		txn_abort( ltid );
		op->o_private = NULL;
	}

	return rc;
}
