/* delete.c - bdb backend delete routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
	struct berval	*dn,
	struct berval	*ndn
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	Entry	*matched;
	struct berval	pdn = {0, NULL};
	Entry	*e, *p = NULL;
	int	rc;
	const char *text;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	DB_TXN		*ltid = NULL;
	struct bdb_op_info opinfo;
#if 0
	u_int32_t	lockid;
	DB_LOCK		lock;
#endif

	Debug( LDAP_DEBUG_ARGS, "==> bdb_delete: %s\n",
		dn->bv_val, 0, 0 );

	if( 0 ) {
retry:	/* transaction retry */
		if( e != NULL ) {
			bdb_cache_return_entry_w(&bdb->bi_cache, e);
		}
		Debug( LDAP_DEBUG_TRACE, "==> bdb_delete: retrying...\n",
			0, 0, 0 );
		rc = txn_abort( ltid );
		ltid = NULL;
		op->o_private = NULL;
		if( rc != 0 ) {
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}
		ldap_pvt_thread_yield();
	}

	/* begin transaction */
	rc = txn_begin( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	text = NULL;
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}
#if 0
	lockid = TXN_ID( ltid );
#endif

	opinfo.boi_bdb = be;
	opinfo.boi_txn = ltid;
	opinfo.boi_err = 0;
	op->o_private = &opinfo;

	if ( !be_issuffix( be, ndn ) ) {
		dnParent( ndn, &pdn );
	}

	if( pdn.bv_len != 0 ) {
#if 0
		if ( ltid ) {
			DBT obj;
			obj.data = pdn.bv_val-1;
			obj.size = pdn.bv_len+1;
			rc = LOCK_GET( bdb->bi_dbenv, lockid, 0, &obj,
				DB_LOCK_WRITE, &lock);
		}
#endif
		/* get parent */
		rc = bdb_dn2entry_r( be, ltid, &pdn, &p, NULL, 0 );

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

		bdb_cache_return_entry_r(&bdb->bi_cache, p);
		p = NULL;

		switch( opinfo.boi_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}

		if ( !rc  ) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: no access to parent\n",
				0, 0, 0 );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( be, &op->o_ndn ) ) {
			if ( be_issuffix( be, (struct berval *)&slap_empty_bv )
				|| be_isupdate( be, &op->o_ndn ) ) {
				p = (Entry *)&slap_entry_root;

				/* check parent for "children" acl */
				rc = access_allowed( be, conn, op, p,
					children, NULL, ACL_WRITE );
				p = NULL;

				switch( opinfo.boi_err ) {
				case DB_LOCK_DEADLOCK:
				case DB_LOCK_NOTGRANTED:
					goto retry;
				}

				if ( !rc  ) {
					Debug( LDAP_DEBUG_TRACE,
						"<=- bdb_delete: no access "
						"to parent\n", 0, 0, 0 );
					rc = LDAP_INSUFFICIENT_ACCESS;
					goto return_results;
				}

			} else {
				Debug( LDAP_DEBUG_TRACE,
					"<=- bdb_delete: no parent "
					"and not root\n", 0, 0, 0);
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}
		}

#if 0
		if ( ltid ) {
			DBT obj;
			obj.data = ",";
			obj.size = 1;
			rc = LOCK_GET( bdb->bi_dbenv, lockid, 0, &obj,
				DB_LOCK_WRITE, &lock);
		}
#endif
	}

	/* get entry for read/modify/write */
	rc = bdb_dn2entry_w( be, ltid, ndn, &e, &matched, DB_RMW );

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
		BerVarray refs;

		Debug( LDAP_DEBUG_ARGS,
			"<=- bdb_delete: no such object %s\n",
			dn->bv_val, 0, 0);

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_cache_return_entry_r(&bdb->bi_cache, matched );
			matched = NULL;

		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		ber_bvarray_free( refs );
		free( matched_dn );

		rc = -1;
		goto done;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: entry is referral\n",
			0, 0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvarray_free( refs );

		rc = 1;
		goto done;
	}

	rc = bdb_dn2id_children( be, ltid, &e->e_nname );
	if( rc != DB_NOTFOUND ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case 0:
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: non-leaf %s\n",
				dn->bv_val, 0, 0);
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
	rc = bdb_dn2id_delete( be, ltid, pdn.bv_val, e );
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
	rc = bdb_id2entry_delete( be, ltid, e );
	if ( rc != 0 ) {
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

	/* delete indices for old attributes */
	rc = bdb_index_entry_del( be, ltid, e, e->e_attrs );
	if ( rc != LDAP_SUCCESS ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rc = LDAP_OTHER;
		}
		Debug( LDAP_DEBUG_ANY, "entry index delete failed!\n",
			0, 0, 0 );
		text = "entry index delete failed";
		goto return_results;
	}

#if 0	/* Do we want to reclaim deleted IDs? */
	ldap_pvt_thread_mutex_lock( &bdb->bi_lastid_mutex );
	if ( e->e_id == bdb->bi_lastid ) {
		bdb_last_id( be, ltid );
	}
	ldap_pvt_thread_mutex_unlock( &bdb->bi_lastid_mutex );
#endif

	rc = txn_commit( ltid, 0 );
	ltid = NULL;
	op->o_private = NULL;

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_commit failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		rc = LDAP_OTHER;
		text = "commit failed";

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: deleted id=%08lx dn=\"%s\"\n",
			e->e_id, e->e_dn, 0 );
		rc = LDAP_SUCCESS;
		text = NULL;
	}

return_results:
	send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );

	if(rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	/* free entry */
	if( e != NULL ) {
		bdb_cache_return_entry_w(&bdb->bi_cache, e);
	}

	if( ltid != NULL ) {
		txn_abort( ltid );
		op->o_private = NULL;
	}

	return rc;
}
