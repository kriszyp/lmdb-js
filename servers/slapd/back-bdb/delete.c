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
	Entry	*e = NULL;
	Entry	*p = NULL;
	int	rc;
	const char *text;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	DB_TXN		*ltid = NULL;
	struct bdb_op_info opinfo;

	u_int32_t	locker;
	DB_LOCK		lock;
#if 0
	u_int32_t	lockid;
	DB_LOCK		lock;
#endif

	int		noop = 0;

#ifdef LDAP_CLIENT_UPDATE
	Operation* ps_list;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS,  "==> bdb_delete: %s\n", dn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "==> bdb_delete: %s\n",
		dn->bv_val, 0, 0 );
#endif

	if( 0 ) {
retry:	/* transaction retry */
		if( e != NULL ) {
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"==> bdb_delete: retrying...\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "==> bdb_delete: retrying...\n",
			0, 0, 0 );
#endif
		rc = TXN_ABORT( ltid );
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
	rc = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	text = NULL;
	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"==> bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	locker = TXN_ID ( ltid );
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
		rc = bdb_dn2entry_r( be, ltid, &pdn, &p, NULL, 0, locker, &lock );

		switch( rc ) {
		case 0:
		case DB_NOTFOUND:
			break;
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case LDAP_BUSY:
			text = "ldap server busy";
			goto return_results;
		default:
			rc = LDAP_OTHER;
			text = "internal error";
			goto return_results;
		}

		if( p == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"<=- bdb_delete: parent does not exist\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: parent does not exist\n",
				0, 0, 0);
#endif
			rc = LDAP_OTHER;
			text = "could not locate parent of entry";
			goto return_results;
		}

		/* check parent for "children" acl */
		rc = access_allowed( be, conn, op, p,
			children, NULL, ACL_WRITE, NULL );

		bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);
		p = NULL;

		switch( opinfo.boi_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}

		if ( !rc  ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"<=- bdb_delete: no write access to parent\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: no write access to parent\n",
				0, 0, 0 );
#endif
			rc = LDAP_INSUFFICIENT_ACCESS;
			text = "no write access to parent";
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
					children, NULL, ACL_WRITE, NULL );

				p = NULL;

				switch( opinfo.boi_err ) {
				case DB_LOCK_DEADLOCK:
				case DB_LOCK_NOTGRANTED:
					goto retry;
				}

				if ( !rc  ) {
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, DETAIL1, 
						"<=- bdb_delete: no access to parent\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- bdb_delete: no access "
						"to parent\n", 0, 0, 0 );
#endif
					rc = LDAP_INSUFFICIENT_ACCESS;
					text = "no write access to parent";
					goto return_results;
				}

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"<=- bdb_delete: no parent and not root\n", 0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"<=- bdb_delete: no parent "
					"and not root\n", 0, 0, 0);
#endif
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
	rc = bdb_dn2entry_w( be, ltid, ndn, &e, &matched, DB_RMW, locker, &lock );

	switch( rc ) {
	case 0:
	case DB_NOTFOUND:
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case LDAP_BUSY:
		text = "ldap server busy";
		goto return_results;
	default:
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		BerVarray refs;

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ARGS, 
			"<=- bdb_delete: no such object %s\n", dn->bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ARGS,
			"<=- bdb_delete: no such object %s\n",
			dn->bv_val, 0, 0);
#endif

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, matched);
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

	rc = access_allowed( be, conn, op, e,
		entry, NULL, ACL_WRITE, NULL );

	switch( opinfo.boi_err ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	}

	if ( !rc  ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"<=- bdb_delete: no write access to entry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<=- bdb_delete: no write access to entry\n",
			0, 0, 0 );
#endif
		rc = LDAP_INSUFFICIENT_ACCESS;
		text = "no write access to entry";
		goto return_results;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow delete */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"<=- bdb_delete: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: entry is referral\n",
			0, 0, 0 );
#endif

		send_ldap_result( conn, op, LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		ber_bvarray_free( refs );

		rc = 1;
		goto done;
	}

	rc = bdb_dn2id_children( be, ltid, &e->e_nname, 0 );
	if( rc != DB_NOTFOUND ) {
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case 0:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"<=- bdb_delete: non-leaf %s\n", dn->bv_val, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: non-leaf %s\n",
				dn->bv_val, 0, 0);
#endif
			rc = LDAP_NOT_ALLOWED_ON_NONLEAF;
			text = "subtree delete not supported";
			break;
		default:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"<=- bdb_delete: has_children failed %s (%d)\n",
				db_strerror(rc), rc, 0 );
#else
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: has_children failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
#endif
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
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"<=- bdb_delete: dn2id failed %s (%d)\n", db_strerror(rc), rc, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb_delete: dn2id failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
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
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"<=- bdb_delete: id2entry failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb_delete: id2entry failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
#endif
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
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"<=- bdb_delete: entry index delete failed!\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "entry index delete failed!\n",
			0, 0, 0 );
#endif
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

	if( op->o_noop ) {
		if ( ( rc = TXN_ABORT( ltid ) ) != 0 ) {
			text = "txn_abort (no-op) failed";
		} else {
			noop = 1;
			rc = LDAP_SUCCESS;
		}
	} else {
		rc = TXN_COMMIT( ltid, 0 );
	}
	ltid = NULL;
	op->o_private = NULL;

	if( rc != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_delete: txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit", db_strerror(rc), rc );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit",
			db_strerror(rc), rc );
#endif
		rc = LDAP_OTHER;
		text = "commit failed";

	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_delete: deleted%s id=%08lx db=\"%s\"\n",
			op->o_noop ? " (no-op)" : "", e->e_id, e->e_dn );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: deleted%s id=%08lx dn=\"%s\"\n",
			op->o_noop ? " (no-op)" : "",
			e->e_id, e->e_dn );
#endif
		rc = LDAP_SUCCESS;
		text = NULL;
	}

return_results:
	send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );

#ifdef LDAP_CLIENT_UPDATE
        if ( rc == LDAP_SUCCESS && !noop ) {
		LDAP_LIST_FOREACH( ps_list, &bdb->psearch_list, link ) {
			bdb_psearch( be, conn, op, ps_list, e, LCUP_PSEARCH_BY_DELETE );
		}
	}
#endif /* LDAP_CLIENT_UPDATE */

	if(rc == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	/* free entry */
	if( e != NULL ) {
		bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
	}

	if( ltid != NULL ) {
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	return ( ( rc == LDAP_SUCCESS ) ? noop : rc );
}
