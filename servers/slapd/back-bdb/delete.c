/* delete.c - bdb backend delete routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_delete( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry	*matched;
	struct berval	pdn = {0, NULL};
	Entry	*e = NULL;
	Entry	*p = NULL;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	DB_TXN		*ltid = NULL;
	struct bdb_op_info opinfo;

	u_int32_t	locker = 0;
	DB_LOCK		lock;

	int		noop = 0;

#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
	Operation* ps_list;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS,  "==> bdb_delete: %s\n", op->o_req_dn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "==> bdb_delete: %s\n",
		op->o_req_dn.bv_val, 0, 0 );
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
		rs->sr_err = TXN_ABORT( ltid );
		ltid = NULL;
		op->o_private = NULL;
		op->o_do_not_cache = opinfo.boi_acl_cache;
		if( rs->sr_err != 0 ) {
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
			goto return_results;
		}
		ldap_pvt_thread_yield();
	}

	/* begin transaction */
	rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"==> bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_begin failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	locker = TXN_ID ( ltid );

	opinfo.boi_bdb = op->o_bd;
	opinfo.boi_txn = ltid;
	opinfo.boi_locker = locker;
	opinfo.boi_err = 0;
	opinfo.boi_acl_cache = op->o_do_not_cache;
	op->o_private = &opinfo;

	if ( !be_issuffix( op->o_bd, &op->o_req_ndn ) ) {
		dnParent( &op->o_req_ndn, &pdn );
	}

	if( pdn.bv_len != 0 ) {
		/* get parent */
		rs->sr_err = bdb_dn2entry_r( op->o_bd, ltid, &pdn, &p, NULL, 0, locker, &lock );

		switch( rs->sr_err ) {
		case 0:
		case DB_NOTFOUND:
			break;
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case LDAP_BUSY:
			rs->sr_text = "ldap server busy";
			goto return_results;
		default:
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
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
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "could not locate parent of entry";
			goto return_results;
		}

		/* check parent for "children" acl */
		rs->sr_err = access_allowed( op, p,
			children, NULL, ACL_WRITE, NULL );

		bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);
		p = NULL;

		if ( !rs->sr_err  ) {
			switch( opinfo.boi_err ) {
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			}

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"<=- bdb_delete: no write access to parent\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_delete: no write access to parent\n",
				0, 0, 0 );
#endif
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			rs->sr_text = "no write access to parent";
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( op->o_bd, &op->o_ndn ) ) {
			if ( be_issuffix( op->o_bd, (struct berval *)&slap_empty_bv )
				|| be_isupdate( op->o_bd, &op->o_ndn ) ) {
				p = (Entry *)&slap_entry_root;

				/* check parent for "children" acl */
				rs->sr_err = access_allowed( op, p,
					children, NULL, ACL_WRITE, NULL );

				p = NULL;

				if ( !rs->sr_err  ) {
					switch( opinfo.boi_err ) {
					case DB_LOCK_DEADLOCK:
					case DB_LOCK_NOTGRANTED:
						goto retry;
					}

#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, DETAIL1, 
						"<=- bdb_delete: no access to parent\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- bdb_delete: no access "
						"to parent\n", 0, 0, 0 );
#endif
					rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
					rs->sr_text = "no write access to parent";
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
				rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}
		}
	}

	/* get entry for read/modify/write */
	rs->sr_err = bdb_dn2entry_w( op->o_bd, ltid, &op->o_req_ndn, &e, &matched, DB_RMW, locker, &lock );

	switch( rs->sr_err ) {
	case 0:
	case DB_NOTFOUND:
		break;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case LDAP_BUSY:
		rs->sr_text = "ldap server busy";
		goto return_results;
	default:
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ARGS, 
			"<=- bdb_delete: no such object %s\n", op->o_req_dn.bv_val, 0, 0);
#else
		Debug( LDAP_DEBUG_ARGS,
			"<=- bdb_delete: no such object %s\n",
			op->o_req_dn.bv_val, 0, 0);
#endif

		if ( matched != NULL ) {
			rs->sr_matched = ch_strdup( matched->e_dn );
			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;
			bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, matched);
			matched = NULL;

		} else {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		rs->sr_err = LDAP_REFERRAL;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		rs->sr_err = -1;
		goto done;
	}

	rs->sr_err = access_allowed( op, e,
		entry, NULL, ACL_WRITE, NULL );

	if ( !rs->sr_err  ) {
		switch( opinfo.boi_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"<=- bdb_delete: no write access to entry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<=- bdb_delete: no write access to entry\n",
			0, 0, 0 );
#endif
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		rs->sr_text = "no write access to entry";
		goto return_results;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow delete */
		rs->sr_ref = get_entry_referrals( op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"<=- bdb_delete: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: entry is referral\n",
			0, 0, 0 );
#endif

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e->e_name.bv_val;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		rs->sr_err = 1;
		goto done;
	}

	rs->sr_err = bdb_dn2id_children( op->o_bd, ltid, &e->e_nname, 0 );
	if( rs->sr_err != DB_NOTFOUND ) {
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case 0:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"<=- bdb_delete: non-leaf %s\n", op->o_req_dn.bv_val, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: non-leaf %s\n",
				op->o_req_dn.bv_val, 0, 0);
#endif
			rs->sr_err = LDAP_NOT_ALLOWED_ON_NONLEAF;
			rs->sr_text = "subtree delete not supported";
			break;
		default:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"<=- bdb_delete: has_children failed %s (%d)\n",
				db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
			Debug(LDAP_DEBUG_ARGS,
				"<=- bdb_delete: has_children failed: %s (%d)\n",
				db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
		}
		goto return_results;
	}

	/* delete from dn2id */
	rs->sr_err = bdb_dn2id_delete( op->o_bd, ltid, pdn.bv_val, e );
	if ( rs->sr_err != 0 ) {
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"<=- bdb_delete: dn2id failed %s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb_delete: dn2id failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
		rs->sr_text = "DN index delete failed";
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

	/* delete from id2entry */
	rs->sr_err = bdb_id2entry_delete( op->o_bd, ltid, e );
	if ( rs->sr_err != 0 ) {
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"<=- bdb_delete: id2entry failed: %s (%d)\n", 
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- bdb_delete: id2entry failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
		rs->sr_text = "entry delete failed";
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

	/* delete indices for old attributes */
	rs->sr_err = bdb_index_entry_del( op->o_bd, ltid, e );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"<=- bdb_delete: entry index delete failed!\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "entry index delete failed!\n",
			0, 0, 0 );
#endif
		rs->sr_text = "entry index delete failed";
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

#if 0	/* Do we want to reclaim deleted IDs? */
	ldap_pvt_thread_mutex_lock( &bdb->bi_lastid_mutex );
	if ( e->e_id == bdb->bi_lastid ) {
		bdb_last_id( op->o_bd, ltid );
	}
	ldap_pvt_thread_mutex_unlock( &bdb->bi_lastid_mutex );
#endif

	if( op->o_noop ) {
		if ( ( rs->sr_err = TXN_ABORT( ltid ) ) != 0 ) {
			rs->sr_text = "txn_abort (no-op) failed";
		} else {
			noop = 1;
			rs->sr_err = LDAP_SUCCESS;
		}
	} else {
		rs->sr_err = TXN_COMMIT( ltid, 0 );
	}
	ltid = NULL;
	op->o_private = NULL;

	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_delete: txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit", db_strerror(rs->sr_err), rs->sr_err );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_delete: txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit",
			db_strerror(rs->sr_err), rs->sr_err );
#endif
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "commit failed";

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
		rs->sr_err = LDAP_SUCCESS;
		rs->sr_text = NULL;
	}

return_results:
	send_ldap_result( op, rs );

#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
        if ( rs->sr_err == LDAP_SUCCESS && !noop ) {
		LDAP_LIST_FOREACH( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
			bdb_psearch( op, rs, ps_list, e, LDAP_PSEARCH_BY_DELETE );
		}
	}
#endif

	if(rs->sr_err == LDAP_SUCCESS && bdb->bi_txn_cp ) {
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

	return ( ( rs->sr_err == LDAP_SUCCESS ) ? noop : rs->sr_err );
}
