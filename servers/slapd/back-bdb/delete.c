/* delete.c - bdb backend delete routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
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

int
bdb_delete( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry	*matched = NULL;
	struct berval	pdn = {0, NULL};
	Entry	*e = NULL;
	Entry	*p = NULL;
	EntryInfo	*ei = NULL, *eip = NULL;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	DB_TXN		*ltid = NULL, *lt2;
	struct bdb_op_info opinfo;
	ID	eid;

	u_int32_t	locker = 0;
	DB_LOCK		lock, plock;

	int		num_retries = 0;

	Operation* ps_list;
	int     rc;
	EntryInfo   *suffix_ei;
	Entry       *ctxcsn_e;
	int         ctxcsn_added = 0;

	LDAPControl **preread_ctrl = NULL;
	LDAPControl *ctrls[SLAP_MAX_RESPONSE_CONTROLS];
	int num_ctrls = 0;

	int	parent_is_glue = 0;
	int parent_is_leaf = 0;

	struct berval ctxcsn_ndn = BER_BVNULL;

	ctrls[num_ctrls] = 0;

	Debug( LDAP_DEBUG_ARGS, "==> " LDAP_XSTRING(bdb_delete) ": %s\n",
		op->o_req_dn.bv_val, 0, 0 );

	build_new_dn( &ctxcsn_ndn, &op->o_bd->be_nsuffix[0],
				(struct berval *)&slap_ldapsync_cn_bv, op->o_tmpmemctx );

	if( 0 ) {
retry:	/* transaction retry */
		if( e != NULL ) {
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
			e = NULL;
		}
		if( p != NULL ) {
			bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);
			p = NULL;
		}
		Debug( LDAP_DEBUG_TRACE,
			"==> " LDAP_XSTRING(bdb_delete) ": retrying...\n",
			0, 0, 0 );
		rs->sr_err = TXN_ABORT( ltid );
		ltid = NULL;
		op->o_private = NULL;
		op->o_do_not_cache = opinfo.boi_acl_cache;
		if( rs->sr_err != 0 ) {
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
			goto return_results;
		}
		parent_is_glue = 0;
		parent_is_leaf = 0;
		ldap_pvt_thread_yield();
		bdb_trans_backoff( ++num_retries );
	}

	/* begin transaction */
	rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rs->sr_err != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(bdb_delete) ": txn_begin failed: "
			"%s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
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

	/* get entry */
	rs->sr_err = bdb_dn2entry( op, ltid, &op->o_req_ndn, &ei, 1,
		locker, &lock );

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

	if ( rs->sr_err == 0 ) {
		e = ei->bei_e;
		eip = ei->bei_parent;
	} else {
		matched = ei->bei_e;
	}

	/* FIXME : dn2entry() should return non-glue entry */
	if ( e == NULL || ( !manageDSAit && is_entry_glue( e ))) {
		BerVarray deref = NULL;

		Debug( LDAP_DEBUG_ARGS,
			"<=- " LDAP_XSTRING(bdb_delete) ": no such object %s\n",
			op->o_req_dn.bv_val, 0, 0);

		if ( matched != NULL ) {
			rs->sr_matched = ch_strdup( matched->e_dn );
			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;
			bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, matched);
			matched = NULL;

		} else {
			if ( !LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
				syncinfo_t *si;
				LDAP_STAILQ_FOREACH( si, &op->o_bd->be_syncinfo, si_next ) {
					struct berval tmpbv;
					ber_dupbv( &tmpbv, &si->si_provideruri_bv[0] );
					ber_bvarray_add( &deref, &tmpbv );
				}
			} else {
				deref = default_referral;
			}
			rs->sr_ref = referral_rewrite( deref, NULL, &op->o_req_dn,
					LDAP_SCOPE_DEFAULT );
		}

		rs->sr_err = LDAP_REFERRAL;
		send_ldap_result( op, rs );

		if ( rs->sr_ref != default_referral ) {
			ber_bvarray_free( rs->sr_ref );
		}
		if ( deref != default_referral ) {
			ber_bvarray_free( deref );
		}
		free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		rs->sr_err = -1;
		goto done;
	}

	rc = bdb_cache_find_id( op, ltid, eip->bei_id, &eip, 0, locker, &plock );
	switch( rc ) {
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
	case 0:
	case DB_NOTFOUND:
		break;
	default:
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}
	if ( eip ) p = eip->bei_e;

	if ( pdn.bv_len != 0 ) {
		if( p == NULL || !bvmatch( &pdn, &p->e_nname )) {
			Debug( LDAP_DEBUG_TRACE,
				"<=- " LDAP_XSTRING(bdb_delete) ": parent "
				"does not exist\n", 0, 0, 0 );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "could not locate parent of entry";
			goto return_results;
		}

		/* check parent for "children" acl */
		rs->sr_err = access_allowed( op, p,
			children, NULL, ACL_WRITE, NULL );

		if ( !rs->sr_err  ) {
			switch( opinfo.boi_err ) {
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			}

			Debug( LDAP_DEBUG_TRACE,
				"<=- " LDAP_XSTRING(bdb_delete) ": no write "
				"access to parent\n", 0, 0, 0 );
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			rs->sr_text = "no write access to parent";
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( op ) ) {
			if ( be_issuffix( op->o_bd, (struct berval *)&slap_empty_bv )
				|| be_shadow_update( op ) ) {
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

					Debug( LDAP_DEBUG_TRACE,
						"<=- " LDAP_XSTRING(bdb_delete)
						": no access to parent\n",
						0, 0, 0 );
					rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
					rs->sr_text = "no write access to parent";
					goto return_results;
				}

			} else {
				Debug( LDAP_DEBUG_TRACE,
					"<=- " LDAP_XSTRING(bdb_delete)
					": no parent and not root\n", 0, 0, 0 );
				rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
				goto return_results;
			}
		}
	}

	if ( get_assert( op ) &&
		( test_filter( op, e, get_assertion( op )) != LDAP_COMPARE_TRUE ))
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		goto return_results;
	}

	rs->sr_err = access_allowed( op, e,
		entry, NULL, ACL_WRITE, NULL );

	if ( !rs->sr_err  ) {
		switch( opinfo.boi_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}

		Debug( LDAP_DEBUG_TRACE,
			"<=- " LDAP_XSTRING(bdb_delete) ": no write access "
			"to entry\n", 0, 0, 0 );
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		rs->sr_text = "no write access to entry";
		goto return_results;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow delete */
		rs->sr_ref = get_entry_referrals( op, e );

		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(bdb_delete) ": entry is referral\n",
			0, 0, 0 );

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e->e_name.bv_val;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		rs->sr_err = 1;
		goto done;
	}

	/* pre-read */
	if( op->o_preread ) {
		if( preread_ctrl == NULL ) {
			preread_ctrl = &ctrls[num_ctrls++];
			ctrls[num_ctrls] = NULL;
		}
		if( slap_read_controls( op, rs, e,
			&slap_pre_read_bv, preread_ctrl ) )
		{
			Debug( LDAP_DEBUG_TRACE,
				"<=- " LDAP_XSTRING(bdb_delete) ": pre-read "
				"failed!\n", 0, 0, 0 );
			goto return_results;
		}
	}

	/* nested transaction */
	rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, ltid, &lt2, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rs->sr_err != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(bdb_delete) ": txn_begin(2) failed: "
			"%s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	/* Can't do it if we have kids */
	rs->sr_err = bdb_cache_children( op, lt2, e );
	if( rs->sr_err != DB_NOTFOUND ) {
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case 0:
			Debug(LDAP_DEBUG_ARGS,
				"<=- " LDAP_XSTRING(bdb_delete)
				": non-leaf %s\n",
				op->o_req_dn.bv_val, 0, 0);
			rs->sr_err = LDAP_NOT_ALLOWED_ON_NONLEAF;
			rs->sr_text = "subtree delete not supported";
			break;
		default:
			Debug(LDAP_DEBUG_ARGS,
				"<=- " LDAP_XSTRING(bdb_delete)
				": has_children failed: %s (%d)\n",
				db_strerror(rs->sr_err), rs->sr_err, 0 );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
		}
		goto return_results;
	}

	ldap_pvt_thread_rdwr_wlock( &bdb->bi_pslist_rwlock );
	LDAP_LIST_FOREACH( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
		rc = bdb_psearch( op, rs, ps_list, e, LDAP_PSEARCH_BY_PREDELETE );
		if ( rc == LDAP_BUSY && op->o_ps_send_wait ) {
			ldap_pvt_thread_rdwr_wunlock( &bdb->bi_pslist_rwlock );
			goto retry;
		} else if ( rc ) {
			Debug( LDAP_DEBUG_TRACE,
				LDAP_XSTRING(bdb_delete) ": persistent search "
				"failed (%d,%d)\n", rc, rs->sr_err, 0 );
		}
	}
	ldap_pvt_thread_rdwr_wunlock( &bdb->bi_pslist_rwlock );

	/* delete from dn2id */
	rs->sr_err = bdb_dn2id_delete( op, lt2, eip, e );
	if ( rs->sr_err != 0 ) {
		Debug(LDAP_DEBUG_TRACE,
			"<=- " LDAP_XSTRING(bdb_delete) ": dn2id failed: "
			"%s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rs->sr_text = "DN index delete failed";
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

	/* delete from id2entry */
	rs->sr_err = bdb_id2entry_delete( op->o_bd, lt2, e );
	if ( rs->sr_err != 0 ) {
		Debug(LDAP_DEBUG_TRACE,
			"<=- " LDAP_XSTRING(bdb_delete) ": id2entry failed: "
			"%s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rs->sr_text = "entry delete failed";
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

	/* delete indices for old attributes */
	rs->sr_err = bdb_index_entry_del( op, lt2, e );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"<=- " LDAP_XSTRING(bdb_delete) ": index failed: "
			"%s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rs->sr_text = "entry index delete failed";
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

	if ( pdn.bv_len != 0 ) {
		parent_is_glue = is_entry_glue(p);
		rs->sr_err = bdb_cache_children( op, lt2, p );
		if ( rs->sr_err != DB_NOTFOUND ) {
			switch( rs->sr_err ) {
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			case 0:
				break;
			default:
				Debug(LDAP_DEBUG_ARGS,
					"<=- " LDAP_XSTRING(bdb_delete)
					": has_children failed: %s (%d)\n",
					db_strerror(rs->sr_err), rs->sr_err, 0 );
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "internal error";
				goto return_results;
			}
			parent_is_leaf = 1;
		}
		bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);
		p = NULL;
	}

	if ( TXN_COMMIT( lt2, 0 ) != 0 ) {
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "txn_commit(2) failed";
		goto return_results;
	}

	eid = e->e_id;

#if 0	/* Do we want to reclaim deleted IDs? */
	ldap_pvt_thread_mutex_lock( &bdb->bi_lastid_mutex );
	if ( e->e_id == bdb->bi_lastid ) {
		bdb_last_id( op->o_bd, ltid );
	}
	ldap_pvt_thread_mutex_unlock( &bdb->bi_lastid_mutex );
#endif

	if ( !dn_match( &ctxcsn_ndn, &op->o_req_ndn ) &&
		 !be_issuffix( op->o_bd, &op->o_req_ndn ) &&
			LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
		rc = bdb_csn_commit( op, rs, ltid, ei, &suffix_ei,
			&ctxcsn_e, &ctxcsn_added, locker );
		switch ( rc ) {
		case BDB_CSN_ABORT :
			goto return_results;
		case BDB_CSN_RETRY :
			goto retry;
		}
	}

	if( op->o_noop ) {
		if ( ( rs->sr_err = TXN_ABORT( ltid ) ) != 0 ) {
			rs->sr_text = "txn_abort (no-op) failed";
		} else {
			rs->sr_err = LDAP_NO_OPERATION;
			goto return_results;
		}
	} else {
		rc = bdb_cache_delete( &bdb->bi_cache, e, bdb->bi_dbenv,
			locker, &lock );
		switch( rc ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}

		if ( LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
			if ( ctxcsn_added ) {
				bdb_cache_add( bdb, suffix_ei,
					ctxcsn_e, (struct berval *)&slap_ldapsync_cn_bv, locker );
			}
		}

		if ( rs->sr_err == LDAP_SUCCESS && !op->o_no_psearch ) {
			Attribute *a;
			a = attr_find( e->e_attrs, slap_schema.si_ad_entryCSN );
			if ( a ) {
				if( (void *) e->e_attrs != (void *) (e+1)) {
					attr_delete( &e->e_attrs, slap_schema.si_ad_entryCSN );
					attr_merge_normalize_one( e, slap_schema.si_ad_entryCSN,
					&op->o_sync_csn, NULL );
				} else {
					a->a_vals[0] = op->o_sync_csn;
				}
			} else {
				/* Hm, the entryCSN ought to exist. ??? */
			}
			ldap_pvt_thread_rdwr_wlock( &bdb->bi_pslist_rwlock );
			LDAP_LIST_FOREACH( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
				rc = bdb_psearch( op, rs, ps_list, e, LDAP_PSEARCH_BY_DELETE );
				if ( rc ) {
					Debug( LDAP_DEBUG_TRACE,
						LDAP_XSTRING(bdb_delete)
						": persistent search failed "
						"(%d,%d)\n",
						rc, rs->sr_err, 0 );
				}
			}
			ldap_pvt_thread_rdwr_wunlock( &bdb->bi_pslist_rwlock );
		}

		rs->sr_err = TXN_COMMIT( ltid, 0 );
	}
	ltid = NULL;
	op->o_private = NULL;

	if( rs->sr_err != 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(bdb_delete) ": txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit",
			db_strerror(rs->sr_err), rs->sr_err );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "commit failed";

		goto return_results;
	}

	Debug( LDAP_DEBUG_TRACE,
		LDAP_XSTRING(bdb_delete) ": deleted%s id=%08lx dn=\"%s\"\n",
		op->o_noop ? " (no-op)" : "",
		eid, op->o_req_dn.bv_val );
	rs->sr_err = LDAP_SUCCESS;
	rs->sr_text = NULL;
	if( num_ctrls ) rs->sr_ctrls = ctrls;

return_results:
	send_ldap_result( op, rs );

	if( rs->sr_err == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

	if ( rs->sr_err == LDAP_SUCCESS && parent_is_glue && parent_is_leaf ) {
		op->o_delete_glue_parent = 1;
	}

done:
	if ( p )
		bdb_unlocked_cache_return_entry_r(&bdb->bi_cache, p);

	/* free entry */
	if( e != NULL ) {
		if ( rs->sr_err == LDAP_SUCCESS ) {
			/* Free the EntryInfo and the Entry */
			bdb_cache_delete_cleanup( &bdb->bi_cache, BEI(e) );
		} else {
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
		}
	}

	if( ltid != NULL ) {
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	slap_sl_free( ctxcsn_ndn.bv_val, op->o_tmpmemctx );

	if( preread_ctrl != NULL ) {
		slap_sl_free( (*preread_ctrl)->ldctl_value.bv_val, op->o_tmpmemctx );
		slap_sl_free( *preread_ctrl, op->o_tmpmemctx );
	}
	return rs->sr_err;
}
