/* add.c - ldap BerkeleyDB back-end add routine */
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
#include "external.h"

int
bdb_add(Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	struct berval	pdn;
	Entry		*p;
	EntryInfo	*ei;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	DB_TXN		*ltid = NULL, *lt2;
	struct bdb_op_info opinfo;
#ifdef BDB_SUBENTRIES
	int subentry;
#endif
	u_int32_t	locker = 0;
	DB_LOCK		lock;

	int		num_retries = 0;

	Operation* ps_list;
	int		rc;
	EntryInfo	*suffix_ei = NULL;
	Entry		*ctxcsn_e;
	int			ctxcsn_added = 0;

	LDAPControl *ctrls[SLAP_MAX_RESPONSE_CONTROLS];
	int num_ctrls = 0;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, "==> bdb_add: %s\n",
		op->oq_add.rs_e->e_name.bv_val, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "==> bdb_add: %s\n",
		op->oq_add.rs_e->e_name.bv_val, 0, 0);
#endif

	/* check entry's schema */
	rs->sr_err = entry_schema_check( op->o_bd, op->oq_add.rs_e,
		NULL, &rs->sr_text, textbuf, textlen );
	if ( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_add: entry failed schema check: %s (%d)\n",
			rs->sr_text, rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_add: entry failed schema check: %s (%d)\n",
			rs->sr_text, rs->sr_err, 0 );
#endif
		goto return_results;
	}

#ifdef BDB_SUBENTRIES
	subentry = is_entry_subentry( op->oq_add.rs_e );
#endif

	/*
	 * acquire an ID outside of the operation transaction
	 * to avoid serializing adds.
	 */
	rs->sr_err = bdb_next_id( op->o_bd, NULL, &op->oq_add.rs_e->e_id );
	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_add: next_id failed (%d)\n", rs->sr_err, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_add: next_id failed (%d)\n", rs->sr_err, 0, 0 );
#endif
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	if( 0 ) {
retry:	/* transaction retry */
		if( p ) {
			/* free parent and reader lock */
			bdb_unlocked_cache_return_entry_r( &bdb->bi_cache, p );
			p = NULL;
		}
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
		bdb_trans_backoff( ++num_retries );
	}

	/* begin transaction */
	rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, NULL, &ltid, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_add: txn_begin failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_add: txn_begin failed: %s (%d)\n",
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
	
	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 */
	if ( be_issuffix( op->o_bd, &op->oq_add.rs_e->e_nname ) ) {
		pdn = slap_empty_bv;
	} else {
		dnParent( &op->oq_add.rs_e->e_nname, &pdn );
	}

	/* get entry or parent */
	rs->sr_err = bdb_dn2entry( op, ltid, &op->ora_e->e_nname, &ei,
		1, locker, &lock );
	switch( rs->sr_err ) {
	case 0:
		rs->sr_err = LDAP_ALREADY_EXISTS;
		goto return_results;
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

	p = ei->bei_e;
	if ( p ) {
		if ( !bvmatch( &pdn, &p->e_nname ) ) {
			rs->sr_matched = ber_strdup_x( p->e_name.bv_val,
				op->o_tmpmemctx );
			rs->sr_ref = is_entry_referral( p )
				? get_entry_referrals( op, p )
				: NULL;
			bdb_unlocked_cache_return_entry_r( &bdb->bi_cache, p );
			p = NULL;
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, "bdb_add: parent does not exist\n",
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_add: parent does not exist\n",
				0, 0, 0 );
#endif

			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			ber_bvarray_free( rs->sr_ref );
			op->o_tmpfree( (char *)rs->sr_matched, op->o_tmpmemctx );
			rs->sr_ref = NULL;
			rs->sr_matched = NULL;

			goto done;
		}

		rs->sr_err = access_allowed( op, p,
			children, NULL, ACL_WRITE, NULL );

		if ( ! rs->sr_err ) {
			switch( opinfo.boi_err ) {
			case DB_LOCK_DEADLOCK:
			case DB_LOCK_NOTGRANTED:
				goto retry;
			}

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_add: no write access to parent\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_add: no write access to parent\n", 0, 0, 0 );
#endif
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			rs->sr_text = "no write access to parent";
			goto return_results;;
		}

#ifdef BDB_SUBENTRIES
		if ( is_entry_subentry( p ) ) {
			/* parent is a subentry, don't allow add */
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_add: parent is subentry\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_add: parent is subentry\n",
				0, 0, 0 );
#endif
			rs->sr_err = LDAP_OBJECT_CLASS_VIOLATION;
			rs->sr_text = "parent is a subentry";
			goto return_results;;
		}
#endif
#ifdef BDB_ALIASES
		if ( is_entry_alias( p ) ) {
			/* parent is an alias, don't allow add */
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_add: parent is alias\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_add: parent is alias\n",
				0, 0, 0 );
#endif
			rs->sr_err = LDAP_ALIAS_PROBLEM;
			rs->sr_text = "parent is an alias";
			goto return_results;;
		}
#endif

		if ( is_entry_referral( p ) ) {
			/* parent is a referral, don't allow add */
			rs->sr_matched = p->e_name.bv_val;
			rs->sr_ref = get_entry_referrals( op, p );

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_add: parent is referral\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_add: parent is referral\n",
				0, 0, 0 );
#endif

			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			ber_bvarray_free( rs->sr_ref );
			bdb_unlocked_cache_return_entry_r( &bdb->bi_cache, p );
			rs->sr_ref = NULL;
			rs->sr_matched = NULL;
			p = NULL;
			goto done;
		}

#ifdef BDB_SUBENTRIES
		if ( subentry ) {
			/* FIXME: */
			/* parent must be an administrative point of the required kind */
		}
#endif

		/* free parent and reader lock */
		bdb_unlocked_cache_return_entry_r( &bdb->bi_cache, p );
		p = NULL;

	} else {
		/*
		 * no parent!
		 *  if not attempting to add entry at suffix or with parent ""
		 */
		if (( !be_isroot_dn( op ) || pdn.bv_len > 0 )
			&& !is_entry_glue( op->oq_add.rs_e ))
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, "bdb_add: %s denied\n", 
				pdn.bv_len == 0 ? "suffix" : "entry at root", 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "bdb_add: %s denied\n",
				pdn.bv_len == 0 ? "suffix" : "entry at root",
				0, 0 );
#endif
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			goto return_results;
		}
	}

	if ( get_assert( op ) &&
		( test_filter( op, op->oq_add.rs_e, get_assertion( op ))
			!= LDAP_COMPARE_TRUE ))
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		goto return_results;
	}

	rs->sr_err = access_allowed( op, op->oq_add.rs_e,
		entry, NULL, ACL_WRITE, NULL );

	if ( ! rs->sr_err ) {
		switch( opinfo.boi_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_add: no write access to entry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_add: no write access to entry\n",
			0, 0, 0 );
#endif
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		rs->sr_text = "no write access to entry";
		goto return_results;;
	}

	/* post-read */
	if( op->o_postread ) {
		if ( slap_read_controls( op, rs, op->oq_add.rs_e,
			&slap_post_read_bv, &ctrls[num_ctrls] ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"<=- bdb_add: post-read failed!\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_add: post-read failed!\n", 0, 0, 0 );
#endif
			goto return_results;
		}
		ctrls[++num_ctrls] = NULL;
	}

	/* nested transaction */
	rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, ltid, &lt2, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_add: txn_begin(2) failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_add: txn_begin(2) failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	/* dn2id index */
	rs->sr_err = bdb_dn2id_add( op, lt2, ei, op->oq_add.rs_e );
	if ( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_add: dn2id_add failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_add: dn2id_add failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif

		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case DB_KEYEXIST:
			rs->sr_err = LDAP_ALREADY_EXISTS;
			break;
		default:
			rs->sr_err = LDAP_OTHER;
		}
		goto return_results;
	}

	/* id2entry index */
	rs->sr_err = bdb_id2entry_add( op->o_bd, lt2, op->oq_add.rs_e );
	if ( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, "bdb_add: id2entry_add failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_add: id2entry_add failed\n",
			0, 0, 0 );
#endif
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rs->sr_err = LDAP_OTHER;
		}
		rs->sr_text = "entry store failed";
		goto return_results;
	}

	/* attribute indexes */
	rs->sr_err = bdb_index_entry_add( op, lt2, op->oq_add.rs_e );
	if ( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_add: index_entry_add failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_add: index_entry_add failed\n",
			0, 0, 0 );
#endif
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		default:
			rs->sr_err = LDAP_OTHER;
		}
		rs->sr_text = "index generation failed";
		goto return_results;
	}
	if ( TXN_COMMIT( lt2, 0 ) != 0 ) {
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "txn_commit(2) failed";
		goto return_results;
	}

	if ( LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
		rc = bdb_csn_commit( op, rs, ltid, ei, &suffix_ei,
			&ctxcsn_e, &ctxcsn_added, locker );
		switch ( rc ) {
		case BDB_CSN_ABORT :
			goto return_results;
		case BDB_CSN_RETRY :
			goto retry;
		}
	}

	if ( op->o_noop ) {
		if (( rs->sr_err=TXN_ABORT( ltid )) != 0 ) {
			rs->sr_text = "txn_abort (no-op) failed";
		} else {
			rs->sr_err = LDAP_NO_OPERATION;
			goto return_results;
		}

	} else {
		struct berval nrdn;
		Entry *e = entry_dup( op->ora_e );

		if (pdn.bv_len) {
			nrdn.bv_val = e->e_nname.bv_val;
			nrdn.bv_len = pdn.bv_val - op->ora_e->e_nname.bv_val - 1;
		} else {
			nrdn = e->e_nname;
		}

		bdb_cache_add( bdb, ei, e, &nrdn, locker );

		if ( suffix_ei == NULL ) {
			suffix_ei = BEI(e);
		}

		if ( LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
			if ( ctxcsn_added ) {
				bdb_cache_add( bdb, suffix_ei, ctxcsn_e,
					(struct berval *)&slap_ldapsync_cn_bv, locker );
			}
		}

		if ( rs->sr_err == LDAP_SUCCESS && !op->o_no_psearch ) {
			ldap_pvt_thread_rdwr_rlock( &bdb->bi_pslist_rwlock );
			assert( BEI(e) );
			LDAP_LIST_FOREACH ( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
				bdb_psearch( op, rs, ps_list, e,
					LDAP_PSEARCH_BY_ADD );
			}
			ldap_pvt_thread_rdwr_runlock( &bdb->bi_pslist_rwlock );
		}

		if(( rs->sr_err=TXN_COMMIT( ltid, 0 )) != 0 ) {
			rs->sr_text = "txn_commit failed";
		} else {
			rs->sr_err = LDAP_SUCCESS;
		}
	}

	ltid = NULL;
	op->o_private = NULL;

	if ( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, "bdb_add: %s : %s (%d)\n",
			rs->sr_text, db_strerror(rs->sr_err), rs->sr_err );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_add: %s : %s (%d)\n",
			rs->sr_text, db_strerror(rs->sr_err), rs->sr_err );
#endif
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, RESULTS, 
		"bdb_add: added%s id=%08lx dn=\"%s\"\n", 
		op->o_noop ? " (no-op)" : "",
		op->oq_add.rs_e->e_id, op->oq_add.rs_e->e_dn );
#else
	Debug(LDAP_DEBUG_TRACE, "bdb_add: added%s id=%08lx dn=\"%s\"\n",
		op->o_noop ? " (no-op)" : "",
		op->oq_add.rs_e->e_id, op->oq_add.rs_e->e_dn );
#endif

	rs->sr_text = NULL;
	if( num_ctrls ) rs->sr_ctrls = ctrls;

return_results:
	send_ldap_result( op, rs );

	if( rs->sr_err == LDAP_SUCCESS && bdb->bi_txn_cp ) {
		ldap_pvt_thread_yield();
		TXN_CHECKPOINT( bdb->bi_dbenv,
			bdb->bi_txn_cp_kbyte, bdb->bi_txn_cp_min, 0 );
	}

done:
	if( ltid != NULL ) {
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	return rs->sr_err;
}
