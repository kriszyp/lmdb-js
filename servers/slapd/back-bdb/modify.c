/* modify.c - bdb backend modify routine */
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
#include <ac/time.h>

#include "back-bdb.h"
#include "external.h"

int bdb_modify_internal(
	Operation *op,
	DB_TXN *tid,
	Modifications *modlist,
	Entry *e,
	const char **text,
	char *textbuf,
	size_t textlen )
{
	int rc, err;
	Modification	*mod;
	Modifications	*ml;
	Attribute	*save_attrs;
	Attribute 	*ap;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "bdb_modify_internal: 0x%08lx: %s\n", 
		e->e_id, e->e_dn, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "bdb_modify_internal: 0x%08lx: %s\n",
		e->e_id, e->e_dn, 0);
#endif

	if ( !acl_check_modlist( op, e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	/* save_attrs will be disposed of by bdb_cache_modify */
	save_attrs = e->e_attrs;
	e->e_attrs = attrs_dup( e->e_attrs );

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, "bdb_modify_internal: add\n", 0,0,0);
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: add\n", 0, 0, 0);
#endif
			err = modify_add_values( e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_DELETE:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: delete\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: delete\n", 0, 0, 0);
#endif
			err = modify_delete_values( e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_REPLACE:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: replace\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: replace\n", 0, 0, 0);
#endif
			err = modify_replace_values( e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case LDAP_MOD_INCREMENT:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: increment\n", 0, 0, 0 );
#else
			Debug(LDAP_DEBUG_ARGS,
				"bdb_modify_internal: increment\n", 0, 0, 0);
#endif
			err = modify_increment_values( e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS,
					"bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
			break;

		case SLAP_MOD_SOFTADD:
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"bdb_modify_internal: softadd\n",0,0,0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: softadd\n", 0, 0, 0);
#endif
 			/* Avoid problems in index_add_mods()
 			 * We need to add index if necessary.
 			 */
 			mod->sm_op = LDAP_MOD_ADD;

			err = modify_add_values( e, mod, get_permissiveModify(op),
				text, textbuf, textlen );

 			mod->sm_op = SLAP_MOD_SOFTADD;

 			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
 			}

			if( err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
				Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
					err, *text, 0);
#endif
			}
 			break;

		default:
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: invalid op %d\n", mod->sm_op, 0, 0 );
#else
			Debug(LDAP_DEBUG_ANY, "bdb_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
#endif
			*text = "Invalid modify operation";
			err = LDAP_OTHER;
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: %d %s\n", err, *text, 0 );
#else
			Debug(LDAP_DEBUG_ARGS, "bdb_modify_internal: %d %s\n",
				err, *text, 0);
#endif
		}

		if ( err != LDAP_SUCCESS ) {
			attrs_free( e->e_attrs );
			e->e_attrs = save_attrs;
			/* unlock entry, delete from cache */
			return err; 
		}

		/* If objectClass was modified, reset the flags */
		if ( mod->sm_desc == slap_schema.si_ad_objectClass ) {
			e->e_ocflags = 0;
		}

		/* check if modified attribute was indexed
		 * but not in case of NOOP... */
		err = bdb_index_is_indexed( op->o_bd, mod->sm_desc );
		if ( err == LDAP_SUCCESS && !op->o_noop ) {
			ap = attr_find( save_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXDEL;

			ap = attr_find( e->e_attrs, mod->sm_desc );
			if ( ap ) ap->a_flags |= SLAP_ATTR_IXADD;
		}
	}

	/* check that the entry still obeys the schema */
	rc = entry_schema_check( op->o_bd, e, save_attrs, text, textbuf, textlen );
	if ( rc != LDAP_SUCCESS || op->o_noop ) {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;

		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, "bdb_modify_internal: "
				"entry failed schema check %s\n", 
				*text, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"entry failed schema check: %s\n",
				*text, 0, 0 );
#endif
		}

		/* if NOOP then silently revert to saved attrs */
		return rc;
	}

	/* update the indices of the modified attributes */

	/* start with deleting the old index entries */
	for ( ap = save_attrs; ap != NULL; ap = ap->a_next ) {
		if ( ap->a_flags & SLAP_ATTR_IXDEL ) {
			rc = bdb_index_values( op, tid, ap->a_desc,
				ap->a_nvals,
				e->e_id, SLAP_INDEX_DELETE_OP );
			if ( rc != LDAP_SUCCESS ) {
				attrs_free( e->e_attrs );
				e->e_attrs = save_attrs;
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: attribute index delete failure\n",
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "Attribute index delete failure",
				       0, 0, 0 );
#endif
				return rc;
			}
			ap->a_flags &= ~SLAP_ATTR_IXDEL;
		}
	}

	/* add the new index entries */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
		if (ap->a_flags & SLAP_ATTR_IXADD) {
			rc = bdb_index_values( op, tid, ap->a_desc,
				ap->a_nvals,
				e->e_id, SLAP_INDEX_ADD_OP );
			if ( rc != LDAP_SUCCESS ) {
				attrs_free( e->e_attrs );
				e->e_attrs = save_attrs;
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"bdb_modify_internal: attribute index add failure\n", 
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "Attribute index add failure",
				       0, 0, 0 );
#endif
				return rc;
			}
			ap->a_flags &= ~SLAP_ATTR_IXADD;
		}
	}

	return rc;
}


int
bdb_modify( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry		*e = NULL;
	EntryInfo	*ei = NULL;
	int		manageDSAit = get_manageDSAit( op );
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	DB_TXN	*ltid = NULL, *lt2;
	struct bdb_op_info opinfo;
	Entry		dummy;

	u_int32_t	locker = 0;
	DB_LOCK		lock;

	int		num_retries = 0;

	LDAPControl *ctrls[SLAP_MAX_RESPONSE_CONTROLS];
	int num_ctrls = 0;

	Operation* ps_list;
	struct psid_entry *pm_list, *pm_prev;
	int rc;
	EntryInfo	*suffix_ei;
	Entry		*ctxcsn_e;
	int			ctxcsn_added = 0;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "bdb_modify: %s\n", op->o_req_dn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "bdb_modify: %s\n", op->o_req_dn.bv_val, 0, 0 );
#endif

	if( 0 ) {
retry:	/* transaction retry */
		if( e != NULL ) {
			bdb_unlocked_cache_return_entry_w(&bdb->bi_cache, e);
			e = NULL;
		}
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "bdb_modify: retrying...\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE,
			"bdb_modify: retrying...\n", 0, 0, 0);
#endif

		pm_list = LDAP_LIST_FIRST(&op->o_pm_list);
		while ( pm_list != NULL ) {
			LDAP_LIST_REMOVE ( pm_list, ps_link );
			pm_prev = pm_list;
			pm_list = LDAP_LIST_NEXT ( pm_list, ps_link );
			ch_free( pm_prev );
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
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_modify: txn_begin failed: %s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_begin failed: %s (%d)\n",
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

	/* get entry or ancestor */
	rs->sr_err = bdb_dn2entry( op, ltid, &op->o_req_ndn, &ei, 1,
		locker, &lock );

	if ( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_modify: dn2entry failed: (%d)\n", rs->sr_err, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: dn2entry failed (%d)\n",
			rs->sr_err, 0, 0 );
#endif
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		case DB_NOTFOUND:
			break;
		case LDAP_BUSY:
			rs->sr_text = "ldap server busy";
			goto return_results;
		default:
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "internal error";
			goto return_results;
		}
	}

	e = ei->bei_e;
	/* acquire and lock entry */
	/* FIXME: dn2entry() should return non-glue entry */
	if (( rs->sr_err == DB_NOTFOUND ) || ( !manageDSAit && e && is_entry_glue( e ))) {
		if ( e != NULL ) {
			rs->sr_matched = ch_strdup( e->e_dn );
			rs->sr_ref = is_entry_referral( e )
				? get_entry_referrals( op, e )
				: NULL;
			bdb_unlocked_cache_return_entry_r (&bdb->bi_cache, e);
			e = NULL;

		} else {
			BerVarray deref = NULL;
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
		free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		goto done;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow modify */
		rs->sr_ref = get_entry_referrals( op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "bdb_modify: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: entry is referral\n",
			0, 0, 0 );
#endif

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e->e_name.bv_val;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		goto done;
	}

	if ( get_assert( op ) &&
		( test_filter( op, e, get_assertion( op )) != LDAP_COMPARE_TRUE ))
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		goto return_results;
	}

	if ( rs->sr_err == LDAP_SUCCESS && !op->o_noop && !op->o_no_psearch ) {
		ldap_pvt_thread_rdwr_rlock( &bdb->bi_pslist_rwlock );
		LDAP_LIST_FOREACH ( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
			bdb_psearch(op, rs, ps_list, e, LDAP_PSEARCH_BY_PREMODIFY );
		}
		ldap_pvt_thread_rdwr_runlock( &bdb->bi_pslist_rwlock );
	}

	if( op->o_preread ) {
		if ( slap_read_controls( op, rs, e,
			&slap_pre_read_bv, &ctrls[num_ctrls] ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1,
				"<=- bdb_modify: pre-read failed!\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_modify: pre-read failed!\n", 0, 0, 0 );
#endif
			goto return_results;
		}
		ctrls[++num_ctrls] = NULL;
		op->o_preread = 0; /* prevent redo on retry */
	}

	/* nested transaction */
	rs->sr_err = TXN_BEGIN( bdb->bi_dbenv, ltid, &lt2, 
		bdb->bi_db_opflags );
	rs->sr_text = NULL;
	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: txn_begin(2) failed: %s (%d)\n", db_strerror(rs->sr_err), rs->sr_err, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_begin(2) failed: %s (%d)\n",
			db_strerror(rs->sr_err), rs->sr_err, 0 );
#endif
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}
	/* Modify the entry */
	dummy = *e;
	rs->sr_err = bdb_modify_internal( op, lt2, op->oq_modify.rs_modlist,
		&dummy, &rs->sr_text, textbuf, textlen );

	if( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: modify failed (%d)\n", rs->sr_err, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: modify failed (%d)\n",
			rs->sr_err, 0, 0 );
#endif
		if ( (rs->sr_err == LDAP_INSUFFICIENT_ACCESS) && opinfo.boi_err ) {
			rs->sr_err = opinfo.boi_err;
		}
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		goto return_results;
	}

	if( op->o_postread ) {
		if( slap_read_controls( op, rs, e,
			&slap_post_read_bv, &ctrls[num_ctrls] ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1,
				"<=- bdb_modify: post-read failed!\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- bdb_modify: post-read failed!\n", 0, 0, 0 );
#endif
			goto return_results;
		}
		ctrls[++num_ctrls] = NULL;
		op->o_postread = 0;  /* prevent redo on retry */
		/* FIXME: should read entry on the last retry */
	}

	/* change the entry itself */
	rs->sr_err = bdb_id2entry_update( op->o_bd, lt2, &dummy );
	if ( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: id2entry update failed (%d)\n", rs->sr_err, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: id2entry update failed (%d)\n",
			rs->sr_err, 0, 0 );
#endif
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
		rs->sr_text = "entry update failed";
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

	if( op->o_noop ) {
		if ( ( rs->sr_err = TXN_ABORT( ltid ) ) != 0 ) {
			rs->sr_text = "txn_abort (no-op) failed";
		} else {
			rs->sr_err = LDAP_NO_OPERATION;
			goto return_results;
		}
	} else {
		bdb_cache_modify( e, dummy.e_attrs, bdb->bi_dbenv, locker, &lock );

		if ( LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
			if ( ctxcsn_added ) {
				bdb_cache_add( bdb, suffix_ei, ctxcsn_e,
					(struct berval *)&slap_ldapsync_cn_bv, locker );
			}
		}

		if ( rs->sr_err == LDAP_SUCCESS ) {
			/* Loop through in-scope entries for each psearch spec */
			ldap_pvt_thread_rdwr_rlock( &bdb->bi_pslist_rwlock );
			LDAP_LIST_FOREACH ( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
				bdb_psearch( op, rs, ps_list, e, LDAP_PSEARCH_BY_MODIFY );
			}
			ldap_pvt_thread_rdwr_runlock( &bdb->bi_pslist_rwlock );
			pm_list = LDAP_LIST_FIRST(&op->o_pm_list);
			while ( pm_list != NULL ) {
				bdb_psearch(op, rs, pm_list->ps_op,
							e, LDAP_PSEARCH_BY_SCOPEOUT);
				LDAP_LIST_REMOVE ( pm_list, ps_link );
				pm_prev = pm_list;
				pm_list = LDAP_LIST_NEXT ( pm_list, ps_link );
				ch_free( pm_prev );
			}
		}

		rs->sr_err = TXN_COMMIT( ltid, 0 );
	}
	ltid = NULL;
	op->o_private = NULL;

	if( rs->sr_err != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_modify: txn_%s failed %s (%d)\n", 
			op->o_noop ? "abort (no_op)" : "commit",
			db_strerror(rs->sr_err), rs->sr_err );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_modify: txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit",
			db_strerror(rs->sr_err), rs->sr_err );
#endif
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "commit failed";

		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, DETAIL1, 
		"bdb_modify: updated%s id=%08lx dn=\"%s\"\n", 
		op->o_noop ? " (no_op)" : "", e->e_id, e->e_dn );
#else
	Debug( LDAP_DEBUG_TRACE,
		"bdb_modify: updated%s id=%08lx dn=\"%s\"\n",
		op->o_noop ? " (no-op)" : "",
		e->e_id, e->e_dn );
#endif

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

done:
	if( ltid != NULL ) {
		pm_list = LDAP_LIST_FIRST(&op->o_pm_list);
		while ( pm_list != NULL ) {
			LDAP_LIST_REMOVE ( pm_list, ps_link );
			pm_prev = pm_list;
			pm_list = LDAP_LIST_NEXT ( pm_list, ps_link );
			ch_free( pm_prev );
		}
		TXN_ABORT( ltid );
		op->o_private = NULL;
	}

	if( e != NULL ) {
		bdb_unlocked_cache_return_entry_w (&bdb->bi_cache, e);
	}
	return rs->sr_err;
}
