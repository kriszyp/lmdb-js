/* modify.cpp - ndb backend modify routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2008 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion
 * in OpenLDAP Software. This work was sponsored by MySQL.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/time.h>

#include "back-ndb.h"

int ndb_modify_internal(
	Operation *op,
	NdbArgs *NA,
	const char **text,
	char *textbuf,
	size_t textlen )
{
	struct ndb_info *ni = (struct ndb_info *) op->o_bd->be_private;
	Modification	*mod;
	Modifications	*ml;
	Modifications	*modlist = op->orm_modlist;
	NdbAttrInfo **modai, *atmp;
	const NdbDictionary::Dictionary *myDict;
	const NdbDictionary::Table *myTable;
	int got_oc = 0, nmods = 0, nai = 0, i;
	int rc, err, indexed = 0;

	Debug( LDAP_DEBUG_TRACE, "ndb_modify_internal: 0x%08lx: %s\n",
		NA->e->e_id, NA->e->e_dn, 0);

	if ( !acl_check_modlist( op, NA->e, modlist )) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;
		nmods++;

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
			Debug(LDAP_DEBUG_ARGS,
				"ndb_modify_internal: add %s\n",
				mod->sm_desc->ad_cname.bv_val, 0, 0);
			err = modify_add_values( NA->e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ndb_modify_internal: %d %s\n",
					err, *text, 0);
			}
			break;

		case LDAP_MOD_DELETE:
			Debug(LDAP_DEBUG_ARGS,
				"ndb_modify_internal: delete %s\n",
				mod->sm_desc->ad_cname.bv_val, 0, 0);
			err = modify_delete_values( NA->e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			assert( err != LDAP_TYPE_OR_VALUE_EXISTS );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ndb_modify_internal: %d %s\n",
					err, *text, 0);
			}
			break;

		case LDAP_MOD_REPLACE:
			Debug(LDAP_DEBUG_ARGS,
				"ndb_modify_internal: replace %s\n",
				mod->sm_desc->ad_cname.bv_val, 0, 0);
			err = modify_replace_values( NA->e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ndb_modify_internal: %d %s\n",
					err, *text, 0);
			}
			break;

		case LDAP_MOD_INCREMENT:
			Debug(LDAP_DEBUG_ARGS,
				"ndb_modify_internal: increment %s\n",
				mod->sm_desc->ad_cname.bv_val, 0, 0);
			err = modify_increment_values( NA->e, mod, get_permissiveModify(op),
				text, textbuf, textlen );
			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS,
					"ndb_modify_internal: %d %s\n",
					err, *text, 0);
			}
			break;

		case SLAP_MOD_SOFTADD:
			Debug(LDAP_DEBUG_ARGS,
				"ndb_modify_internal: softadd %s\n",
				mod->sm_desc->ad_cname.bv_val, 0, 0);
 			mod->sm_op = LDAP_MOD_ADD;

			err = modify_add_values( NA->e, mod, get_permissiveModify(op),
				text, textbuf, textlen );

 			mod->sm_op = SLAP_MOD_SOFTADD;

 			if ( err == LDAP_TYPE_OR_VALUE_EXISTS ) {
 				err = LDAP_SUCCESS;
 			}

			if( err != LDAP_SUCCESS ) {
				Debug(LDAP_DEBUG_ARGS, "ndb_modify_internal: %d %s\n",
					err, *text, 0);
			}
 			break;

		default:
			Debug(LDAP_DEBUG_ANY, "ndb_modify_internal: invalid op %d\n",
				mod->sm_op, 0, 0);
			*text = "Invalid modify operation";
			err = LDAP_OTHER;
			Debug(LDAP_DEBUG_ARGS, "ndb_modify_internal: %d %s\n",
				err, *text, 0);
		}

		if ( err != LDAP_SUCCESS ) {
			return err; 
		}

		/* If objectClass was modified, reset the flags */
		if ( mod->sm_desc == slap_schema.si_ad_objectClass ) {
			NA->e->e_ocflags = 0;
			got_oc = 1;
		}
	}

	/* check that the entry still obeys the schema */
	rc = entry_schema_check( op, NA->e, NULL, get_relax(op), 0,
		text, textbuf, textlen );
	if ( rc != LDAP_SUCCESS || op->o_noop ) {
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"entry failed schema check: %s\n",
				*text, 0, 0 );
		}
		return rc;
	}

	/* apply modifications to DB */
	modai = (NdbAttrInfo **)op->o_tmpalloc( nmods * sizeof(NdbAttrInfo*), op->o_tmpmemctx );

	/* Get the unique list of modified attributes */
	ldap_pvt_thread_rdwr_rlock( &ni->ni_ai_rwlock );
	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		/* Already took care of objectclass */
		if ( ml->sml_desc == slap_schema.si_ad_objectClass )
			continue;
		for ( i=0; i<nai; i++ ) {
			if ( ml->sml_desc->ad_type == modai[i]->na_attr )
				break;
		}
		/* This attr was already updated */
		if ( i < nai )
			continue;
		modai[nai] = ndb_ai_find( ni, ml->sml_desc->ad_type );
		if ( modai[nai]->na_flag & NDB_INFO_INDEX )
			indexed++;
		nai++;
	}
	ldap_pvt_thread_rdwr_runlock( &ni->ni_ai_rwlock );

	if ( got_oc || indexed ) {
		rc = ndb_entry_put_info( op->o_bd, NA, 1 );
		if ( rc ) return rc;
	}

	myDict = NA->ndb->getDictionary();

	/* One operation per table... */
	for ( i=0; i<nai; i++ ) {
		NdbOperation *myOp;
		int j;

		if ( !modai[i] ) continue;
		atmp = modai[i];
		modai[i] = NULL;
		myTable = myDict->getTable( atmp->na_oi->no_table.bv_val );
		if ( !myTable ) continue;
		myOp = NULL;
		nmods = 0;
		rc = ndb_oc_attrs( NA->txn, myTable, NA->e, atmp->na_oi, &atmp, 1, 1, &nmods, &myOp );
		if ( rc ) return rc;
		for ( j=i+1; j<nai; j++ ) {
			if ( !modai[j] ) continue;
			if ( modai[j]->na_oi == atmp->na_oi ) {
				atmp = modai[j];
				modai[j] = NULL;
				rc = ndb_oc_attrs( NA->txn, myTable, NA->e, atmp->na_oi, &atmp, 1, 1, &nmods, &myOp );
				if ( rc ) return rc;
			}
		}
	}
	return 0;
}


int
ndb_back_modify( Operation *op, SlapReply *rs )
{
	struct ndb_info *ni = (struct ndb_info *) op->o_bd->be_private;
	Entry		e = {0};
	int		manageDSAit = get_manageDSAit( op );
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

	int		num_retries = 0;

	NdbArgs NA;
	NdbRdns rdns;
	struct berval matched;

	LDAPControl **preread_ctrl = NULL;
	LDAPControl **postread_ctrl = NULL;
	LDAPControl *ctrls[SLAP_MAX_RESPONSE_CONTROLS];
	int num_ctrls = 0;

	int rc;

	Debug( LDAP_DEBUG_ARGS, LDAP_XSTRING(ndb_back_modify) ": %s\n",
		op->o_req_dn.bv_val, 0, 0 );

	ctrls[num_ctrls] = NULL;

	slap_mods_opattrs( op, &op->orm_modlist, 1 );

	e.e_name = op->o_req_dn;
	e.e_nname = op->o_req_ndn;

	/* Get our NDB handle */
	rs->sr_err = ndb_thread_handle( op, &NA.ndb );
	rdns.nr_num = 0;
	NA.rdns = &rdns;
	NA.e = &e;

	if( 0 ) {
retry:	/* transaction retry */
		NA.txn->close();
		NA.txn = NULL;
		if( e.e_attrs ) {
			attrs_free( e.e_attrs );
			e.e_attrs = NULL;
		}
		Debug(LDAP_DEBUG_TRACE,
			LDAP_XSTRING(ndb_back_modify) ": retrying...\n", 0, 0, 0);
		if ( op->o_abandon ) {
			rs->sr_err = SLAPD_ABANDON;
			goto return_results;
		}
		if ( NA.ocs ) {
			ber_bvarray_free( NA.ocs );
		}
		ndb_trans_backoff( ++num_retries );
	}
	NA.ocs = NULL;

	/* begin transaction */
	NA.txn = NA.ndb->startTransaction();
	rs->sr_text = NULL;
	if( !NA.txn ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(ndb_back_modify) ": startTransaction failed: %s (%d)\n",
			NA.ndb->getNdbError().message, NA.ndb->getNdbError().code, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	/* get entry or ancestor */
	rs->sr_err = ndb_entry_get_info( op->o_bd, &NA, 0, &matched );
	switch( rs->sr_err ) {
	case 0:
		break;
	case LDAP_NO_SUCH_OBJECT:
		Debug( LDAP_DEBUG_ARGS,
			"<=- ndb_back_modify: no such object %s\n",
			op->o_req_dn.bv_val, 0, 0 );
		rs->sr_matched = matched.bv_val;
		goto return_results;
#if 0
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto retry;
#endif
	case LDAP_BUSY:
		rs->sr_text = "ldap server busy";
		goto return_results;
	default:
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	/* acquire and lock entry */
	rs->sr_err = ndb_entry_get_data( op->o_bd, &NA, 1 );

	if ( !manageDSAit && is_entry_referral( &e ) ) {
		/* entry is a referral, don't allow modify */
		rs->sr_ref = get_entry_referrals( op, &e );

		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(ndb_back_modify) ": entry is referral\n",
			0, 0, 0 );

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e.e_name.bv_val;
		rs->sr_flags = REP_REF_MUSTBEFREED;
		goto return_results;
	}

	if ( get_assert( op ) &&
		( test_filter( op, &e, (Filter*)get_assertion( op )) != LDAP_COMPARE_TRUE ))
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		goto return_results;
	}

	if( op->o_preread ) {
		if( preread_ctrl == NULL ) {
			preread_ctrl = &ctrls[num_ctrls++];
			ctrls[num_ctrls] = NULL;
		}
		if ( slap_read_controls( op, rs, &e,
			&slap_pre_read_bv, preread_ctrl ) )
		{
			Debug( LDAP_DEBUG_TRACE,
				"<=- " LDAP_XSTRING(ndb_back_modify) ": pre-read "
				"failed!\n", 0, 0, 0 );
			if ( op->o_preread & SLAP_CONTROL_CRITICAL ) {
				/* FIXME: is it correct to abort
				 * operation if control fails? */
				goto return_results;
			}
		}
	}

	/* Modify the entry */
	rs->sr_err = ndb_modify_internal( op, &NA, &rs->sr_text, textbuf, textlen );

	if( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(ndb_back_modify) ": modify failed (%d)\n",
			rs->sr_err, 0, 0 );
#if 0
		switch( rs->sr_err ) {
		case DB_LOCK_DEADLOCK:
		case DB_LOCK_NOTGRANTED:
			goto retry;
		}
#endif
		goto return_results;
	}

	if( op->o_postread ) {
		if( postread_ctrl == NULL ) {
			postread_ctrl = &ctrls[num_ctrls++];
			ctrls[num_ctrls] = NULL;
		}
		if( slap_read_controls( op, rs, &e,
			&slap_post_read_bv, postread_ctrl ) )
		{
			Debug( LDAP_DEBUG_TRACE,
				"<=- " LDAP_XSTRING(ndb_back_modify)
				": post-read failed!\n", 0, 0, 0 );
			if ( op->o_postread & SLAP_CONTROL_CRITICAL ) {
				/* FIXME: is it correct to abort
				 * operation if control fails? */
				goto return_results;
			}
		}
	}

	if( op->o_noop ) {
		if ( ( rs->sr_err = NA.txn->execute( Rollback ) ) != 0 ) {
			rs->sr_text = "txn_abort (no-op) failed";
		} else {
			rs->sr_err = LDAP_X_NO_OPERATION;
		}
	} else {
		if ( ( rs->sr_err = NA.txn->execute( Commit ) ) != 0 ) {
			rs->sr_text = "txn_commit failed";
		} else {
			rs->sr_err = LDAP_SUCCESS;
		}
	}

	if( rs->sr_err != LDAP_SUCCESS && rs->sr_err != LDAP_X_NO_OPERATION ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(ndb_back_modify) ": txn_%s failed: %s (%d)\n",
			op->o_noop ? "abort (no-op)" : "commit",
			NA.txn->getNdbError().message, NA.txn->getNdbError().code );
		rs->sr_err = LDAP_OTHER;
		goto return_results;
	}
	NA.txn->close();
	NA.txn = NULL;

	Debug( LDAP_DEBUG_TRACE,
		LDAP_XSTRING(ndb_back_modify) ": updated%s id=%08lx dn=\"%s\"\n",
		op->o_noop ? " (no-op)" : "",
		e.e_id, op->o_req_dn.bv_val );

	rs->sr_err = LDAP_SUCCESS;
	rs->sr_text = NULL;
	if( num_ctrls ) rs->sr_ctrls = ctrls;

return_results:
	if ( NA.ocs ) {
		ber_bvarray_free( NA.ocs );
		NA.ocs = NULL;
	}

	if ( e.e_attrs != NULL ) {
		attrs_free( e.e_attrs );
		e.e_attrs = NULL;
	}

	if( NA.txn != NULL ) {
		NA.txn->execute( Rollback );
		NA.txn->close();
	}

	send_ldap_result( op, rs );
	slap_graduate_commit_csn( op );

	if( preread_ctrl != NULL && (*preread_ctrl) != NULL ) {
		slap_sl_free( (*preread_ctrl)->ldctl_value.bv_val, op->o_tmpmemctx );
		slap_sl_free( *preread_ctrl, op->o_tmpmemctx );
	}
	if( postread_ctrl != NULL && (*postread_ctrl) != NULL ) {
		slap_sl_free( (*postread_ctrl)->ldctl_value.bv_val, op->o_tmpmemctx );
		slap_sl_free( *postread_ctrl, op->o_tmpmemctx );
	}

	rs->sr_text = NULL;
	return rs->sr_err;
}
