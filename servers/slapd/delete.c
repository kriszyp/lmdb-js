/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "slap.h"

#include "lutil.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

int
do_delete(
    Operation	*op,
    SlapReply	*rs )
{
	struct berval dn = BER_BVNULL;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"do_delete: conn %d\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_delete\n", 0, 0, 0 );
#endif

	/*
	 * Parse the delete request.  It looks like this:
	 *
	 *	DelRequest := DistinguishedName
	 */

	if ( ber_scanf( op->o_ber, "m", &dn ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_delete: conn: %d  ber_scanf failed\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_delete: conn %d  get_ctrls failed\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_delete: get_ctrls failed\n", 0, 0, 0 );
#endif
		goto cleanup;
	} 

	rs->sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn,
		op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_delete: conn %d  invalid dn (%s)\n",
			op->o_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_delete: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto cleanup;
	}

	if( op->o_req_ndn.bv_len == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_delete: conn %d: Attempt to delete root DSE.\n", 
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_delete: root dse!\n", 0, 0, 0 );
#endif
		/* protocolError would likely be a more appropriate error */
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"cannot delete the root DSE" );
		goto cleanup;

	} else if ( bvmatch( &op->o_req_ndn, &frontendDB->be_schemandn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_delete: conn %d: "
			"Attempt to delete subschema subentry.\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_delete: subschema subentry!\n", 0, 0, 0 );
#endif
		/* protocolError would likely be a more appropriate error */
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"cannot delete the root DSE" );
		goto cleanup;
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu DEL dn=\"%s\"\n",
		op->o_connid, op->o_opid, op->o_req_dn.bv_val, 0, 0 );

	op->o_bd = frontendDB;
	rs->sr_err = frontendDB->be_delete( op, rs );

cleanup:;
	slap_graduate_commit_csn( op );

	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );
	return rs->sr_err;
}

int
fe_op_delete( Operation *op, SlapReply *rs )
{
	struct berval	pdn = BER_BVNULL;
	int		manageDSAit;
	
	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	op->o_bd = select_backend( &op->o_req_ndn, manageDSAit, 0 );
	if ( op->o_bd == NULL ) {
		rs->sr_ref = referral_rewrite( default_referral,
			NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );

		if (!rs->sr_ref) rs->sr_ref = default_referral;
		if ( rs->sr_ref != NULL ) {
			rs->sr_err = LDAP_REFERRAL;

			send_ldap_result( op, rs );

			if (rs->sr_ref != default_referral) ber_bvarray_free( rs->sr_ref );
		} else {
			send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"no global superior knowledge" );
		}
		goto cleanup;
	}

	/* check restrictions */
	if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto cleanup;
	}

	/* check for referrals */
	if( backend_check_referrals( op, rs ) != LDAP_SUCCESS ) {
		goto cleanup;
	}

#if defined( LDAP_SLAPI )
#define pb op->o_pb
	if ( pb ) {
		slapi_int_pblock_set_operation( pb, op );
		slapi_pblock_set( pb, SLAPI_DELETE_TARGET, (void *)op->o_req_dn.bv_val );
		slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );

		rs->sr_err = slapi_int_call_plugins( op->o_bd,
			SLAPI_PLUGIN_PRE_DELETE_FN, pb );
		if ( rs->sr_err < 0 ) {
			/*
			 * A preoperation plugin failure will abort the
			 * entire operation.
			 */
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, "do_delete: "
				"delete preoperation plugin failed\n", 0, 0, 0 );
#else
			Debug (LDAP_DEBUG_TRACE, "do_delete: "
				"delete preoperation plugin failed.\n", 0, 0, 0);
#endif
			if ( ( slapi_pblock_get( pb, SLAPI_RESULT_CODE,
				(void *)&rs->sr_err ) != 0 ) ||
				rs->sr_err == LDAP_SUCCESS )
			{
				rs->sr_err = LDAP_OTHER;
			}
			goto cleanup;
		}
	}
#endif /* defined( LDAP_SLAPI ) */

	/*
	 * do the delete if 1 && (2 || 3)
	 * 1) there is a delete function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( op->o_bd->be_delete ) {
		/* do the update here */
		int repl_user = be_isupdate( op );
#ifndef SLAPD_MULTIMASTER
		if ( !SLAP_SHADOW(op->o_bd) || repl_user )
#endif
		{
			struct berval	org_req_dn = BER_BVNULL;
			struct berval	org_req_ndn = BER_BVNULL;
			struct berval	org_dn = BER_BVNULL;
			struct berval	org_ndn = BER_BVNULL;
			int		org_managedsait;
			char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
			slap_callback 	cb = { NULL, slap_replog_cb, NULL, NULL };

			if ( !repl_user ) {
				slap_get_csn( op, csnbuf, sizeof(csnbuf), &op->ord_csn, 1 );
			}

#ifdef SLAPD_MULTIMASTER
			if ( !op->o_bd->be_update_ndn.bv_len || !repl_user )
#endif
			{
				cb.sc_next = op->o_callback;
				op->o_callback = &cb;
			}

			op->o_bd->be_delete( op, rs );

			org_req_dn = op->o_req_dn;
			org_req_ndn = op->o_req_ndn;
			org_dn = op->o_dn;
			org_ndn = op->o_ndn;
			org_managedsait = get_manageDSAit( op );
			op->o_dn = op->o_bd->be_rootdn;
			op->o_ndn = op->o_bd->be_rootndn;
			op->o_managedsait = 1;

			while ( rs->sr_err == LDAP_SUCCESS &&
				op->o_delete_glue_parent )
			{
				op->o_delete_glue_parent = 0;
				if ( !be_issuffix( op->o_bd, &op->o_req_ndn )) {
					slap_callback cb = { NULL };
					cb.sc_response = slap_null_cb;
					dnParent( &op->o_req_ndn, &pdn );
					op->o_req_dn = pdn;
					op->o_req_ndn = pdn;
					op->o_callback = &cb;
					op->o_bd->be_delete( op, rs );
				} else {
					break;
				}
			}

			op->o_managedsait = org_managedsait;
			op->o_dn = org_dn;
			op->o_ndn = org_ndn;
			op->o_req_dn = org_req_dn;
			op->o_req_ndn = org_req_ndn;
			op->o_delete_glue_parent = 0;

#ifndef SLAPD_MULTIMASTER
		} else {
			BerVarray defref = op->o_bd->be_update_refs
				? op->o_bd->be_update_refs : default_referral;

			if ( defref != NULL ) {
				rs->sr_ref = referral_rewrite( defref,
					NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
				if (!rs->sr_ref) rs->sr_ref = defref;
				rs->sr_err = LDAP_REFERRAL;
				send_ldap_result( op, rs );

				if (rs->sr_ref != defref) ber_bvarray_free( rs->sr_ref );

			} else {
				send_ldap_error( op, rs,
					LDAP_UNWILLING_TO_PERFORM,
					"shadow context; no update referral" );
			}
#endif
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within namingContext" );
	}

#if defined( LDAP_SLAPI )
	if ( pb != NULL && slapi_int_call_plugins( op->o_bd,
		SLAPI_PLUGIN_POST_DELETE_FN, pb ) < 0)
	{
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO,
			"do_delete: delete postoperation plugins failed\n",
			0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE,
			"do_delete: delete postoperation plugins failed\n",
			0, 0, 0 );
#endif
	}
#endif /* defined( LDAP_SLAPI ) */

cleanup:;
	return rs->sr_err;
}
