/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
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
#include "slapi_common.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "slap.h"
#include "slapi.h"

int
do_delete(
    Connection	*conn,
    Operation	*op
)
{
	struct berval dn = { 0, NULL };
	struct berval pdn = { 0, NULL };
	struct berval ndn = { 0, NULL };
	const char *text;
	Backend	*be;
	int rc;
	int manageDSAit;

	Slapi_PBlock *pb = op->o_pb;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"do_delete: conn %d\n", conn->c_connid, 0, 0 );
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
			"do_delete: conn: %d  ber_scanf failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if( ( rc = get_ctrls( conn, op, 1 ) ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_delete: conn %d  get_ctrls failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_delete: get_ctrls failed\n", 0, 0, 0 );
#endif
		goto cleanup;
	} 

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_delete: conn %d  invalid dn (%s)\n",
			conn->c_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_delete: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	if( ndn.bv_len == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_delete: conn %d: Attempt to delete root DSE.\n", 
			conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_delete: root dse!\n", 0, 0, 0 );
#endif
		/* protocolError would likely be a more appropriate error */
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "cannot delete the root DSE", NULL, NULL );
		goto cleanup;

	} else if ( bvmatch( &ndn, &global_schemandn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_delete: conn %d: "
			"Attempt to delete subschema subentry.\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_delete: subschema subentry!\n", 0, 0, 0 );
#endif
		/* protocolError would likely be a more appropriate error */
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "cannot delete the root DSE", NULL, NULL );
		goto cleanup;
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu DEL dn=\"%s\"\n",
		op->o_connid, op->o_opid, pdn.bv_val, 0, 0 );

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( &ndn, manageDSAit, 0 )) == NULL ) {
		BerVarray ref = referral_rewrite( default_referral,
			NULL, &pdn, LDAP_SCOPE_DEFAULT );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, ref ? ref : default_referral, NULL );

		ber_bvarray_free( ref );
		goto cleanup;
	}

	/* check restrictions */
	rc = backend_check_restrictions( be, conn, op, NULL, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto cleanup;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, &pdn, &ndn );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}

	/* deref suffix alias if appropriate */
	suffix_alias( be, &ndn );

#if defined( LDAP_SLAPI )
	slapi_backend_set_pb( pb, be );
	slapi_connection_set_pb( pb, conn );
	slapi_operation_set_pb( pb, op );
	slapi_pblock_set( pb, SLAPI_DELETE_TARGET, (void *)dn.bv_val );
	slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)(1) );

	rc = doPluginFNs( be, SLAPI_PLUGIN_PRE_DELETE_FN, pb );
	if ( rc != 0 && rc != LDAP_OTHER ) {
		/*
		 * either there is no preOp (delete) plugins
		 * or a plugin failed. Just log it
		 *
		 * FIXME: is this correct?
		 */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_delete: delete preOps "
				"failed\n", 0, 0, 0 );
#else
		Debug (LDAP_DEBUG_TRACE, "do_delete: delete preOps failed.\n",
				0, 0, 0);
#endif
	}
#endif /* defined( LDAP_SLAPI ) */

	/*
	 * do the delete if 1 && (2 || 3)
	 * 1) there is a delete function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_delete ) {
		/* do the update here */
		int repl_user = be_isupdate( be, &op->o_ndn );
#ifndef SLAPD_MULTIMASTER
		if ( !be->be_update_ndn.bv_len || repl_user )
#endif
		{
			if ( (*be->be_delete)( be, conn, op, &pdn, &ndn ) == 0 ) {
#ifdef SLAPD_MULTIMASTER
				if ( !be->be_update_ndn.bv_len || !repl_user )
#endif
				{
					replog( be, op, &pdn, &ndn, NULL );
				}
			}
#ifndef SLAPD_MULTIMASTER
		} else {
			BerVarray defref = be->be_update_refs
				? be->be_update_refs : default_referral;
			BerVarray ref = referral_rewrite( default_referral,
				NULL, &pdn, LDAP_SCOPE_DEFAULT );

			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				ref ? ref : defref, NULL );

			ber_bvarray_free( ref );
#endif
		}

	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext", NULL, NULL );
	}

#if defined( LDAP_SLAPI )
	rc = doPluginFNs( be, SLAPI_PLUGIN_POST_DELETE_FN, pb );
	if ( rc != 0 && rc != LDAP_OTHER ) {
		/*
		 * either there is no postOp (delete) plugins
		 * or a plugin failed. Just log it
		 *
		 * FIXME: is this correct?
		 */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_delete: delete postOps "
				"failed\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE, "do_delete: delete postOps "
				"failed.\n", 0, 0, 0);
#endif
	}
#endif /* defined( LDAP_SLAPI ) */

cleanup:
	free( pdn.bv_val );
	free( ndn.bv_val );
	return rc;
}
