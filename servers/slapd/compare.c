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

#include <stdio.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "slap.h"
#include "slapi.h"

static int compare_entry(
	Connection *conn,
	Operation *op,
	Entry *e,
	AttributeAssertion *ava );

int
do_compare(
    Connection	*conn,
    Operation	*op
)
{
	Entry *entry = NULL;
	Entry *fentry = NULL;
	struct berval dn = { 0, NULL };
	struct berval pdn = { 0, NULL };
	struct berval ndn = { 0, NULL };
	struct berval desc = { 0, NULL };
	struct berval value = { 0, NULL };
	AttributeAssertion ava = { NULL, { 0, NULL } };
	Backend	*be;
	int rc = LDAP_SUCCESS;
	const char *text = NULL;
	int manageDSAit;

	Slapi_PBlock *pb = op->o_pb;

	ava.aa_desc = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_compare: conn %d\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_compare\n", 0, 0, 0 );
#endif
	/*
	 * Parse the compare request.  It looks like this:
	 *
	 *	CompareRequest := [APPLICATION 14] SEQUENCE {
	 *		entry	DistinguishedName,
	 *		ava	SEQUENCE {
	 *			type	AttributeType,
	 *			value	AttributeValue
	 *		}
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{m" /*}*/, &dn ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_compare: conn %d  ber_scanf failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if ( ber_scanf( op->o_ber, "{mm}", &desc, &value ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_compare: conn %d  get ava failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_compare: get ava failed\n", 0, 0, 0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if ( ber_scanf( op->o_ber, /*{*/ "}" ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_compare: conn %d  ber_scanf failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( ( rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_compare: conn %d  get_ctrls failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_compare: get_ctrls failed\n", 0, 0, 0 );
#endif
		goto cleanup;
	} 

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_compare: conn %d  invalid dn (%s)\n",
			conn->c_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_compare: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	rc = slap_bv2ad( &desc, &ava.aa_desc, &text );
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );
		goto cleanup;
	}

	rc = value_validate_normalize( ava.aa_desc, SLAP_MR_EQUALITY,
		&value, &ava.aa_value, &text );
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );
		goto cleanup;
	}

	if( strcasecmp( ndn.bv_val, LDAP_ROOT_DSE ) == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"do_compare: dn (%s) attr(%s) value (%s)\n",
			pdn.bv_val, ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );
#else
		Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
			pdn.bv_val, ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );
#endif

		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu CMP dn=\"%s\" attr=\"%s\"\n",
			op->o_connid, op->o_opid, pdn.bv_val,
			ava.aa_desc->ad_cname.bv_val, 0 );

		rc = backend_check_restrictions( NULL, conn, op, NULL, &text ) ;
		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );
			goto cleanup;
		}

		rc = root_dse_info( conn, &entry, &text );
		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );
			goto cleanup;
		}

		fentry = entry;

	} else if ( bvmatch( &ndn, &global_schemandn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ARGS, 
			"do_compare: dn (%s) attr(%s) value (%s)\n",
			pdn.bv_val, ava.aa_desc->ad_cname.bv_val,
			ava.aa_value.bv_val );
#else
		Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
			pdn.bv_val, ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );
#endif

		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu CMP dn=\"%s\" attr=\"%s\"\n",
			op->o_connid, op->o_opid, pdn.bv_val,
			ava.aa_desc->ad_cname.bv_val, 0 );

		rc = backend_check_restrictions( NULL, conn, op, NULL, &text ) ;
		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );
			rc = 0;
			goto cleanup;
		}

		rc = schema_info( &entry, &text );
		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );
			rc = 0;
			goto cleanup;
		}
		fentry = entry;
	}

	if( entry ) {
		rc = compare_entry( conn, op, entry, &ava );
		if( fentry) entry_free( fentry );

		send_ldap_result( conn, op, rc, NULL, text, NULL, NULL );

		if( rc == LDAP_COMPARE_TRUE || rc == LDAP_COMPARE_FALSE ) {
			rc = 0;
		}

		goto cleanup;
	}

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
		rc = 0;
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

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"do_compare: dn (%s) attr(%s) value (%s)\n",
		pdn.bv_val, ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );
#else
	Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
	    pdn.bv_val, ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );
#endif

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu CMP dn=\"%s\" attr=\"%s\"\n",
	    op->o_connid, op->o_opid, pdn.bv_val,
		ava.aa_desc->ad_cname.bv_val, 0 );


	/* deref suffix alias if appropriate */
	suffix_alias( be, &ndn );

#if defined( LDAP_SLAPI )
	slapi_x_backend_set_pb( pb, be );
	slapi_x_connection_set_pb( pb, conn );
	slapi_x_operation_set_pb( pb, op );
	slapi_pblock_set( pb, SLAPI_COMPARE_TARGET, (void *)dn.bv_val );
	slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );
	slapi_pblock_set( pb, SLAPI_COMPARE_TYPE, (void *)desc.bv_val );
	slapi_pblock_set( pb, SLAPI_COMPARE_VALUE, (void *)&value );

	rc = doPluginFNs( be, SLAPI_PLUGIN_PRE_COMPARE_FN, pb );
	if ( rc != 0 ) {
		/*
		 * A preoperation plugin failure will abort the
		 * entire operation.
		 */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_compare: compare preoperation plugin "
				"failed\n", 0, 0, 0);
#else
		Debug(LDAP_DEBUG_TRACE, "do_compare: compare preoperation plugin "
				"failed.\n", 0, 0, 0);
#endif
		if ( slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void *)&rc ) != 0)
			rc = LDAP_OTHER;
		goto cleanup;
	}
#endif /* defined( LDAP_SLAPI ) */

	if ( be->be_compare ) {
		(*be->be_compare)( be, conn, op, &pdn, &ndn, &ava );
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext",
			NULL, NULL );
	}

#if defined( LDAP_SLAPI )
	if ( doPluginFNs( be, SLAPI_PLUGIN_POST_COMPARE_FN, pb ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_compare: compare postoperation plugins "
				"failed\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE, "do_compare: compare postoperation plugins "
				"failed.\n", 0, 0, 0);
#endif
	}
#endif /* defined( LDAP_SLAPI ) */

cleanup:
	free( pdn.bv_val );
	free( ndn.bv_val );
	if ( ava.aa_value.bv_val ) free( ava.aa_value.bv_val );

	return rc;
}

static int compare_entry(
	Connection *conn,
	Operation *op,
	Entry *e,
	AttributeAssertion *ava )
{
	int rc = LDAP_NO_SUCH_ATTRIBUTE;
	Attribute *a;

	if ( ! access_allowed( NULL, conn, op, e,
		ava->aa_desc, &ava->aa_value, ACL_COMPARE, NULL ) )
	{	
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for(a = attrs_find( e->e_attrs, ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, ava->aa_desc ))
	{
		rc = LDAP_COMPARE_FALSE;

		if ( value_find( ava->aa_desc, a->a_vals, &ava->aa_value ) == 0 ) {
			rc = LDAP_COMPARE_TRUE;
			break;
		}
	}

	return rc;
}
