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

/*
 * LDAP v3 newSuperior support.
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "ldap_pvt.h"
#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi.h"
#endif

int
do_modrdn(
    Connection	*conn,
    Operation	*op
)
{
	struct berval dn = { 0, NULL };
	struct berval newrdn = { 0, NULL };
	struct berval newSuperior = { 0, NULL };
	ber_int_t	deloldrdn;

	struct berval pdn = { 0, NULL };
	struct berval pnewrdn = { 0, NULL };
	struct berval pnewSuperior = { 0, NULL }, *pnewS = NULL;

	struct berval ndn = { 0, NULL };
	struct berval nnewrdn = { 0, NULL };
	struct berval nnewSuperior = { 0, NULL }, *nnewS = NULL;

	Backend	*be;
	Backend	*newSuperior_be = NULL;
	ber_len_t	length;
	int rc;
	const char *text;
	int manageDSAit;

#ifdef LDAP_SLAPI
	Slapi_PBlock *pb = op->o_pb;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_modrdn: begin\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_modrdn\n", 0, 0, 0 );
#endif


	/*
	 * Parse the modrdn request.  It looks like this:
	 *
	 *	ModifyRDNRequest := SEQUENCE {
	 *		entry	DistinguishedName,
	 *		newrdn	RelativeDistinguishedName
	 *		deleteoldrdn	BOOLEAN,
	 *		newSuperior	[0] LDAPDN OPTIONAL (v3 Only!)
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{mmb", &dn, &newrdn, &deloldrdn )
	    == LBER_ERROR )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_modrdn: ber_scanf failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
#endif

		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	/* Check for newSuperior parameter, if present scan it */

	if ( ber_peek_tag( op->o_ber, &length ) == LDAP_TAG_NEWSUPERIOR ) {
		if ( op->o_protocol < LDAP_VERSION3 ) {
			/* Conection record indicates v2 but field 
			 * newSuperior is present: report error.
			 */
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"do_modrdn: (v2) invalid field newSuperior.\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
			    "modrdn(v2): invalid field newSuperior!\n",
			    0, 0, 0 );
#endif

			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "newSuperior requires LDAPv3" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}

		if ( ber_scanf( op->o_ber, "m", &newSuperior ) 
		     == LBER_ERROR ) {

#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
				"do_modrdn: ber_scanf(\"m\") failed\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "ber_scanf(\"m\") failed\n",
				0, 0, 0 );
#endif

			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}
		pnewS = &pnewSuperior;
		nnewS = &nnewSuperior;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, 
		"do_modrdn: dn (%s) newrdn (%s) newsuperior(%s)\n",
		dn.bv_val, newrdn.bv_val,
		newSuperior.bv_len ? newSuperior.bv_val : "" );
#else
	Debug( LDAP_DEBUG_ARGS,
	    "do_modrdn: dn (%s) newrdn (%s) newsuperior (%s)\n",
		dn.bv_val, newrdn.bv_val,
		newSuperior.bv_len ? newSuperior.bv_val : "" );
#endif

	if ( ber_scanf( op->o_ber, /*{*/ "}") == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_modrdn: ber_scanf failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: ber_scanf failed\n", 0, 0, 0 );
#endif

		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_modrdn: get_ctrls failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: get_ctrls failed\n", 0, 0, 0 );
#endif

		/* get_ctrls has sent results.	Now clean up. */
		goto cleanup;
	} 

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_modrdn: conn %d  invalid dn (%s)\n",
			conn->c_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_modrdn: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	if( ndn.bv_len == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_modrdn:  attempt to modify root DSE.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: root dse!\n", 0, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "cannot rename the root DSE", NULL, NULL );
		goto cleanup;

	} else if ( bvmatch( &ndn, &global_schemandn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_modrdn: attempt to modify subschema subentry: %s (%ld)\n",
			global_schemandn.bv_val, (long) global_schemandn.bv_len, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: subschema subentry: %s (%ld)\n",
			global_schemandn.bv_val, (long) global_schemandn.bv_len, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "cannot rename subschema subentry", NULL, NULL );
		goto cleanup;
	}

	/* FIXME: should have/use rdnPretty / rdnNormalize routines */

	rc = dnPrettyNormal( NULL, &newrdn, &pnewrdn, &nnewrdn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_modrdn: conn %d  invalid newrdn (%s)\n",
			conn->c_connid, newrdn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_modrdn: invalid newrdn (%s)\n", newrdn.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid new RDN", NULL, NULL );
		goto cleanup;
	}

	if( rdnValidate( &pnewrdn ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_modrdn: invalid rdn (%s).\n", pnewrdn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: invalid rdn (%s)\n",
			pnewrdn.bv_val, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid new RDN", NULL, NULL );
		goto cleanup;
	}

	if( pnewS ) {
		rc = dnPrettyNormal( NULL, &newSuperior, &pnewSuperior,
			&nnewSuperior );
		if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				"do_modrdn: conn %d  invalid newSuperior (%s)\n",
				conn->c_connid, newSuperior.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"do_modrdn: invalid newSuperior (%s)\n",
				newSuperior.bv_val, 0, 0 );
#endif
			send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
				"invalid newSuperior", NULL, NULL );
			goto cleanup;
		}
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu MODRDN dn=\"%s\"\n",
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

	/* Make sure that the entry being changed and the newSuperior are in 
	 * the same backend, otherwise we return an error.
	 */
	if( pnewS ) {
		newSuperior_be = select_backend( &nnewSuperior, 0, 0 );

		if ( newSuperior_be != be ) {
			/* newSuperior is in same backend */
			rc = LDAP_AFFECTS_MULTIPLE_DSAS;

			send_ldap_result( conn, op, rc,
				NULL, "cannot rename between DSAa", NULL, NULL );

			goto cleanup;
		}
	}

#if defined( LDAP_SLAPI )
	slapi_x_backend_set_pb( pb, be );
	slapi_x_connection_set_pb( pb, conn );
	slapi_x_operation_set_pb( pb, op );
	slapi_pblock_set( pb, SLAPI_MODRDN_TARGET, (void *)dn.bv_val );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWRDN, (void *)newrdn.bv_val );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWSUPERIOR,
			(void *)newSuperior.bv_val );
	slapi_pblock_set( pb, SLAPI_MODRDN_DELOLDRDN, (void *)deloldrdn );
	slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );

	rc = doPluginFNs( be, SLAPI_PLUGIN_PRE_MODRDN_FN, pb );
	if ( rc != 0 ) {
		/*
		 * A preoperation plugin failure will abort the
		 * entire operation.
		 */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_modrdn: modrdn preoperation plugin "
				"failed\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE, "do_modrdn: modrdn preoperation plugin "
				"failed.\n", 0, 0, 0);
#endif
		if ( slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void *)&rc ) != 0)
			rc = LDAP_OTHER;
		goto cleanup;
	}
#endif /* defined( LDAP_SLAPI ) */

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modrdn ) {
		/* do the update here */
		int repl_user = be_isupdate( be, &op->o_ndn );
#ifndef SLAPD_MULTIMASTER
		if ( !be->be_update_ndn.bv_len || repl_user )
#endif
		{
			if ( (*be->be_modrdn)( be, conn, op, &pdn, &ndn,
				&pnewrdn, &nnewrdn, deloldrdn,
				pnewS, nnewS ) == 0
#ifdef SLAPD_MULTIMASTER
				&& ( !be->be_update_ndn.bv_len || !repl_user )
#endif
			) {
				struct slap_replog_moddn moddn;
				moddn.newrdn = &pnewrdn;
				moddn.deloldrdn = deloldrdn;
				moddn.newsup = &pnewSuperior;

				replog( be, op, &pdn, &ndn, &moddn );
			}
#ifndef SLAPD_MULTIMASTER
		} else {
			BerVarray defref = be->be_update_refs
				? be->be_update_refs : default_referral;
			BerVarray ref = referral_rewrite( defref,
				NULL, &pdn, LDAP_SCOPE_DEFAULT );

			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				ref ? ref : defref, NULL );

			ber_bvarray_free( ref );
#endif
		}
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext",
			NULL, NULL );
	}

#if defined( LDAP_SLAPI )
	if ( doPluginFNs( be, SLAPI_PLUGIN_POST_MODRDN_FN, pb ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_modrdn: modrdn postoperation plugins "
				"failed\n", 0, 0, 0 );
#else
		Debug(LDAP_DEBUG_TRACE, "do_modrdn: modrdn postoperation plugins "
				"failed.\n", 0, 0, 0);
#endif
	}
#endif /* defined( LDAP_SLAPI ) */

cleanup:
	free( pdn.bv_val );
	free( ndn.bv_val );

	free( pnewrdn.bv_val );	
	free( nnewrdn.bv_val );	

	if ( pnewSuperior.bv_val ) free( pnewSuperior.bv_val );
	if ( nnewSuperior.bv_val ) free( nnewSuperior.bv_val );

	return rc;
}

int
slap_modrdn2mods(
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*e,
	LDAPRDN		*old_rdn,
	LDAPRDN		*new_rdn,
	int		deleteoldrdn,
	Modifications	**pmod )
{
	int		rc = LDAP_SUCCESS;
	const char	*text;
	Modifications	*mod = NULL;
	int		a_cnt, d_cnt;

	assert( new_rdn != NULL );
	assert( !deleteoldrdn || old_rdn != NULL );

	/* Add new attribute values to the entry */
	for ( a_cnt = 0; new_rdn[0][a_cnt]; a_cnt++ ) {
		AttributeDescription	*desc = NULL;
		Modifications 		*mod_tmp;

		rc = slap_bv2ad( &new_rdn[0][a_cnt]->la_attr, &desc, &text );

		if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"slap_modrdn2modlist: %s: %s (new)\n", 
				text, 
				new_rdn[ 0 ][ a_cnt ]->la_attr.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"slap_modrdn2modlist: %s: %s (new)\n",
				text, 
				new_rdn[ 0 ][ a_cnt ]->la_attr.bv_val, 0 );
#endif
			goto done;		
		}

		/* ACL check of newly added attrs */
		if ( be && !access_allowed( be, conn, op, e, desc,
			&new_rdn[0][a_cnt]->la_value, ACL_WRITE, NULL ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"slap_modrdn2modlist: access to attr \"%s\" "
				"(new) not allowed\n", 
				new_rdn[0][a_cnt]->la_attr.bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"slap_modrdn2modlist: access to attr \"%s\" "
				"(new) not allowed\n", 
				new_rdn[0][ a_cnt ]->la_attr.bv_val, 0, 0 );
#endif
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto done;
		}

		/* Apply modification */
#ifdef SLAP_NVALUES
		mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
			+ 4 * sizeof( struct berval ) );
#else
		mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
			+ 2 * sizeof( struct berval ) );
#endif
		mod_tmp->sml_desc = desc;
		mod_tmp->sml_values = ( BerVarray )( mod_tmp + 1 );
		mod_tmp->sml_values[0] = new_rdn[0][a_cnt]->la_value;
		mod_tmp->sml_values[1].bv_val = NULL;
#ifdef SLAP_NVALUES
		if( desc->ad_type->sat_equality->smr_normalize) {
			mod_tmp->sml_nvalues = &mod_tmp->sml_values[2];
			(void) (*desc->ad_type->sat_equality->smr_normalize)(
				SLAP_MR_EQUALITY,
				desc->ad_type->sat_syntax,
				desc->ad_type->sat_equality,
				&mod_tmp->sml_values[0],
				&mod_tmp->sml_nvalues[0] );
			mod_tmp->sml_nvalues[1].bv_val = NULL;
		} else {
			mod_tmp->sml_nvalues = NULL;
		}
#endif
		mod_tmp->sml_op = SLAP_MOD_SOFTADD;
		mod_tmp->sml_next = mod;
		mod = mod_tmp;
	}

	/* Remove old rdn value if required */
	if ( deleteoldrdn ) {
		for ( d_cnt = 0; old_rdn[0][d_cnt]; d_cnt++ ) {
			AttributeDescription	*desc = NULL;
			Modifications 		*mod_tmp;

			rc = slap_bv2ad( &old_rdn[0][d_cnt]->la_attr, &desc, &text );
			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"slap_modrdn2modlist: %s: %s (old)\n", 
					text, 
					old_rdn[0][d_cnt]->la_attr.bv_val, 
					0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"slap_modrdn2modlist: %s: %s (old)\n",
					text, 
					old_rdn[0][d_cnt]->la_attr.bv_val, 
					0 );
#endif
				goto done;		
			}

			/* ACL check of newly added attrs */
			if ( be && !access_allowed( be, conn, op, e, desc,
				&old_rdn[0][d_cnt]->la_value, ACL_WRITE, 
				NULL ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"slap_modrdn2modlist: access "
					"to attr \"%s\" (old) not allowed\n", 
					old_rdn[ 0 ][ d_cnt ]->la_attr.bv_val, 
					0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"slap_modrdn2modlist: access "
					"to attr \"%s\" (old) not allowed\n", 
					old_rdn[ 0 ][ d_cnt ]->la_attr.bv_val,
					0, 0 );
#endif
				rc = LDAP_INSUFFICIENT_ACCESS;
				goto done;
			}

			/* Apply modification */
#ifdef SLAP_NVALUES
			mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
				+ 2 * sizeof ( struct berval ) );
#else
			mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
				+ 2 * sizeof ( struct berval ) );
#endif
			mod_tmp->sml_desc = desc;
			mod_tmp->sml_values = ( BerVarray )(mod_tmp+1);
			mod_tmp->sml_values[0] = old_rdn[0][d_cnt]->la_value;
			mod_tmp->sml_values[1].bv_val = NULL;
#ifdef SLAP_NVALUES
			if( desc->ad_type->sat_equality->smr_normalize) {
				mod_tmp->sml_nvalues = &mod_tmp->sml_values[2];
				(void) (*desc->ad_type->sat_equality->smr_normalize)(
					SLAP_MR_EQUALITY,
					desc->ad_type->sat_syntax,
					desc->ad_type->sat_equality,
					&mod_tmp->sml_values[0],
					&mod_tmp->sml_nvalues[0] );
				mod_tmp->sml_nvalues[1].bv_val = NULL;
			} else {
				mod_tmp->sml_nvalues = NULL;
			}
#endif
			mod_tmp->sml_op = LDAP_MOD_DELETE;
			mod_tmp->sml_next = mod;
			mod = mod_tmp;
		}
	}
	
done:
	/* LDAP v2 supporting correct attribute handling. */
	if ( rc != LDAP_SUCCESS && mod != NULL ) {
		Modifications *tmp;
		for ( ; mod; mod = tmp ) {
			tmp = mod->sml_next;
			ch_free( mod );
		}
	}

	*pmod = mod;

	return rc;
}
