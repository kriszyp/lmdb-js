/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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
/* Portions Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
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

#include <ac/socket.h>
#include <ac/string.h>

#include "ldap_pvt.h"
#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi.h"
#endif

int
do_modrdn(
    Operation	*op,
    SlapReply	*rs
)
{
	struct berval dn = { 0, NULL };
	struct berval newrdn = { 0, NULL };
	struct berval newSuperior = { 0, NULL };
	ber_int_t	deloldrdn;

	struct berval pnewSuperior = { 0, NULL };

	struct berval nnewSuperior = { 0, NULL };

	Backend	*newSuperior_be = NULL;
	ber_len_t	length;
	int manageDSAit;

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

		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
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

			send_ldap_discon( op, rs,
				LDAP_PROTOCOL_ERROR, "newSuperior requires LDAPv3" );
			rs->sr_err = SLAPD_DISCONNECT;
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

			send_ldap_discon( op, rs,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rs->sr_err = SLAPD_DISCONNECT;
			goto cleanup;
		}
		op->orr_newSup = &pnewSuperior;
		op->orr_nnewSup = &nnewSuperior;
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

		send_ldap_discon( op, rs,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_modrdn: get_ctrls failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: get_ctrls failed\n", 0, 0, 0 );
#endif

		/* get_ctrls has sent results.	Now clean up. */
		goto cleanup;
	} 

	rs->sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn, op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_modrdn: conn %d  invalid dn (%s)\n",
			op->o_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_modrdn: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto cleanup;
	}

	if( op->o_req_ndn.bv_len == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_modrdn:  attempt to modify root DSE.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: root dse!\n", 0, 0, 0 );
#endif

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"cannot rename the root DSE" );
		goto cleanup;

	} else if ( bvmatch( &op->o_req_ndn, &global_schemandn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_modrdn: attempt to modify subschema subentry: %s (%ld)\n",
			global_schemandn.bv_val, (long) global_schemandn.bv_len, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: subschema subentry: %s (%ld)\n",
			global_schemandn.bv_val, (long) global_schemandn.bv_len, 0 );
#endif

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"cannot rename subschema subentry" );
		goto cleanup;
	}

	/* FIXME: should have/use rdnPretty / rdnNormalize routines */

	rs->sr_err = dnPrettyNormal( NULL, &newrdn, &op->orr_newrdn, &op->orr_nnewrdn, op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_modrdn: conn %d  invalid newrdn (%s)\n",
			op->o_connid, newrdn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_modrdn: invalid newrdn (%s)\n", newrdn.bv_val, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid new RDN" );
		goto cleanup;
	}

	if( rdnValidate( &op->orr_newrdn ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_modrdn: invalid rdn (%s).\n", op->orr_newrdn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: invalid rdn (%s)\n",
			op->orr_newrdn.bv_val, 0, 0 );
#endif

		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid new RDN" );
		goto cleanup;
	}

	if( op->orr_newSup ) {
		rs->sr_err = dnPrettyNormal( NULL, &newSuperior, &pnewSuperior,
			&nnewSuperior, op->o_tmpmemctx );
		if( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				"do_modrdn: conn %d  invalid newSuperior (%s)\n",
				op->o_connid, newSuperior.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"do_modrdn: invalid newSuperior (%s)\n",
				newSuperior.bv_val, 0, 0 );
#endif
			send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid newSuperior" );
			goto cleanup;
		}
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu MODRDN dn=\"%s\"\n",
	    op->o_connid, op->o_opid, op->o_req_dn.bv_val, 0, 0 );

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (op->o_bd = select_backend( &op->o_req_ndn, manageDSAit, 0 )) == NULL ) {
		rs->sr_ref = referral_rewrite( default_referral,
			NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		if (!rs->sr_ref) rs->sr_ref = default_referral;

		if ( rs->sr_ref != NULL ) {
			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			if (rs->sr_ref != default_referral) ber_bvarray_free( rs->sr_ref );
		} else {
			send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
					"referral missing" );
		}
		goto cleanup;
	}

	/* check restrictions */
	if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto cleanup;
	}

	/* check for referrals */
	if ( backend_check_referrals( op, rs ) != LDAP_SUCCESS ) {
		goto cleanup;
	}

	/* Make sure that the entry being changed and the newSuperior are in 
	 * the same backend, otherwise we return an error.
	 */
	if( op->orr_newSup ) {
		newSuperior_be = select_backend( &nnewSuperior, 0, 0 );

		if ( newSuperior_be != op->o_bd ) {
			/* newSuperior is in different backend */
			send_ldap_error( op, rs, LDAP_AFFECTS_MULTIPLE_DSAS,
				"cannot rename between DSAs" );

			goto cleanup;
		}
	}

#if defined( LDAP_SLAPI )
#define	pb	op->o_pb
	if ( pb ) {
		slapi_int_pblock_set_operation( pb, op );
		slapi_pblock_set( pb, SLAPI_MODRDN_TARGET, (void *)dn.bv_val );
		slapi_pblock_set( pb, SLAPI_MODRDN_NEWRDN, (void *)newrdn.bv_val );
		slapi_pblock_set( pb, SLAPI_MODRDN_NEWSUPERIOR,
				(void *)newSuperior.bv_val );
		slapi_pblock_set( pb, SLAPI_MODRDN_DELOLDRDN, (void *)deloldrdn );
		slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );

		rs->sr_err = doPluginFNs( op->o_bd, SLAPI_PLUGIN_PRE_MODRDN_FN, pb );
		if ( rs->sr_err < 0 ) {
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
			if ( ( slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void *)&rs->sr_err ) != 0 ) ||
				 rs->sr_err == LDAP_SUCCESS ) {
				rs->sr_err = LDAP_OTHER;
			}
			goto cleanup;
		}
	}
#endif /* defined( LDAP_SLAPI ) */

	/*
	 * do the modrdn if 1 && (2 || 3)
	 * 1) there is a modrdn function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( op->o_bd->be_modrdn ) {
		/* do the update here */
		int repl_user = be_isupdate( op->o_bd, &op->o_ndn );
#ifndef SLAPD_MULTIMASTER
		if ( LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo ) &&
			( !op->o_bd->be_update_ndn.bv_len || repl_user ))
#else
		if ( LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo ))
#endif
		{
			op->orr_deleteoldrdn = deloldrdn;
			if ( (op->o_bd->be_modrdn)( op, rs ) == 0
#ifdef SLAPD_MULTIMASTER
				&& ( !op->o_bd->be_update_ndn.bv_len || !repl_user )
#endif
			) {
				replog( op );
			}
#ifndef SLAPD_MULTIMASTER
		} else {
			BerVarray defref = NULL;
			if ( !LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
				syncinfo_t *si;
				LDAP_STAILQ_FOREACH( si, &op->o_bd->be_syncinfo, si_next ) {
					struct berval tmpbv;
					ber_dupbv( &tmpbv, &si->si_provideruri_bv[0] );
					ber_bvarray_add( &defref, &tmpbv );
				}
			} else {
				defref = op->o_bd->be_update_refs
					? op->o_bd->be_update_refs : default_referral;
			}
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
					"referral missing" );
			}
#endif
		}
	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within namingContext" );
	}

#if defined( LDAP_SLAPI )
	if ( pb && doPluginFNs( op->o_bd, SLAPI_PLUGIN_POST_MODRDN_FN, pb ) < 0 ) {
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

	slap_graduate_commit_csn( op );

	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );

	op->o_tmpfree( op->orr_newrdn.bv_val, op->o_tmpmemctx );	
	op->o_tmpfree( op->orr_nnewrdn.bv_val, op->o_tmpmemctx );	

	if ( pnewSuperior.bv_val ) op->o_tmpfree( pnewSuperior.bv_val, op->o_tmpmemctx );
	if ( nnewSuperior.bv_val ) op->o_tmpfree( nnewSuperior.bv_val, op->o_tmpmemctx );

	return rs->sr_err;
}

int
slap_modrdn2mods(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	LDAPRDN		old_rdn,
	LDAPRDN		new_rdn,
	Modifications	**pmod )
{
	Modifications	*mod = NULL;
	Modifications	**modtail = &mod;
	int		a_cnt, d_cnt;
	int repl_user;

	assert( new_rdn != NULL );
	assert( !op->orr_deleteoldrdn || old_rdn != NULL );

	repl_user = be_isupdate( op->o_bd, &op->o_ndn );

	/* Add new attribute values to the entry */
	for ( a_cnt = 0; new_rdn[a_cnt]; a_cnt++ ) {
		AttributeDescription	*desc = NULL;
		Modifications 		*mod_tmp;

		rs->sr_err = slap_bv2ad( &new_rdn[a_cnt]->la_attr, &desc, &rs->sr_text );

		if ( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"slap_modrdn2modlist: %s: %s (new)\n", 
				rs->sr_text, 
				new_rdn[ a_cnt ]->la_attr.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"slap_modrdn2modlist: %s: %s (new)\n",
				rs->sr_text, 
				new_rdn[ a_cnt ]->la_attr.bv_val, 0 );
#endif
			goto done;		
		}

		/* ACL check of newly added attrs */
		if ( op->o_bd && !access_allowed( op, e, desc,
			&new_rdn[a_cnt]->la_value, ACL_WRITE, NULL ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"slap_modrdn2modlist: access to attr \"%s\" "
				"(new) not allowed\n", 
				new_rdn[a_cnt]->la_attr.bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"slap_modrdn2modlist: access to attr \"%s\" "
				"(new) not allowed\n", 
				new_rdn[ a_cnt ]->la_attr.bv_val, 0, 0 );
#endif
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			goto done;
		}

		/* Apply modification */
		mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
			+ 4 * sizeof( struct berval ) );
		mod_tmp->sml_desc = desc;
		mod_tmp->sml_values = ( BerVarray )( mod_tmp + 1 );
		mod_tmp->sml_values[0] = new_rdn[a_cnt]->la_value;
		mod_tmp->sml_values[1].bv_val = NULL;
		if( desc->ad_type->sat_equality->smr_normalize) {
			mod_tmp->sml_nvalues = &mod_tmp->sml_values[2];
			(void) (*desc->ad_type->sat_equality->smr_normalize)(
				SLAP_MR_EQUALITY|SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
				desc->ad_type->sat_syntax,
				desc->ad_type->sat_equality,
				&mod_tmp->sml_values[0],
				&mod_tmp->sml_nvalues[0], op->o_tmpmemctx );
			mod_tmp->sml_nvalues[1].bv_val = NULL;
		} else {
			mod_tmp->sml_nvalues = NULL;
		}
		mod_tmp->sml_op = SLAP_MOD_SOFTADD;
		mod_tmp->sml_next = mod;
		mod = mod_tmp;
	}

	/* Remove old rdn value if required */
	if ( op->orr_deleteoldrdn ) {
		for ( d_cnt = 0; old_rdn[d_cnt]; d_cnt++ ) {
			AttributeDescription	*desc = NULL;
			Modifications 		*mod_tmp;

			rs->sr_err = slap_bv2ad( &old_rdn[d_cnt]->la_attr, &desc, &rs->sr_text );
			if ( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"slap_modrdn2modlist: %s: %s (old)\n", 
					rs->sr_text, 
					old_rdn[d_cnt]->la_attr.bv_val, 
					0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"slap_modrdn2modlist: %s: %s (old)\n",
					rs->sr_text, 
					old_rdn[d_cnt]->la_attr.bv_val, 
					0 );
#endif
				goto done;		
			}

			/* ACL check of newly added attrs */
			if ( op->o_bd && !access_allowed( op, e, desc,
				&old_rdn[d_cnt]->la_value, ACL_WRITE, 
				NULL ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, ERR, 
					"slap_modrdn2modlist: access "
					"to attr \"%s\" (old) not allowed\n", 
					old_rdn[ d_cnt ]->la_attr.bv_val, 
					0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"slap_modrdn2modlist: access "
					"to attr \"%s\" (old) not allowed\n", 
					old_rdn[ d_cnt ]->la_attr.bv_val,
					0, 0 );
#endif
				rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
				goto done;
			}

			/* Apply modification */
			mod_tmp = ( Modifications * )ch_malloc( sizeof( Modifications )
				+ 4 * sizeof ( struct berval ) );
			mod_tmp->sml_desc = desc;
			mod_tmp->sml_values = ( BerVarray )(mod_tmp+1);
			mod_tmp->sml_values[0] = old_rdn[d_cnt]->la_value;
			mod_tmp->sml_values[1].bv_val = NULL;
			if( desc->ad_type->sat_equality->smr_normalize) {
				mod_tmp->sml_nvalues = &mod_tmp->sml_values[2];
				(void) (*desc->ad_type->sat_equality->smr_normalize)(
					SLAP_MR_EQUALITY|SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
					desc->ad_type->sat_syntax,
					desc->ad_type->sat_equality,
					&mod_tmp->sml_values[0],
					&mod_tmp->sml_nvalues[0], op->o_tmpmemctx );
				mod_tmp->sml_nvalues[1].bv_val = NULL;
			} else {
				mod_tmp->sml_nvalues = NULL;
			}
			mod_tmp->sml_op = LDAP_MOD_DELETE;
			mod_tmp->sml_next = mod;
			mod = mod_tmp;
		}
	}
	
done:

	if ( !repl_user ) {
		char textbuf[ SLAP_TEXT_BUFLEN ];
		size_t textlen = sizeof textbuf;

		for( modtail = &mod;
			*modtail != NULL;
			modtail = &(*modtail)->sml_next )
		{
			/* empty */
		}

		rs->sr_err = slap_mods_opattrs( op, mod, modtail, &rs->sr_text, textbuf, textlen );
	}

	/* LDAP v2 supporting correct attribute handling. */
	if ( rs->sr_err != LDAP_SUCCESS && mod != NULL ) {
		Modifications *tmp;
		for ( ; mod; mod = tmp ) {
			tmp = mod->sml_next;
			ch_free( mod );
		}
	}

	*pmod = mod;

	return rs->sr_err;
}
