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
#include <ac/socket.h>
#include <ac/string.h>

#include "ldap_pvt.h"
#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

static int compare_entry(
	Operation *op,
	Entry *e,
	AttributeAssertion *ava );

int
do_compare(
    Operation	*op,
    SlapReply	*rs )
{
	struct berval dn = BER_BVNULL;
	struct berval desc = BER_BVNULL;
	struct berval value = BER_BVNULL;
	AttributeAssertion ava = { NULL, BER_BVNULL };

	ava.aa_desc = NULL;

	Debug( LDAP_DEBUG_TRACE, "do_compare\n", 0, 0, 0 );
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
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if ( ber_scanf( op->o_ber, "{mm}", &desc, &value ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: get ava failed\n", 0, 0, 0 );
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if ( ber_scanf( op->o_ber, /*{*/ "}" ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: get_ctrls failed\n", 0, 0, 0 );
		goto cleanup;
	} 

	rs->sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn,
		op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"do_compare: invalid dn (%s)\n", dn.bv_val, 0, 0 );
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto cleanup;
	}

	rs->sr_err = slap_bv2ad( &desc, &ava.aa_desc, &rs->sr_text );
	if( rs->sr_err != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto cleanup;
	}

	rs->sr_err = asserted_value_validate_normalize( ava.aa_desc,
		ava.aa_desc->ad_type->sat_equality,
		SLAP_MR_EQUALITY|SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
		&value, &ava.aa_value, &rs->sr_text, op->o_tmpmemctx );
	if( rs->sr_err != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto cleanup;
	}

	op->orc_ava = &ava;

	op->o_bd = frontendDB;
	rs->sr_err = frontendDB->be_compare( op, rs );

cleanup:;
	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );
	if ( ava.aa_value.bv_val ) {
		op->o_tmpfree( ava.aa_value.bv_val, op->o_tmpmemctx );
	}

	return rs->sr_err;
}

int
fe_op_compare( Operation *op, SlapReply *rs )
{
	Entry *entry = NULL;
	int manageDSAit;
	AttributeAssertion ava = *op->orc_ava;

	if( strcasecmp( op->o_req_ndn.bv_val, LDAP_ROOT_DSE ) == 0 ) {
		Debug( LDAP_DEBUG_ARGS,
			"do_compare: dn (%s) attr (%s) value (%s)\n",
			op->o_req_dn.bv_val,
			ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );

		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu CMP dn=\"%s\" attr=\"%s\"\n",
			op->o_connid, op->o_opid, op->o_req_dn.bv_val,
			ava.aa_desc->ad_cname.bv_val, 0 );

		if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
			goto cleanup;
		}

		rs->sr_err = root_dse_info( op->o_conn, &entry, &rs->sr_text );
		if( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
			goto cleanup;
		}

	} else if ( bvmatch( &op->o_req_ndn, &frontendDB->be_schemandn ) ) {
		Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
			op->o_req_dn.bv_val,
			ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );

		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu CMP dn=\"%s\" attr=\"%s\"\n",
			op->o_connid, op->o_opid, op->o_req_dn.bv_val,
			ava.aa_desc->ad_cname.bv_val, 0 );

		if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
			rs->sr_err = 0;
			goto cleanup;
		}

		rs->sr_err = schema_info( &entry, &rs->sr_text );
		if( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
			rs->sr_err = 0;
			goto cleanup;
		}
	}

	if( entry ) {
		rs->sr_err = compare_entry( op, entry, &ava );
		entry_free( entry );

		send_ldap_result( op, rs );

		if( rs->sr_err == LDAP_COMPARE_TRUE ||
			rs->sr_err == LDAP_COMPARE_FALSE )
		{
			rs->sr_err = LDAP_SUCCESS;
		}

		goto cleanup;
	}

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

		rs->sr_err = LDAP_REFERRAL;
		if (!rs->sr_ref) rs->sr_ref = default_referral;
		send_ldap_result( op, rs );

		if (rs->sr_ref != default_referral) ber_bvarray_free( rs->sr_ref );
		rs->sr_err = 0;
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

	Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
	    op->o_req_dn.bv_val,
		ava.aa_desc->ad_cname.bv_val, ava.aa_value.bv_val );

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu CMP dn=\"%s\" attr=\"%s\"\n",
	    op->o_connid, op->o_opid, op->o_req_dn.bv_val,
		ava.aa_desc->ad_cname.bv_val, 0 );

#if defined( LDAP_SLAPI )
#define	pb	op->o_pb
	if ( pb ) {
		slapi_int_pblock_set_operation( pb, op );
		slapi_pblock_set( pb, SLAPI_COMPARE_TARGET, (void *)op->o_req_dn.bv_val );
		slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)manageDSAit );
		slapi_pblock_set( pb, SLAPI_COMPARE_TYPE, (void *)ava.aa_desc->ad_cname.bv_val );
		slapi_pblock_set( pb, SLAPI_COMPARE_VALUE, (void *)&ava.aa_value );

		rs->sr_err = slapi_int_call_plugins( op->o_bd,
			SLAPI_PLUGIN_PRE_COMPARE_FN, pb );
		if ( rs->sr_err < 0 ) {
			/*
			 * A preoperation plugin failure will abort the
			 * entire operation.
			 */
			Debug(LDAP_DEBUG_TRACE,
				"do_compare: compare preoperation plugin failed\n",
				0, 0, 0);
			if ( ( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE,
				(void *)&rs->sr_err ) != 0 ) || rs->sr_err == LDAP_SUCCESS )
			{
				rs->sr_err = LDAP_OTHER;
			}
			goto cleanup;
		}
	}
#endif /* defined( LDAP_SLAPI ) */

	op->orc_ava = &ava;
	if ( ava.aa_desc == slap_schema.si_ad_entryDN ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"entryDN compare not supported" );

	} else if ( ava.aa_desc == slap_schema.si_ad_subschemaSubentry ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"subschemaSubentry compare not supported" );

	} else if ( ava.aa_desc == slap_schema.si_ad_hasSubordinates
		&& op->o_bd->be_has_subordinates )
	{
		int	rc, hasSubordinates = LDAP_SUCCESS;

		rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &entry );
		if ( rc == 0 && entry ) {
			rc = op->o_bd->be_has_subordinates( op, entry,
				&hasSubordinates );
			be_entry_release_r( op, entry );
		}

		if ( rc == 0 ) {
			int	asserted;

			asserted = bvmatch( &ava.aa_value, &slap_true_bv )
				? LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE;
			if ( hasSubordinates == asserted ) {
				rs->sr_err = LDAP_COMPARE_TRUE;
			} else {
				rs->sr_err = LDAP_COMPARE_FALSE;
			}
		}
		send_ldap_result( op, rs );

		if( rc == 0 ) rs->sr_err = LDAP_SUCCESS;

	} else if ( op->o_bd->be_compare ) {
		op->o_bd->be_compare( op, rs );

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within namingContext" );
	}

#if defined( LDAP_SLAPI )
	if ( pb != NULL && slapi_int_call_plugins( op->o_bd,
		SLAPI_PLUGIN_POST_COMPARE_FN, pb ) < 0 )
	{
		Debug(LDAP_DEBUG_TRACE,
			"do_compare: compare postoperation plugins failed\n", 0, 0, 0 );
	}
#endif /* defined( LDAP_SLAPI ) */

cleanup:;
	return rs->sr_err;
}

static int compare_entry(
	Operation *op,
	Entry *e,
	AttributeAssertion *ava )
{
	int rc = LDAP_NO_SUCH_ATTRIBUTE;
	Attribute *a;

	if ( ! access_allowed( op, e,
		ava->aa_desc, &ava->aa_value, ACL_COMPARE, NULL ) )
	{	
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for(a = attrs_find( e->e_attrs, ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, ava->aa_desc ))
	{
		rc = LDAP_COMPARE_FALSE;

		if ( value_find_ex( ava->aa_desc,
			SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
				SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
			a->a_nvals,
			&ava->aa_value, op->o_tmpmemctx ) == 0 )
		{
			rc = LDAP_COMPARE_TRUE;
			break;
		}
	}

	return rc;
}
