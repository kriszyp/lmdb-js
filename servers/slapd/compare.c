/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

int
do_compare(
    Connection	*conn,
    Operation	*op
)
{
	char	*dn = NULL, *ndn=NULL;
	struct berval desc;
	struct berval value;
	struct berval *nvalue;
	AttributeAssertion ava;
	Backend	*be;
	int rc = LDAP_SUCCESS;
	struct berval **urls = NULL;
	const char *text = NULL;

	ava.aa_desc = NULL;
	desc.bv_val = NULL;
	value.bv_val = NULL;

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

	if ( ber_scanf( op->o_ber, "{a" /*}*/, &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	if ( ber_scanf( op->o_ber, "{oo}", &desc, &value ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: get ava failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if ( ber_scanf( op->o_ber, /*{*/ "}" ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( ( rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: get_ctrls failed\n", 0, 0, 0 );
		goto cleanup;
	} 

	ndn = ch_strdup( dn );

	if( dn_normalize( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_compare: invalid dn (%s)\n", dn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		rc = 1;
		goto cleanup;
	}

	/* make sure this backend recongizes critical controls */
	rc = backend_check_controls( be, conn, op, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto cleanup;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, &urls, &text );
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, urls, NULL );
		ber_bvecfree( urls );
		goto cleanup;
	}

	rc = slap_bv2ad( &desc, &ava.aa_desc, &text );
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc, NULL,
		    text, NULL, NULL );
		goto cleanup;
	}

	if( !ava.aa_desc->ad_type->sat_equality ) {
		/* no equality matching rule */
		send_ldap_result( conn, op, rc = LDAP_INAPPROPRIATE_MATCHING, NULL,
		    "no equality matching rule defined", NULL, NULL );
		goto cleanup;
	}

	rc = value_normalize( ava.aa_desc, SLAP_MR_EQUALITY, &value, &nvalue, &text );

	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc, NULL,
		    text, NULL, NULL );
		goto cleanup;
	}

	ava.aa_value = nvalue;

	Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
	    dn, ava.aa_desc->ad_cname->bv_val, ava.aa_value->bv_val );

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d CMP dn=\"%s\" attr=\"%s\"\n",
	    op->o_connid, op->o_opid, dn, ava.aa_desc->ad_cname->bv_val, 0 );


	/* deref suffix alias if appropriate */
	ndn = suffix_alias( be, ndn );

	if ( be->be_compare ) {
		(*be->be_compare)( be, conn, op, dn, ndn, &ava );
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext", NULL, NULL );
	}

cleanup:
	free( dn );
	free( ndn );
	free( desc.bv_val );
	free( value.bv_val );
	if( ava.aa_desc != NULL ) {
		ad_free( ava.aa_desc, 1 );
	}

	return rc;
}
