/* $OpenLDAP$ */
/* 
 * Copyright 1999 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/*
 * LDAPv3 Extended Operation Request
 *	ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *		requestName      [0] LDAPOID,
 *		requestValue     [1] OCTET STRING OPTIONAL
 *	}
 *
 * LDAPv3 Extended Operation Response
 *	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *		COMPONENTS OF LDAPResult,
 *		responseName     [10] LDAPOID OPTIONAL,
 *		response         [11] OCTET STRING OPTIONAL
 *	}
 *
 */

#include "portable.h"

#include <stdio.h>
#include <ac/socket.h>

#include "slap.h"

char *supportedExtensions[] = {
	NULL
};


int
do_extended(
    Connection	*conn,
    Operation	*op
)
{
	int rc = LDAP_SUCCESS;
	char* reqoid ;
	struct berval reqdata;
	ber_tag_t tag;
	ber_len_t len;

	Debug( LDAP_DEBUG_TRACE, "do_extended\n", 0, 0, 0 );

	reqoid = NULL;
	reqdata.bv_val = NULL;

	if( op->o_protocol < LDAP_VERSION3 ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: protocol version (%d) too low\n",
			op->o_protocol, 0 ,0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "requires LDAPv3" );
		rc = -1;
		goto done;
	}

	if ( ber_scanf( op->o_ber, "a", &reqoid ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto done;
	}

	if( !charray_inlist( supportedExtensions, reqoid ) ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: unsupported operation \"%s\"\n",
			reqoid, 0 ,0 );
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "unsuppored extended operation", NULL, NULL );
		goto done;
	}

	tag = ber_peek_tag( op->o_ber, &len );
	
	if( ber_peek_tag( op->o_ber, &len ) == LDAP_TAG_EXOP_REQ_VALUE ) {
		if( ber_scanf( op->o_ber, "o", &reqdata ) != LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = -1;
			goto done;
		}
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_extended: get_ctrls failed\n", 0, 0 ,0 );
		return rc;
	} 

	Debug( LDAP_DEBUG_ARGS, "do_extended: oid \"%s\"\n", reqoid, 0 ,0 );

	send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
		NULL, "unsupported extended operation", NULL, NULL );

done:
	if ( reqoid != NULL ) {
		free( reqoid );
	}
	if ( reqdata.bv_val != NULL ) {
		free( reqdata.bv_val );
	}

	return rc;
}
