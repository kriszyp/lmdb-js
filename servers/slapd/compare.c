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

#include "slap.h"

extern Backend	*select_backend();

extern char	*default_referral;

void
do_compare(
    Connection	*conn,
    Operation	*op
)
{
	char	*dn;
	Ava	ava;
	int	rc;
	Backend	*be;

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

	if ( ber_scanf( op->o_ber, "{a{ao}}", &dn, &ava.ava_type,
	    &ava.ava_value ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}
	value_normalize( ava.ava_value.bv_val, attr_syntax( ava.ava_type ) );
	dn_normalize( dn );

	Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
	    dn, ava.ava_type, ava.ava_value.bv_val );

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d CMP dn=\"%s\" attr=\"%s\"\n",
	    conn->c_connid, op->o_opid, dn, ava.ava_type, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( dn )) == NULL ) {
		free( dn );
		ava_free( &ava, 0 );

		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
	}

	if ( be->be_compare != NULL ) {
		(*be->be_compare)( be, conn, op, dn, &ava );
	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	free( dn );
	ava_free( &ava, 0 );
}
