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
#include <ac/string.h>

#include "slap.h"

void
do_modrdn(
    Connection	*conn,
    Operation	*op
)
{
	char	*ndn, *newrdn;
	int	deloldrdn;
	Backend	*be;

	Debug( LDAP_DEBUG_TRACE, "do_modrdn\n", 0, 0, 0 );

	/*
	 * Parse the modrdn request.  It looks like this:
	 *
	 *	ModifyRDNRequest := SEQUENCE {
	 *		entry	DistinguishedName,
	 *		newrdn	RelativeDistinguishedName
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{aab}", &ndn, &newrdn, &deloldrdn )
	    == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}

	Debug( LDAP_DEBUG_ARGS,
	    "do_modrdn: dn (%s) newrdn (%s) deloldrdn (%d)\n", ndn, newrdn,
	    deloldrdn );

	dn_normalize_case( ndn );

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d MODRDN dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */

	if ( (be = select_backend( ndn )) == NULL ) {
		free( ndn );
		free( newrdn );
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
	}

	/* alias suffix if approp */
	ndn = suffixAlias( ndn, op, be );

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modrdn ) {
		/* do the update here */
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
		{
			if ( (*be->be_modrdn)( be, conn, op, ndn, newrdn,
			    deloldrdn ) == 0 ) {
				replog( be, LDAP_REQ_MODRDN, ndn, newrdn,
				    deloldrdn );
			}
		} else {
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
			    default_referral );
		}
	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	free( ndn );
	free( newrdn );
}
