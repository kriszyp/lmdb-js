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

#include "portable.h"

#include <stdio.h>
#include <ac/socket.h>

#include "slap.h"

#ifdef HAVE_TLS

int
starttls_extop (
	SLAP_EXTOP_CALLBACK_FN cb,
	Connection *conn,
	Operation *op,
	char * oid,
	struct berval * reqdata,
	struct berval ** rspdata,
	LDAPControl ***rspctrls,
	char ** text )
{
	void *ctx;

	if ( reqdata != NULL ) {
		/* no request data should be provided */
		return LDAP_PROTOCOL_ERROR;
	}

	/* can't start TLS if it is already started */
	if (conn->c_is_tls != 0)
		return(LDAP_OPERATIONS_ERROR);

	/* fail if TLS could not be initialized */
	if (ldap_pvt_tls_get_option(NULL, LDAP_OPT_X_TLS_CERT, &ctx) != 0
		|| ctx == NULL)
	{
		if (default_referral != NULL) {
			/* caller will put the referral into the result */
			return(LDAP_REFERRAL);
		}
		return(LDAP_UNAVAILABLE);
	}

	/* can't start TLS if there are other op's around */
	if (conn->c_ops != NULL) {
		if (conn->c_ops != op || op->o_next != NULL)
			return(LDAP_OPERATIONS_ERROR);
	}
	if (conn->c_pending_ops != NULL) {
		if (conn->c_pending_ops != op || op->o_next != NULL)
			return(LDAP_OPERATIONS_ERROR);
	}

    conn->c_is_tls = 1;
    conn->c_needs_tls_accept = 1;

    return(LDAP_SUCCESS);
}

#endif	/* HAVE_TLS */
