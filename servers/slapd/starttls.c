/* $OpenLDAP$ */
/* 
 * Copyright 1999-2000 The OpenLDAP Foundation.
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
	Connection *conn,
	Operation *op,
	const char * reqoid,
	struct berval * reqdata,
	char ** rspoid,
	struct berval ** rspdata,
	LDAPControl ***rspctrls,
	const char ** text,
	struct berval *** refs )
{
	void *ctx;
	int rc;

	if ( reqdata != NULL ) {
		/* no request data should be provided */
		*text = "no request data expected";
		return LDAP_PROTOCOL_ERROR;
	}

	/* acquire connection lock */
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	/* can't start TLS if it is already started */
	if (conn->c_is_tls != 0) {
		*text = "TLS already started";
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	/* fail if TLS could not be initialized */
	if (ldap_pvt_tls_get_option(NULL, LDAP_OPT_X_TLS_CERT, &ctx) != 0
		|| ctx == NULL)
	{
		if (default_referral != NULL) {
			/* caller will put the referral in the result */
			rc = LDAP_REFERRAL;
			goto done;
		}

		*text = "Could not initialize TLS";
		rc = LDAP_UNAVAILABLE;
		goto done;
	}

	/* can't start TLS if there are other op's around */
	if (( conn->c_ops != NULL &&
			(conn->c_ops != op || op->o_next != NULL)) ||
		( conn->c_pending_ops != NULL))
	{
		*text = "cannot start TLS when operations our outstanding";
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}

    conn->c_is_tls = 1;
    conn->c_needs_tls_accept = 1;

    rc = LDAP_SUCCESS;

done:
	/* give up connection lock */
	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	/*
	 * RACE CONDITION: we give up lock before sending result
	 * Should be resolved by reworking connection state, not
	 * by moving send here (so as to ensure proper TLS sequencing)
	 */

	return rc;
}

#endif	/* HAVE_TLS */
