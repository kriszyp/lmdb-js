/* bind.c - ldap backend bind function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* This is an altered version */
/*
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_bind(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    const char		*dn,
    const char		*ndn,
    int			method,
    struct berval	*cred,
	char		**edn
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;

	*edn = NULL;

	lc = ldap_back_getconn(li, conn, op);
	if (!lc)
		return( -1 );

	if (ldap_bind_s(lc->ld, dn, cred->bv_val, method) != LDAP_SUCCESS)
		return( ldap_back_op_result(lc, op) );

	lc->bound = 1;
	return( 0 );
}

struct ldapconn *
ldap_back_getconn(struct ldapinfo *li, Connection *conn, Operation *op)
{
	struct ldapconn *lc;
	LDAP *ld;

	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	for (lc = li->lcs; lc; lc=lc->next)
		if (lc->conn == conn)
			break;
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	/* Looks like we didn't get a bind. Open a new session... */
	if (!lc) {
		int vers = conn->c_protocol;
		int err = ldap_initialize(&ld, li->url);
		if (err != LDAP_SUCCESS) {
			err = ldap_back_map_result(err);
			send_ldap_result( conn, op, err,
				NULL, "ldap_init failed", NULL, NULL );
			return( NULL );
		}
		/* Set LDAP version. This will always succeed: If the client
		 * bound with a particular version, then so can we.
		 */
		ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &vers);

		lc = (struct ldapconn *)ch_malloc(sizeof(struct ldapconn));
		lc->conn = conn;
		lc->ld = ld;
		lc->bound = 0;
		ldap_pvt_thread_mutex_lock( &li->conn_mutex );
		lc->next = li->lcs;
		li->lcs = lc;
		ldap_pvt_thread_mutex_unlock( &li->conn_mutex );
	}
	return( lc );
}

void
ldap_back_dobind(struct ldapconn *lc, Operation *op)
{
	if (lc->bound)
		return;

	if (ldap_bind_s(lc->ld, lc->conn->c_cdn, NULL, LDAP_AUTH_SIMPLE) !=
		LDAP_SUCCESS)
		ldap_back_op_result(lc, op);
	else
		lc->bound = 1;
}

/* Map API errors to protocol errors... */

int
ldap_back_map_result(int err)
{
	switch(err)
	{
	case LDAP_SERVER_DOWN:
		return LDAP_UNAVAILABLE;
	case LDAP_LOCAL_ERROR:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_ENCODING_ERROR:
	case LDAP_DECODING_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_TIMEOUT:
		return LDAP_UNAVAILABLE;
	case LDAP_AUTH_UNKNOWN:
		return LDAP_AUTH_METHOD_NOT_SUPPORTED;
	case LDAP_FILTER_ERROR:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_USER_CANCELLED:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_PARAM_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_MEMORY:
		return LDAP_OPERATIONS_ERROR;
	case LDAP_CONNECT_ERROR:
		return LDAP_UNAVAILABLE;
	case LDAP_NOT_SUPPORTED:
		return LDAP_UNWILLING_TO_PERFORM;
	case LDAP_CONTROL_NOT_FOUND:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_RESULTS_RETURNED:
		return LDAP_NO_SUCH_OBJECT;
	case LDAP_MORE_RESULTS_TO_RETURN:
		return LDAP_OTHER;
	case LDAP_CLIENT_LOOP:
	case LDAP_REFERRAL_LIMIT_EXCEEDED:
		return LDAP_LOOP_DETECT;
	default:
		if LDAP_API_ERROR(err)
			return LDAP_OTHER;
		else
			return err;
	}
}

int
ldap_back_op_result(struct ldapconn *lc, Operation *op)
{
	int err;
	char *msg;
	char *match;

	ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &err);
	ldap_get_option(lc->ld, LDAP_OPT_ERROR_STRING, &msg);
	ldap_get_option(lc->ld, LDAP_OPT_MATCHED_DN, &match);
	err = ldap_back_map_result(err);
	send_ldap_result( lc->conn, op, err, match, msg, NULL, NULL );
	free(match);
	free(msg);
	return( (err==LDAP_SUCCESS) ? 0 : -1 );
}
