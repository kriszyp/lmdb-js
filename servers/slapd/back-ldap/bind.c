/* bind.c - ldap backend bind function */
/* $OpenLDAP$ */

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
		if (ldap_initialize(&ld, li->url) != LDAP_SUCCESS) {
			send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "ldap_init failed", NULL, NULL );
			return( NULL );
		}
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

int
ldap_back_op_result(struct ldapconn *lc, Operation *op)
{
	int err;
	char *msg;
	char *match;

	ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &err);
	ldap_get_option(lc->ld, LDAP_OPT_ERROR_STRING, &msg);
	ldap_get_option(lc->ld, LDAP_OPT_MATCHED_DN, &match);
	send_ldap_result( lc->conn, op, err, match, msg, NULL, NULL );
	free(match);
	free(msg);
	return( (err==LDAP_SUCCESS) ? 0 : -1 );
}
