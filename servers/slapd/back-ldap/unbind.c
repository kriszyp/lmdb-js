/* unbind.c - ldap backend unbind function */
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
ldap_back_conn_destroy(
    Backend		*be,
    Connection		*conn
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc, *lp;

	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	for (lc = li->lcs, lp = (struct ldapconn *)&li->lcs; lc;
		lp=lc, lc=lc->next)
		if (lc->conn == conn) {
			lp->next = lc->next;
			break;
		}
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	if (lc) {
		ldap_unbind(lc->ld);
		free(lc);
	}

	/* no response to unbind */

	return 0;
}
