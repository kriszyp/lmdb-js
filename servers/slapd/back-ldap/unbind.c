/* unbind.c - ldap backend unbind function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.
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
	struct ldapconn *lc, lc_curr;

	Debug( LDAP_DEBUG_TRACE,
		"=>ldap_back_conn_destroy: fetching conn %d\n",
		conn->c_connid, 0, 0 );
	

	lc_curr.conn = conn;
	
	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	lc = avl_delete( &li->conntree, (caddr_t)&lc_curr, conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	if (lc) {
		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_conn_destroy: destroying conn %d\n",
			lc->conn->c_connid, 0, 0 );
		
		/*
		 * Needs a test because the handler may be corrupted,
		 * and calling ldap_unbind on a corrupted header results
		 * in a segmentation fault
		 */
		ldap_unbind(lc->ld);
		if ( lc->bound_dn ) {
			free( lc->bound_dn );
		}
		free( lc );
	}

	/* no response to unbind */

	return 0;
}
