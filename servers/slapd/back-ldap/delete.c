/* delete.c - ldap backend delete function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_delete(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;
	int rc;
	ber_int_t msgid;

	struct berval mdn = { 0, NULL };

	lc = ldap_back_getconn( op, rs );
	
	if ( !lc || !ldap_back_dobind( lc, op, rs ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the request dn, if needed
	 */
#ifdef ENABLE_REWRITE
	switch ( rewrite_session( li->rwinfo, "deleteDn", op->o_req_dn.bv_val, op->o_conn, &mdn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
	if ( mdn.bv_val == NULL ) {
			mdn.bv_val = ( char * )op->o_req_dn.bv_val;
		}
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDAP, DETAIL1, 
		"[rw] deleteDn: \"%s\" -> \"%s\"\n", op->o_req_dn.bv_val, mdn.bv_val, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ARGS, "rw> deleteDn: \"%s\" -> \"%s\"\n%s",
			op->o_req_dn.bv_val, mdn.bv_val, "" );
#endif /* !NEW_LOGGING */
	break;
		
	case REWRITE_REGEXEC_UNWILLING:
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"Operation not allowed" );
		return( -1 );

	case REWRITE_REGEXEC_ERR:
		send_ldap_error( op, rs, LDAP_OTHER,
				"Rewrite error" );
		return( -1 );
	}
#else /* !ENABLE_REWRITE */
	ldap_back_dn_massage( li, &op->o_req_dn, &mdn, 0, 1 );
#endif /* !ENABLE_REWRITE */
	
	rc = ldap_delete_ext( lc->ld, mdn.bv_val, op->o_ctrls, NULL, &msgid );

	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}
	
	return( ldap_back_op_result( li, lc, op, rs, msgid, rc, 1 ) );
}
