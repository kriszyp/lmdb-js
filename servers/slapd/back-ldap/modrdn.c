/* modrdn.c - ldap backend modrdn function */
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

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_modrdn(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval	*dn,
    struct berval	*ndn,
    struct berval	*newrdn,
    struct berval	*nnewrdn,
    int		deleteoldrdn,
    struct berval	*newSuperior,
    struct berval	*nnewSuperior
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	int rc;
	ber_int_t msgid;

	struct berval mdn = { 0, NULL }, mnewSuperior = { 0, NULL };

	lc = ldap_back_getconn( li, conn, op );
	if ( !lc || !ldap_back_dobind(lc, conn, op) ) {
		return( -1 );
	}

	if (newSuperior) {
		int version = LDAP_VERSION3;
		ldap_set_option( lc->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
		
		/*
		 * Rewrite the new superior, if defined and required
	 	 */
#ifdef ENABLE_REWRITE
		switch ( rewrite_session( li->rwinfo, "newSuperiorDn",
					newSuperior->bv_val, conn, &mnewSuperior.bv_val ) ) {
		case REWRITE_REGEXEC_OK:
			if ( mnewSuperior.bv_val == NULL ) {
				mnewSuperior.bv_val = ( char * )newSuperior;
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDAP, DETAIL1, 
				"[rw] newSuperiorDn:" " \"%s\" -> \"%s\"\n",
				newSuperior, mnewSuperior.bv_val, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> newSuperiorDn:"
					" \"%s\" -> \"%s\"\n%s",
					newSuperior->bv_val, mnewSuperior.bv_val, "" );
#endif /* !NEW_LOGGING */
			break;

		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, "Operation not allowed",
					NULL, NULL );
			return( -1 );

		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "Rewrite error",
					NULL, NULL );
			return( -1 );
		}
#else /* !ENABLE_REWRITE */
		ldap_back_dn_massage( li, newSuperior, &mnewSuperior, 0, 1 );
		if ( mnewSuperior.bv_val == NULL ) {
			return( -1 );
		}
#endif /* !ENABLE_REWRITE */
	}

#ifdef ENABLE_REWRITE
	/*
	 * Rewrite the modrdn dn, if required
	 */
	switch ( rewrite_session( li->rwinfo, "modrDn", dn->bv_val, conn, &mdn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mdn.bv_val == NULL ) {
			mdn.bv_val = ( char * )dn->bv_val;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] modrDn: \"%s\" -> \"%s\"\n", dn->bv_val, mdn.bv_val, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> modrDn: \"%s\" -> \"%s\"\n%s",
				dn->bv_val, mdn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
				NULL, "Operation not allowed", NULL, NULL );
		return( -1 );

	case REWRITE_REGEXEC_ERR:
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "Rewrite error", NULL, NULL );
		return( -1 );
	}
#else /* !ENABLE_REWRITE */
	ldap_back_dn_massage( li, dn, &mdn, 0, 1 );
#endif /* !ENABLE_REWRITE */

	rc = ldap_rename( lc->ld, mdn.bv_val, newrdn->bv_val, mnewSuperior.bv_val,
		deleteoldrdn, op->o_ctrls, NULL, &msgid );

	if ( mdn.bv_val != dn->bv_val ) {
		free( mdn.bv_val );
	}
	if ( mnewSuperior.bv_val != NULL
		&& mnewSuperior.bv_val != newSuperior->bv_val ) {
		free( mnewSuperior.bv_val );
	}
	
	return( ldap_back_op_result( lc, conn, op, msgid, rc ) );
}
