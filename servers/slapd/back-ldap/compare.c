/* compare.c - ldap backend compare function */
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
ldap_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval	*dn,
    struct berval	*ndn,
	AttributeAssertion *ava
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	struct berval mapped_at, mapped_val;
	struct berval mdn = { 0, NULL };
	int freeval = 0;

	lc = ldap_back_getconn(li, conn, op);
	if (!lc || !ldap_back_dobind( lc, op ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the compare dn, if needed
	 */
#ifdef ENABLE_REWRITE
	switch ( rewrite_session( li->rwinfo, "compareDn", dn->bv_val, conn, &mdn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mdn.bv_val == NULL ) {
			mdn.bv_val = ( char * )dn->bv_val;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] compareDn: \"%s\" -> \"%s\"\n", dn->bv_val, mdn.bv_val, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> compareDn: \"%s\" -> \"%s\"\n%s",
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
 	if ( mdn.bv_val == NULL ) {
 		return -1;
	}
#endif /* !ENABLE_REWRITE */

	if ( ava->aa_desc == slap_schema.si_ad_objectClass ) {
		ldap_back_map(&li->oc_map, &ava->aa_value, &mapped_val,
				BACKLDAP_MAP);
		if (mapped_val.bv_val == NULL || mapped_val.bv_val[0] == '\0') {
			return( -1 );
		}
		mapped_at = ava->aa_desc->ad_cname;
		
	} else {
		ldap_back_map(&li->at_map, &ava->aa_desc->ad_cname, &mapped_at, 
				BACKLDAP_MAP);
		if (mapped_at.bv_val == NULL || mapped_at.bv_val[0] == '\0') {
			return( -1 );
		}
		if (ava->aa_desc->ad_type->sat_syntax ==
			slap_schema.si_syn_distinguishedName) {
#ifdef ENABLE_REWRITE
			switch ( rewrite_session( li->rwinfo, "bindDn", ava->aa_value.bv_val, conn, &mapped_val.bv_val ) ) {
			case REWRITE_REGEXEC_OK:
				if ( mapped_val.bv_val == NULL ) {
					mapped_val.bv_val = ( char * )ava->aa_value.bv_val;
				} else {
					freeval = 1;
				}
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDAP, DETAIL1, 
					"[rw] bindDn (dnAttr): \"%s\" -> \"%s\"\n", ava->aa_value.bv_val, mapped_val.bv_val, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ARGS,
					"[rw] bindDn (dnAttr): \"%s\" -> \"%s\"\n", ava->aa_value.bv_val, mapped_val.bv_val, 0 );
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
			ldap_back_dn_massage( li, &ava->aa_value, &mapped_val, 0, 1 );
			if ( mapped_val.bv_val == NULL ) {
				mapped_val = ava->aa_value;
			} else {
				freeval = 1;
			}
#endif /* !ENABLE_REWRITE */

		}
	}

	ldap_compare_s( lc->ld, mdn.bv_val, mapped_at.bv_val, mapped_val.bv_val );

	if ( mdn.bv_val != dn->bv_val ) {
		free( mdn.bv_val );
	}
	if ( freeval ) {
		free( mapped_val.bv_val );
	}
	
	return( ldap_back_op_result( lc, op ) );
}
