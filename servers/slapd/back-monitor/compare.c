/* compare.c - monitor backend compare routine */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This work has beed deveolped for the OpenLDAP Foundation 
 * in the hope that it may be useful to the Open Source community, 
 * but WITHOUT ANY WARRANTY.
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from
 *    flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 * 
 * 4. This notice may not be removed or altered.
 */

#include "portable.h"

#include <stdio.h>

#include <slap.h>
#include "back-monitor.h"

int
monitor_back_compare(
	Backend			*be,
	Connection		*conn,
	Operation		*op,
	struct berval		*dn,
	struct berval		*ndn,
	AttributeAssertion 	*ava
)
{
	struct monitorinfo      *mi = (struct monitorinfo *) be->be_private;	        int             rc;
	Entry           *e, *matched = NULL;
	Attribute	*a;

	/* get entry with reader lock */
	monitor_cache_dn2entry( mi, ndn, &e, &matched );
	if ( e == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
				matched ? matched->e_dn : NULL,
				NULL, NULL, NULL );
		if ( matched ) {
			monitor_cache_release( mi, matched );
		}

		return( 0 );
	}

	rc = access_allowed( be, conn, op, e, ava->aa_desc, 
			&ava->aa_value, ACL_COMPARE, NULL );
	if ( !rc ) {
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
		rc = 1;
		goto return_results;
	}

	rc = LDAP_NO_SUCH_ATTRIBUTE;

	for ( a = attrs_find( e->e_attrs, ava->aa_desc );
			a != NULL;
			a = attrs_find( a->a_next, ava->aa_desc )) {
		rc = LDAP_COMPARE_FALSE;

		if ( value_find( ava->aa_desc, a->a_vals, &ava->aa_value ) == 0 ) {
			rc = LDAP_COMPARE_TRUE;
			break;
		}
	}

	send_ldap_result( conn, op, rc, NULL, NULL, NULL, NULL );

	if( rc != LDAP_NO_SUCH_ATTRIBUTE ) {
		rc = 0;
	}
	
return_results:;
	monitor_cache_release( mi, e );

	return( rc );
}

