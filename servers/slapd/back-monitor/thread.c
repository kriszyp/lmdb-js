/* thread.c - deal with thread subsystem */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 * 
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

#include "slap.h"
#include "back-monitor.h"


int 
monitor_subsys_thread_update( 
	struct monitorinfo 	*mi,
	Entry 			*e
)
{
	Attribute		*a;
	struct berval           *bv[2], val, **b = NULL;
	char 			buf[1024];

	bv[0] = &val;
	bv[1] = NULL;

	snprintf( buf, sizeof( buf ), "threads=%d", 
			ldap_pvt_thread_pool_backload( &connection_pool ) );

	if ( ( a = attr_find( e->e_attrs, monitor_ad_desc ) ) != NULL ) {

		for ( b = a->a_vals; b[0] != NULL; b++ ) {
			if ( strncmp( b[0]->bv_val, "threads=", 
					sizeof( "threads=" ) - 1 ) == 0 ) {
				free( b[0]->bv_val );
				b[0] = ber_bvstrdup( buf );
				break;
			}
		}
	}

	if ( b == NULL || b[0] == NULL ) {
		val.bv_val = buf;
		val.bv_len = strlen( buf );
		attr_merge( e, monitor_ad_desc, bv );
	}

	return( 0 );
}

