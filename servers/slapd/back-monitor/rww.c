/* readw.c - deal with read waiters subsystem */
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

#include "slap.h"
#include "back-monitor.h"

static int monitor_subsys_readw_update_internal( struct monitorinfo *mi, Entry *e, int rw );

int 
monitor_subsys_readw_update( 
	struct monitorinfo 	*mi,
	Entry 			*e
)
{
	return monitor_subsys_readw_update_internal( mi, e, 0 );
}

int 
monitor_subsys_writew_update( 
	struct monitorinfo 	*mi,
	Entry 			*e
)
{
	return monitor_subsys_readw_update_internal( mi, e, 1 );
}

static int 
monitor_subsys_readw_update_internal( 
	struct monitorinfo 	*mi,
	Entry 			*e,
	int			rw
)
{
	Connection              *c;
	int                     connindex;
	int                     nconns, nwritewaiters, nreadwaiters;
	
	Attribute		*a;
	struct berval           bv[2], *b = NULL;
	char 			buf[1024];
	
	char			*str = NULL;
	int			num = 0;

	assert( mi != NULL );
	assert( e != NULL );
	
	bv[1].bv_val = NULL;
	
	nconns = nwritewaiters = nreadwaiters = 0;
	for ( c = connection_first( &connindex );
			c != NULL;
			c = connection_next( c, &connindex ), nconns++ ) {
		if ( c->c_writewaiter ) {
			nwritewaiters++;
		}
		if ( c->c_currentber != NULL ) {
			nreadwaiters++;
		}
	}
	connection_done(c);

	switch ( rw ) {
	case 0:
		str = "read waiters";
		num = nreadwaiters;
		break;
	case 1:
		str = "write waiters";
		num = nwritewaiters;
		break;
	}
	snprintf( buf, sizeof( buf ), "%s=%d", str, num );

	if ( ( a = attr_find( e->e_attrs, monitor_ad_desc ) ) != NULL ) {
		for ( b = a->a_vals; b[0].bv_val != NULL; b++ ) {
			if ( strncmp( b[0].bv_val, str, strlen( str ) ) == 0 ) {
				free( b[0].bv_val );
				ber_str2bv( buf, 0, 1, b );
				break;
			}
		}
	}

	if ( b == NULL || b[0].bv_val == NULL ) {
		bv[0].bv_val = buf;
		bv[0].bv_len = strlen( buf );
		attr_merge( e, monitor_ad_desc, bv );
	}

	return( 0 );
}

