/* thread.c - deal with thread subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-monitor.h"

/*
*  * initializes log subentry
*   */
int
monitor_subsys_thread_init(
	BackendDB       *be
)
{
	struct monitorinfo      *mi;
	Entry                   *e;
	static char		buf[ BACKMONITOR_BUFSIZE ];
	struct berval		bv;

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
		&monitor_subsys[SLAPD_MONITOR_THREAD].mss_ndn, &e ) )
	{
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_thread_init: unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_THREAD].mss_ndn.bv_val, 
			0, 0 );
		return( -1 );
	}

	/* initialize the thread number */
	snprintf( buf, sizeof( buf ), "max=%d", connection_pool_max );

	bv.bv_val = buf;
	bv.bv_len = strlen( bv.bv_val );

	attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo, &bv, NULL );

	monitor_cache_release( mi, e );

	return( 0 );
}

int 
monitor_subsys_thread_update( 
	Operation		*op,
	Entry 			*e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	Attribute		*a;
	struct berval           *b = NULL;
	char 			buf[ BACKMONITOR_BUFSIZE ];

	assert( mi != NULL );

	snprintf( buf, sizeof( buf ), "backload=%d", 
			ldap_pvt_thread_pool_backload( &connection_pool ) );

	a = attr_find( e->e_attrs, mi->mi_ad_monitoredInfo );
	if ( a != NULL ) {
		for ( b = a->a_vals; b[0].bv_val != NULL; b++ ) {
			if ( strncmp( b[0].bv_val, "backload=", 
					sizeof( "backload=" ) - 1 ) == 0 ) {
				free( b[0].bv_val );
				ber_str2bv( buf, 0, 1, &b[0] );
				break;
			}
		}
	}

	if ( b == NULL || b[0].bv_val == NULL ) {
		struct berval	bv;

		bv.bv_val = buf;
		bv.bv_len = strlen( buf );
		attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
				&bv, NULL );
	}

	return( 0 );
}

