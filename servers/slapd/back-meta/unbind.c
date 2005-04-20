/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/errno.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_conn_destroy(
		Backend		*be,
		Connection	*conn
)
{
	struct metainfo	*li = ( struct metainfo * )be->be_private;
	struct metaconn *lc,
			lc_curr = { 0 };

	Debug( LDAP_DEBUG_TRACE,
		"=>meta_back_conn_destroy: fetching conn %ld\n",
		conn->c_connid, 0, 0 );
	
	lc_curr.mc_conn = conn;
	
	ldap_pvt_thread_mutex_lock( &li->mi_conn_mutex );
	lc = avl_delete( &li->mi_conntree, ( caddr_t )&lc_curr,
			meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->mi_conn_mutex );

	if ( lc ) {
		int	i;

		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_conn_destroy: destroying conn %ld\n",
			lc->mc_conn->c_connid, 0, 0 );
		
		/*
		 * Cleanup rewrite session
		 */
		for ( i = 0; i < li->mi_ntargets; ++i ) {
			if ( lc->mc_conns[ i ].msc_ld == NULL ) {
				continue;
			}

			rewrite_session_delete( li->mi_targets[ i ]->mt_rwmap.rwm_rw, conn );
			meta_clear_one_candidate( &lc->mc_conns[ i ] );
		}
		free( lc );
	}

	/* no response to unbind */

	return 0;
}

