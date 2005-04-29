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
	Connection	*conn )
{
	metainfo_t	*mi = ( metainfo_t * )be->be_private;
	metaconn_t *mc,
			mc_curr = { 0 };

	Debug( LDAP_DEBUG_TRACE,
		"=>meta_back_conn_destroy: fetching conn %ld\n",
		conn->c_connid, 0, 0 );
	
	mc_curr.mc_conn = conn;
	
	ldap_pvt_thread_mutex_lock( &mi->mi_conn_mutex );
	mc = avl_delete( &mi->mi_conntree, ( caddr_t )&mc_curr,
			meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &mi->mi_conn_mutex );

	if ( mc ) {
		int	i;

		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_conn_destroy: destroying conn %ld\n",
			mc->mc_conn->c_connid, 0, 0 );
		
		/*
		 * Cleanup rewrite session
		 */
		for ( i = 0; i < mi->mi_ntargets; ++i ) {
			if ( mc->mc_conns[ i ].msc_ld == NULL ) {
				continue;
			}

			rewrite_session_delete( mi->mi_targets[ i ]->mt_rwmap.rwm_rw, conn );
			meta_clear_one_candidate( &mc->mc_conns[ i ] );
		}
		meta_back_conn_free( mc );
	}

	/* no response to unbind */

	return 0;
}

