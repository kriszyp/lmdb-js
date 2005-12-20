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

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_conn_destroy(
	Backend		*be,
	Connection	*conn )
{
	metainfo_t	*mi = ( metainfo_t * )be->be_private;
	metaconn_t	*mc,
			mc_curr = { 0 };
	int		i;


	Debug( LDAP_DEBUG_TRACE,
		"=>meta_back_conn_destroy: fetching conn=%ld DN=\"%s\"\n",
		conn->c_connid,
		BER_BVISNULL( &conn->c_ndn ) ? "" : conn->c_ndn.bv_val, 0 );
	
	mc_curr.mc_conn = conn;
	mc_curr.mc_local_ndn = conn->c_ndn;
	
	ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
	mc = avl_delete( &mi->mi_conninfo.lai_tree, ( caddr_t )&mc_curr,
			meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );

	if ( mc ) {
		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_conn_destroy: destroying conn %ld\n",
			LDAP_BACK_PCONN_ID( mc->mc_conn ), 0, 0 );
		
		assert( mc->mc_refcnt == 0 );

		meta_back_conn_free( mc );
	}

	/*
	 * Cleanup rewrite session
	 */
	for ( i = 0; i < mi->mi_ntargets; ++i ) {
		rewrite_session_delete( mi->mi_targets[ i ].mt_rwmap.rwm_rw, conn );
	}

	return 0;
}

