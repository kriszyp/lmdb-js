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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_delete( Operation *op, SlapReply *rs )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	metaconn_t	*mc;
	int		candidate = -1;
	struct berval	mdn = BER_BVNULL;
	dncookie	dc;
	int		msgid, do_retry = 1;

	mc = meta_back_getconn( op, rs, &candidate, LDAP_BACK_SENDERR );
	if ( !mc || !meta_back_dobind( op, rs, mc, LDAP_BACK_SENDERR ) ) {
		return rs->sr_err;
	}

	assert( mc->mc_conns[ candidate ].msc_ld != NULL );

	/*
	 * Rewrite the compare dn, if needed
	 */
	dc.rwmap = &mi->mi_targets[ candidate ]->mt_rwmap;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "deleteDN";

	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

retry:;
	rs->sr_err = ldap_delete_ext_s( mc->mc_conns[ candidate ].msc_ld,
			mdn.bv_val, op->o_ctrls, NULL );
	if ( rs->sr_err == LDAP_UNAVAILABLE && do_retry ) {
		do_retry = 0;
		if ( meta_back_retry( op, rs, mc, candidate, LDAP_BACK_SENDERR ) ) {
			goto retry;
		}
	}

	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
		BER_BVZERO( &mdn );
	}
	
	return meta_back_op_result( mc, op, rs, candidate );
}

