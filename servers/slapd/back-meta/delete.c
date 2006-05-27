/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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
	metaconn_t	*mc = NULL;
	int		candidate = -1;
	struct berval	mdn = BER_BVNULL;
	dncookie	dc;
	int		msgid;
	int		do_retry = 1;
	int		maperr = 1;

	mc = meta_back_getconn( op, rs, &candidate, LDAP_BACK_SENDERR );
	if ( !mc || !meta_back_dobind( op, rs, mc, LDAP_BACK_SENDERR ) ) {
		return rs->sr_err;
	}

	assert( mc->mc_conns[ candidate ].msc_ld != NULL );

	/*
	 * Rewrite the compare dn, if needed
	 */
	dc.target = mi->mi_targets[ candidate ];
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "deleteDN";

	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		goto done;
	}

retry:;
	rs->sr_err = ldap_delete_ext( mc->mc_conns[ candidate ].msc_ld,
			mdn.bv_val, op->o_ctrls, NULL, &msgid );
	if ( rs->sr_err == LDAP_UNAVAILABLE && do_retry ) {
		do_retry = 0;
		if ( meta_back_retry( op, rs, &mc, candidate, LDAP_BACK_SENDERR ) ) {
			goto retry;
		}
		goto cleanup;

	} else if ( rs->sr_err == LDAP_SUCCESS ) {
		struct timeval	tv, *tvp = NULL;
		LDAPMessage	*res = NULL;
		int		rc;

		if ( mi->mi_targets[ candidate ]->mt_timeout[ LDAP_BACK_OP_DELETE ] != 0 ) {
			tv.tv_sec = mi->mi_targets[ candidate ]->mt_timeout[ LDAP_BACK_OP_DELETE ];
			tv.tv_usec = 0;
			tvp = &tv;
		}

		rs->sr_err = LDAP_OTHER;
		maperr = 0;
		rc = ldap_result( mc->mc_conns[ candidate ].msc_ld,
			msgid, LDAP_MSG_ALL, tvp, &res );
		switch ( rc ) {
		case -1:
			rs->sr_err = LDAP_OTHER;
			break;

		case 0:
			(void)meta_back_cancel( mc, op, rs, msgid, candidate, LDAP_BACK_DONTSEND );
			rs->sr_err = op->o_protocol >= LDAP_VERSION3 ?
				LDAP_ADMINLIMIT_EXCEEDED : LDAP_OPERATIONS_ERROR;
			break;

		case LDAP_RES_DELETE:
			rc = ldap_parse_result( mc->mc_conns[ candidate ].msc_ld,
				res, &rs->sr_err, NULL, NULL, NULL, NULL, 1 );
			if ( rc != LDAP_SUCCESS ) {
				rs->sr_err = rc;
			}
			maperr = 1;
			break;

		default:
			ldap_msgfree( res );
			break;
		}
	}

	if ( maperr ) {
		rs->sr_err = meta_back_op_result( mc, op, rs, candidate );

	} else {
		send_ldap_result( op, rs );

		if ( META_BACK_QUARANTINE( mi ) ) {
			meta_back_quarantine( op, rs, candidate, 1 );
		}
	}

cleanup:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
		BER_BVZERO( &mdn );
	}
	
done:;
	if ( mc ) {
		meta_back_release_conn( op, mc );
	}

	return rs->sr_err;
}

