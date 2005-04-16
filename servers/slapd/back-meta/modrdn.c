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

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_modrdn( Operation *op, SlapReply *rs )
{
	struct metainfo		*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn		*lc;
	int			rc = 0;
	int			candidate = -1;
	struct berval		mdn = BER_BVNULL,
				mnewSuperior = BER_BVNULL;
	dncookie		dc;

	lc = meta_back_getconn( op, rs, &candidate, LDAP_BACK_SENDERR );
	if ( !lc ) {
		return rs->sr_err;
	}

	assert( candidate != META_TARGET_NONE );

	if ( !meta_back_dobind( lc, op, LDAP_BACK_SENDERR ) ) {
		return rs->sr_err;
	}
		
	if ( !meta_back_is_valid( lc, candidate ) ) {
		rs->sr_err = LDAP_OTHER;
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	dc.conn = op->o_conn;
	dc.rs = rs;

	if ( op->orr_newSup ) {
		int	version = LDAP_VERSION3;

		/*
		 * NOTE: the newParent, if defined, must be on the 
		 * same target as the entry to be renamed.  This check
		 * has been anticipated in meta_back_getconn()
		 */
		/*
		 * FIXME: one possibility is to delete the entry
		 * from one target and add it to the other;
		 * unfortunately we'd need write access to both,
		 * which is nearly impossible; for administration
		 * needs, the rootdn of the metadirectory could
		 * be mapped to an administrative account on each
		 * target (the binddn?); we'll see.
		 */
		/*
		 * NOTE: we need to port the identity assertion
		 * feature from back-ldap
		 */

		/* newSuperior needs LDAPv3; if we got here, we can safely
		 * enforce it */
		ldap_set_option( lc->mc_conns[ candidate ].msc_ld,
				LDAP_OPT_PROTOCOL_VERSION, &version );

		/*
		 * Rewrite the new superior, if defined and required
	 	 */
		dc.rwmap = &li->mi_targets[ candidate ]->mt_rwmap;
		dc.ctx = "newSuperiorDN";
		if ( ldap_back_dn_massage( &dc, op->orr_newSup, &mnewSuperior ) ) {
			rc = -1;
			goto cleanup;
		}
	}

	/*
	 * Rewrite the modrdn dn, if required
	 */
	dc.rwmap = &li->mi_targets[ candidate ]->mt_rwmap;
	dc.ctx = "modrDN";
	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		rc = -1;
		goto cleanup;
	}

	rc = ldap_rename_s( lc->mc_conns[ candidate ].msc_ld, mdn.bv_val,
			op->orr_newrdn.bv_val,
			mnewSuperior.bv_val,
			op->orr_deleteoldrdn,
			op->o_ctrls, NULL ) != LDAP_SUCCESS;

cleanup:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
		BER_BVZERO( &mdn );
	}
	
	if ( !BER_BVISNULL( &mnewSuperior )
			&& mnewSuperior.bv_val != op->orr_newSup->bv_val )
	{
		free( mnewSuperior.bv_val );
		BER_BVZERO( &mnewSuperior );
	}

	if ( rc == 0 ) {
		return meta_back_op_result( lc, op, rs, candidate ) == LDAP_SUCCESS
			? 0 : 1;
	} /* else */

	send_ldap_result( op, rs );

	return rc;
}

