/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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
		/*
		Backend		*be,
		Connection	*conn,
		Operation	*op,
		struct berval	*dn,
		struct berval	*ndn,
		struct berval	*newrdn,
		struct berval	*nnewrdn,
		int		deleteoldrdn,
		struct berval	*newSuperior,
		struct berval	*nnewSuperior
) */
{
	struct metainfo		*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn		*lc;
	int			rc = 0;
	int			candidate = -1;
	struct berval		mdn = { 0, NULL },
				mnewSuperior = { 0, NULL };
	dncookie		dc;

	lc = meta_back_getconn( op, rs, META_OP_REQUIRE_SINGLE,
			&op->o_req_ndn, &candidate );
	if ( !lc ) {
		rc = -1;
		goto cleanup;
	}

	if ( !meta_back_dobind( lc, op ) 
			|| !meta_back_is_valid( lc, candidate ) ) {
		rs->sr_err = LDAP_OTHER;
		rc = -1;
		goto cleanup;
	}

	dc.conn = op->o_conn;
	dc.rs = rs;

	if ( op->oq_modrdn.rs_newSup ) {
		int nsCandidate, version = LDAP_VERSION3;

		nsCandidate = meta_back_select_unique_candidate( li,
				op->oq_modrdn.rs_newSup );

		if ( nsCandidate != candidate ) {
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
			 * FIXME: is this the correct return code?
			 */
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rc = -1;
			goto cleanup;
		}

		ldap_set_option( lc->conns[ nsCandidate ].ld,
				LDAP_OPT_PROTOCOL_VERSION, &version );

		/*
		 * Rewrite the new superior, if defined and required
	 	 */
		dc.rwmap = &li->targets[ nsCandidate ]->rwmap;
		dc.ctx = "newSuperiorDN";
		if ( ldap_back_dn_massage( &dc, op->oq_modrdn.rs_newSup, &mnewSuperior ) ) {
			rc = -1;
			goto cleanup;
		}
	}

	/*
	 * Rewrite the modrdn dn, if required
	 */
	dc.rwmap = &li->targets[ candidate ]->rwmap;
	dc.ctx = "modrDN";
	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		rc = -1;
		goto cleanup;
	}

	ldap_rename2_s( lc->conns[ candidate ].ld, mdn.bv_val,
			op->oq_modrdn.rs_newrdn.bv_val,
			mnewSuperior.bv_val,
			op->oq_modrdn.rs_deleteoldrdn );

cleanup:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}
	
	if ( mnewSuperior.bv_val != NULL 
			&& mnewSuperior.bv_val != op->oq_modrdn.rs_newSup->bv_val ) {
		free( mnewSuperior.bv_val );
	}

	if ( rc == 0 ) {
		return meta_back_op_result( lc, op, rs ) == LDAP_SUCCESS
			? 0 : 1;
	} /* else */

	send_ldap_result( op, rs );
	return rc;

}

