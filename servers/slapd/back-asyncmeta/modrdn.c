/* modrdn.c - modrdn request handler for back-syncmeta */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2016-2018 The OpenLDAP Foundation.
 * Portions Copyright 2016 Symas Corporation.
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
 * This work was developed by Symas Corporation
 * based on back-meta module for inclusion in OpenLDAP Software.
 * This work was sponsored by Ericsson. */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"
#include "../../../libraries/liblber/lber-int.h"
#include "../../../libraries/libldap/ldap-int.h"

meta_search_candidate_t
asyncmeta_back_modrdn_start(Operation *op,
			    SlapReply *rs,
			    a_metaconn_t *mc,
			    bm_context_t *bc,
			    int candidate)
{
	a_dncookie	dc;
	a_metainfo_t	*mi = mc->mc_info;
	a_metatarget_t	*mt = mi->mi_targets[ candidate ];
	struct berval	mdn = BER_BVNULL,
		mnewSuperior = BER_BVNULL,
		newrdn = BER_BVNULL;
	int rc = 0, nretries = 1;
	LDAPControl	**ctrls = NULL;
	meta_search_candidate_t retcode = META_SEARCH_CANDIDATE;
	BerElement *ber = NULL;
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	SlapReply		*candidates = bc->candidates;
	ber_int_t	msgid;

	dc.target = mt;
	dc.conn = op->o_conn;
	dc.rs = rs;

	if ( op->orr_newSup ) {

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

		/* needs LDAPv3 */
		switch ( mt->mt_version ) {
		case LDAP_VERSION3:
			break;

		case 0:
			if ( op->o_protocol == 0 || op->o_protocol == LDAP_VERSION3 ) {
				break;
			}
			/* fall thru */

		default:
			/* op->o_protocol cannot be anything but LDAPv3,
			 * otherwise wouldn't be here */
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			retcode = META_SEARCH_ERR;
			goto done;
		}

		/*
		 * Rewrite the new superior, if defined and required
		 */
		dc.ctx = "newSuperiorDN";
		if ( asyncmeta_dn_massage( &dc, op->orr_newSup, &mnewSuperior ) ) {
			rs->sr_err = LDAP_OTHER;
			retcode = META_SEARCH_ERR;
			goto done;
		}
	}

	/*
	 * Rewrite the modrdn dn, if required
	 */
	dc.ctx = "modrDN";
	if ( asyncmeta_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		rs->sr_err = LDAP_OTHER;
		retcode = META_SEARCH_ERR;
		goto done;
	}

	/* NOTE: we need to copy the newRDN in case it was formed
	 * from a DN by simply changing the length (ITS#5397) */
	newrdn = op->orr_newrdn;
	if ( newrdn.bv_val[ newrdn.bv_len ] != '\0' ) {
		ber_dupbv_x( &newrdn, &op->orr_newrdn, op->o_tmpmemctx );
	}
retry:;
	ctrls = op->o_ctrls;
	if ( asyncmeta_controls_add( op, rs, mc, candidate, &ctrls ) != LDAP_SUCCESS )
	{
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		retcode = META_SEARCH_ERR;
		goto done;
	}

	ber = ldap_build_moddn_req( msc->msc_ld, mdn.bv_val, newrdn.bv_val,
			mnewSuperior.bv_val, op->orr_deleteoldrdn, ctrls, NULL, &msgid);
	if (ber) {
		candidates[ candidate ].sr_msgid = msgid;
		rc = ldap_send_initial_request( msc->msc_ld, LDAP_REQ_MODRDN,
						mdn.bv_val, ber, msgid );
		if (rc == msgid)
			rc = LDAP_SUCCESS;
		else
			rc = LDAP_SERVER_DOWN;

		switch ( rc ) {
		case LDAP_SUCCESS:
			retcode = META_SEARCH_CANDIDATE;
			asyncmeta_set_msc_time(msc);
			break;

		case LDAP_SERVER_DOWN:
			ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
			asyncmeta_clear_one_msc(NULL, mc, candidate);
			ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
			if ( nretries && asyncmeta_retry( op, rs, &mc, candidate, LDAP_BACK_DONTSEND ) ) {
				nretries = 0;
				/* if the identity changed, there might be need to re-authz */
				(void)mi->mi_ldap_extra->controls_free( op, rs, &ctrls );
				goto retry;
			}

		default:
			candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
			retcode = META_SEARCH_ERR;
		}
	}

done:
	(void)mi->mi_ldap_extra->controls_free( op, rs, &ctrls );

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

	if ( newrdn.bv_val != op->orr_newrdn.bv_val ) {
		op->o_tmpfree( newrdn.bv_val, op->o_tmpmemctx );
	}

doreturn:;
	Debug( LDAP_DEBUG_TRACE, "%s <<< asyncmeta_back_modrdn_start[%p]=%d\n", op->o_log_prefix, msc, candidates[candidate].sr_msgid );
	return retcode;
}

int
asyncmeta_back_modrdn( Operation *op, SlapReply *rs )
{
	a_metainfo_t	*mi = ( a_metainfo_t * )op->o_bd->be_private;
	a_metatarget_t	*mt;
	a_metaconn_t	*mc;
	int		rc, candidate = -1;
	OperationBuffer opbuf;
	bm_context_t *bc;
	SlapReply *candidates;
	slap_callback *cb = op->o_callback;

	Debug(LDAP_DEBUG_ARGS, "==> asyncmeta_back_modrdn: %s\n",
	      op->o_req_dn.bv_val, 0, 0 );

	asyncmeta_new_bm_context(op, rs, &bc, mi->mi_ntargets );
	if (bc == NULL) {
		rs->sr_err = LDAP_OTHER;
		asyncmeta_sender_error(op, rs, cb);
		return rs->sr_err;
	}

	candidates = bc->candidates;
	mc = asyncmeta_getconn( op, rs, candidates, &candidate, LDAP_BACK_DONTSEND, 0);
	if ( !mc || rs->sr_err != LDAP_SUCCESS) {
		asyncmeta_sender_error(op, rs, cb);
		asyncmeta_clear_bm_context(bc);
		return rs->sr_err;
	}

	mt = mi->mi_targets[ candidate ];
	bc->timeout = mt->mt_timeout[ SLAP_OP_MODRDN ];
	bc->retrying = LDAP_BACK_RETRYING;
	bc->sendok = ( LDAP_BACK_SENDRESULT | bc->retrying );
	bc->stoptime = op->o_time + bc->timeout;

	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	rc = asyncmeta_add_message_queue(mc, bc);
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);

	if (rc != LDAP_SUCCESS) {
		rs->sr_err = LDAP_BUSY;
		rs->sr_text = "Maximum pending ops limit exceeded";
		asyncmeta_clear_bm_context(bc);
		asyncmeta_sender_error(op, rs, cb);
		goto finish;
	}

	rc = asyncmeta_dobind_init_with_retry(op, rs, bc, mc, candidate);
	switch (rc)
	{
	case META_SEARCH_CANDIDATE:
		/* target is already bound, just send the request */
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modrdn:  "
		       "cnd=\"%ld\"\n", op->o_log_prefix, candidate , 0);

		rc = asyncmeta_back_modrdn_start( op, rs, mc, bc, candidate);
		if (rc == META_SEARCH_ERR) {
			ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
			asyncmeta_drop_bc(mc, bc);
			ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
			asyncmeta_sender_error(op, rs, cb);
			asyncmeta_clear_bm_context(bc);
			goto finish;

		}
			break;
	case META_SEARCH_NOT_CANDIDATE:
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modrdn: NOT_CANDIDATE "
		       "cnd=\"%ld\"\n", op->o_log_prefix, candidate , 0);
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
		asyncmeta_drop_bc(mc, bc);
		ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
		asyncmeta_sender_error(op, rs, cb);
		asyncmeta_clear_bm_context(bc);
		goto finish;

	case META_SEARCH_NEED_BIND:
	case META_SEARCH_CONNECTING:
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modrdn: NEED_BIND "
		       "cnd=\"%ld\" %p\n", op->o_log_prefix, candidate , &mc->mc_conns[candidate]);
		rc = asyncmeta_dobind_init(op, rs, bc, mc, candidate);
		if (rc == META_SEARCH_ERR) {
			ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
			asyncmeta_drop_bc(mc, bc);
			ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
			asyncmeta_sender_error(op, rs, cb);
			asyncmeta_clear_bm_context(bc);
			goto finish;
		}
		break;
	case META_SEARCH_BINDING:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modrdn: BINDING "
			       "cnd=\"%ld\" %p\n", op->o_log_prefix, candidate , &mc->mc_conns[candidate]);
			/* Todo add the context to the message queue but do not send the request
			   the receiver must send this when we are done binding */
			/* question - how would do receiver know to which targets??? */
			break;

	case META_SEARCH_ERR:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_modrdn: ERR "
			       "cnd=\"%ldd\"\n", op->o_log_prefix, candidate , 0);
			candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
			candidates[ candidate ].sr_type = REP_RESULT;
			ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
			asyncmeta_drop_bc(mc, bc);
			ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
			asyncmeta_sender_error(op, rs, cb);
			asyncmeta_clear_bm_context(bc);
			goto finish;
		default:
			assert( 0 );
			break;
		}
	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	asyncmeta_start_one_listener(mc, candidates, bc, candidate);
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
finish:
	return rs->sr_err;
}
