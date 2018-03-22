/* add.c - add request handler for back-asyncmeta */
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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"
#include "ldap_rq.h"
#include "../../../libraries/liblber/lber-int.h"
#include "../../../libraries/libldap/ldap-int.h"

void
asyncmeta_sender_error(Operation *op,
		       SlapReply *rs,
		       slap_callback *cb)
{
	if (cb != NULL) {
		op->o_callback = cb;
	}
	send_ldap_result(op, rs);
}

meta_search_candidate_t
asyncmeta_back_add_start(Operation *op,
			 SlapReply *rs,
			 a_metaconn_t *mc,
			 bm_context_t *bc,
			 int candidate)
{
	int		isupdate;
	Attribute	*a;
	int i;
	LDAPMod		**attrs;
	struct berval	mapped;
	a_dncookie	dc;
	a_metainfo_t	*mi = mc->mc_info;
	a_metatarget_t	*mt = mi->mi_targets[ candidate ];
	struct berval   mdn;
	meta_search_candidate_t retcode = META_SEARCH_CANDIDATE;
	BerElement *ber = NULL;
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	SlapReply		*candidates = bc->candidates;
	ber_int_t	msgid;
	LDAPControl		**ctrls = NULL;
	int rc, nretries = 1;


	dc.target = mt;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "addDN";

	mdn.bv_len = 0;

	switch (asyncmeta_dn_massage( &dc, &bc->op->o_req_dn, &mdn ) )
	{
	case LDAP_SUCCESS:
		break;
	case LDAP_UNWILLING_TO_PERFORM:
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "Operation not allowed";
		retcode = META_SEARCH_ERR;
		goto doreturn;
	default:
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto doreturn;
	}

	/* Count number of attributes in entry ( +1 ) */
	for ( i = 1, a = op->ora_e->e_attrs; a; i++, a = a->a_next );

	/* Create array of LDAPMods for ldap_add() */
	attrs = ch_malloc( sizeof( LDAPMod * )*i );

	dc.ctx = "addAttrDN";
	isupdate = be_shadow_update( op );
	for ( i = 0, a = op->ora_e->e_attrs; a; a = a->a_next ) {
		int j, is_oc = 0;

		if ( !isupdate && !get_relax( op ) && a->a_desc->ad_type->sat_no_user_mod  )
		{
			continue;
		}

		if ( a->a_desc == slap_schema.si_ad_objectClass
				|| a->a_desc == slap_schema.si_ad_structuralObjectClass )
		{
			is_oc = 1;
			mapped = a->a_desc->ad_cname;

		} else {
			asyncmeta_map( &mt->mt_rwmap.rwm_at,
					&a->a_desc->ad_cname, &mapped, BACKLDAP_MAP );
			if ( BER_BVISNULL( &mapped ) || BER_BVISEMPTY( &mapped ) ) {
				continue;
			}
		}

		attrs[ i ] = ch_malloc( sizeof( LDAPMod ) );
		if ( attrs[ i ] == NULL ) {
			continue;
		}
		attrs[ i ]->mod_op = LDAP_MOD_BVALUES;
		attrs[ i ]->mod_type = mapped.bv_val;

		if ( is_oc ) {
			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ );

			attrs[ i ]->mod_bvalues =
				(struct berval **)ch_malloc( ( j + 1 ) *
				sizeof( struct berval * ) );
			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); ) {
				struct ldapmapping	*mapping;

				asyncmeta_mapping( &mt->mt_rwmap.rwm_oc,
						&a->a_vals[ j ], &mapping, BACKLDAP_MAP );

				if ( mapping == NULL ) {
					if ( mt->mt_rwmap.rwm_oc.drop_missing ) {
						continue;
					}
					attrs[ i ]->mod_bvalues[ j ] = &a->a_vals[ j ];

				} else {
					attrs[ i ]->mod_bvalues[ j ] = &mapping->dst;
				}
				j++;
			}
			attrs[ i ]->mod_bvalues[ j ] = NULL;

		} else {
			/*
			 * FIXME: dn-valued attrs should be rewritten
			 * to allow their use in ACLs at the back-ldap
			 * level.
			 */
			if ( a->a_desc->ad_type->sat_syntax ==
				slap_schema.si_syn_distinguishedName )
			{
				(void)asyncmeta_dnattr_rewrite( &dc, a->a_vals );
				if ( a->a_vals == NULL ) {
					continue;
				}
			}

			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ )
				;

			attrs[ i ]->mod_bvalues = ch_malloc( ( j + 1 ) * sizeof( struct berval * ) );
			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ ) {
				attrs[ i ]->mod_bvalues[ j ] = &a->a_vals[ j ];
			}
			attrs[ i ]->mod_bvalues[ j ] = NULL;
		}
		i++;
	}
	attrs[ i ] = NULL;

retry:;
	ctrls = op->o_ctrls;
	if ( asyncmeta_controls_add( op, rs, mc, candidate, &ctrls ) != LDAP_SUCCESS )
	{
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		retcode = META_SEARCH_ERR;
		goto done;
	}

	ber = ldap_build_add_req( msc->msc_ld, mdn.bv_val, attrs, ctrls, NULL, &msgid);
	if (ber) {
		candidates[ candidate ].sr_msgid = msgid;
		rc = ldap_send_initial_request( msc->msc_ld, LDAP_REQ_ADD,
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

	for ( --i; i >= 0; --i ) {
		free( attrs[ i ]->mod_bvalues );
		free( attrs[ i ] );
	}
	free( attrs );
	if ( mdn.bv_val != op->ora_e->e_dn ) {
		free( mdn.bv_val );
		BER_BVZERO( &mdn );
	}

doreturn:;
	Debug( LDAP_DEBUG_TRACE, "%s <<< asyncmeta_back_add_start[%p]=%d\n", op->o_log_prefix, msc, candidates[candidate].sr_msgid );
	return retcode;
}


int
asyncmeta_back_add( Operation *op, SlapReply *rs )
{
	a_metainfo_t	*mi = ( a_metainfo_t * )op->o_bd->be_private;
	a_metatarget_t	*mt;
	a_metaconn_t	*mc;
	int		rc, candidate = -1;
	OperationBuffer opbuf;
	bm_context_t *bc;
	SlapReply *candidates;
	slap_callback *cb = op->o_callback;

	Debug(LDAP_DEBUG_ARGS, "==> asyncmeta_back_add: %s\n",
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
	bc->timeout = mt->mt_timeout[ SLAP_OP_ADD ];
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
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_add:  "
		       "cnd=\"%ld\"\n", op->o_log_prefix, candidate , 0);

		rc = asyncmeta_back_add_start( op, rs, mc, bc, candidate);
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
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_add: NOT_CANDIDATE "
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
		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_add: NEED_BIND "
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
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_add: BINDING "
			       "cnd=\"%ld\" %p\n", op->o_log_prefix, candidate , &mc->mc_conns[candidate]);
			/* Todo add the context to the message queue but do not send the request
			   the receiver must send this when we are done binding */
			/* question - how would do receiver know to which targets??? */
			break;

	case META_SEARCH_ERR:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_add: ERR "
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
