/* search.c - search request handler for back-asyncmeta */
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
#include <ac/time.h>

#include "lutil.h"
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"
#include "../../../libraries/liblber/lber-int.h"

#include "../../../libraries/libldap/ldap-int.h"
#undef	ldap_debug
#define	ldap_debug	slap_debug

static void
asyncmeta_handle_onerr_stop(Operation *op,
			    SlapReply *rs,
			    a_metaconn_t *mc,
			    bm_context_t *bc,
			    int candidate,
			    slap_callback *cb)
{
	a_metainfo_t *mi = mc->mc_info;
	int j;
	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	if (bc->bc_active > 0) {
		ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
		return;
	}
	bc->bc_active = 1;
	asyncmeta_drop_bc(mc, bc);
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);

	for (j=0; j<mi->mi_ntargets; j++) {
		if (j != candidate && bc->candidates[j].sr_msgid >= 0
		    && mc->mc_conns[j].msc_ld != NULL) {
			asyncmeta_back_abandon_candidate( mc, op,
						bc->candidates[ j ].sr_msgid, j );
		}
	}
	if (cb != NULL) {
		op->o_callback = cb;
	}
	send_ldap_result(op, rs);
	asyncmeta_clear_bm_context(bc);
}

meta_search_candidate_t
asyncmeta_back_search_start(
				Operation *op,
				SlapReply *rs,
			    a_metaconn_t *mc,
			    bm_context_t *bc,
			    int candidate,
			    struct berval		*prcookie,
			    ber_int_t		prsize )
{
	SlapReply		*candidates = bc->candidates;
	a_metainfo_t		*mi = ( a_metainfo_t * )mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	a_dncookie		dc;
	struct berval		realbase = op->o_req_dn;
	int			realscope = op->ors_scope;
	struct berval		mbase = BER_BVNULL;
	struct berval		mfilter = BER_BVNULL;
	char			**mapped_attrs = NULL;
	int			rc;
	meta_search_candidate_t	retcode;
	int timelimit;
	int			nretries = 1;
	LDAPControl		**ctrls = NULL;
	BerElement *ber;
	ber_int_t	msgid;
#ifdef SLAPD_META_CLIENT_PR
	LDAPControl		**save_ctrls = NULL;
#endif /* SLAPD_META_CLIENT_PR */

	/* this should not happen; just in case... */
	if ( msc->msc_ld == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"%s: asyncmeta_back_search_start candidate=%d ld=NULL%s.\n",
			op->o_log_prefix, candidate,
			META_BACK_ONERR_STOP( mi ) ? "" : " (ignored)" );
		candidates[ candidate ].sr_err = LDAP_OTHER;
		if ( META_BACK_ONERR_STOP( mi ) ) {
			return META_SEARCH_ERR;
		}
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		return META_SEARCH_NOT_CANDIDATE;
	}

	Debug( LDAP_DEBUG_TRACE, "%s >>> asyncmeta_back_search_start[%d]\n", op->o_log_prefix, candidate, 0 );
	/*
	 * modifies the base according to the scope, if required
	 */
	if ( mt->mt_nsuffix.bv_len > op->o_req_ndn.bv_len ) {
		switch ( op->ors_scope ) {
		case LDAP_SCOPE_SUBTREE:
			/*
			 * make the target suffix the new base
			 * FIXME: this is very forgiving, because
			 * "illegal" searchBases may be turned
			 * into the suffix of the target; however,
			 * the requested searchBase already passed
			 * thru the candidate analyzer...
			 */
			if ( dnIsSuffix( &mt->mt_nsuffix, &op->o_req_ndn ) ) {
				realbase = mt->mt_nsuffix;
				if ( mt->mt_scope == LDAP_SCOPE_SUBORDINATE ) {
					realscope = LDAP_SCOPE_SUBORDINATE;
				}

			} else {
				/*
				 * this target is no longer candidate
				 */
				retcode = META_SEARCH_NOT_CANDIDATE;
				goto doreturn;
			}
			break;

		case LDAP_SCOPE_SUBORDINATE:
		case LDAP_SCOPE_ONELEVEL:
		{
			struct berval	rdn = mt->mt_nsuffix;
			rdn.bv_len -= op->o_req_ndn.bv_len + STRLENOF( "," );
			if ( dnIsOneLevelRDN( &rdn )
					&& dnIsSuffix( &mt->mt_nsuffix, &op->o_req_ndn ) )
			{
				/*
				 * if there is exactly one level,
				 * make the target suffix the new
				 * base, and make scope "base"
				 */
				realbase = mt->mt_nsuffix;
				if ( op->ors_scope == LDAP_SCOPE_SUBORDINATE ) {
					if ( mt->mt_scope == LDAP_SCOPE_SUBORDINATE ) {
						realscope = LDAP_SCOPE_SUBORDINATE;
					} else {
						realscope = LDAP_SCOPE_SUBTREE;
					}
				} else {
					realscope = LDAP_SCOPE_BASE;
				}
				break;
			} /* else continue with the next case */
		}

		case LDAP_SCOPE_BASE:
			/*
			 * this target is no longer candidate
			 */
			retcode = META_SEARCH_NOT_CANDIDATE;
			goto doreturn;
		}
	}

	/* check filter expression */
	if ( mt->mt_filter ) {
		metafilter_t *mf;
		for ( mf = mt->mt_filter; mf; mf = mf->mf_next ) {
			if ( regexec( &mf->mf_regex, op->ors_filterstr.bv_val, 0, NULL, 0 ) == 0 )
				break;
		}
		/* nothing matched, this target is no longer a candidate */
		if ( !mf ) {
			retcode = META_SEARCH_NOT_CANDIDATE;
			goto doreturn;
		}
	}

	/*
	 * Rewrite the search base, if required
	 */
	dc.target = mt;
	dc.ctx = "searchBase";
	dc.conn = op->o_conn;
	dc.rs = rs;
	switch ( asyncmeta_dn_massage( &dc, &realbase, &mbase ) ) {
	case LDAP_SUCCESS:
		break;

	case LDAP_UNWILLING_TO_PERFORM:
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "Operation not allowed";
		retcode = META_SEARCH_ERR;
		goto doreturn;

	default:

		/*
		 * this target is no longer candidate
		 */
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto doreturn;
	}

	/*
	 * Maps filter
	 */
	rc = asyncmeta_filter_map_rewrite( &dc, op->ors_filter,
			&mfilter, BACKLDAP_MAP, NULL );
	switch ( rc ) {
	case LDAP_SUCCESS:
		break;

	case LDAP_COMPARE_FALSE:
	default:
		/*
		 * this target is no longer candidate
		 */
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto done;
	}

	/*
	 * Maps required attributes
	 */
	rc = asyncmeta_map_attrs( op, &mt->mt_rwmap.rwm_at,
			op->ors_attrs, BACKLDAP_MAP, &mapped_attrs );
	if ( rc != LDAP_SUCCESS ) {
		/*
		 * this target is no longer candidate
		 */
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto done;
	}

	if ( op->ors_tlimit != SLAP_NO_LIMIT ) {
		timelimit = op->ors_tlimit > 0 ? op->ors_tlimit : 1;
	} else {
		timelimit = -1;	/* no limit */
	}

#ifdef SLAPD_META_CLIENT_PR
	save_ctrls = op->o_ctrls;
	{
		LDAPControl *pr_c = NULL;
		int i = 0, nc = 0;

		if ( save_ctrls ) {
			for ( ; save_ctrls[i] != NULL; i++ );
			nc = i;
			pr_c = ldap_control_find( LDAP_CONTROL_PAGEDRESULTS, save_ctrls, NULL );
		}

		if ( pr_c != NULL ) nc--;
		if ( mt->mt_ps > 0 || prcookie != NULL ) nc++;

		if ( mt->mt_ps > 0 || prcookie != NULL || pr_c != NULL ) {
			int src = 0, dst = 0;
			BerElementBuffer berbuf;
			BerElement *ber = (BerElement *)&berbuf;
			struct berval val = BER_BVNULL;
			ber_len_t len;

			len = sizeof( LDAPControl * )*( nc + 1 ) + sizeof( LDAPControl );

			if ( mt->mt_ps > 0 || prcookie != NULL ) {
				struct berval nullcookie = BER_BVNULL;
				ber_tag_t tag;

				if ( prsize == 0 && mt->mt_ps > 0 ) prsize = mt->mt_ps;
				if ( prcookie == NULL ) prcookie = &nullcookie;

				ber_init2( ber, NULL, LBER_USE_DER );
				tag = ber_printf( ber, "{iO}", prsize, prcookie );
				if ( tag == LBER_ERROR ) {
					/* error */
					(void) ber_free_buf( ber );
					goto done_pr;
				}

				tag = ber_flatten2( ber, &val, 0 );
				if ( tag == LBER_ERROR ) {
					/* error */
					(void) ber_free_buf( ber );
					goto done_pr;
				}

				len += val.bv_len + 1;
			}

			op->o_ctrls = op->o_tmpalloc( len, op->o_tmpmemctx );
			if ( save_ctrls ) {
				for ( ; save_ctrls[ src ] != NULL; src++ ) {
					if ( save_ctrls[ src ] != pr_c ) {
						op->o_ctrls[ dst ] = save_ctrls[ src ];
						dst++;
					}
				}
			}

			if ( mt->mt_ps > 0 || prcookie != NULL ) {
				op->o_ctrls[ dst ] = (LDAPControl *)&op->o_ctrls[ nc + 1 ];

				op->o_ctrls[ dst ]->ldctl_oid = LDAP_CONTROL_PAGEDRESULTS;
				op->o_ctrls[ dst ]->ldctl_iscritical = 1;

				op->o_ctrls[ dst ]->ldctl_value.bv_val = (char *)&op->o_ctrls[ dst ][ 1 ];
				AC_MEMCPY( op->o_ctrls[ dst ]->ldctl_value.bv_val, val.bv_val, val.bv_len + 1 );
				op->o_ctrls[ dst ]->ldctl_value.bv_len = val.bv_len;
				dst++;

				(void)ber_free_buf( ber );
			}

			op->o_ctrls[ dst ] = NULL;
		}
done_pr:;
	}
#endif /* SLAPD_META_CLIENT_PR */

retry:;
	asyncmeta_set_msc_time(msc);
	ctrls = op->o_ctrls;
	if (nretries == 0)
	{
		if (rc != LDAP_SUCCESS)
		{
			rs->sr_err = LDAP_BUSY;
			retcode = META_SEARCH_ERR;
			candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		        goto done;
		}
	}

	if ( asyncmeta_controls_add( op, rs, mc, candidate, &ctrls )
		!= LDAP_SUCCESS )
	{
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		retcode = META_SEARCH_NOT_CANDIDATE;
		goto done;
	}

	/*
	 * Starts the search
	 */
	ber = ldap_build_search_req( msc->msc_ld,
			mbase.bv_val, realscope, mfilter.bv_val,
			mapped_attrs, op->ors_attrsonly,
			ctrls, NULL, timelimit, op->ors_slimit, op->ors_deref,
			&msgid );
	if (ber) {
		candidates[ candidate ].sr_msgid = msgid;
		rc = ldap_send_initial_request( msc->msc_ld, LDAP_REQ_SEARCH,
			mbase.bv_val, ber, msgid );
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
			if (mc->mc_active < 1) {
				asyncmeta_clear_one_msc(NULL, mc, candidate);
			}
			ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
			if ( nretries && asyncmeta_retry( op, rs, &mc, candidate, LDAP_BACK_DONTSEND ) ) {
				nretries = 0;
				/* if the identity changed, there might be need to re-authz */
				(void)mi->mi_ldap_extra->controls_free( op, rs, &ctrls );
				goto retry;
			}
			rs->sr_err = LDAP_UNAVAILABLE;
			retcode = META_SEARCH_ERR;
			break;
		default:
			candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
			retcode = META_SEARCH_NOT_CANDIDATE;
		}
	}

done:;
	(void)mi->mi_ldap_extra->controls_free( op, rs, &ctrls );
#ifdef SLAPD_META_CLIENT_PR
	if ( save_ctrls != op->o_ctrls ) {
		op->o_tmpfree( op->o_ctrls, op->o_tmpmemctx );
		op->o_ctrls = save_ctrls;
	}
#endif /* SLAPD_META_CLIENT_PR */

	if ( mapped_attrs ) {
		ber_memfree_x( mapped_attrs, op->o_tmpmemctx );
	}
	if ( mfilter.bv_val != op->ors_filterstr.bv_val ) {
		ber_memfree_x( mfilter.bv_val, NULL );
	}
	if ( mbase.bv_val != realbase.bv_val ) {
		free( mbase.bv_val );
	}

doreturn:;
	Debug( LDAP_DEBUG_TRACE, "%s <<< asyncmeta_back_search_start[%p]=%d\n", op->o_log_prefix, msc, candidates[candidate].sr_msgid );
	return retcode;
}

int
asyncmeta_back_search( Operation *op, SlapReply *rs )
{
	a_metainfo_t	*mi = ( a_metainfo_t * )op->o_bd->be_private;
	struct timeval	save_tv = { 0, 0 },
			tv;
	time_t		stoptime = (time_t)(-1),
			lastres_time = slap_get_time(),
			timeout = 0;
	int		rc = 0, sres = LDAP_SUCCESS;
	char		*matched = NULL;
	int		last = 0, ncandidates = 0,
			initial_candidates = 0, candidate_match = 0,
			needbind = 0;
	ldap_back_send_t	sendok = LDAP_BACK_SENDERR;
	long		i,j;
	int		is_ok = 0;
	void		*savepriv;
	SlapReply	*candidates = NULL;
	int		do_taint = 0;
	bm_context_t *bc;
	a_metaconn_t *mc;
	slap_callback *cb = op->o_callback;

	rs_assert_ready( rs );
	rs->sr_flags &= ~REP_ENTRY_MASK; /* paranoia, we can set rs = non-entry */

	/*
	 * controls are set in ldap_back_dobind()
	 *
	 * FIXME: in case of values return filter, we might want
	 * to map attrs and maybe rewrite value
	 */

	asyncmeta_new_bm_context(op, rs, &bc, mi->mi_ntargets );
	if (bc == NULL) {
		rs->sr_err = LDAP_OTHER;
		send_ldap_result(op, rs);
		return rs->sr_err;
	}

	candidates = bc->candidates;
	mc = asyncmeta_getconn( op, rs, candidates, NULL, LDAP_BACK_DONTSEND, 0);
	if ( !mc || rs->sr_err != LDAP_SUCCESS) {
		op->o_callback = cb;
		send_ldap_result(op, rs);
		asyncmeta_clear_bm_context(bc);
		return rs->sr_err;
	}

	/*
	 * Inits searches
	 */

	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		/* reset sr_msgid; it is used in most loops
		 * to check if that target is still to be considered */
		candidates[i].sr_msgid = META_MSGID_UNDEFINED;
		/* a target is marked as candidate by asyncmeta_getconn();
		 * if for any reason (an error, it's over or so) it is
		 * no longer active, sr_msgid is set to META_MSGID_IGNORE
		 * but it remains candidate, which means it has been active
		 * at some point during the operation.  This allows to
		 * use its response code and more to compute the final
		 * response */
		if ( !META_IS_CANDIDATE( &candidates[ i ] ) ) {
			continue;
		}

		candidates[ i ].sr_matched = NULL;
		candidates[ i ].sr_text = NULL;
		candidates[ i ].sr_ref = NULL;
		candidates[ i ].sr_ctrls = NULL;
		candidates[ i ].sr_nentries = 0;
		candidates[ i ].sr_type = -1;

		/* get largest timeout among candidates */
		if ( mi->mi_targets[ i ]->mt_timeout[ SLAP_OP_SEARCH ]
			&& mi->mi_targets[ i ]->mt_timeout[ SLAP_OP_SEARCH ] > timeout )
		{
			timeout = mi->mi_targets[ i ]->mt_timeout[ SLAP_OP_SEARCH ];
		}
	}

	bc->timeout = timeout;
	bc->stoptime = op->o_time + bc->timeout;

	if ( op->ors_tlimit != SLAP_NO_LIMIT ) {
		stoptime = op->o_time + op->ors_tlimit;
		if (stoptime < bc->stoptime) {
			bc->stoptime = stoptime;
			bc->searchtime = 1;
			bc->timeout = op->ors_tlimit;
		}
	}

	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	rc = asyncmeta_add_message_queue(mc, bc);
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);

	if (rc != LDAP_SUCCESS) {
		rs->sr_err = LDAP_BUSY;
		rs->sr_text = "Maximum pending ops limit exceeded";
		asyncmeta_clear_bm_context(bc);
		op->o_callback = cb;
		send_ldap_result(op, rs);
		goto finish;
	}

	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		if ( !META_IS_CANDIDATE( &candidates[ i ] )
			|| candidates[ i ].sr_err != LDAP_SUCCESS )
		{
			continue;
		}

		rc = asyncmeta_dobind_init_with_retry(op, rs, bc, mc, i);
		switch (rc)
		{
		case META_SEARCH_CANDIDATE:
			/* target is already bound, just send the search request */
			ncandidates++;
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_search: IS_CANDIDATE "
			       "cnd=\"%ld\"\n", op->o_log_prefix, i , 0);

			rc = asyncmeta_back_search_start( op, rs, mc, bc, i,  NULL, 0 );
			if (rc == META_SEARCH_ERR) {
				META_CANDIDATE_CLEAR(&candidates[i]);
				candidates[ i ].sr_msgid = META_MSGID_IGNORE;
				if ( META_BACK_ONERR_STOP( mi ) ) {
					asyncmeta_handle_onerr_stop(op,rs,mc,bc,i,cb);
					goto finish;
				}
				else {
					continue;
				}
			}
			break;
		case META_SEARCH_NOT_CANDIDATE:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_search: NOT_CANDIDATE "
			       "cnd=\"%ld\"\n", op->o_log_prefix, i , 0);
			candidates[ i ].sr_msgid = META_MSGID_IGNORE;
			break;

		case META_SEARCH_NEED_BIND:
		case META_SEARCH_CONNECTING:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_search: NEED_BIND "
			       "cnd=\"%ld\" %p\n", op->o_log_prefix, i , &mc->mc_conns[i]);
			ncandidates++;
			rc = asyncmeta_dobind_init(op, rs, bc, mc, i);
			if (rc == META_SEARCH_ERR) {
				candidates[ i ].sr_msgid = META_MSGID_IGNORE;
				if ( META_BACK_ONERR_STOP( mi ) ) {
					asyncmeta_handle_onerr_stop(op,rs,mc,bc,i,cb);
					goto finish;
				}
				else {
					continue;
				}
			}
			break;
		case META_SEARCH_BINDING:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_search: BINDING "
			       "cnd=\"%ld\" %p\n", op->o_log_prefix, i , &mc->mc_conns[i]);
			ncandidates++;
			/* Todo add the context to the message queue but do not send the request
			 the receiver must send this when we are done binding */
			/* question - how would do receiver know to which targets??? */
			break;

		case META_SEARCH_ERR:
			Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_search: SEARCH_ERR "
			       "cnd=\"%ldd\"\n", op->o_log_prefix, i , 0);
			candidates[ i ].sr_msgid = META_MSGID_IGNORE;
			candidates[ i ].sr_type = REP_RESULT;

			if ( META_BACK_ONERR_STOP( mi ) ) {
				asyncmeta_handle_onerr_stop(op,rs,mc,bc,i,cb);
				goto finish;
			}
			else {
				continue;
			}
			break;

		default:
			assert( 0 );
			break;
		}
	}

	initial_candidates = ncandidates;

	if ( LogTest( LDAP_DEBUG_TRACE ) ) {
		char	cnd[ SLAP_TEXT_BUFLEN ];
		int	c;

		for ( c = 0; c < mi->mi_ntargets; c++ ) {
			if ( META_IS_CANDIDATE( &candidates[ c ] ) ) {
				cnd[ c ] = '*';
			} else {
				cnd[ c ] = ' ';
			}
		}
		cnd[ c ] = '\0';

		Debug( LDAP_DEBUG_TRACE, "%s asyncmeta_back_search: ncandidates=%d "
			"cnd=\"%s\"\n", op->o_log_prefix, ncandidates, cnd );
	}

	if ( initial_candidates == 0 ) {
		/* NOTE: here we are not sending any matchedDN;
		 * this is intended, because if the back-meta
		 * is serving this search request, but no valid
		 * candidate could be looked up, it means that
		 * there is a hole in the mapping of the targets
		 * and thus no knowledge of any remote superior
		 * is available */
		Debug( LDAP_DEBUG_ANY, "%s asyncmeta_back_search: "
			"base=\"%s\" scope=%d: "
			"no candidate could be selected\n",
			op->o_log_prefix, op->o_req_dn.bv_val,
			op->ors_scope );

		/* FIXME: we're sending the first error we encounter;
		 * maybe we should pick the worst... */
		rc = LDAP_NO_SUCH_OBJECT;
		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( META_IS_CANDIDATE( &candidates[ i ] )
				&& candidates[ i ].sr_err != LDAP_SUCCESS )
			{
				rc = candidates[ i ].sr_err;
				break;
			}
		}
		rs->sr_err = rc;
		ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
		asyncmeta_drop_bc(mc, bc);
		ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
		op->o_callback = cb;
		send_ldap_result(op, rs);
		asyncmeta_clear_bm_context(bc);
		goto finish;
	}
	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex);
	asyncmeta_start_listeners(mc, candidates, bc);
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex);
finish:
	return rs->sr_err;
}
