/* bind.c - bind request handler functions for binding
 * to remote targets for back-asyncmeta */
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

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>


#define AVL_INTERNAL
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"

#include "lutil_ldap.h"

static int
asyncmeta_proxy_authz_bind(
	a_metaconn_t		*mc,
	int			candidate,
	Operation		*op,
	SlapReply		*rs,
	ldap_back_send_t	sendok,
	int			dolock );

static int
asyncmeta_single_bind(
	Operation		*op,
	SlapReply		*rs,
	a_metaconn_t		*mc,
	int			candidate );

int
asyncmeta_back_bind( Operation *op, SlapReply *rs )
{
	a_metainfo_t	*mi = ( a_metainfo_t * )op->o_bd->be_private;
	a_metaconn_t	*mc = NULL;

	int		rc = LDAP_OTHER,
			i,
			gotit = 0,
			isroot = 0;

	SlapReply	*candidates;

	candidates = op->o_tmpcalloc(mi->mi_ntargets, sizeof(SlapReply),op->o_tmpmemctx);
	rs->sr_err = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_ARGS, "%s asyncmeta_back_bind: dn=\"%s\".\n",
		op->o_log_prefix, op->o_req_dn.bv_val, 0 );

	/* the test on the bind method should be superfluous */
	switch ( be_rootdn_bind( op, rs ) ) {
	case LDAP_SUCCESS:
		if ( META_BACK_DEFER_ROOTDN_BIND( mi ) ) {
			/* frontend will return success */
			return rs->sr_err;
		}

		isroot = 1;
		/* fallthru */

	case SLAP_CB_CONTINUE:
		break;

	default:
		/* be_rootdn_bind() sent result */
		return rs->sr_err;
	}

	/* we need asyncmeta_getconn() not send result even on error,
	 * because we want to intercept the error and make it
	 * invalidCredentials */
	mc = asyncmeta_getconn( op, rs, candidates, NULL, LDAP_BACK_BIND_DONTSEND, 1 );
	if ( !mc ) {
		if ( LogTest( LDAP_DEBUG_ANY ) ) {
			char	buf[ SLAP_TEXT_BUFLEN ];

			snprintf( buf, sizeof( buf ),
				"asyncmeta_back_bind: no target "
				"for dn \"%s\" (%d%s%s).",
				op->o_req_dn.bv_val, rs->sr_err,
				rs->sr_text ? ". " : "",
				rs->sr_text ? rs->sr_text : "" );
			Debug( LDAP_DEBUG_ANY,
				"%s %s\n",
				op->o_log_prefix, buf, 0 );
		}

		/* FIXME: there might be cases where we don't want
		 * to map the error onto invalidCredentials */
		switch ( rs->sr_err ) {
		case LDAP_NO_SUCH_OBJECT:
		case LDAP_UNWILLING_TO_PERFORM:
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			rs->sr_text = NULL;
			break;
		}
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/*
	 * Each target is scanned ...
	 */
	mc->mc_authz_target = META_BOUND_NONE;
	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		a_metatarget_t	*mt = mi->mi_targets[ i ];
		int		lerr;

		/*
		 * Skip non-candidates
		 */
		if ( !META_IS_CANDIDATE( &candidates[ i ] ) ) {
			continue;
		}

		if ( gotit == 0 ) {
			/* set rc to LDAP_SUCCESS only if at least
			 * one candidate has been tried */
			rc = LDAP_SUCCESS;
			gotit = 1;

		} else if ( !isroot ) {
			/*
			 * A bind operation is expected to have
			 * ONE CANDIDATE ONLY!
			 */
			Debug( LDAP_DEBUG_ANY,
				"### %s asyncmeta_back_bind: more than one"
				" candidate selected...\n",
				op->o_log_prefix, 0, 0 );
		}

		if ( isroot ) {
			if ( mt->mt_idassert_authmethod == LDAP_AUTH_NONE
				|| BER_BVISNULL( &mt->mt_idassert_authcDN ) )
			{
				a_metasingleconn_t	*msc = &mc->mc_conns[ i ];

				if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
					ch_free( msc->msc_bound_ndn.bv_val );
					BER_BVZERO( &msc->msc_bound_ndn );
				}

				if ( !BER_BVISNULL( &msc->msc_cred ) ) {
					/* destroy sensitive data */
					memset( msc->msc_cred.bv_val, 0,
						msc->msc_cred.bv_len );
					ch_free( msc->msc_cred.bv_val );
					BER_BVZERO( &msc->msc_cred );
				}

				continue;
			}


			(void)asyncmeta_proxy_authz_bind( mc, i, op, rs, LDAP_BACK_DONTSEND, 1 );
			lerr = rs->sr_err;

		} else {
			lerr = asyncmeta_single_bind( op, rs, mc, i );
		}

		if ( lerr != LDAP_SUCCESS ) {
			rc = rs->sr_err = lerr;

			/* FIXME: in some cases (e.g. unavailable)
			 * do not assume it's not candidate; rather
			 * mark this as an error to be eventually
			 * reported to client */
			META_CANDIDATE_CLEAR( &candidates[ i ] );
			break;
		}
	}

	if ( mc != NULL ) {
		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			a_metasingleconn_t	*msc = &mc->mc_conns[ i ];
			if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
				ch_free( msc->msc_bound_ndn.bv_val );
			}

			if ( !BER_BVISNULL( &msc->msc_cred ) ) {
				/* destroy sensitive data */
				memset( msc->msc_cred.bv_val, 0,
					msc->msc_cred.bv_len );
				ch_free( msc->msc_cred.bv_val );
			}
		}
		asyncmeta_back_conn_free( mc );
	}

	/*
	 * rc is LDAP_SUCCESS if at least one bind succeeded,
	 * err is the last error that occurred during a bind;
	 * if at least (and at most?) one bind succeeds, fine.
	 */
	if ( rc != LDAP_SUCCESS ) {

		/*
		 * deal with bind failure ...
		 */

		/*
		 * no target was found within the naming context,
		 * so bind must fail with invalid credentials
		 */
		if ( rs->sr_err == LDAP_SUCCESS && gotit == 0 ) {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
		} else {
			rs->sr_err = slap_map_api2result( rs );
		}
		send_ldap_result( op, rs );
		return rs->sr_err;

	}
	return LDAP_SUCCESS;
}

static int
asyncmeta_bind_op_result(
	Operation		*op,
	SlapReply		*rs,
	a_metaconn_t		*mc,
	int			candidate,
	int			msgid,
	ldap_back_send_t	sendok,
	int			dolock )
{
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	LDAPMessage		*res;
	struct timeval		tv;
	int			rc;
	int			nretries = mt->mt_nretries;
	char			buf[ SLAP_TEXT_BUFLEN ];

	Debug( LDAP_DEBUG_TRACE,
		">>> %s asyncmeta_bind_op_result[%d]\n",
		op->o_log_prefix, candidate, 0 );

	/* make sure this is clean */
	assert( rs->sr_ctrls == NULL );

	if ( rs->sr_err == LDAP_SUCCESS ) {
		time_t		stoptime = (time_t)(-1),
				timeout;
		int		timeout_err = op->o_protocol >= LDAP_VERSION3 ?
				LDAP_ADMINLIMIT_EXCEEDED : LDAP_OTHER;
		const char	*timeout_text = "Operation timed out";
		slap_op_t	opidx = slap_req2op( op->o_tag );

		/* since timeout is not specified, compute and use
		 * the one specific to the ongoing operation */
		if ( opidx == LDAP_REQ_SEARCH ) {
			if ( op->ors_tlimit <= 0 ) {
				timeout = 0;

			} else {
				timeout = op->ors_tlimit;
				timeout_err = LDAP_TIMELIMIT_EXCEEDED;
				timeout_text = NULL;
			}

		} else {
			timeout = mt->mt_timeout[ opidx ];
		}

		/* better than nothing :) */
		if ( timeout == 0 ) {
			if ( mi->mi_idle_timeout ) {
				timeout = mi->mi_idle_timeout;

			}
		}

		if ( timeout ) {
			stoptime = op->o_time + timeout;
		}

		LDAP_BACK_TV_SET( &tv );

		/*
		 * handle response!!!
		 */
retry:;
		rc = ldap_result( msc->msc_ld, msgid, LDAP_MSG_ALL, &tv, &res );
		switch ( rc ) {
		case 0:
			if ( nretries != META_RETRY_NEVER
				|| ( timeout && slap_get_time() <= stoptime ) )
			{
				ldap_pvt_thread_yield();
				if ( nretries > 0 ) {
					nretries--;
				}
				tv = mt->mt_bind_timeout;
				goto retry;
			}

			/* don't let anyone else use this handler,
			 * because there's a pending bind that will not
			 * be acknowledged */
			assert( LDAP_BACK_CONN_BINDING( msc ) );

#ifdef DEBUG_205
			Debug( LDAP_DEBUG_ANY, "### %s asyncmeta_bind_op_result ldap_unbind_ext[%d] ld=%p\n",
				op->o_log_prefix, candidate, (void *)msc->msc_ld );
#endif /* DEBUG_205 */

			rs->sr_err = timeout_err;
			rs->sr_text = timeout_text;
			break;

		case -1:
			ldap_get_option( msc->msc_ld, LDAP_OPT_ERROR_NUMBER,
				&rs->sr_err );

			snprintf( buf, sizeof( buf ),
				"err=%d (%s) nretries=%d",
				rs->sr_err, ldap_err2string( rs->sr_err ), nretries );
			Debug( LDAP_DEBUG_ANY,
				"### %s asyncmeta_bind_op_result[%d]: %s.\n",
				op->o_log_prefix, candidate, buf );
			break;

		default:
			/* only touch when activity actually took place... */
			if ( mi->mi_idle_timeout != 0 && msc->msc_time < op->o_time ) {
				msc->msc_time = op->o_time;
			}

			/* FIXME: matched? referrals? response controls? */
			rc = ldap_parse_result( msc->msc_ld, res, &rs->sr_err,
					NULL, NULL, NULL, NULL, 1 );
			if ( rc != LDAP_SUCCESS ) {
				rs->sr_err = rc;
			}
			rs->sr_err = slap_map_api2result( rs );
			break;
		}
	}

	rs->sr_err = slap_map_api2result( rs );
	Debug( LDAP_DEBUG_TRACE,
		"<<< %s asyncmeta_bind_op_result[%d] err=%d\n",
		op->o_log_prefix, candidate, rs->sr_err );

	return rs->sr_err;
}

/*
 * asyncmeta_single_bind
 *
 * attempts to perform a bind with creds
 */
static int
asyncmeta_single_bind(
	Operation		*op,
	SlapReply		*rs,
	a_metaconn_t		*mc,
	int			candidate )
{
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	struct berval		mdn = BER_BVNULL;
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	int			msgid;
	a_dncookie		dc;
	struct berval		save_o_dn;
	int			save_o_do_not_cache;
	LDAPControl		**ctrls = NULL;

	if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
		ch_free( msc->msc_bound_ndn.bv_val );
		BER_BVZERO( &msc->msc_bound_ndn );
	}

	if ( !BER_BVISNULL( &msc->msc_cred ) ) {
		/* destroy sensitive data */
		memset( msc->msc_cred.bv_val, 0, msc->msc_cred.bv_len );
		ch_free( msc->msc_cred.bv_val );
		BER_BVZERO( &msc->msc_cred );
	}

	/*
	 * Rewrite the bind dn if needed
	 */
	dc.target = mt;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "bindDN";

	if ( asyncmeta_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		rs->sr_text = "DN rewrite error";
		rs->sr_err = LDAP_OTHER;
		return rs->sr_err;
	}

	/* don't add proxyAuthz; set the bindDN */
	save_o_dn = op->o_dn;
	save_o_do_not_cache = op->o_do_not_cache;
	op->o_do_not_cache = 1;
	op->o_dn = op->o_req_dn;

	ctrls = op->o_ctrls;
	rs->sr_err = asyncmeta_controls_add( op, rs, mc, candidate, &ctrls );
	op->o_dn = save_o_dn;
	op->o_do_not_cache = save_o_do_not_cache;
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto return_results;
	}

	/* FIXME: this fixes the bind problem right now; we need
	 * to use the asynchronous version to get the "matched"
	 * and more in case of failure ... */
	/* FIXME: should we check if at least some of the op->o_ctrls
	 * can/should be passed? */
	for (;;) {
		rs->sr_err = ldap_sasl_bind( msc->msc_ld, mdn.bv_val,
			LDAP_SASL_SIMPLE, &op->orb_cred,
			ctrls, NULL, &msgid );
		if ( rs->sr_err != LDAP_X_CONNECTING ) {
			break;
		}
		ldap_pvt_thread_yield();
	}

	mi->mi_ldap_extra->controls_free( op, rs, &ctrls );

	asyncmeta_bind_op_result( op, rs, mc, candidate, msgid, LDAP_BACK_DONTSEND, 1 );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto return_results;
	}

	/* If defined, proxyAuthz will be used also when
	 * back-ldap is the authorizing backend; for this
	 * purpose, a successful bind is followed by a
	 * bind with the configured identity assertion */
	/* NOTE: use with care */
	if ( mt->mt_idassert_flags & LDAP_BACK_AUTH_OVERRIDE ) {
		asyncmeta_proxy_authz_bind( mc, candidate, op, rs, LDAP_BACK_SENDERR, 1 );
		if ( !LDAP_BACK_CONN_ISBOUND( msc ) ) {
			goto return_results;
		}
		goto cache_refresh;
	}

	ber_bvreplace( &msc->msc_bound_ndn, &op->o_req_ndn );
	LDAP_BACK_CONN_ISBOUND_SET( msc );
	mc->mc_authz_target = candidate;

	if ( META_BACK_TGT_SAVECRED( mt ) ) {
		if ( !BER_BVISNULL( &msc->msc_cred ) ) {
			memset( msc->msc_cred.bv_val, 0,
				msc->msc_cred.bv_len );
		}
		ber_bvreplace( &msc->msc_cred, &op->orb_cred );
		ldap_set_rebind_proc( msc->msc_ld, mt->mt_rebind_f, msc );
	}

cache_refresh:;
	if ( mi->mi_cache.ttl != META_DNCACHE_DISABLED
			&& !BER_BVISEMPTY( &op->o_req_ndn ) )
	{
		( void )asyncmeta_dncache_update_entry( &mi->mi_cache,
				&op->o_req_ndn, candidate );
	}

return_results:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}

	if ( META_BACK_TGT_QUARANTINE( mt ) ) {
		asyncmeta_quarantine( op, mi, rs, candidate );
	}
	ldap_unbind_ext( msc->msc_ld, NULL, NULL );
	msc->msc_ld = NULL;
	ldap_ld_free( msc->msc_ldr, 0, NULL, NULL );
	msc->msc_ldr = NULL;
	return rs->sr_err;
}

/*
 * asyncmeta_back_single_dobind
 */
int
asyncmeta_back_single_dobind(
	Operation		*op,
	SlapReply		*rs,
	a_metaconn_t		**mcp,
	int			candidate,
	ldap_back_send_t	sendok,
	int			nretries,
	int			dolock )
{
	a_metaconn_t		*mc = *mcp;
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	int			msgid;

	assert( !LDAP_BACK_CONN_ISBOUND( msc ) );

	if ( op->o_conn != NULL &&
		!op->o_do_not_cache &&
		( BER_BVISNULL( &msc->msc_bound_ndn ) ||
			BER_BVISEMPTY( &msc->msc_bound_ndn ) ||
			( LDAP_BACK_CONN_ISPRIV( mc ) && dn_match( &msc->msc_bound_ndn, &mt->mt_idassert_authcDN ) ) ||
			( mt->mt_idassert_flags & LDAP_BACK_AUTH_OVERRIDE ) ) )
	{
		(void)asyncmeta_proxy_authz_bind( mc, candidate, op, rs, sendok, dolock );

	} else {
		char *binddn = "";
		struct berval cred = BER_BVC( "" );

		/* use credentials if available */
		if ( !BER_BVISNULL( &msc->msc_bound_ndn )
			&& !BER_BVISNULL( &msc->msc_cred ) )
		{
			binddn = msc->msc_bound_ndn.bv_val;
			cred = msc->msc_cred;
		}

		for (;;) {
			rs->sr_err = ldap_sasl_bind( msc->msc_ld,
				binddn, LDAP_SASL_SIMPLE, &cred,
				NULL, NULL, &msgid );
			if ( rs->sr_err != LDAP_X_CONNECTING ) {
				break;
			}
			ldap_pvt_thread_yield();
		}

		rs->sr_err = asyncmeta_bind_op_result( op, rs, mc, candidate, msgid, sendok, dolock );

		/* if bind succeeded, but anonymous, clear msc_bound_ndn */
		if ( rs->sr_err != LDAP_SUCCESS || binddn[0] == '\0' ) {
			if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
				ber_memfree( msc->msc_bound_ndn.bv_val );
				BER_BVZERO( &msc->msc_bound_ndn );
			}

			if ( !BER_BVISNULL( &msc->msc_cred ) ) {
				memset( msc->msc_cred.bv_val, 0, msc->msc_cred.bv_len );
				ber_memfree( msc->msc_cred.bv_val );
				BER_BVZERO( &msc->msc_cred );
			}
		}
	}

	if ( META_BACK_TGT_QUARANTINE( mt ) ) {
		asyncmeta_quarantine( op, mi, rs, candidate );
	}

	return rs->sr_err;
}

/*
 * asyncmeta_back_default_rebind
 *
 * This is a callback used for chasing referrals using the same
 * credentials as the original user on this session.
 */
int
asyncmeta_back_default_rebind(
	LDAP			*ld,
	LDAP_CONST char		*url,
	ber_tag_t		request,
	ber_int_t		msgid,
	void			*params )
{
	a_metasingleconn_t	*msc = ( a_metasingleconn_t * )params;

	return ldap_sasl_bind_s( ld, msc->msc_bound_ndn.bv_val,
			LDAP_SASL_SIMPLE, &msc->msc_cred,
			NULL, NULL, NULL );
}

/*
 * meta_back_default_urllist
 *
 * This is a callback used for mucking with the urllist
 */
int
asyncmeta_back_default_urllist(
	LDAP		*ld,
	LDAPURLDesc	**urllist,
	LDAPURLDesc	**url,
	void		*params )
{
	a_metatarget_t	*mt = (a_metatarget_t *)params;
	LDAPURLDesc	**urltail;

	if ( urllist == url ) {
		return LDAP_SUCCESS;
	}

	for ( urltail = &(*url)->lud_next; *urltail; urltail = &(*urltail)->lud_next )
		/* count */ ;

	*urltail = *urllist;
	*urllist = *url;
	*url = NULL;

	ldap_pvt_thread_mutex_lock( &mt->mt_uri_mutex );
	if ( mt->mt_uri ) {
		ch_free( mt->mt_uri );
	}

	ldap_get_option( ld, LDAP_OPT_URI, (void *)&mt->mt_uri );
	ldap_pvt_thread_mutex_unlock( &mt->mt_uri_mutex );

	return LDAP_SUCCESS;
}

int
asyncmeta_back_cancel(
	a_metaconn_t		*mc,
	Operation		*op,
	ber_int_t		msgid,
	int			candidate )
{

	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

	int			rc = LDAP_OTHER;

	Debug( LDAP_DEBUG_TRACE, ">>> %s asyncmeta_back_cancel[%d] msgid=%d\n",
		op->o_log_prefix, candidate, msgid );

	if (msc->msc_ld == NULL) {
		Debug( LDAP_DEBUG_TRACE, ">>> %s asyncmeta_back_cancel[%d] msgid=%d\n already reset",
		op->o_log_prefix, candidate, msgid );
		return LDAP_SUCCESS;
	}

	/* default behavior */
	if ( META_BACK_TGT_ABANDON( mt ) ) {
		rc = ldap_abandon_ext( msc->msc_ld, msgid, NULL, NULL );

	} else if ( META_BACK_TGT_IGNORE( mt ) ) {
		rc = ldap_pvt_discard( msc->msc_ld, msgid );

	} else if ( META_BACK_TGT_CANCEL( mt ) ) {
		rc = ldap_cancel_s( msc->msc_ld, msgid, NULL, NULL );

	} else {
		assert( 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< %s asyncmeta_back_cancel[%d] err=%d\n",
		op->o_log_prefix, candidate, rc );

	return rc;
}


int
asyncmeta_back_abandon_candidate(
	a_metaconn_t		*mc,
	Operation		*op,
	ber_int_t		msgid,
	int			candidate )
{

	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

	int			rc = LDAP_OTHER;

	Debug( LDAP_DEBUG_TRACE, ">>> %s asyncmeta_back_abandon[%d] msgid=%d\n",
		op->o_log_prefix, candidate, msgid );

	rc = ldap_abandon_ext( msc->msc_ld, msgid, NULL, NULL );

	Debug( LDAP_DEBUG_TRACE, "<<< %s asyncmeta_back_abandon[%d] err=%d\n",
		op->o_log_prefix, candidate, rc );

	return rc;
}

int
asyncmeta_back_cancel_msc(
	Operation		*op,
	SlapReply		*rs,
	ber_int_t		msgid,
	a_metasingleconn_t	*msc,
	int                     candidate,
	ldap_back_send_t	sendok )
{
	a_metainfo_t		*mi = (a_metainfo_t *)op->o_bd->be_private;

	a_metatarget_t		*mt = mi->mi_targets[ candidate ];

	int			rc = LDAP_OTHER;

	Debug( LDAP_DEBUG_TRACE, ">>> %s asyncmeta_back_cancel_msc[%d] msgid=%d\n",
		op->o_log_prefix, candidate, msgid );

	/* default behavior */
	if ( META_BACK_TGT_ABANDON( mt ) ) {
		rc = ldap_abandon_ext( msc->msc_ld, msgid, NULL, NULL );

	} else if ( META_BACK_TGT_IGNORE( mt ) ) {
		rc = ldap_pvt_discard( msc->msc_ld, msgid );

	} else if ( META_BACK_TGT_CANCEL( mt ) ) {
		rc = ldap_cancel_s( msc->msc_ld, msgid, NULL, NULL );

	} else {
		assert( 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "<<< %s asyncmeta_back_cancel_msc[%d] err=%d\n",
		op->o_log_prefix, candidate, rc );

	return rc;
}

/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
asyncmeta_back_op_result(
	a_metaconn_t		*mc,
	Operation		*op,
	SlapReply		*rs,
	int			candidate,
	ber_int_t		msgid,
	time_t			timeout,
	ldap_back_send_t	sendok )
{
	a_metainfo_t	*mi = mc->mc_info;

	const char	*save_text = rs->sr_text,
			*save_matched = rs->sr_matched;
	BerVarray	save_ref = rs->sr_ref;
	LDAPControl	**save_ctrls = rs->sr_ctrls;
	void		*matched_ctx = NULL;

	char		*matched = NULL;
	char		*text = NULL;
	char		**refs = NULL;
	LDAPControl	**ctrls = NULL;

	assert( mc != NULL );

	rs->sr_text = NULL;
	rs->sr_matched = NULL;
	rs->sr_ref = NULL;
	rs->sr_ctrls = NULL;

	if ( candidate != META_TARGET_NONE ) {
		a_metatarget_t		*mt = mi->mi_targets[ candidate ];
		a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

		if ( LDAP_ERR_OK( rs->sr_err ) ) {
			int		rc;
			struct timeval	tv;
			LDAPMessage	*res = NULL;
			time_t		stoptime = (time_t)(-1);
			int		timeout_err = op->o_protocol >= LDAP_VERSION3 ?
						LDAP_ADMINLIMIT_EXCEEDED : LDAP_OTHER;
			const char	*timeout_text = "Operation timed out";

			/* if timeout is not specified, compute and use
			 * the one specific to the ongoing operation */
			if ( timeout == (time_t)(-1) ) {
				slap_op_t	opidx = slap_req2op( op->o_tag );

				if ( opidx == SLAP_OP_SEARCH ) {
					if ( op->ors_tlimit <= 0 ) {
						timeout = 0;

					} else {
						timeout = op->ors_tlimit;
						timeout_err = LDAP_TIMELIMIT_EXCEEDED;
						timeout_text = NULL;
					}

				} else {
					timeout = mt->mt_timeout[ opidx ];
				}
			}

			/* better than nothing :) */
			if ( timeout == 0 ) {
				if ( mi->mi_idle_timeout ) {
					timeout = mi->mi_idle_timeout;

				}
			}

			if ( timeout ) {
				stoptime = op->o_time + timeout;
			}

			LDAP_BACK_TV_SET( &tv );

retry:;
			rc = ldap_result( msc->msc_ld, msgid, LDAP_MSG_ALL, &tv, &res );
			switch ( rc ) {
			case 0:
				if ( timeout && slap_get_time() > stoptime ) {
					(void)asyncmeta_back_cancel( mc, op, msgid, candidate );
					rs->sr_err = timeout_err;
					rs->sr_text = timeout_text;
					break;
				}

				LDAP_BACK_TV_SET( &tv );
				ldap_pvt_thread_yield();
				goto retry;

			case -1:
				ldap_get_option( msc->msc_ld, LDAP_OPT_RESULT_CODE,
						&rs->sr_err );
				break;


			/* otherwise get the result; if it is not
			 * LDAP_SUCCESS, record it in the reply
			 * structure (this includes
			 * LDAP_COMPARE_{TRUE|FALSE}) */
			default:
				/* only touch when activity actually took place... */
				if ( mi->mi_idle_timeout != 0 && msc->msc_time < op->o_time ) {
					msc->msc_time = op->o_time;
				}

				rc = ldap_parse_result( msc->msc_ld, res, &rs->sr_err,
						&matched, &text, &refs, &ctrls, 1 );
				res = NULL;
				if ( rc == LDAP_SUCCESS ) {
					rs->sr_text = text;
				} else {
					rs->sr_err = rc;
				}
				rs->sr_err = slap_map_api2result( rs );

				/* RFC 4511: referrals can only appear
				 * if result code is LDAP_REFERRAL */
				if ( refs != NULL
					&& refs[ 0 ] != NULL
					&& refs[ 0 ][ 0 ] != '\0' )
				{
					if ( rs->sr_err != LDAP_REFERRAL ) {
						Debug( LDAP_DEBUG_ANY,
							"%s asyncmeta_back_op_result[%d]: "
							"got referrals with err=%d\n",
							op->o_log_prefix,
							candidate, rs->sr_err );

					} else {
						int	i;

						for ( i = 0; refs[ i ] != NULL; i++ )
							/* count */ ;
						rs->sr_ref = op->o_tmpalloc( sizeof( struct berval ) * ( i + 1 ),
							op->o_tmpmemctx );
						for ( i = 0; refs[ i ] != NULL; i++ ) {
							ber_str2bv( refs[ i ], 0, 0, &rs->sr_ref[ i ] );
						}
						BER_BVZERO( &rs->sr_ref[ i ] );
					}

				} else if ( rs->sr_err == LDAP_REFERRAL ) {
					Debug( LDAP_DEBUG_ANY,
						"%s asyncmeta_back_op_result[%d]: "
						"got err=%d with null "
						"or empty referrals\n",
						op->o_log_prefix,
						candidate, rs->sr_err );

					rs->sr_err = LDAP_NO_SUCH_OBJECT;
				}

				if ( ctrls != NULL ) {
					rs->sr_ctrls = ctrls;
				}
			}

			assert( res == NULL );
		}

		/* if the error in the reply structure is not
		 * LDAP_SUCCESS, try to map it from client
		 * to server error */
		if ( !LDAP_ERR_OK( rs->sr_err ) ) {
			rs->sr_err = slap_map_api2result( rs );

			/* internal ops ( op->o_conn == NULL )
			 * must not reply to client */
			if ( op->o_conn && !op->o_do_not_cache && matched ) {

				/* record the (massaged) matched
				 * DN into the reply structure */
				rs->sr_matched = matched;
			}
		}

		if ( META_BACK_TGT_QUARANTINE( mt ) ) {
			asyncmeta_quarantine( op, mi, rs, candidate );
		}

	} else {
		int	i,
			err = rs->sr_err;

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			a_metasingleconn_t	*msc = &mc->mc_conns[ i ];
			char			*xtext = NULL;
			char			*xmatched = NULL;

			if ( msc->msc_ld == NULL ) {
				continue;
			}

			rs->sr_err = LDAP_SUCCESS;

			ldap_get_option( msc->msc_ld, LDAP_OPT_RESULT_CODE, &rs->sr_err );
			if ( rs->sr_err != LDAP_SUCCESS ) {
				/*
				 * better check the type of error. In some cases
				 * (search ?) it might be better to return a
				 * success if at least one of the targets gave
				 * positive result ...
				 */
				ldap_get_option( msc->msc_ld,
						LDAP_OPT_DIAGNOSTIC_MESSAGE, &xtext );
				if ( xtext != NULL && xtext [ 0 ] == '\0' ) {
					ldap_memfree( xtext );
					xtext = NULL;
				}

				ldap_get_option( msc->msc_ld,
						LDAP_OPT_MATCHED_DN, &xmatched );
				if ( xmatched != NULL && xmatched[ 0 ] == '\0' ) {
					ldap_memfree( xmatched );
					xmatched = NULL;
				}

				rs->sr_err = slap_map_api2result( rs );

				if ( LogTest( LDAP_DEBUG_ANY ) ) {
					char	buf[ SLAP_TEXT_BUFLEN ];

					snprintf( buf, sizeof( buf ),
						"asyncmeta_back_op_result[%d] "
						"err=%d text=\"%s\" matched=\"%s\"",
						i, rs->sr_err,
						( xtext ? xtext : "" ),
						( xmatched ? xmatched : "" ) );
					Debug( LDAP_DEBUG_ANY, "%s %s.\n",
						op->o_log_prefix, buf, 0 );
				}

				/*
				 * FIXME: need to rewrite "match" (need rwinfo)
				 */
				switch ( rs->sr_err ) {
				default:
					err = rs->sr_err;
					if ( xtext != NULL ) {
						if ( text ) {
							ldap_memfree( text );
						}
						text = xtext;
						xtext = NULL;
					}
					if ( xmatched != NULL ) {
						if ( matched ) {
							ldap_memfree( matched );
						}
						matched = xmatched;
						xmatched = NULL;
					}
					break;
				}

				if ( xtext ) {
					ldap_memfree( xtext );
				}

				if ( xmatched ) {
					ldap_memfree( xmatched );
				}
			}

			if ( META_BACK_TGT_QUARANTINE( mi->mi_targets[ i ] ) ) {
				asyncmeta_quarantine( op, mi, rs, i );
			}
		}

		if ( err != LDAP_SUCCESS ) {
			rs->sr_err = err;
		}
	}

	if ( matched != NULL ) {
		struct berval	dn, pdn;

		ber_str2bv( matched, 0, 0, &dn );
		if ( dnPretty( NULL, &dn, &pdn, op->o_tmpmemctx ) == LDAP_SUCCESS ) {
			ldap_memfree( matched );
			matched_ctx = op->o_tmpmemctx;
			matched = pdn.bv_val;
		}
		rs->sr_matched = matched;
	}

	if ( rs->sr_err == LDAP_UNAVAILABLE ) {
		if ( !( sendok & LDAP_BACK_RETRYING ) ) {
			if ( op->o_conn && ( sendok & LDAP_BACK_SENDERR ) ) {
				if ( rs->sr_text == NULL ) rs->sr_text = "Proxy operation retry failed";
				send_ldap_result( op, rs );
			}
		}

	} else if ( op->o_conn &&
		( ( ( sendok & LDAP_BACK_SENDOK ) && LDAP_ERR_OK( rs->sr_err ) )
			|| ( ( sendok & LDAP_BACK_SENDERR ) && !LDAP_ERR_OK( rs->sr_err ) ) ) )
	{
		send_ldap_result( op, rs );
	}
	if ( matched ) {
		op->o_tmpfree( (char *)rs->sr_matched, matched_ctx );
	}
	if ( text ) {
		ldap_memfree( text );
	}
	if ( rs->sr_ref ) {
		op->o_tmpfree( rs->sr_ref, op->o_tmpmemctx );
		rs->sr_ref = NULL;
	}
	if ( refs ) {
		ber_memvfree( (void **)refs );
	}
	if ( ctrls ) {
		assert( rs->sr_ctrls != NULL );
		ldap_controls_free( ctrls );
	}

	rs->sr_text = save_text;
	rs->sr_matched = save_matched;
	rs->sr_ref = save_ref;
	rs->sr_ctrls = save_ctrls;

	return( LDAP_ERR_OK( rs->sr_err ) ? LDAP_SUCCESS : rs->sr_err );
}

/*
 * meta_back_proxy_authz_cred()
 *
 * prepares credentials & method for meta_back_proxy_authz_bind();
 * or, if method is SASL, performs the SASL bind directly.
 */
int
asyncmeta_back_proxy_authz_cred(
	a_metaconn_t		*mc,
	int			candidate,
	Operation		*op,
	SlapReply		*rs,
	ldap_back_send_t	sendok,
	struct berval		*binddn,
	struct berval		*bindcred,
	int			*method )
{
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	struct berval		ndn;
	int			dobind = 0;

	/* don't proxyAuthz if protocol is not LDAPv3 */
	switch ( mt->mt_version ) {
	case LDAP_VERSION3:
		break;

	case 0:
		if ( op->o_protocol == 0 || op->o_protocol == LDAP_VERSION3 ) {
			break;
		}
		/* fall thru */

	default:
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		if ( sendok & LDAP_BACK_SENDERR ) {
			send_ldap_result( op, rs );
		}
		LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
		goto done;
	}

	if ( op->o_tag == LDAP_REQ_BIND ) {
		ndn = op->o_req_ndn;

	} else if ( !BER_BVISNULL( &op->o_conn->c_ndn ) ) {
		ndn = op->o_conn->c_ndn;

	} else {
		ndn = op->o_ndn;
	}
	rs->sr_err = LDAP_SUCCESS;

	/*
	 * FIXME: we need to let clients use proxyAuthz
	 * otherwise we cannot do symmetric pools of servers;
	 * we have to live with the fact that a user can
	 * authorize itself as any ID that is allowed
	 * by the authzTo directive of the "proxyauthzdn".
	 */
	/*
	 * NOTE: current Proxy Authorization specification
	 * and implementation do not allow proxy authorization
	 * control to be provided with Bind requests
	 */
	/*
	 * if no bind took place yet, but the connection is bound
	 * and the "proxyauthzdn" is set, then bind as
	 * "proxyauthzdn" and explicitly add the proxyAuthz
	 * control to every operation with the dn bound
	 * to the connection as control value.
	 */

	/* bind as proxyauthzdn only if no idassert mode
	 * is requested, or if the client's identity
	 * is authorized */
	switch ( mt->mt_idassert_mode ) {
	case LDAP_BACK_IDASSERT_LEGACY:
		if ( !BER_BVISNULL( &ndn ) && !BER_BVISEMPTY( &ndn ) ) {
			if ( !BER_BVISNULL( &mt->mt_idassert_authcDN ) && !BER_BVISEMPTY( &mt->mt_idassert_authcDN ) )
			{
				*binddn = mt->mt_idassert_authcDN;
				*bindcred = mt->mt_idassert_passwd;
				dobind = 1;
			}
		}
		break;

	default:
		/* NOTE: rootdn can always idassert */
		if ( BER_BVISNULL( &ndn )
			&& mt->mt_idassert_authz == NULL
			&& !( mt->mt_idassert_flags & LDAP_BACK_AUTH_AUTHZ_ALL ) )
		{
			if ( mt->mt_idassert_flags & LDAP_BACK_AUTH_PRESCRIPTIVE ) {
				rs->sr_err = LDAP_INAPPROPRIATE_AUTH;
				if ( sendok & LDAP_BACK_SENDERR ) {
					send_ldap_result( op, rs );
				}
				LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
				goto done;

			}

			rs->sr_err = LDAP_SUCCESS;
			*binddn = slap_empty_bv;
			*bindcred = slap_empty_bv;
			break;

		} else if ( mt->mt_idassert_authz && !be_isroot( op ) ) {
			struct berval authcDN;

			if ( BER_BVISNULL( &ndn ) ) {
				authcDN = slap_empty_bv;

			} else {
				authcDN = ndn;
			}
			rs->sr_err = slap_sasl_matches( op, mt->mt_idassert_authz,
					&authcDN, &authcDN );
			if ( rs->sr_err != LDAP_SUCCESS ) {
				if ( mt->mt_idassert_flags & LDAP_BACK_AUTH_PRESCRIPTIVE ) {
					if ( sendok & LDAP_BACK_SENDERR ) {
						send_ldap_result( op, rs );
					}
					LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
					goto done;
				}

				rs->sr_err = LDAP_SUCCESS;
				*binddn = slap_empty_bv;
				*bindcred = slap_empty_bv;
				break;
			}
		}

		*binddn = mt->mt_idassert_authcDN;
		*bindcred = mt->mt_idassert_passwd;
		dobind = 1;
		break;
	}

	if ( dobind && mt->mt_idassert_authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		void		*defaults = NULL;
		struct berval	authzID = BER_BVNULL;
		int		freeauthz = 0;

		/* if SASL supports native authz, prepare for it */
		if ( ( !op->o_do_not_cache || !op->o_is_auth_check ) &&
				( mt->mt_idassert_flags & LDAP_BACK_AUTH_NATIVE_AUTHZ ) )
		{
			switch ( mt->mt_idassert_mode ) {
			case LDAP_BACK_IDASSERT_OTHERID:
			case LDAP_BACK_IDASSERT_OTHERDN:
				authzID = mt->mt_idassert_authzID;
				break;

			case LDAP_BACK_IDASSERT_ANONYMOUS:
				BER_BVSTR( &authzID, "dn:" );
				break;

			case LDAP_BACK_IDASSERT_SELF:
				if ( BER_BVISNULL( &ndn ) ) {
					/* connection is not authc'd, so don't idassert */
					BER_BVSTR( &authzID, "dn:" );
					break;
				}
				authzID.bv_len = STRLENOF( "dn:" ) + ndn.bv_len;
				authzID.bv_val = slap_sl_malloc( authzID.bv_len + 1, op->o_tmpmemctx );
				AC_MEMCPY( authzID.bv_val, "dn:", STRLENOF( "dn:" ) );
				AC_MEMCPY( authzID.bv_val + STRLENOF( "dn:" ),
						ndn.bv_val, ndn.bv_len + 1 );
				freeauthz = 1;
				break;

			default:
				break;
			}
		}

		if ( mt->mt_idassert_secprops != NULL ) {
			rs->sr_err = ldap_set_option( msc->msc_ld,
				LDAP_OPT_X_SASL_SECPROPS,
				(void *)mt->mt_idassert_secprops );

			if ( rs->sr_err != LDAP_OPT_SUCCESS ) {
				rs->sr_err = LDAP_OTHER;
				if ( sendok & LDAP_BACK_SENDERR ) {
					send_ldap_result( op, rs );
				}
				LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
				goto done;
			}
		}

		defaults = lutil_sasl_defaults( msc->msc_ld,
				mt->mt_idassert_sasl_mech.bv_val,
				mt->mt_idassert_sasl_realm.bv_val,
				mt->mt_idassert_authcID.bv_val,
				mt->mt_idassert_passwd.bv_val,
				authzID.bv_val );
		if ( defaults == NULL ) {
			rs->sr_err = LDAP_OTHER;
			LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
			}
			goto done;
		}

		rs->sr_err = ldap_sasl_interactive_bind_s( msc->msc_ld, binddn->bv_val,
				mt->mt_idassert_sasl_mech.bv_val, NULL, NULL,
				LDAP_SASL_QUIET, lutil_sasl_interact,
				defaults );

		rs->sr_err = slap_map_api2result( rs );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
			}

		} else {
			LDAP_BACK_CONN_ISBOUND_SET( msc );
		}

		lutil_sasl_freedefs( defaults );
		if ( freeauthz ) {
			slap_sl_free( authzID.bv_val, op->o_tmpmemctx );
		}

		goto done;
#endif /* HAVE_CYRUS_SASL */
	}

	*method = mt->mt_idassert_authmethod;
	switch ( mt->mt_idassert_authmethod ) {
	case LDAP_AUTH_NONE:
		BER_BVSTR( binddn, "" );
		BER_BVSTR( bindcred, "" );
		/* fallthru */

	case LDAP_AUTH_SIMPLE:
		break;

	default:
		/* unsupported! */
		LDAP_BACK_CONN_ISBOUND_CLEAR( msc );
		rs->sr_err = LDAP_AUTH_METHOD_NOT_SUPPORTED;
		if ( sendok & LDAP_BACK_SENDERR ) {
			send_ldap_result( op, rs );
		}
		break;
	}

done:;

	if ( !BER_BVISEMPTY( binddn ) ) {
		LDAP_BACK_CONN_ISIDASSERT_SET( msc );
	}

	return rs->sr_err;
}

static int
asyncmeta_proxy_authz_bind(
	a_metaconn_t *mc,
	int candidate,
	Operation *op,
	SlapReply *rs,
	ldap_back_send_t sendok,
	int dolock )
{
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	struct berval		binddn = BER_BVC( "" ),
				cred = BER_BVC( "" );
	int			method = LDAP_AUTH_NONE,
				rc;

	rc = asyncmeta_back_proxy_authz_cred( mc, candidate, op, rs, sendok, &binddn, &cred, &method );
	if ( rc == LDAP_SUCCESS && !LDAP_BACK_CONN_ISBOUND( msc ) ) {
		int	msgid;

		switch ( method ) {
		case LDAP_AUTH_NONE:
		case LDAP_AUTH_SIMPLE:
			for (;;) {
				rs->sr_err = ldap_sasl_bind( msc->msc_ld,
					binddn.bv_val, LDAP_SASL_SIMPLE,
					&cred, NULL, NULL, &msgid );
				if ( rs->sr_err != LDAP_X_CONNECTING ) {
					break;
				}
				ldap_pvt_thread_yield();
			}

			rc = asyncmeta_bind_op_result( op, rs, mc, candidate, msgid, sendok, dolock );
			if ( rc == LDAP_SUCCESS ) {
				/* set rebind stuff in case of successful proxyAuthz bind,
				 * so that referral chasing is attempted using the right
				 * identity */
				LDAP_BACK_CONN_ISBOUND_SET( msc );
				ber_bvreplace( &msc->msc_bound_ndn, &binddn );

				if ( META_BACK_TGT_SAVECRED( mt ) ) {
					if ( !BER_BVISNULL( &msc->msc_cred ) ) {
						memset( msc->msc_cred.bv_val, 0,
							msc->msc_cred.bv_len );
					}
					ber_bvreplace( &msc->msc_cred, &cred );
					ldap_set_rebind_proc( msc->msc_ld, mt->mt_rebind_f, msc );
				}
			}
			break;

		default:
			assert( 0 );
			break;
		}
	}

	return LDAP_BACK_CONN_ISBOUND( msc );
}

/*
 * Add controls;
 *
 * if any needs to be added, it is prepended to existing ones,
 * in a newly allocated array.  The companion function
 * mi->mi_ldap_extra->controls_free() must be used to restore the original
 * status of op->o_ctrls.
 */
int
asyncmeta_controls_add(
		Operation	*op,
		SlapReply	*rs,
		a_metaconn_t	*mc,
		int		candidate,
		LDAPControl	***pctrls )
{
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

	LDAPControl		**ctrls = NULL;
	/* set to the maximum number of controls this backend can add */
	LDAPControl		c[ 2 ] = {{ 0 }};
	int			n = 0, i, j1 = 0, j2 = 0;

	*pctrls = NULL;

	rs->sr_err = LDAP_SUCCESS;

	/* don't add controls if protocol is not LDAPv3 */
	switch ( mt->mt_version ) {
	case LDAP_VERSION3:
		break;

	case 0:
		if ( op->o_protocol == 0 || op->o_protocol == LDAP_VERSION3 ) {
			break;
		}
		/* fall thru */

	default:
		goto done;
	}

	/* put controls that go __before__ existing ones here */

	/* proxyAuthz for identity assertion */
	switch ( mi->mi_ldap_extra->proxy_authz_ctrl( op, rs, &msc->msc_bound_ndn,
		mt->mt_version, &mt->mt_idassert, &c[ j1 ] ) )
	{
	case SLAP_CB_CONTINUE:
		break;

	case LDAP_SUCCESS:
		j1++;
		break;

	default:
		goto done;
	}

	/* put controls that go __after__ existing ones here */

#ifdef SLAP_CONTROL_X_SESSION_TRACKING
	/* session tracking */
	if ( META_BACK_TGT_ST_REQUEST( mt ) ) {
		switch ( slap_ctrl_session_tracking_request_add( op, rs, &c[ j1 + j2 ] ) ) {
		case SLAP_CB_CONTINUE:
			break;

		case LDAP_SUCCESS:
			j2++;
			break;

		default:
			goto done;
		}
	}
#endif /* SLAP_CONTROL_X_SESSION_TRACKING */

	if ( rs->sr_err == SLAP_CB_CONTINUE ) {
		rs->sr_err = LDAP_SUCCESS;
	}

	/* if nothing to do, just bail out */
	if ( j1 == 0 && j2 == 0 ) {
		goto done;
	}

	assert( j1 + j2 <= (int) (sizeof( c )/sizeof( c[0] )) );

	if ( op->o_ctrls ) {
		for ( n = 0; op->o_ctrls[ n ]; n++ )
			/* just count ctrls */ ;
	}

	ctrls = op->o_tmpalloc( (n + j1 + j2 + 1) * sizeof( LDAPControl * ) + ( j1 + j2 ) * sizeof( LDAPControl ),
			op->o_tmpmemctx );
	if ( j1 ) {
		ctrls[ 0 ] = (LDAPControl *)&ctrls[ n + j1 + j2 + 1 ];
		*ctrls[ 0 ] = c[ 0 ];
		for ( i = 1; i < j1; i++ ) {
			ctrls[ i ] = &ctrls[ 0 ][ i ];
			*ctrls[ i ] = c[ i ];
		}
	}

	i = 0;
	if ( op->o_ctrls ) {
		for ( i = 0; op->o_ctrls[ i ]; i++ ) {
			ctrls[ i + j1 ] = op->o_ctrls[ i ];
		}
	}

	n += j1;
	if ( j2 ) {
		ctrls[ n ] = (LDAPControl *)&ctrls[ n + j2 + 1 ] + j1;
		*ctrls[ n ] = c[ j1 ];
		for ( i = 1; i < j2; i++ ) {
			ctrls[ n + i ] = &ctrls[ n ][ i ];
			*ctrls[ n + i ] = c[ i ];
		}
	}

	ctrls[ n + j2 ] = NULL;

done:;
	if ( ctrls == NULL ) {
		ctrls = op->o_ctrls;
	}

	*pctrls = ctrls;

	return rs->sr_err;
}

#if 0
/*
 * Add controls;
 *
 * same as asyncmeta_controls_add, but creates a new controls array
 * to be used by the operation copy
 */
int
asyncmeta_controls_add_copy(
		Operation	*op,
		SlapReply	*rs,
		a_metaconn_t	*mc,
		int		candidate,
		LDAPControl	***pctrls )
{
	a_metainfo_t		*mi = (a_metainfo_t *)op->o_bd->be_private;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = mc->mc_conns[ candidate ];

	LDAPControl		**ctrls = NULL;
	/* set to the maximum number of controls this backend can add */
	LDAPControl		c[ 2 ] = {{ 0 }};
	int			n = 0, i, j1 = 0, j2 = 0;

	*pctrls = NULL;

	rs->sr_err = LDAP_SUCCESS;

	/* don't add controls if protocol is not LDAPv3 */
	switch ( mt->mt_version ) {
	case LDAP_VERSION3:
		break;

	case 0:
		if ( op->o_protocol == 0 || op->o_protocol == LDAP_VERSION3 ) {
			break;
		}
		/* fall thru */

	default:
		goto done;
	}

	/* put controls that go __before__ existing ones here */

	/* proxyAuthz for identity assertion */
	switch ( mi->mi_ldap_extra->proxy_authz_ctrl( op, rs, &msc->msc_bound_ndn,
		mt->mt_version, &mt->mt_idassert, &c[ j1 ] ) )
	{
	case SLAP_CB_CONTINUE:
		break;

	case LDAP_SUCCESS:
		j1++;
		break;

	default:
		goto done;
	}

	/* put controls that go __after__ existing ones here */

#ifdef SLAP_CONTROL_X_SESSION_TRACKING
	/* session tracking */
	if ( META_BACK_TGT_ST_REQUEST( mt ) ) {
		switch ( slap_ctrl_session_tracking_request_add( op, rs, &c[ j1 + j2 ] ) ) {
		case SLAP_CB_CONTINUE:
			break;

		case LDAP_SUCCESS:
			j2++;
			break;

		default:
			goto copy;
		}
	}
#endif /* SLAP_CONTROL_X_SESSION_TRACKING */

	if ( rs->sr_err == SLAP_CB_CONTINUE ) {
		rs->sr_err = LDAP_SUCCESS;
	}

copy:
	if ( op->o_ctrls ) {
		for ( n = 0; op->o_ctrls[ n ]; n++ )
			/* just count ctrls */ ;
	}

	ctrls = ch_calloc( (n + j1 + j2 + 1) * sizeof( LDAPControl * ) + ( j1 + j2 ) * sizeof( LDAPControl ));
	if ( j1 ) {
		ctrls[ 0 ] = (LDAPControl *)&ctrls[ n + j1 + j2 + 1 ];
		*ctrls[ 0 ] = c[ 0 ];
		for ( i = 1; i < j1; i++ ) {
			ctrls[ i ] = &ctrls[ 0 ][ i ];
			*ctrls[ i ] = c[ i ];
		}
	}

	i = 0;
	if ( op->o_ctrls ) {
		for ( i = 0; op->o_ctrls[ i ]; i++ ) {
			ctrls[ i + j1 ] = op->o_ctrls[ i ];
		}
	}

	n += j1;
	if ( j2 ) {
		ctrls[ n ] = (LDAPControl *)&ctrls[ n + j2 + 1 ] + j1;
		*ctrls[ n ] = c[ j1 ];
		for ( i = 1; i < j2; i++ ) {
			ctrls[ n + i ] = &ctrls[ n ][ i ];
			*ctrls[ n + i ] = c[ i ];
		}
	}

	ctrls[ n + j2 ] = NULL;

done:;

	op->o_ctrls = ctrls;

	return rs->sr_err;
}
#endif

/*
 * asyncmeta_dobind_init()
 *
 * initiates bind for a candidate target
 */
meta_search_candidate_t
asyncmeta_dobind_init(Operation *op, SlapReply *rs, bm_context_t *bc, a_metaconn_t *mc, int candidate)
{
	SlapReply		*candidates = bc->candidates;
	a_metainfo_t		*mi = ( a_metainfo_t * )mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	a_metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	ber_socket_t s;
	struct berval		binddn = msc->msc_bound_ndn,
				cred = msc->msc_cred;
	int			method;

	int			rc;
	ber_int_t	msgid;

	meta_search_candidate_t	retcode;

	Debug( LDAP_DEBUG_TRACE, "%s >>> asyncmeta_search_dobind_init[%d]\n",
		op->o_log_prefix, candidate, 0 );

	if ( mc->mc_authz_target == META_BOUND_ALL ) {
		return META_SEARCH_CANDIDATE;
	}

	retcode = META_SEARCH_BINDING;
	if ( LDAP_BACK_CONN_ISBOUND( msc ) || LDAP_BACK_CONN_ISANON( msc ) ) {
		/* already bound (or anonymous) */

#ifdef DEBUG_205
		char	buf[ SLAP_TEXT_BUFLEN ] = { '\0' };
		int	bound = 0;

		if ( LDAP_BACK_CONN_ISBOUND( msc ) ) {
			bound = 1;
		}

		snprintf( buf, sizeof( buf ), " mc=%p ld=%p%s DN=\"%s\"",
			(void *)mc, (void *)msc->msc_ld,
			bound ? " bound" : " anonymous",
			bound == 0 ? "" : msc->msc_bound_ndn.bv_val );
		Debug( LDAP_DEBUG_ANY, "### %s asyncmeta_search_dobind_init[%d]%s\n",
			op->o_log_prefix, candidate, buf );
#endif /* DEBUG_205 */

		retcode = META_SEARCH_CANDIDATE;

	} else if ( META_BACK_CONN_CREATING( msc ) || LDAP_BACK_CONN_BINDING( msc ) ) {
		/* another thread is binding the target for this conn; wait */

#ifdef DEBUG_205
		char	buf[ SLAP_TEXT_BUFLEN ] = { '\0' };

		snprintf( buf, sizeof( buf ), " mc=%p ld=%p needbind",
			(void *)mc, (void *)msc->msc_ld );
		Debug( LDAP_DEBUG_ANY, "### %s asyncmeta_search_dobind_init[%d]%s\n",
			op->o_log_prefix, candidate, buf );
#endif /* DEBUG_205 */

		candidates[ candidate ].sr_msgid = META_MSGID_NEED_BIND;
		retcode = META_SEARCH_NEED_BIND;

	} else {
		/* we'll need to bind the target for this conn */

#ifdef DEBUG_205
		char buf[ SLAP_TEXT_BUFLEN ];

		snprintf( buf, sizeof( buf ), " mc=%p ld=%p binding",
			(void *)mc, (void *)msc->msc_ld );
		Debug( LDAP_DEBUG_ANY, "### %s asyncmeta_search_dobind_init[%d]%s\n",
			op->o_log_prefix, candidate, buf );
#endif /* DEBUG_205 */

		if ( msc->msc_ld == NULL ) {
			/* for some reason (e.g. because formerly in "binding"
			 * state, with eventual connection expiration or invalidation)
			 * it was not initialized as expected */

			Debug( LDAP_DEBUG_ANY, "%s asyncmeta_search_dobind_init[%d] mc=%p ld=NULL\n",
				op->o_log_prefix, candidate, (void *)mc );

			rc = asyncmeta_init_one_conn( op, rs, mc, candidate,
				LDAP_BACK_CONN_ISPRIV( mc ), LDAP_BACK_DONTSEND, 0 );
			switch ( rc ) {
			case LDAP_SUCCESS:
				assert( msc->msc_ld != NULL );
				break;

			case LDAP_SERVER_DOWN:
			case LDAP_UNAVAILABLE:
				goto down;

			default:
				goto other;
			}
		}

		LDAP_BACK_CONN_BINDING_SET( msc );
	}

	if ( retcode != META_SEARCH_BINDING ) {
		return retcode;
	}

	if ( op->o_conn != NULL &&
		!op->o_do_not_cache &&
		( BER_BVISNULL( &msc->msc_bound_ndn ) ||
			BER_BVISEMPTY( &msc->msc_bound_ndn ) ||
			( mt->mt_idassert_flags & LDAP_BACK_AUTH_OVERRIDE ) ) )
	{
		rc = asyncmeta_back_proxy_authz_cred( mc, candidate, op, rs, LDAP_BACK_DONTSEND, &binddn, &cred, &method );
		switch ( rc ) {
		case LDAP_SUCCESS:
			break;
		case LDAP_UNAVAILABLE:
			goto down;
		default:
			goto other;
		}

		/* NOTE: we copy things here, even if bind didn't succeed yet,
		 * because the connection is not shared until bind is over */
		if ( !BER_BVISNULL( &binddn ) ) {
			ldap_pvt_thread_mutex_lock(&mc->mc_om_mutex);

			ber_bvreplace( &msc->msc_bound_ndn, &binddn );
			if ( META_BACK_TGT_SAVECRED( mt ) && !BER_BVISNULL( &cred ) ) {
				if ( !BER_BVISNULL( &msc->msc_cred ) ) {
					memset( msc->msc_cred.bv_val, 0,
						msc->msc_cred.bv_len );
				}
				ber_bvreplace( &msc->msc_cred, &cred );
			}
			ldap_pvt_thread_mutex_unlock(&mc->mc_om_mutex);
		}
		if ( LDAP_BACK_CONN_ISBOUND( msc ) ) {
			/* apparently, idassert was configured with SASL bind,
			 * so bind occurred inside meta_back_proxy_authz_cred() */
			LDAP_BACK_CONN_BINDING_CLEAR( msc );
			return META_SEARCH_CANDIDATE;
		}

		/* paranoid */
		switch ( method ) {
		case LDAP_AUTH_NONE:
		case LDAP_AUTH_SIMPLE:
			/* do a simple bind with binddn, cred */
			break;

		default:
			assert( 0 );
			break;
		}
	}

	assert( msc->msc_ld != NULL );

	if ( !BER_BVISEMPTY( &binddn ) && BER_BVISEMPTY( &cred ) ) {
		/* bind anonymously? */
		Debug( LDAP_DEBUG_ANY, "%s asyncmeta_search_dobind_init[%d] mc=%p: "
			"non-empty dn with empty cred; binding anonymously\n",
			op->o_log_prefix, candidate, (void *)mc );
		cred = slap_empty_bv;

	} else if ( BER_BVISEMPTY( &binddn ) && !BER_BVISEMPTY( &cred ) ) {
		/* error */
		Debug( LDAP_DEBUG_ANY, "%s asyncmeta_search_dobind_init[%d] mc=%p: "
			"empty dn with non-empty cred: error\n",
			op->o_log_prefix, candidate, (void *)mc );
		rc = LDAP_OTHER;
		goto other;
	}
retry_bind:
	rc = ldap_sasl_bind( msc->msc_ld, binddn.bv_val, LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, &msgid );
	ldap_get_option( msc->msc_ld, LDAP_OPT_RESULT_CODE, &rc );

	if (rc == LDAP_SERVER_DOWN ) {
		goto down;
	}
	candidates[ candidate ].sr_msgid = msgid;
	asyncmeta_set_msc_time(msc);
#ifdef DEBUG_205
	{
		char buf[ SLAP_TEXT_BUFLEN ];

		snprintf( buf, sizeof( buf ), "asyncmeta_search_dobind_init[%d] mc=%p ld=%p rc=%d",
			candidate, (void *)mc, (void *)mc->mc_conns[ candidate ].msc_ld, rc );
		Debug( LDAP_DEBUG_ANY, "### %s %s\n",
			op->o_log_prefix, buf, 0 );
	}
#endif /* DEBUG_205 */

	switch ( rc ) {
	case LDAP_SUCCESS:
		assert( msgid >= 0 );
		META_BINDING_SET( &candidates[ candidate ] );
		rs->sr_err = LDAP_SUCCESS;
		return META_SEARCH_BINDING;

	case LDAP_X_CONNECTING:
		/* must retry, same conn */
		candidates[ candidate ].sr_msgid = META_MSGID_CONNECTING;
		LDAP_BACK_CONN_BINDING_CLEAR( msc );
		goto retry_bind;

	case LDAP_SERVER_DOWN:
down:;
		retcode = META_SEARCH_ERR;
		rs->sr_err = LDAP_UNAVAILABLE;
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		break;

		/* fall thru */

	default:
other:;
		rs->sr_err = rc;
		rc = slap_map_api2result( rs );
		candidates[ candidate ].sr_err = rc;
		if ( META_BACK_ONERR_STOP( mi ) ) {
			retcode = META_SEARCH_ERR;

		} else {
			retcode = META_SEARCH_NOT_CANDIDATE;
		}
		candidates[ candidate ].sr_msgid = META_MSGID_IGNORE;
		break;
	}

	return retcode;
}




meta_search_candidate_t
asyncmeta_dobind_init_with_retry(Operation *op, SlapReply *rs, bm_context_t *bc, a_metaconn_t *mc, int candidate)
{

	int rc, retries = 1;
	a_metasingleconn_t *msc = &mc->mc_conns[candidate];
	a_metainfo_t		*mi = mc->mc_info;
	a_metatarget_t		*mt = mi->mi_targets[ candidate ];
	SlapReply		*candidates = bc->candidates;

retry_dobind:
	rc = asyncmeta_dobind_init(op, rs, bc, mc, candidate);
	if (rs->sr_err != LDAP_UNAVAILABLE) {
		return rc;
	} else if (retries <= 0) {
		ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex );
		if (mc->mc_active < 1) {
			asyncmeta_clear_one_msc(NULL, mc, candidate);
		}
		ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex );
		return rc;
	}
	/* need to retry */
	retries--;
	if ( LogTest( LDAP_DEBUG_ANY ) ) {
		char	buf[ SLAP_TEXT_BUFLEN ];

		/* this lock is required; however,
		 * it's invoked only when logging is on */
		ldap_pvt_thread_mutex_lock( &mt->mt_uri_mutex );
		snprintf( buf, sizeof( buf ),
			  "retrying URI=\"%s\" DN=\"%s\"",
			  mt->mt_uri,
			  BER_BVISNULL( &msc->msc_bound_ndn ) ?
			  "" : msc->msc_bound_ndn.bv_val );
		ldap_pvt_thread_mutex_unlock( &mt->mt_uri_mutex );

		Debug( LDAP_DEBUG_ANY,
		       "%s asyncmeta_search_dobind_init_with_retry[%d]: %s.\n",
		       op->o_log_prefix, candidate, buf );
	}

	ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex );
	if (mc->mc_active < 1) {
		asyncmeta_clear_one_msc(NULL, mc, candidate);
	}
	ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex );

	( void )rewrite_session_delete( mt->mt_rwmap.rwm_rw, op->o_conn );

	rc = asyncmeta_init_one_conn( op, rs, mc, candidate,
				      LDAP_BACK_CONN_ISPRIV( mc ), LDAP_BACK_DONTSEND, 0 );

	if (rs->sr_err != LDAP_SUCCESS) {
		ldap_pvt_thread_mutex_lock( &mc->mc_om_mutex );
		if (mc->mc_active < 1) {
			asyncmeta_clear_one_msc(NULL, mc, candidate);
		}
		ldap_pvt_thread_mutex_unlock( &mc->mc_om_mutex );
		return META_SEARCH_ERR;
	}

	goto retry_dobind;
	return rc;
}
