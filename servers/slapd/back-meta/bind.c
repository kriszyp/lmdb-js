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

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>


#define AVL_INTERNAL
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_bind( Operation *op, SlapReply *rs )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	metaconn_t	*mc = NULL;

	int		rc = LDAP_OTHER,
			i,
			gotit = 0,
			isroot = 0;

	SlapReply	*candidates = meta_back_candidates_get( op );

	rs->sr_err = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_ARGS, "%s meta_back_bind: dn=\"%s\".\n",
		op->o_log_prefix, op->o_req_dn.bv_val, 0 );

	/* the test on the bind method should be superfluous */
	if ( op->orb_method == LDAP_AUTH_SIMPLE
		&& be_isroot_dn( op->o_bd, &op->o_req_ndn ) )
	{
		if ( !be_isroot_pw( op ) ) {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			rs->sr_text = NULL;
			send_ldap_result( op, rs );
			return rs->sr_err;
		}

		if ( META_BACK_DEFER_ROOTDN_BIND( mi ) ) {
			rs->sr_err = LDAP_SUCCESS;
			rs->sr_text = NULL;
			/* frontend will return success */
			return rs->sr_err;
		}

		isroot = 1;
	}

	/* we need meta_back_getconn() not send result even on error,
	 * because we want to intercept the error and make it
	 * invalidCredentials */
	mc = meta_back_getconn( op, rs, NULL, LDAP_BACK_BIND_DONTSEND );
	if ( !mc ) {
		if ( LogTest( LDAP_DEBUG_ANY ) ) {
			char	buf[ SLAP_TEXT_BUFLEN ];

			snprintf( buf, sizeof( buf ),
				"meta_back_bind: no target "
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
		metatarget_t	*mt = mi->mi_targets[ i ];
		int		lerr;
		Operation	op2 = *op;
		int		massage = 1;

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

		} else if ( isroot == 0 ) {
			/*
			 * A bind operation is expected to have
			 * ONE CANDIDATE ONLY!
			 */
			Debug( LDAP_DEBUG_ANY,
				"### %s meta_back_bind: more than one"
				" candidate selected...\n",
				op->o_log_prefix, 0, 0 );
		}

		if ( isroot ) {
			if ( BER_BVISNULL( &mt->mt_pseudorootdn ) )
			{
				metasingleconn_t	*msc = &mc->mc_conns[ i ];

				/* skip the target if no pseudorootdn is provided */
				if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
					ch_free( msc->msc_bound_ndn.bv_val );
					BER_BVZERO( &msc->msc_bound_ndn );
				}

				if ( LDAP_BACK_SAVECRED( mi ) &&
					!BER_BVISNULL( &msc->msc_cred ) )
				{
					/* destroy sensitive data */
					memset( msc->msc_cred.bv_val, 0,
						msc->msc_cred.bv_len );
					ch_free( msc->msc_cred.bv_val );
					BER_BVZERO( &msc->msc_cred );
				}

				continue;
			}

			op2.o_req_dn = mt->mt_pseudorootdn;
			op2.o_req_ndn = mt->mt_pseudorootdn;
			op2.orb_cred = mt->mt_pseudorootpw;
			op2.orb_method = LDAP_AUTH_SIMPLE;

			massage = 0;
		}
		
		lerr = meta_back_single_bind( &op2, rs, mc, i, massage );

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

	/* must re-insert if local DN changed as result of bind */
	if ( rc == LDAP_SUCCESS ) {
		if ( isroot ) {
			mc->mc_authz_target = META_BOUND_ALL;
			ber_dupbv( &op->orb_edn, be_root_dn( op->o_bd ) );
		}

		if ( !dn_match( &op->o_req_ndn, &mc->mc_local_ndn ) ) {
			metaconn_t	*tmpmc;
			int		lerr;

			/* wait for all other ops to release the connection */
retry_lock:;
			ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
			if ( mc->mc_refcnt > 1 ) {
				ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
				ldap_pvt_thread_yield();
				goto retry_lock;
			}

			assert( mc->mc_refcnt == 1 );
			tmpmc = avl_delete( &mi->mi_conninfo.lai_tree, (caddr_t)mc,
				meta_back_conndn_cmp );
			assert( tmpmc == mc );

			/* delete all cached connections with the current connection */
			if ( LDAP_BACK_SINGLECONN( mi ) ) {
				while ( ( tmpmc = avl_delete( &mi->mi_conninfo.lai_tree, (caddr_t)mc, meta_back_conn_cmp ) ) != NULL )
				{
					Debug( LDAP_DEBUG_TRACE,
						"=>meta_back_bind: destroying conn %ld (refcnt=%u)\n",
						LDAP_BACK_PCONN_ID( mc->mc_conn ), mc->mc_refcnt, 0 );

					if ( tmpmc->mc_refcnt != 0 ) {
						/* taint it */
						LDAP_BACK_CONN_TAINTED_SET( tmpmc );

					} else {
						/*
						 * Needs a test because the handler may be corrupted,
						 * and calling ldap_unbind on a corrupted header results
						 * in a segmentation fault
						 */
						meta_back_conn_free( tmpmc );
					}
				}
			}

			ber_bvreplace( &mc->mc_local_ndn, &op->o_req_ndn );
			if ( be_isroot_dn( op->o_bd, &op->o_req_ndn ) ) {
				mc->mc_conn = LDAP_BACK_PCONN_SET( op );
			}
			lerr = avl_insert( &mi->mi_conninfo.lai_tree, (caddr_t)mc,
				meta_back_conndn_cmp, meta_back_conndn_dup );
			ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
			if ( lerr == -1 ) {
				meta_clear_candidates( op, mc );

				/* we can do this because mc_refcnt == 1 */
				mc->mc_refcnt = 0;
				meta_back_conn_free( mc );
				mc = NULL;
			}
		}
	}

	if ( mc != NULL ) {
		meta_back_release_conn( op, mc );
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
meta_back_bind_op_result(
	Operation		*op,
	SlapReply		*rs,
	metaconn_t		*mc,
	int			candidate,
	int			msgid,
	ldap_back_send_t	sendok )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metatarget_t		*mt = mi->mi_targets[ candidate ];
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	LDAPMessage		*res;
	struct timeval		tv;
	int			rc;
	int			nretries = mt->mt_nretries;
	char			buf[ SLAP_TEXT_BUFLEN ];

	if ( rs->sr_err == LDAP_SUCCESS ) {
		LDAP_BACK_TV_SET( &tv );

		/*
		 * handle response!!!
		 */
retry:;
		switch ( ldap_result( msc->msc_ld, msgid, LDAP_MSG_ALL, &tv, &res ) ) {
		case 0:
			Debug( LDAP_DEBUG_ANY,
				"%s meta_back_single_bind[%d]: ldap_result=0 nretries=%d.\n",
				op->o_log_prefix, candidate, nretries );

			if ( nretries != META_RETRY_NEVER ) {
				ldap_pvt_thread_yield();
				if ( nretries > 0 ) {
					nretries--;
				}
				tv = mt->mt_bind_timeout;
				goto retry;
			}

			rs->sr_err = LDAP_BUSY;
			(void)meta_back_cancel( mc, op, rs, msgid, candidate, sendok );
			break;

		case -1:
			ldap_get_option( msc->msc_ld, LDAP_OPT_ERROR_NUMBER,
				&rs->sr_err );

			snprintf( buf, sizeof( buf ),
				"err=%d (%s) nretries=%d",
				rs->sr_err, ldap_err2string( rs->sr_err ), nretries );
			Debug( LDAP_DEBUG_ANY,
				"### %s meta_back_single_bind[%d]: %s.\n",
				op->o_log_prefix, candidate, buf );
			break;

		default:
			rc = ldap_parse_result( msc->msc_ld, res, &rs->sr_err,
					NULL, NULL, NULL, NULL, 1 );
			if ( rc != LDAP_SUCCESS ) {
				rs->sr_err = rc;
			}
			break;
		}
	}

	return rs->sr_err = slap_map_api2result( rs );
}

/*
 * meta_back_single_bind
 *
 * attempts to perform a bind with creds
 */
int
meta_back_single_bind(
	Operation		*op,
	SlapReply		*rs,
	metaconn_t		*mc,
	int			candidate,
	int			massage )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metatarget_t		*mt = mi->mi_targets[ candidate ];
	struct berval		mdn = BER_BVNULL;
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	int			msgid;
	
	if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
		ch_free( msc->msc_bound_ndn.bv_val );
		BER_BVZERO( &msc->msc_bound_ndn );
	}

	if ( LDAP_BACK_SAVECRED( mi ) && !BER_BVISNULL( &msc->msc_cred ) ) {
		/* destroy sensitive data */
		memset( msc->msc_cred.bv_val, 0, msc->msc_cred.bv_len );
		ch_free( msc->msc_cred.bv_val );
		BER_BVZERO( &msc->msc_cred );
	}

	/*
	 * Rewrite the bind dn if needed
	 */
	if ( massage ) {
		dncookie		dc;

		dc.target = mt;
		dc.conn = op->o_conn;
		dc.rs = rs;
		dc.ctx = "bindDN";

		if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
			rs->sr_text = "DN rewrite error";
			rs->sr_err = LDAP_OTHER;
			return rs->sr_err;
		}

	} else {
		mdn = op->o_req_dn;
	}

	/* FIXME: this fixes the bind problem right now; we need
	 * to use the asynchronous version to get the "matched"
	 * and more in case of failure ... */
	/* FIXME: should we check if at least some of the op->o_ctrls
	 * can/should be passed? */
	rs->sr_err = ldap_sasl_bind( msc->msc_ld, mdn.bv_val,
			LDAP_SASL_SIMPLE, &op->orb_cred,
			op->o_ctrls, NULL, &msgid );
	meta_back_bind_op_result( op, rs, mc, candidate, msgid, LDAP_BACK_DONTSEND );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto return_results;
	}

	ber_bvreplace( &msc->msc_bound_ndn, &op->o_req_dn );
	LDAP_BACK_CONN_ISBOUND_SET( msc );
	mc->mc_authz_target = candidate;

	if ( LDAP_BACK_SAVECRED( mi ) ) {
		ber_bvreplace( &msc->msc_cred, &op->orb_cred );
		ldap_set_rebind_proc( msc->msc_ld, mt->mt_rebind_f, msc );
	}

cache_refresh:;
	if ( mi->mi_cache.ttl != META_DNCACHE_DISABLED
			&& !BER_BVISEMPTY( &op->o_req_ndn ) )
	{
		( void )meta_dncache_update_entry( &mi->mi_cache,
				&op->o_req_ndn, candidate );
	}

return_results:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}

	if ( META_BACK_TGT_QUARANTINE( mt ) ) {
		meta_back_quarantine( op, rs, candidate );
	}

	return rs->sr_err;
}

/*
 * meta_back_single_dobind
 */
int
meta_back_single_dobind(
	Operation		*op,
	SlapReply		*rs,
	metaconn_t		**mcp,
	int			candidate,
	ldap_back_send_t	sendok,
	int			nretries,
	int			dolock )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metatarget_t		*mt = mi->mi_targets[ candidate ];
	metaconn_t		*mc = *mcp;
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	int			rc;
	static struct berval	cred = BER_BVC( "" );
	int			msgid;

	assert( !LDAP_BACK_CONN_ISBOUND( msc ) );

	/*
	 * meta_back_single_dobind() calls meta_back_single_bind()
	 * if required.
	 */
	if ( be_isroot( op ) && !BER_BVISNULL( &mt->mt_pseudorootdn ) )
	{
		Operation	op2 = *op;

		op2.o_tag = LDAP_REQ_BIND;
		op2.o_req_dn = mt->mt_pseudorootdn;
		op2.o_req_ndn = mt->mt_pseudorootdn;
		op2.orb_cred = mt->mt_pseudorootpw;
		op2.orb_method = LDAP_AUTH_SIMPLE;

		rc = meta_back_single_bind( &op2, rs, *mcp, candidate, 0 );
		goto done;
	}

	/*
	 * Otherwise an anonymous bind is performed
	 * (note: if the target was already bound, the anonymous
	 * bind clears the previous bind).
	 */
	if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
		ber_memfree( msc->msc_bound_ndn.bv_val );
		BER_BVZERO( &msc->msc_bound_ndn );
	}
		
	if ( LDAP_BACK_SAVECRED( mi ) && !BER_BVISNULL( &msc->msc_cred ) ) {
		/* destroy sensitive data */
		memset( msc->msc_cred.bv_val, 0, msc->msc_cred.bv_len );
		ber_memfree( msc->msc_cred.bv_val );
		BER_BVZERO( &msc->msc_cred );
	}

	/* FIXME: should we check if at least some of the op->o_ctrls
	 * can/should be passed? */
	rs->sr_err = ldap_sasl_bind( msc->msc_ld, "", LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, &msgid );
	rc = meta_back_bind_op_result( op, rs, mc, candidate, msgid, sendok );

done:;
	rs->sr_err = rc;
	if ( rc != LDAP_SUCCESS ) {
		if ( dolock ) {
			ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
		}
	        LDAP_BACK_CONN_BINDING_CLEAR( msc );
		if ( META_BACK_ONERR_STOP( mi ) ) {
	        	LDAP_BACK_CONN_TAINTED_SET( mc );
			meta_back_release_conn_lock( op, mc, 0 );
			*mcp = NULL;
		}
		if ( dolock ) {
			ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
		}

		if ( META_BACK_ONERR_STOP( mi ) && ( sendok & LDAP_BACK_SENDERR ) ) {
			send_ldap_result( op, rs );
		}
	}

	if ( META_BACK_TGT_QUARANTINE( mt ) ) {
		meta_back_quarantine( op, rs, candidate );
	}

	return rc;
}

/*
 * meta_back_dobind
 */
int
meta_back_dobind(
	Operation		*op,
	SlapReply		*rs,
	metaconn_t		*mc,
	ldap_back_send_t	sendok )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;

	int			bound = 0,
				i,
				isroot = 0;

	SlapReply		*candidates = meta_back_candidates_get( op );

	if ( be_isroot( op ) ) {
		isroot = 1;
	}

	Debug( LDAP_DEBUG_TRACE,
		"%s meta_back_dobind: conn=%ld%s\n",
		op->o_log_prefix,
		LDAP_BACK_PCONN_ID( mc->mc_conn ),
		isroot ? " (isroot)" : "" );

	/*
	 * all the targets are bound as pseudoroot
	 */
	if ( mc->mc_authz_target == META_BOUND_ALL ) {
		bound = 1;
		goto done;
	}

	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		metatarget_t		*mt = mi->mi_targets[ i ];
		metasingleconn_t	*msc = &mc->mc_conns[ i ];
		int			rc, do_retry = 1;

		/*
		 * Not a candidate
		 */
		if ( !META_IS_CANDIDATE( &candidates[ i ] ) ) {
			continue;
		}

		assert( msc->msc_ld != NULL );

		/*
		 * If the target is already bound it is skipped
		 */

retry_binding:;
		ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
		if ( LDAP_BACK_CONN_ISBOUND( msc ) || LDAP_BACK_CONN_ISANON( msc ) ) {
			ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
			++bound;
			continue;

		} else if ( LDAP_BACK_CONN_BINDING( msc ) ) {
			ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
			ldap_pvt_thread_yield();
			goto retry_binding;

		}

		LDAP_BACK_CONN_BINDING_SET( msc );
		ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );

retry:;
		rc = meta_back_single_dobind( op, rs, &mc, i,
			LDAP_BACK_DONTSEND, mt->mt_nretries, 1 );
		/*
		 * NOTE: meta_back_single_dobind() already retries;
		 * in case of failure, it resets mc...
		 */
		if ( rc != LDAP_SUCCESS ) {
			char		buf[ SLAP_TEXT_BUFLEN ];

			if ( mc == NULL ) {
				/* meta_back_single_dobind() already sent 
				 * response and released connection */
				goto send_err;
			}


			if ( rc == LDAP_UNAVAILABLE && do_retry ) {
				do_retry = 0;
				if ( meta_back_retry( op, rs, &mc, i, sendok ) ) {
					goto retry;
				}

				if ( mc != NULL ) {
					ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
					LDAP_BACK_CONN_BINDING_CLEAR( msc );
					ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
				}

				return 0;
			}

			ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
			LDAP_BACK_CONN_BINDING_CLEAR( msc );
			ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );

			snprintf( buf, sizeof( buf ),
				"meta_back_dobind[%d]: (%s) err=%d (%s).",
				i, isroot ? op->o_bd->be_rootdn.bv_val : "anonymous",
				rc, ldap_err2string( rc ) );
			Debug( LDAP_DEBUG_ANY,
				"%s %s\n",
				op->o_log_prefix, buf, 0 );

			/*
			 * null cred bind should always succeed
			 * as anonymous, so a failure means
			 * the target is no longer candidate possibly
			 * due to technical reasons (remote host down?)
			 * so better clear the handle
			 */
			/* leave the target candidate, but record the error for later use */
			candidates[ i ].sr_err = rc;
			if ( META_BACK_ONERR_STOP( mi ) ) {
				bound = 0;
				goto done;
			}

			continue;
		} /* else */
		
		Debug( LDAP_DEBUG_TRACE,
			"%s meta_back_dobind[%d]: "
			"(%s)\n",
			op->o_log_prefix, i,
			isroot ? op->o_bd->be_rootdn.bv_val : "anonymous" );

		ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
		LDAP_BACK_CONN_BINDING_CLEAR( msc );
		if ( isroot ) {
			LDAP_BACK_CONN_ISBOUND_SET( msc );
		} else {
			LDAP_BACK_CONN_ISANON_SET( msc );
		}
		ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
		++bound;
	}

done:;
	Debug( LDAP_DEBUG_TRACE,
		"%s meta_back_dobind: conn=%ld bound=%d\n",
		op->o_log_prefix, LDAP_BACK_PCONN_ID( mc->mc_conn ), bound );

	if ( bound == 0 ) {
		meta_back_release_conn( op, mc );

send_err:;
		if ( sendok & LDAP_BACK_SENDERR ) {
			if ( rs->sr_err == LDAP_SUCCESS ) {
				rs->sr_err = LDAP_BUSY;
			}
			send_ldap_result( op, rs );
		}

		return 0;
	}

	return ( bound > 0 );
}

/*
 * meta_back_default_rebind
 *
 * This is a callback used for chasing referrals using the same
 * credentials as the original user on this session.
 */
int 
meta_back_default_rebind(
	LDAP			*ld,
	LDAP_CONST char		*url,
	ber_tag_t		request,
	ber_int_t		msgid,
	void			*params )
{
	metasingleconn_t	*msc = ( metasingleconn_t * )params;

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
meta_back_default_urllist(
	LDAP		*ld,
	LDAPURLDesc	**urllist,
	LDAPURLDesc	**url,
	void		*params )
{
	metatarget_t	*mt = (metatarget_t *)params;
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
meta_back_cancel(
	metaconn_t		*mc,
	Operation		*op,
	SlapReply		*rs,
	ber_int_t		msgid,
	int			candidate,
	ldap_back_send_t	sendok )
{
	metainfo_t		*mi = (metainfo_t *)op->o_bd->be_private;

	metatarget_t		*mt = mi->mi_targets[ candidate ];
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

	/* default behavior */
	if ( META_BACK_TGT_ABANDON( mt ) ) {
		return ldap_abandon_ext( msc->msc_ld, msgid, NULL, NULL );
	}

	if ( META_BACK_TGT_IGNORE( mt ) ) {
		return LDAP_SUCCESS;
	}

	if ( META_BACK_TGT_CANCEL( mt ) ) {
		/* FIXME: asynchronous? */
		return ldap_cancel_s( msc->msc_ld, msgid, NULL, NULL );
	}

	assert( 0 );

	return LDAP_OTHER;
}



/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
meta_back_op_result(
	metaconn_t	*mc,
	Operation	*op,
	SlapReply	*rs,
	int		candidate )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;

	int			i,
				rerr = LDAP_SUCCESS;
	char			*rmsg = NULL,
				*rmatch = NULL;
	const char		*save_rmsg = NULL,
				*save_rmatch = NULL;
	void			*rmatch_ctx = NULL;

	assert( mc != NULL );

	if ( candidate != META_TARGET_NONE ) {
		metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

		rs->sr_err = LDAP_SUCCESS;

		ldap_get_option( msc->msc_ld, LDAP_OPT_ERROR_NUMBER, &rs->sr_err );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			/*
			 * better check the type of error. In some cases
			 * (search ?) it might be better to return a
			 * success if at least one of the targets gave
			 * positive result ...
			 */
			ldap_get_option( msc->msc_ld,
					LDAP_OPT_ERROR_STRING, &rmsg );
			if ( rmsg != NULL && rmsg[ 0 ] == '\0' ) {
				ldap_memfree( rmsg );
				rmsg = NULL;
			}

			ldap_get_option( msc->msc_ld,
					LDAP_OPT_MATCHED_DN, &rmatch );
			if ( rmatch != NULL && rmatch[ 0 ] == '\0' ) {
				ldap_memfree( rmatch );
				rmatch = NULL;
			}

			rerr = rs->sr_err = slap_map_api2result( rs );

			if ( LogTest( LDAP_DEBUG_ANY ) ) {
				char	buf[ SLAP_TEXT_BUFLEN ];

				snprintf( buf, sizeof( buf ),
					"meta_back_op_result[%d] "
					"err=%d text=\"%s\" matched=\"%s\"", 
					candidate, rs->sr_err,
					( rmsg ? rmsg : "" ),
					( rmatch ? rmatch : "" ) );
				Debug( LDAP_DEBUG_ANY, "%s %s.\n",
					op->o_log_prefix, buf, 0 );
			}
		}

		if ( META_BACK_TGT_QUARANTINE( mi->mi_targets[ candidate ] ) ) {
			meta_back_quarantine( op, rs, candidate );
		}

	} else {
		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			metasingleconn_t	*msc = &mc->mc_conns[ i ];
			char			*msg = NULL;
			char			*match = NULL;

			rs->sr_err = LDAP_SUCCESS;

			ldap_get_option( msc->msc_ld, LDAP_OPT_ERROR_NUMBER, &rs->sr_err );
			if ( rs->sr_err != LDAP_SUCCESS ) {
				/*
				 * better check the type of error. In some cases
				 * (search ?) it might be better to return a
				 * success if at least one of the targets gave
				 * positive result ...
				 */
				ldap_get_option( msc->msc_ld,
						LDAP_OPT_ERROR_STRING, &msg );
				if ( msg != NULL && msg[ 0 ] == '\0' ) {
					ldap_memfree( msg );
					msg = NULL;
				}

				ldap_get_option( msc->msc_ld,
						LDAP_OPT_MATCHED_DN, &match );
				if ( match != NULL && match[ 0 ] == '\0' ) {
					ldap_memfree( match );
					match = NULL;
				}

				rs->sr_err = slap_map_api2result( rs );
	
				if ( LogTest( LDAP_DEBUG_ANY ) ) {
					char	buf[ SLAP_TEXT_BUFLEN ];

					snprintf( buf, sizeof( buf ),
						"meta_back_op_result[%d] "
						"err=%d text=\"%s\" matched=\"%s\"", 
						candidate, rs->sr_err,
						( rmsg ? rmsg : "" ),
						( rmatch ? rmatch : "" ) );
					Debug( LDAP_DEBUG_ANY, "%s %s.\n",
						op->o_log_prefix, buf, 0 );
				}
	
				/*
				 * FIXME: need to rewrite "match" (need rwinfo)
				 */
				switch ( rs->sr_err ) {
				default:
					rerr = rs->sr_err;
					if ( msg != NULL ) {
						if ( rmsg ) {
							ldap_memfree( rmsg );
						}
						rmsg = msg;
						msg = NULL;
					}
					if ( match != NULL ) {
						if ( rmatch ) {
							ldap_memfree( rmatch );
						}
						rmatch = match;
						match = NULL;
					}
					break;
				}

				if ( msg ) {
					ldap_memfree( msg );
				}
	
				if ( match ) {
					ldap_memfree( match );
				}
			}

			if ( META_BACK_TGT_QUARANTINE( mi->mi_targets[ i ] ) ) {
				meta_back_quarantine( op, rs, i );
			}
		}
	}
	
	rs->sr_err = rerr;
	if ( rmsg != NULL ) {
		save_rmsg = rs->sr_text;
		rs->sr_text = rmsg;
	}
	if ( rmatch != NULL ) {
		struct berval	dn, pdn;

		ber_str2bv( rmatch, 0, 0, &dn );
		if ( dnPretty( NULL, &dn, &pdn, op->o_tmpmemctx ) == LDAP_SUCCESS ) {
			ldap_memfree( rmatch );
			rmatch_ctx = op->o_tmpmemctx;
			rmatch = pdn.bv_val;
		}
		save_rmatch = rs->sr_matched;
		rs->sr_matched = rmatch;
	}
	send_ldap_result( op, rs );
	if ( rmsg != NULL ) {
		ber_memfree( rmsg );
		rs->sr_text = save_rmsg;
	}
	if ( rmatch != NULL ) {
		ber_memfree_x( rmatch, rmatch_ctx );
		rs->sr_matched = save_rmatch;
	}

	return ( ( rerr == LDAP_SUCCESS ) ? 0 : -1 );
}

