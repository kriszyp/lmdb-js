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


#define AVL_INTERNAL
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

static LDAP_REBIND_PROC	meta_back_rebind;

static int
meta_back_single_bind(
		Operation		*op,
		SlapReply		*rs,
		struct metaconn		*mc,
		int			candidate );

int
meta_back_bind( Operation *op, SlapReply *rs )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn *mc;

	int		rc = LDAP_OTHER,
			i, gotit = 0, isroot = 0;

	SlapReply	*candidates = meta_back_candidates_get( op );

	rs->sr_err = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_ARGS, "meta_back_bind: dn: %s.\n%s%s",
			op->o_req_dn.bv_val, "", "" );

	if ( op->orb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op ) ) {
		isroot = 1;
		ber_dupbv( &op->orb_edn, be_root_dn( op->o_bd ) );
	}

	/* we need meta_back_getconn() not send result even on error,
	 * because we want to intercept the error and make it
	 * invalidCredentials */
	mc = meta_back_getconn( op, rs, NULL, LDAP_BACK_DONTSEND );
	if ( !mc ) {
		Debug( LDAP_DEBUG_ANY,
				"meta_back_bind: no target "
				"for dn \"%s\" (%d: %s).\n",
				op->o_req_dn.bv_val, rs->sr_err,
				rs->sr_text ? rs->sr_text : "" );
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
	mc->mc_auth_target = META_BOUND_NONE;
	for ( i = 0; i < li->mi_ntargets; i++ ) {
		int		lerr;
		Operation	op2 = *op;

		/*
		 * Skip non-candidates
		 */
		if ( candidates[ i ].sr_tag != META_CANDIDATE ) {
			continue;
		}

		if ( gotit == 0 ) {
			gotit = 1;

		} else if ( isroot == 0 ) {
			/*
			 * A bind operation is expected to have
			 * ONE CANDIDATE ONLY!
			 */
			Debug( LDAP_DEBUG_ANY,
					"==>meta_back_bind: more than one"
					" candidate is trying to bind...\n",
					0, 0, 0 );
		}

		if ( isroot && !BER_BVISNULL( &li->mi_targets[ i ]->mt_pseudorootdn ) )
		{
			op2.o_req_dn = li->mi_targets[ i ]->mt_pseudorootdn;
			op2.o_req_ndn = li->mi_targets[ i ]->mt_pseudorootdn;
			op2.orb_cred = li->mi_targets[ i ]->mt_pseudorootpw;
			op2.orb_method = LDAP_AUTH_SIMPLE;
		}
		
		lerr = meta_back_single_bind( &op2, rs, mc, i );
		if ( lerr != LDAP_SUCCESS ) {
			rs->sr_err = lerr;
			candidates[ i ].sr_tag = META_NOT_CANDIDATE;

		} else {
			rc = LDAP_SUCCESS;
		}
	}

	if ( isroot ) {
		mc->mc_auth_target = META_BOUND_ALL;
	}

	/*
	 * rc is LDAP_SUCCESS if at least one bind succeeded,
	 * err is the last error that occurred during a bind;
	 * if at least (and at most?) one bind succeedes, fine.
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
		}

		rs->sr_err = slap_map_api2result( rs );
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	return LDAP_SUCCESS;
}

/*
 * meta_back_single_bind
 *
 * attempts to perform a bind with creds
 */
static int
meta_back_single_bind(
		Operation		*op,
		SlapReply		*rs,
		struct metaconn		*mc,
		int			candidate
)
{
	struct metainfo		*li = ( struct metainfo * )op->o_bd->be_private;
	struct berval		mdn = BER_BVNULL;
	dncookie		dc;
	struct metasingleconn	*msc = &mc->mc_conns[ candidate ];
	int			msgid;
	
	/*
	 * Rewrite the bind dn if needed
	 */
	dc.rwmap = &li->mi_targets[ candidate ]->mt_rwmap;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "bindDN";

	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	/* FIXME: this fixes the bind problem right now; we need
	 * to use the asynchronous version to get the "matched"
	 * and more in case of failure ... */
	/* FIXME: should be check if at least some of the op->o_ctrls
	 * can/should be passed? */
	rs->sr_err = ldap_sasl_bind( msc->msc_ld, mdn.bv_val,
			LDAP_SASL_SIMPLE, &op->orb_cred,
			op->o_ctrls, NULL, &msgid );
	if ( rs->sr_err == LDAP_SUCCESS ) {
		LDAPMessage	*res;
		struct timeval	tv = { 0, 0 };
		int		rc;
		int		nretries = META_BIND_NRETRIES;

		/*
		 * handle response!!!
		 */
retry:;
		switch ( ldap_result( msc->msc_ld, msgid, 0, &tv, &res ) ) {
		case 0:
			if ( nretries > 0 ) {
				ldap_pvt_thread_yield();
				tv.tv_sec = 0;
				tv.tv_usec = META_BIND_TIMEOUT;
				nretries--;
				goto retry;
			}
			rs->sr_err = LDAP_BUSY;
			break;

		case -1:
			ldap_get_option( msc->msc_ld, LDAP_OPT_ERROR_NUMBER,
					&rs->sr_err );
			if ( rs->sr_err == LDAP_UNAVAILABLE && nretries > 0 ) {
				nretries--;
				if ( meta_back_retry( op, rs, mc, candidate, LDAP_BACK_SENDERR ) ) {
					goto retry;
				}
			}
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

	if ( rs->sr_err != LDAP_SUCCESS ) {
		rs->sr_err = slap_map_api2result( rs );
		goto return_results;
	}

	ber_bvreplace( &msc->msc_bound_ndn, &op->o_req_dn );
	msc->msc_bound = META_BOUND;
	mc->mc_auth_target = candidate;

	if ( LDAP_BACK_SAVECRED( li ) ) {
		ber_bvreplace( &msc->msc_cred, &op->orb_cred );
		ldap_set_rebind_proc( msc->msc_ld, meta_back_rebind, msc );
	}

	if ( li->mi_cache.ttl != META_DNCACHE_DISABLED
			&& op->o_req_ndn.bv_len != 0 )
	{
		( void )meta_dncache_update_entry( &li->mi_cache,
				&op->o_req_ndn, candidate );
	}

return_results:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}

	return rs->sr_err;
}

/*
 * meta_back_single_dobind
 */
int
meta_back_single_dobind(
	Operation		*op,
	struct metasingleconn	*msc,
	ldap_back_send_t	sendok,
	int			retries )
{
	int		rc;
	struct berval	cred = BER_BVC( "" );
	int		msgid;

	/*
	 * Otherwise an anonymous bind is performed
	 * (note: if the target was already bound, the anonymous
	 * bind clears the previous bind).
	 */
	if ( !BER_BVISNULL( &msc->msc_bound_ndn ) ) {
		ber_memfree( msc->msc_bound_ndn.bv_val );
		BER_BVZERO( &msc->msc_bound_ndn );
	}
		
	if ( /* FIXME: need li ... li->savecred && */ 
			!BER_BVISNULL( &msc->msc_cred ) )
	{
		/* destroy sensitive data */
		memset( msc->msc_cred.bv_val, 0, msc->msc_cred.bv_len );
		ber_memfree( msc->msc_cred.bv_val );
		BER_BVZERO( &msc->msc_cred );
	}

	/* FIXME: should we check if at least some of the op->o_ctrls
	 * can/should be passed? */
	rc = ldap_sasl_bind( msc->msc_ld, "", LDAP_SASL_SIMPLE, &cred,
			NULL, NULL, &msgid );
	if ( rc == LDAP_SUCCESS ) {
		LDAPMessage	*res;
		struct timeval	tv = { 0, 0 };
		int		err;

		/*
		 * handle response!!!
		 */
retry:;
		switch ( ldap_result( msc->msc_ld, msgid, 0, &tv, &res ) ) {
		case 0:
			if ( retries > 0 ) {
				ldap_pvt_thread_yield();
				tv.tv_sec = 0;
				tv.tv_usec = META_BIND_TIMEOUT;
				retries--;
				goto retry;
			}

			rc = LDAP_BUSY;
			break;

		case -1:
			ldap_get_option( msc->msc_ld,
					LDAP_OPT_ERROR_NUMBER, &rc );
			break;

		default:
			rc = ldap_parse_result( msc->msc_ld, res, &err,
					NULL, NULL, NULL, NULL, 1 );
			if ( rc == LDAP_SUCCESS ) {
				rc = err;
			}
			break;
		}
	}

	return rc;
}

/*
 * meta_back_dobind
 */
int
meta_back_dobind( struct metaconn *mc, Operation *op, ldap_back_send_t sendok )
{
	struct metasingleconn	*msc;
	int			bound = 0, i;

	SlapReply		*candidates = meta_back_candidates_get( op );

	ldap_pvt_thread_mutex_lock( &mc->mc_mutex );

	/*
	 * all the targets are bound as pseudoroot
	 */
	if ( mc->mc_auth_target == META_BOUND_ALL ) {
		bound = 1;
		goto done;
	}

	for ( i = 0, msc = &mc->mc_conns[ 0 ]; !META_LAST( msc ); ++i, ++msc ) {
		int		rc;

		/*
		 * Not a candidate or something wrong with this target ...
		 */
		if ( msc->msc_ld == NULL ) {
			continue;
		}

		/*
		 * If the target is already bound it is skipped
		 */
		if ( msc->msc_bound == META_BOUND && mc->mc_auth_target == i ) {
			++bound;
			continue;
		}

		rc = meta_back_single_dobind( op, msc, sendok, META_BIND_NRETRIES );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "%s meta_back_dobind[%d]: "
					"(anonymous) err=%d\n",
					op->o_log_prefix, i, rc );

			/*
			 * null cred bind should always succeed
			 * as anonymous, so a failure means
			 * the target is no longer candidate possibly
			 * due to technical reasons (remote host down?)
			 * so better clear the handle
			 */
			candidates[ i ].sr_tag = META_NOT_CANDIDATE;
#if 0
			( void )meta_clear_one_candidate( msc );
#endif
			continue;
		} /* else */
		
		candidates[ i ].sr_tag = META_CANDIDATE;
		msc->msc_bound = META_ANONYMOUS;
		++bound;
	}

done:;
        ldap_pvt_thread_mutex_unlock( &mc->mc_mutex );

	return( bound > 0 );
}

/*
 *
 */
int
meta_back_is_valid( struct metaconn *mc, int candidate )
{
	struct metasingleconn 	*msc;
	int			i;

	assert( mc );

	if ( candidate < 0 ) {
		return 0;
	}

	for ( i = 0, msc = &mc->mc_conns[ 0 ]; !META_LAST( msc ) && i < candidate; 
			++i, ++msc );
	
	if ( !META_LAST( msc ) ) {
		return ( msc->msc_ld != NULL );
	}

	return 0;
}

/*
 * meta_back_rebind
 *
 * This is a callback used for chasing referrals using the same
 * credentials as the original user on this session.
 */
static int 
meta_back_rebind( LDAP *ld, LDAP_CONST char *url, ber_tag_t request,
	ber_int_t msgid, void *params )
{
	struct metasingleconn	*msc = (struct metasingleconn *)params;

	return ldap_sasl_bind_s( ld, msc->msc_bound_ndn.bv_val,
			LDAP_SASL_SIMPLE, &msc->msc_cred,
			NULL, NULL, NULL );
}

/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
meta_back_op_result(
	struct metaconn	*mc,
	Operation	*op,
	SlapReply	*rs,
	int		candidate )
{
	int			i,
				rerr = LDAP_SUCCESS;
	struct metasingleconn	*msc;
	char			*rmsg = NULL;
	char			*rmatch = NULL;
	int			free_rmsg = 0,
				free_rmatch = 0;

	if ( candidate != META_TARGET_NONE ) {
		msc = &mc->mc_conns[ candidate ];

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
			ldap_get_option( msc->msc_ld,
					LDAP_OPT_MATCHED_DN, &rmatch );
			rerr = rs->sr_err = slap_map_api2result( rs );

			if ( rmsg ) {
				free_rmsg = 1;
			}
			if ( rmatch ) {
				free_rmatch = 1;
			}

			Debug(LDAP_DEBUG_ANY,
					"==> meta_back_op_result: target"
					" <%d> sending msg \"%s\""
					" (matched \"%s\")\n", 
					candidate, ( rmsg ? rmsg : "" ),
					( rmatch ? rmatch : "" ) );
		}

	} else {
		for ( i = 0, msc = &mc->mc_conns[ 0 ]; !META_LAST( msc ); ++i, ++msc ) {
			char	*msg = NULL;
			char	*match = NULL;

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
				ldap_get_option( msc->msc_ld,
						LDAP_OPT_MATCHED_DN, &match );
				rs->sr_err = slap_map_api2result( rs );
	
				Debug(LDAP_DEBUG_ANY,
						"==> meta_back_op_result: target"
						" <%d> sending msg \"%s\""
						" (matched \"%s\")\n", 
						i, ( msg ? msg : "" ),
						( match ? match : "" ) );
	
				/*
				 * FIXME: need to rewrite "match" (need rwinfo)
				 */
				switch ( rs->sr_err ) {
				default:
					rerr = rs->sr_err;
					if ( rmsg ) {
						ber_memfree( rmsg );
					}
					rmsg = msg;
					free_rmsg = 1;
					msg = NULL;
					if ( rmatch ) {
						ber_memfree( rmatch );
					}
					rmatch = match;
					free_rmatch = 1;
					match = NULL;
					break;
				}
	
				/* better test the pointers before freeing? */
				if ( match ) {
					free( match );
				}
				if ( msg ) {
					free( msg );
				}
			}
		}
	}
	
	rs->sr_err = rerr;
	rs->sr_text = rmsg;
	rs->sr_matched = rmatch;
	send_ldap_result( op, rs );
	if ( free_rmsg ) {
		ber_memfree( rmsg );
	}
	if ( free_rmatch ) {
		ber_memfree( rmatch );
	}
	rs->sr_text = NULL;
	rs->sr_matched = NULL;

	return ( ( rerr == LDAP_SUCCESS ) ? 0 : -1 );
}

