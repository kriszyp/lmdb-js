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
meta_back_do_single_bind(
		struct metaconn		*lc,
		Operation		*op,
		SlapReply		*rs,
		int			candidate
);

int
meta_back_bind( Operation *op, SlapReply *rs )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn *lc;

	int rc = -1, i, gotit = 0, ndnlen, isroot = 0;
	int op_type = META_OP_ALLOW_MULTIPLE;

	rs->sr_err = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_ARGS, "meta_back_bind: dn: %s.\n%s%s",
			op->o_req_dn.bv_val, "", "" );

	if ( op->orb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op ) ) {
		isroot = 1;
		ber_dupbv( &op->orb_edn, be_root_dn( op->o_bd ) );
		op_type = META_OP_REQUIRE_ALL;
	}
	lc = meta_back_getconn( op, rs, op_type,
			&op->o_req_ndn, NULL );
	if ( !lc ) {
		Debug( LDAP_DEBUG_ANY,
				"meta_back_bind: no target for dn %s.\n%s%s",
				op->o_req_dn.bv_val, "", "");

		send_ldap_result( op, rs );
		return -1;
	}

	/*
	 * Each target is scanned ...
	 */
	lc->mc_bound_target = META_BOUND_NONE;
	ndnlen = op->o_req_ndn.bv_len;
	for ( i = 0; i < li->ntargets; i++ ) {
		int		lerr;
		struct berval	orig_dn = op->o_req_dn;
		struct berval	orig_ndn = op->o_req_ndn;
		struct berval	orig_cred = op->orb_cred;
		int		orig_method = op->orb_method;
		

		/*
		 * Skip non-candidates
		 */
		if ( lc->mc_conns[ i ].msc_candidate != META_CANDIDATE ) {
			continue;
		}

		if ( gotit == 0 ) {
			gotit = 1;
		} else {
			/*
			 * A bind operation is expected to have
			 * ONE CANDIDATE ONLY!
			 */
			Debug( LDAP_DEBUG_ANY,
					"==>meta_back_bind: more than one"
					" candidate is attempting to bind"
					" ...\n%s%s%s", 
					"", "", "" );
		}

		if ( isroot && li->targets[ i ]->mt_pseudorootdn.bv_val != NULL ) {
			op->o_req_dn = li->targets[ i ]->mt_pseudorootdn;
			op->o_req_ndn = li->targets[ i ]->mt_pseudorootdn;
			op->orb_cred = li->targets[ i ]->mt_pseudorootpw;
			op->orb_method = LDAP_AUTH_SIMPLE;
		}
		
		lerr = meta_back_do_single_bind( lc, op, rs, i );
		if ( lerr != LDAP_SUCCESS ) {
			rs->sr_err = lerr;
			( void )meta_clear_one_candidate( &lc->mc_conns[ i ], 1 );

		} else {
			rc = LDAP_SUCCESS;
		}

		op->o_req_dn = orig_dn;
		op->o_req_ndn = orig_ndn;
		op->orb_cred = orig_cred;
		op->orb_method = orig_method;
	}

	if ( isroot ) {
		lc->mc_bound_target = META_BOUND_ALL;
	}

	/*
	 * rc is LDAP_SUCCESS if at least one bind succeeded,
	 * err is the last error that occurred during a bind;
	 * if at least (and at most?) one bind succeedes, fine.
	 */
	if ( rc != LDAP_SUCCESS /* && rs->sr_err != LDAP_SUCCESS */ ) {
		
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
		return -1;
	}

	return 0;
}

/*
 * meta_back_do_single_bind
 *
 * attempts to perform a bind with creds
 */
static int
meta_back_do_single_bind(
		struct metaconn		*lc,
		Operation		*op,
		SlapReply		*rs,
		int			candidate
)
{
	struct metainfo		*li = ( struct metainfo * )op->o_bd->be_private;
	struct berval		mdn = BER_BVNULL;
	dncookie		dc;
	struct metasingleconn	*lsc = &lc->mc_conns[ candidate ];
	int			msgid;
	
	/*
	 * Rewrite the bind dn if needed
	 */
	dc.rwmap = &li->targets[ candidate ]->mt_rwmap;
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
	rs->sr_err = ldap_sasl_bind( lsc->msc_ld, mdn.bv_val,
			LDAP_SASL_SIMPLE, &op->orb_cred,
			op->o_ctrls, NULL, &msgid );
	if ( rs->sr_err == LDAP_SUCCESS ) {
		LDAPMessage	*res;
		struct timeval	tv = { 0, 0 };
		int		rc;
		int		nretries = 0;

		/*
		 * handle response!!!
		 */
retry:;
		switch ( ldap_result( lsc->msc_ld, msgid, 0, &tv, &res ) ) {
		case 0:
			if ( ++nretries <= META_BIND_NRETRIES ) {
				ldap_pvt_thread_yield();
				tv.tv_sec = 0;
				tv.tv_usec = META_BIND_TIMEOUT;
				goto retry;
			}
			rs->sr_err = LDAP_BUSY;
			break;

		case -1:
			ldap_get_option( lsc->msc_ld, LDAP_OPT_ERROR_NUMBER,
					&rs->sr_err );
			break;

		default:
			rc = ldap_parse_result( lsc->msc_ld, res, &rs->sr_err,
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

	if ( !BER_BVISNULL( &lsc->msc_bound_ndn ) ) {
		ber_memfree( lsc->msc_bound_ndn.bv_val );
	}
	ber_dupbv( &lsc->msc_bound_ndn, &op->o_req_dn );
	lsc->msc_bound = META_BOUND;
	lc->mc_bound_target = candidate;

	if ( li->flags & LDAP_BACK_F_SAVECRED ) {
		if ( !BER_BVISNULL( &lsc->msc_cred ) ) {
			/* destroy sensitive data */
			memset( lsc->msc_cred.bv_val, 0, lsc->msc_cred.bv_len );
			ber_memfree( lsc->msc_cred.bv_val );
		}
		ber_dupbv( &lsc->msc_cred, &op->orb_cred );
		ldap_set_rebind_proc( lsc->msc_ld, meta_back_rebind, lsc );
	}

	if ( li->cache.ttl != META_DNCACHE_DISABLED
			&& op->o_req_ndn.bv_len != 0 ) {
		( void )meta_dncache_update_entry( &li->cache,
				&op->o_req_ndn, candidate );
	}

return_results:;
	
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}

	return rs->sr_err;
}

/*
 * meta_back_dobind
 */
int
meta_back_dobind( struct metaconn *lc, Operation *op )
{
	struct metasingleconn	*lsc;
	int			bound = 0, i;

	/*
	 * all the targets are bound as pseudoroot
	 */
	if ( lc->mc_bound_target == META_BOUND_ALL ) {
		return 1;
	}

	for ( i = 0, lsc = lc->mc_conns; !META_LAST( lsc ); ++i, ++lsc ) {
		int		rc;
		struct berval	cred = BER_BVC("");
		int		msgid;

		/*
		 * Not a candidate or something wrong with this target ...
		 */
		if ( lsc->msc_ld == NULL ) {
			continue;
		}

		/*
		 * If the target is already bound it is skipped
		 */
		if ( lsc->msc_bound == META_BOUND && lc->mc_bound_target == i ) {
			++bound;
			continue;
		}

		/*
		 * Otherwise an anonymous bind is performed
		 * (note: if the target was already bound, the anonymous
		 * bind clears the previous bind).
		 */
		if ( !BER_BVISNULL( &lsc->msc_bound_ndn ) ) {
			ber_memfree( lsc->msc_bound_ndn.bv_val );
			BER_BVZERO( &lsc->msc_bound_ndn );
		}
		
		if ( /* FIXME: need li ... li->savecred && */ 
				!BER_BVISNULL( &lsc->msc_cred ) )
		{
			/* destroy sensitive data */
			memset( lsc->msc_cred.bv_val, 0, lsc->msc_cred.bv_len );
			ber_memfree( lsc->msc_cred.bv_val );
			BER_BVZERO( &lsc->msc_cred );
		}

		/* FIXME: should we check if at least some of the op->o_ctrls
		 * can/should be passed? */
		rc = ldap_sasl_bind( lsc->msc_ld, "", LDAP_SASL_SIMPLE, &cred,
				NULL, NULL, &msgid );
		if ( rc == LDAP_SUCCESS ) {
			LDAPMessage	*res;
			struct timeval	tv = { 0, 0 };
			int		err;
			int		nretries = 0;

			/*
			 * handle response!!!
			 */
retry:;
			switch ( ldap_result( lsc->msc_ld, msgid, 0, &tv, &res ) ) {
			case 0:
				if ( ++nretries <= META_BIND_NRETRIES ) {
					ldap_pvt_thread_yield();
					tv.tv_sec = 0;
					tv.tv_usec = META_BIND_TIMEOUT;
					goto retry;
				}

				rc = LDAP_BUSY;
				break;

			case -1:
				ldap_get_option( lsc->msc_ld, LDAP_OPT_ERROR_NUMBER,
						&rc );
				break;

			default:
				rc = ldap_parse_result( lsc->msc_ld, res, &err,
						NULL, NULL, NULL, NULL, 1 );
				if ( rc == LDAP_SUCCESS ) {
					rc = err;
				}
				break;
			}
		}

		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
					"==>meta_back_dobind: (anonymous)"
					" bind failed"
					" with error %d (%s)\n",
					rc, ldap_err2string( rc ), 0 );

			/*
			 * null cred bind should always succeed
			 * as anonymous, so a failure means
			 * the target is no longer candidate possibly
			 * due to technical reasons (remote host down?)
			 * so better clear the handle
			 */
			( void )meta_clear_one_candidate( lsc, 1 );
			continue;
		} /* else */
		
		lsc->msc_bound = META_ANONYMOUS;
		++bound;
	}

	return( bound > 0 );
}

/*
 *
 */
int
meta_back_is_valid( struct metaconn *lc, int candidate )
{
	struct metasingleconn 	*lsc;
	int			i;

	assert( lc );

	if ( candidate < 0 ) {
		return 0;
	}

	for ( i = 0, lsc = lc->mc_conns; !META_LAST( lsc ) && i < candidate; 
			++i, ++lsc );
	
	if ( !META_LAST( lsc ) ) {
		return ( lsc->msc_ld != NULL );
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
	struct metasingleconn	*lsc = params;

	return ldap_sasl_bind_s( ld, lsc->msc_bound_ndn.bv_val,
			LDAP_SASL_SIMPLE, &lsc->msc_cred,
			NULL, NULL, NULL );
}

/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
meta_back_op_result( struct metaconn *lc, Operation *op, SlapReply *rs )
{
	int			i,
				rerr = LDAP_SUCCESS;
	struct metasingleconn	*lsc;
	char			*rmsg = NULL;
	char			*rmatch = NULL;
	int			free_rmsg = 0,
				free_rmatch = 0;

	for ( i = 0, lsc = lc->mc_conns; !META_LAST( lsc ); ++i, ++lsc ) {
		char	*msg = NULL;
		char	*match = NULL;

		rs->sr_err = LDAP_SUCCESS;

		ldap_get_option( lsc->msc_ld, LDAP_OPT_ERROR_NUMBER, &rs->sr_err );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			/*
			 * better check the type of error. In some cases
			 * (search ?) it might be better to return a
			 * success if at least one of the targets gave
			 * positive result ...
			 */
			ldap_get_option( lsc->msc_ld,
					LDAP_OPT_ERROR_STRING, &msg );
			ldap_get_option( lsc->msc_ld,
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

