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

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, ENTRY, "meta_back_bind: dn: %s.\n",
			op->o_req_dn.bv_val, 0, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ARGS, "meta_back_bind: dn: %s.\n%s%s",
			op->o_req_dn.bv_val, "", "" );
#endif /* !NEW_LOGGING */

	if ( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op ) ) {
		isroot = 1;
		ber_dupbv( &op->oq_bind.rb_edn, be_root_dn( op->o_bd ) );
		op_type = META_OP_REQUIRE_ALL;
	}
	lc = meta_back_getconn( op, rs, op_type,
			&op->o_req_ndn, NULL );
	if ( !lc ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, NOTICE,
				"meta_back_bind: no target for dn %s.\n",
				op->o_req_dn.bv_val, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY,
				"meta_back_bind: no target for dn %s.\n%s%s",
				op->o_req_dn.bv_val, "", "");
#endif /* !NEW_LOGGING */

		send_ldap_result( op, rs );
		return -1;
	}

	/*
	 * Each target is scanned ...
	 */
	lc->bound_target = META_BOUND_NONE;
	ndnlen = op->o_req_ndn.bv_len;
	for ( i = 0; i < li->ntargets; i++ ) {
		int		lerr;
		struct berval	orig_dn = op->o_req_dn;
		struct berval	orig_ndn = op->o_req_ndn;
		struct berval	orig_cred = op->oq_bind.rb_cred;
		int		orig_method = op->oq_bind.rb_method;
		

		/*
		 * Skip non-candidates
		 */
		if ( lc->conns[ i ].candidate != META_CANDIDATE ) {
			continue;
		}

		if ( gotit == 0 ) {
			gotit = 1;
		} else {
			/*
			 * A bind operation is expected to have
			 * ONE CANDIDATE ONLY!
			 */
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, WARNING,
					"==>meta_back_bind: more than one"
					" candidate is attempting to bind"
					" ...\n" , 0, 0, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
					"==>meta_back_bind: more than one"
					" candidate is attempting to bind"
					" ...\n%s%s%s", 
					"", "", "" );
#endif /* !NEW_LOGGING */
		}

		if ( isroot && li->targets[ i ]->pseudorootdn.bv_val != NULL ) {
			op->o_req_dn = li->targets[ i ]->pseudorootdn;
			op->o_req_ndn = li->targets[ i ]->pseudorootdn;
			op->oq_bind.rb_cred = li->targets[ i ]->pseudorootpw;
			op->oq_bind.rb_method = LDAP_AUTH_SIMPLE;
		}
		
		lerr = meta_back_do_single_bind( lc, op, rs, i );
		if ( lerr != LDAP_SUCCESS ) {
			rs->sr_err = lerr;
			( void )meta_clear_one_candidate( &lc->conns[ i ], 1 );
		} else {
			rc = LDAP_SUCCESS;
		}

		op->o_req_dn = orig_dn;
		op->o_req_ndn = orig_ndn;
		op->oq_bind.rb_cred = orig_cred;
		op->oq_bind.rb_method = orig_method;
	}

	if ( isroot ) {
		lc->bound_target = META_BOUND_ALL;
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

		rs->sr_err = ldap_back_map_result( rs );
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
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct berval	mdn = { 0, NULL };
	ber_int_t	msgid;
	dncookie	dc;
	struct metasingleconn	*lsc = &lc->conns[ candidate ];
	LDAPMessage	*res;
	
	/*
	 * Rewrite the bind dn if needed
	 */
	dc.rwmap = &li->targets[ candidate ]->rwmap;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "bindDn";

	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	if ( op->o_ctrls ) {
		rs->sr_err = ldap_set_option( lsc->ld, 
				LDAP_OPT_SERVER_CONTROLS, op->o_ctrls );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			rs->sr_err = ldap_back_map_result( rs );
			goto return_results;
		}
	}

	/* FIXME: this fixes the bind problem right now; we need
	 * to use the asynchronous version to get the "matched"
	 * and more in case of failure ... */
	rs->sr_err = ldap_sasl_bind_s(lsc->ld, mdn.bv_val,
			LDAP_SASL_SIMPLE, &op->oq_bind.rb_cred,
			op->o_ctrls, NULL, NULL);
	if ( rs->sr_err != LDAP_SUCCESS ) {
		rs->sr_err = ldap_back_map_result( rs );
		goto return_results;
	}

	/*
	 * FIXME: handle response!!!
	 */
	if ( lsc->bound_dn.bv_val != NULL ) {
		ber_memfree( lsc->bound_dn.bv_val );
	}
	ber_dupbv( &lsc->bound_dn, &op->o_req_dn );
	lsc->bound = META_BOUND;
	lc->bound_target = candidate;

	if ( li->savecred ) {
		if ( lsc->cred.bv_val ) {
			memset( lsc->cred.bv_val, 0, lsc->cred.bv_len );
			ber_memfree( lsc->cred.bv_val );
		}
		ber_dupbv( &lsc->cred, &op->oq_bind.rb_cred );
		ldap_set_rebind_proc( lsc->ld, meta_back_rebind, lsc );
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
	struct metasingleconn *lsc;
	int bound = 0, i;

	/*
	 * all the targets are bound as pseudoroot
	 */
	if ( lc->bound_target == META_BOUND_ALL ) {
		return 1;
	}

	for ( i = 0, lsc = lc->conns; !META_LAST(lsc); ++i, ++lsc ) {
		int		rc;
		struct berval	cred = BER_BVC("");

		/*
		 * Not a candidate or something wrong with this target ...
		 */
		if ( lsc->ld == NULL ) {
			continue;
		}

		/*
		 * If required, set controls
		 */
		if ( op->o_ctrls ) {
			if ( ldap_set_option( lsc->ld, LDAP_OPT_SERVER_CONTROLS,
					op->o_ctrls ) != LDAP_SUCCESS ) {
				( void )meta_clear_one_candidate( lsc, 1 );
				continue;
			}
		}
	
		/*
		 * If the target is already bound it is skipped
		 */
		if ( lsc->bound == META_BOUND && lc->bound_target == i ) {
			++bound;
			continue;
		}

		/*
		 * Otherwise an anonymous bind is performed
		 * (note: if the target was already bound, the anonymous
		 * bind clears the previous bind).
		 */
		if ( lsc->bound_dn.bv_val ) {
			ber_memfree( lsc->bound_dn.bv_val );
			lsc->bound_dn.bv_val = NULL;
			lsc->bound_dn.bv_len = 0;
		}
		
		if ( /* FIXME: need li ... li->savecred && */ 
				lsc->cred.bv_val ) {
			memset( lsc->cred.bv_val, 0, lsc->cred.bv_len );
			ber_memfree( lsc->cred.bv_val );
			lsc->cred.bv_val = NULL;
			lsc->cred.bv_len = 0;
		}

		rc = ldap_sasl_bind_s(lsc->ld, "", LDAP_SASL_SIMPLE, &cred,
				op->o_ctrls, NULL, NULL);
		if ( rc != LDAP_SUCCESS ) {
			
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, WARNING,
					"meta_back_dobind: (anonymous)"
					" bind failed"
					" with error %d (%s)\n",
					rc, ldap_err2string( rc ), 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
					"==>meta_back_dobind: (anonymous)"
					" bind failed"
					" with error %d (%s)\n",
					rc, ldap_err2string( rc ), 0 );
#endif /* !NEW_LOGGING */

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
		
		lsc->bound = META_ANONYMOUS;
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

	for ( i = 0, lsc = lc->conns; !META_LAST(lsc) && i < candidate; 
			++i, ++lsc );
	
	if ( !META_LAST(lsc) ) {
		return( lsc->ld != NULL );
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
	struct metasingleconn *lc = params;

	return ldap_bind_s( ld, lc->bound_dn.bv_val, lc->cred.bv_val,
			LDAP_AUTH_SIMPLE );
}

/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
meta_back_op_result( struct metaconn *lc, Operation *op, SlapReply *rs )
{
	int i, rerr = LDAP_SUCCESS;
	struct metasingleconn *lsc;
	char *rmsg = NULL;
	char *rmatch = NULL;
	int	free_rmsg = 0, free_rmatch = 0;

	for ( i = 0, lsc = lc->conns; !META_LAST(lsc); ++i, ++lsc ) {
		char *msg = NULL;
		char *match = NULL;

		rs->sr_err = LDAP_SUCCESS;

		ldap_get_option( lsc->ld, LDAP_OPT_ERROR_NUMBER, &rs->sr_err );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			/*
			 * better check the type of error. In some cases
			 * (search ?) it might be better to return a
			 * success if at least one of the targets gave
			 * positive result ...
			 */
			ldap_get_option( lsc->ld,
					LDAP_OPT_ERROR_STRING, &msg );
			ldap_get_option( lsc->ld,
					LDAP_OPT_MATCHED_DN, &match );
			rs->sr_err = ldap_back_map_result( rs );

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_META, RESULTS,
					"meta_back_op_result: target"
					" <%d> sending msg \"%s\""
					" (matched \"%s\")\n",
					i, ( msg ? msg : "" ),
					( match ? match : "" ) );
#else /* !NEW_LOGGING */
			Debug(LDAP_DEBUG_ANY,
					"==> meta_back_op_result: target"
					" <%d> sending msg \"%s\""
					" (matched \"%s\")\n", 
					i, ( msg ? msg : "" ),
					( match ? match : "" ) );
#endif /* !NEW_LOGGING */

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

