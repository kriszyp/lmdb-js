/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This work has been developed to fulfill the requirements
 * of SysNet s.n.c. <http:www.sys-net.it> and it has been donated
 * to the OpenLDAP Foundation in the hope that it may be useful
 * to the Open Source community, but WITHOUT ANY WARRANTY.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from 
 *    flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 *
 * 4. This notice may not be removed or altered.
 *
 *
 * This software is based on the backend back-ldap, implemented
 * by Howard Chu <hyc@highlandsun.com>, and modified by Mark Valence
 * <kurash@sassafras.com>, Pierangelo Masarati <ando@sys-net.it> and other
 * contributors. The contribution of the original software to the present
 * implementation is acknowledged in this copyright statement.
 *
 * A special acknowledgement goes to Howard for the overall architecture
 * (and for borrowing large pieces of code), and to Mark, who implemented
 * from scratch the attribute/objectclass mapping.
 *
 * The original copyright statement follows.
 *
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the
 *    documentation.
 *
 * 4. This notice may not be removed or altered.
 *
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
		struct metainfo		*li,
		struct metaconn		*lc,
		Operation		*op,
		struct berval		*dn,
		struct berval		*ndn,
		struct berval		*cred,
		int			method,
		int			candidate
);

int
meta_back_bind(
		Backend		*be,
		Connection	*conn,
		Operation	*op,
		struct berval	*dn,
		struct berval	*ndn,
		int		method,
		struct berval	*cred,
		struct berval	*edn
)
{
	struct metainfo	*li = ( struct metainfo * )be->be_private;
	struct metaconn *lc;

	int rc = -1, i, gotit = 0, ndnlen, isroot = 0;
	int op_type = META_OP_ALLOW_MULTIPLE;
	int err = LDAP_SUCCESS;

	struct berval *realdn = dn;
	struct berval *realndn = ndn;
	struct berval *realcred = cred;
	int realmethod = method;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, ENTRY,
			"meta_back_bind: dn: %s.\n", dn->bv_val, 0, 0 );
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ARGS, "meta_back_bind: dn: %s.\n%s%s", dn->bv_val, "", "" );
#endif /* !NEW_LOGGING */

	if ( method == LDAP_AUTH_SIMPLE 
			&& be_isroot_pw( be, conn, ndn, cred ) ) {
		isroot = 1;
		ber_dupbv( edn, be_root_dn( be ) );
		op_type = META_OP_REQUIRE_ALL;
	}
	lc = meta_back_getconn( li, conn, op, op_type, ndn, NULL );
	if ( !lc ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, NOTICE,
				"meta_back_bind: no target for dn %s.\n", dn->bv_val, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY,
				"meta_back_bind: no target for dn %s.\n%s%s",
				dn->bv_val, "", "");
#endif /* !NEW_LOGGING */
		send_ldap_result( conn, op, LDAP_OTHER, 
				NULL, NULL, NULL, NULL );
		return -1;
	}

	/*
	 * Each target is scanned ...
	 */
	lc->bound_target = META_BOUND_NONE;
	ndnlen = ndn->bv_len;
	for ( i = 0; i < li->ntargets; i++ ) {
		int lerr;

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
			realdn = &li->targets[ i ]->pseudorootdn;
			realndn = &li->targets[ i ]->pseudorootdn;
			realcred = &li->targets[ i ]->pseudorootpw;
			realmethod = LDAP_AUTH_SIMPLE;
		} else {
			realdn = dn;
			realndn = ndn;
			realcred = cred;
			realmethod = method;
		}
		
		lerr = meta_back_do_single_bind( li, lc, op,
				realdn, realndn, realcred, realmethod, i );
		if ( lerr != LDAP_SUCCESS ) {
			err = lerr;
			( void )meta_clear_one_candidate( &lc->conns[ i ], 1 );
		} else {
			rc = LDAP_SUCCESS;
		}
	}

	if ( isroot ) {
		lc->bound_target = META_BOUND_ALL;
	}

	/*
	 * rc is LDAP_SUCCESS if at least one bind succeeded,
	 * err is the last error that occurred during a bind;
	 * if at least (and at most?) one bind succeedes, fine.
	 */
	if ( rc != LDAP_SUCCESS /* && err != LDAP_SUCCESS */ ) {
		
		/*
		 * deal with bind failure ...
		 */

		/*
		 * no target was found within the naming context, 
		 * so bind must fail with invalid credentials
		 */
		if ( err == LDAP_SUCCESS && gotit == 0 ) {
			err = LDAP_INVALID_CREDENTIALS;
		}

		err = ldap_back_map_result( err );
		send_ldap_result( conn, op, err, NULL, NULL, NULL, NULL );
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
		struct metainfo		*li,
		struct metaconn		*lc,
		Operation		*op,
		struct berval		*dn,
		struct berval		*ndn,
		struct berval		*cred,
		int			method,
		int			candidate
)
{
	struct berval mdn = { 0, NULL };
	int rc;
	
	/*
	 * Rewrite the bind dn if needed
	 */
	switch ( rewrite_session( li->targets[ candidate ]->rwinfo,
				"bindDn", dn->bv_val, lc->conn, &mdn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mdn.bv_val == NULL ) {
			mdn = *dn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
				"[rw] bindDn: \"%s\" -> \"%s\"\n", dn->bv_val, mdn.bv_val, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
				"rw> bindDn: \"%s\" -> \"%s\"\n%s",
				dn->bv_val, mdn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		return LDAP_UNWILLING_TO_PERFORM;

	case REWRITE_REGEXEC_ERR:
		return LDAP_OTHER;
	}

	if ( op->o_ctrls ) {
		rc = ldap_set_option( lc->conns[ candidate ].ld, 
				LDAP_OPT_SERVER_CONTROLS, op->o_ctrls );
		if ( rc != LDAP_SUCCESS ) {
			rc = ldap_back_map_result( rc );
			goto return_results;
		}
	}
	
	rc = ldap_bind_s( lc->conns[ candidate ].ld, mdn.bv_val, cred->bv_val, method );
	if ( rc != LDAP_SUCCESS ) {
		rc = ldap_back_map_result( rc );
	} else {
		ber_dupbv( &lc->conns[ candidate ].bound_dn, dn );
		lc->conns[ candidate ].bound = META_BOUND;
		lc->bound_target = candidate;

		if ( li->savecred ) {
			if ( lc->conns[ candidate ].cred.bv_val )
				ch_free( lc->conns[ candidate ].cred.bv_val );
			ber_dupbv( &lc->conns[ candidate ].cred, cred );
			ldap_set_rebind_proc( lc->conns[ candidate ].ld, 
					meta_back_rebind, 
					&lc->conns[ candidate ] );
		}

		if ( li->cache.ttl != META_DNCACHE_DISABLED
				&& ndn->bv_len != 0 ) {
			( void )meta_dncache_update_entry( &li->cache,
					ndn, candidate );
		}
	}

return_results:;
	
	if ( mdn.bv_val != dn->bv_val ) {
		free( mdn.bv_val );
	}

	return rc;
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
		int rc;

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
			ch_free( lsc->bound_dn.bv_val );
			lsc->bound_dn.bv_val = NULL;
			lsc->bound_dn.bv_len = 0;
		}
		

		rc = ldap_bind_s( lsc->ld, 0, NULL, LDAP_AUTH_SIMPLE );
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

	return ldap_bind_s( ld, lc->bound_dn.bv_val, lc->cred.bv_val, LDAP_AUTH_SIMPLE );
}

/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
meta_back_op_result( struct metaconn *lc, Operation *op )
{
	int i, rerr = LDAP_SUCCESS;
	struct metasingleconn *lsc;
	char *rmsg = NULL;
	char *rmatch = NULL;

	for ( i = 0, lsc = lc->conns; !META_LAST(lsc); ++i, ++lsc ) {
		int err = LDAP_SUCCESS;
		char *msg = NULL;
		char *match = NULL;

		ldap_get_option( lsc->ld, LDAP_OPT_ERROR_NUMBER, &err );
		if ( err != LDAP_SUCCESS ) {
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
			err = ldap_back_map_result( err );

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
			switch ( err ) {
			default:
				rerr = err;
				rmsg = msg;
				msg = NULL;
				rmatch = match;
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

	send_ldap_result( lc->conn, op, rerr, rmatch, rmsg, NULL, NULL );

	return ( ( rerr == LDAP_SUCCESS ) ? 0 : -1 );
}

