/*
 * Copyright 1998-2001 The OpenLDAP Foundation, All Rights Reserved.
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

int
meta_back_bind(
		Backend		*be,
		Connection	*conn,
		Operation	*op,
		const char	*dn,
		const char	*ndn,
		int		method,
		struct berval	*cred,
		char		**edn
)
{
	struct metainfo	*li = ( struct metainfo * )be->be_private;
	struct metaconn *lc;

	int rc = -1, i, gotit = 0, ndnlen, err = LDAP_SUCCESS;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
			"meta_back_bind: dn: %s.\n", dn ));
#else /* !NEW_LOGGING */
	Debug( LDAP_DEBUG_ARGS, "meta_back_bind: dn: %s.\n%s%s", dn, "", "" );
#endif /* !NEW_LOGGING */

	*edn = NULL;

	lc = meta_back_getconn( li, conn, op, META_OP_ALLOW_MULTIPLE,
			ndn, NULL );
	if ( !lc ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_NOTICE,
				"meta_back_bind: no target for dn %s.\n",
				dn ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ANY,
				"meta_back_bind: no target for dn %s.\n%s%s",
				dn, "", "");
#endif /* !NEW_LOGGING */
		return -1;
	}

	/*
	 * Each target is scanned ...
	 */
	ndnlen = strlen( ndn );
	for ( i = 0; i < li->ntargets; i++ ) {
		int lerr;

		/*
		 * Skip non-candidates
		 */
		if ( lc->conns[ i ]->candidate != META_CANDIDATE ) {
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
			LDAP_LOG(( "backend", LDAP_LEVEL_WARNING,
					"==>meta_back_bind: more than one"
					" candidate is attempting to bind"
					" ...\n" ));
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
					"==>meta_back_bind: more than one"
					" candidate is attempting to bind"
					" ...\n%s%s%s", 
					"", "", "" );
#endif /* !NEW_LOGGING */
		}


		lerr = meta_back_do_single_bind( li, lc, dn, ndn, cred,
				method, i );
		if ( lerr != LDAP_SUCCESS ) {
			err = lerr;
			( void )meta_clear_one_candidate( lc->conns[ i ], 1 );
		} else {
			rc = LDAP_SUCCESS;
		}
	}

	if ( rc != LDAP_SUCCESS && err != LDAP_SUCCESS ) {
		
		/*
		 * deal with bind failure ...
		 */
		err = ldap_back_map_result( err );
		send_ldap_result( conn, op, err, NULL, "", NULL, NULL );
	}

	return LDAP_SUCCESS;
}

/*
 * meta_back_do_single_bind
 *
 * attempts to perform a bind with creds
 */
int
meta_back_do_single_bind(
		struct metainfo		*li,
		struct metaconn		*lc,
		const char		*dn,
		const char		*ndn,
		struct berval		*cred,
		int			method,
		int			candidate
)
{
	char *mdn = NULL;
	int rc;
	
	/*
	 * Rewrite the bind dn if needed
	 */
	switch ( rewrite_session( li->targets[ candidate ]->rwinfo,
				"bindDn", dn, lc->conn, &mdn ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mdn == NULL ) {
			mdn = ( char * )dn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] bindDn: \"%s\" -> \"%s\"\n", dn, mdn ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
				"rw> bindDn: \"%s\" -> \"%s\"\n%s",
				dn, mdn, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		return LDAP_UNWILLING_TO_PERFORM;

	case REWRITE_REGEXEC_ERR:
		return LDAP_OPERATIONS_ERROR;
	}

	rc = ldap_bind_s( lc->conns[ candidate ]->ld, mdn,
			cred->bv_val, method );
	if ( rc != LDAP_SUCCESS ) {
		rc = ldap_back_map_result( rc );
	} else {
		lc->conns[ candidate ]->bound_dn = ch_strdup( dn );
		lc->conns[ candidate ]->bound = META_BOUND;
		lc->bound_target = candidate;

		if ( li->cache.ttl != META_DNCACHE_DISABLED
				&& ndn[ 0 ] != '\0' ) {
			( void )meta_dncache_update_entry( &li->cache,
					ch_strdup( ndn ), candidate );
		}
	}
	
	if ( mdn != dn ) {
		free( mdn );
	}

	return rc;
}

/*
 * meta_back_dobind
 */
int
meta_back_dobind( struct metaconn *lc, Operation *op )
{
	struct metasingleconn **lsc;
	int bound = 0, i;

	for ( i = 0, lsc = lc->conns; lsc[ 0 ] != NULL; ++i, ++lsc ) {
		int rc;

		/*
		 * Not a candidate or something wrong with this target ...
		 */
		if ( lsc[ 0 ]->ld == NULL ) {
			continue;
		}

		/*
		 * If the target is already bound it is skipped
		 */
		if ( lsc[ 0 ]->bound == META_BOUND && lc->bound_target == i ) {
			++bound;
			continue;
		}

		/*
		 * Otherwise an anonymous bind is performed
		 * (note: if the target was already bound, the anonymous
		 * bind clears the previous bind).
		 */
		rc = ldap_bind_s( lsc[ 0 ]->ld, lsc[ 0 ]->bound_dn,
				NULL, LDAP_AUTH_SIMPLE );
		if ( rc != LDAP_SUCCESS ) {
			
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_WARNING,
					"meta_back_dobind: (anonymous)"
					" bind as \"%s\" failed"
					" with error \"%s\"\n",
					lsc[ 0 ]->bound_dn,
					ldap_err2string( rc ) ));
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ANY,
	"==>meta_back_dobind: (anonymous) bind as \"%s\" failed"
	" with error \"%s\"\n%s",
				lsc[ 0 ]->bound_dn,
				ldap_err2string( rc ), "" );
#endif /* !NEW_LOGGING */

			/*
			 * null cred bind should always succeed
			 * as anonymous, so a failure means
			 * the target is no longer candidate possibly
			 * due to technical reasons (remote host down?)
			 *
			 * so better clear the handle
			 */
			( void )meta_clear_one_candidate( lsc[ 0 ], 1 );
			continue;
		} /* else */
		
		lsc[ 0 ]->bound = META_ANONYMOUS;
		++bound;
	}

	return( bound > 0 );
}

/*
 * FIXME: error return must be handled in a cleaner way ...
 */
int
meta_back_op_result( struct metaconn *lc, Operation *op )
{
	int i, err = LDAP_SUCCESS;
	char *msg = NULL;
	char *match = NULL;
	struct metasingleconn **lsc;

	for ( i = 0, lsc = lc->conns; lsc[ 0 ] != NULL; ++i, ++lsc ) {
		ldap_get_option( lsc[ 0 ]->ld, LDAP_OPT_ERROR_NUMBER, &err );
		if ( err != LDAP_SUCCESS ) {
			/*
			 * better check the type of error. In some cases
			 * (search ?) it might be better to return a
			 * success if at least one of the targets gave
			 * positive result ...
			 */
			ldap_get_option( lsc[ 0 ]->ld,
					LDAP_OPT_ERROR_STRING, &msg );
			ldap_get_option( lsc[ 0 ]->ld,
					LDAP_OPT_MATCHED_DN, &match );
			err = ldap_back_map_result( err );

			/*
			 * FIXME: need to rewrite "match"
			 */
			send_ldap_result( lc->conn, op, err, match, msg,
				       	NULL, NULL );
			
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_DEBUG_NOTICE,
						"meta_back_op_result: target"
						" <%d> sending msg \"%s\""
						" (matched \"%s\")\n",
						i, ( msg ? msg : "" ),
						( match ? match : "" ) ));
#else /* !NEW_LOGGING */
			Debug(LDAP_DEBUG_ANY,
"==> meta_back_op_result: target <%d> sending msg \"%s\" (matched \"%s\")\n", 
				i,
				( msg ? msg : "" ),
				( match ? match : "" ) );
#endif /* !NEW_LOGGING */

			/* better test the pointers before freeing? */
			if ( match ) {
				free( match );
			}
			if ( msg ) {
				free( msg );
			}
			return -1;
		}
	}

	return ( err == LDAP_SUCCESS ) ? 0 : -1;
}

