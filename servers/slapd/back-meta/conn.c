/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

/*
 * Set PRINT_CONNTREE larger than 0 to dump the connection tree (debug only)
 */
#define PRINT_CONNTREE 0

/*
 * meta_back_conn_cmp
 *
 * compares two struct metaconn based on the value of the conn pointer;
 * used by avl stuff
 */
int
meta_back_conn_cmp(
	const void *c1,
	const void *c2
	)
{
	struct metaconn *lc1 = ( struct metaconn * )c1;
        struct metaconn *lc2 = ( struct metaconn * )c2;
	
	return ( ( lc1->conn < lc2->conn ) ? -1 :
			( ( lc1->conn > lc2-> conn ) ? 1 : 0 ) );
}

/*
 * meta_back_conn_dup
 *
 * returns -1 in case a duplicate struct metaconn has been inserted;
 * used by avl stuff
 */
int
meta_back_conn_dup(
	void *c1,
	void *c2
	)
{
	struct metaconn *lc1 = ( struct metaconn * )c1;
	struct metaconn *lc2 = ( struct metaconn * )c2;

	return( ( lc1->conn == lc2->conn ) ? -1 : 0 );
}

/*
 * Debug stuff (got it from libavl)
 */
#if PRINT_CONNTREE > 0
static void
ravl_print( Avlnode *root, int depth )
{
	int     i;
	
	if ( root == 0 ) {
		return;
	}
	
	ravl_print( root->avl_right, depth+1 );
	
	for ( i = 0; i < depth; i++ ) {
		printf( "    " );
	}

	printf( "c(%d) %d\n", ( ( struct metaconn * )root->avl_data )->conn->c_connid, root->avl_bf );
	
	ravl_print( root->avl_left, depth+1 );
}

static void
myprint( Avlnode *root )
{
	printf( "********\n" );
	
	if ( root == 0 ) {
		printf( "\tNULL\n" );
	} else {
		ravl_print( root, 0 );
	}
	
	printf( "********\n" );
}
#endif /* PRINT_CONNTREE */
/*
 * End of debug stuff
 */

/*
 * metaconn_alloc
 * 
 * Allocates a connection structure, making room for all the referenced targets
 */
static struct metaconn *
metaconn_alloc( int ntargets )
{
	struct metaconn *lc;
	int i;

	assert( ntargets > 0 );

	lc = ch_calloc( sizeof( struct metaconn ), 1 );
	if ( lc == NULL ) {
		return NULL;
	}
	
	/*
	 * make it a null-terminated array ...
	 */
	lc->conns = ch_calloc( sizeof( struct metasingleconn * ), ntargets+1 );
	if ( lc->conns == NULL ) {
		free( lc );
		return NULL;
	}

	for ( i = 0; i < ntargets; i++ ) {
		lc->conns[ i ] =
			ch_calloc( sizeof( struct metasingleconn ), 1 );
		if ( lc->conns[ i ] == NULL ) {
			charray_free( ( char ** )lc->conns );
			free( lc->conns );
			free( lc );
			return NULL;
		}
	}

	lc->bound_target = META_BOUND_NONE;

	return lc;
}

/*
 * metaconn_free
 *
 * clears a metaconn
 */
static void
metaconn_free(
		struct metaconn *lc
)
{
	if ( !lc ) {
		return;
	}
	
	if ( lc->conns ) {
		int i;

		for ( i = 0; lc->conns[ i ] != NULL; ++i ) {
			free( lc->conns[ i ] );
		}
		charray_free( ( char ** )lc->conns );
	}

	free( lc );
}

/*
 * init_one_conn
 * 
 * Initializes one connection
 */
static int
init_one_conn(
		Connection *conn, 
		Operation *op, 
		struct metatarget *lt, 
		int vers,
		struct metasingleconn *lsc
		)
{
	int err;

	/*
	 * Already init'ed
	 */
	if ( lsc->ld != NULL ) {
		return LDAP_SUCCESS;
	}
       
	/*
	 * Attempts to initialize the connection to the target ds
	 */
	err = ldap_initialize( &lsc->ld, lt->uri );
	if ( err != LDAP_SUCCESS ) {
		return ldap_back_map_result( err );
	}
	
	/*
	 * Set LDAP version. This will always succeed: If the client
	 * bound with a particular version, then so can we.
	 */
	ldap_set_option( lsc->ld, LDAP_OPT_PROTOCOL_VERSION, &vers );

	/*
	 * Sets a cookie for the rewrite session
	 */
	( void )rewrite_session_init( lt->rwinfo, conn );

	/*
	 * If the connection dn is not null, an attempt to rewrite it is made
	 */
	if ( conn->c_cdn.bv_len != 0 ) {
		
		/*
		 * Rewrite the bind dn if needed
		 */
		lsc->bound_dn.bv_val = NULL;
		switch ( rewrite_session( lt->rwinfo, "bindDn",
					conn->c_cdn.bv_val, conn, 
					&lsc->bound_dn.bv_val ) ) {
		case REWRITE_REGEXEC_OK:
			if ( lsc->bound_dn.bv_val == NULL ) {
				ber_dupbv( &lsc->bound_dn, &conn->c_cdn );
			}
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
					"[rw] bindDn: \"%s\" -> \"%s\"\n",
					conn->c_cdn.bv_val, lsc->bound_dn.bv_val ));
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS,
				       	"rw> bindDn: \"%s\" -> \"%s\"\n",
					conn->c_cdn.bv_val, lsc->bound_dn.bv_val, 0 );
#endif /* !NEW_LOGGING */
			break;
			
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op,
					LDAP_UNWILLING_TO_PERFORM,
					NULL, "Unwilling to perform",
					NULL, NULL );
			return LDAP_UNWILLING_TO_PERFORM;
			
		case REWRITE_REGEXEC_ERR:
			send_ldap_result( conn, op,
					LDAP_OPERATIONS_ERROR,
					NULL, "Operations error",
					NULL, NULL );
			return LDAP_OPERATIONS_ERROR;
		}

		assert( lsc->bound_dn.bv_val );

	} else {
		ber_str2bv( "", 0, 1, &lsc->bound_dn );
	}

	lsc->bound = META_UNBOUND;

	/*
	 * The candidate is activated
	 */
	lsc->candidate = META_CANDIDATE;
	return LDAP_SUCCESS;
}

/*
 * meta_back_getconn
 * 
 * Prepares the connection structure
 * 
 * FIXME: This function needs to receive some info on the type of operation
 * it is invoked by, so that only the correct pool of candidate targets
 * is initialized in case no connection was available yet.
 * 
 * At present a flag that says whether the candidate target must be unique
 * is passed; eventually an operation agent will be used.
 */
struct metaconn *
meta_back_getconn(
		struct metainfo *li,
	       	Connection 	*conn,
	       	Operation 	*op,
		int 		op_type,
		struct berval	*ndn,
		int 		*candidate )
{
	struct metaconn *lc, lc_curr;
	int vers, cached = -1, i = -1, err = LDAP_SUCCESS;
	int new_conn = 0;

	/* Searches for a metaconn in the avl tree */
	lc_curr.conn = conn;
	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	lc = (struct metaconn *)avl_find( li->conntree, 
		(caddr_t)&lc_curr, meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	/* Looks like we didn't get a bind. Open a new session... */
	if ( !lc ) {
		lc = metaconn_alloc( li->ntargets );
		lc->conn = conn;
		new_conn = 1;
	}

	vers = conn->c_protocol;

	/*
	 * looks in cache, if any
	 */
	if ( li->cache.ttl != META_DNCACHE_DISABLED ) {
		cached = i = meta_dncache_get_target( &li->cache, ndn );
	}

	if ( op_type == META_OP_REQUIRE_SINGLE ) {

		/*
		 * tries to get a unique candidate
		 * (takes care of default target 
		 */
		if ( i < 0 ) {
			i = meta_back_select_unique_candidate( li, ndn );
		}

		/*
		 * if any is found, inits the connection
		 */
		if ( i < 0 ) {
			if ( new_conn ) {
				metaconn_free( lc );
			}

			send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
				NULL, "", NULL, NULL );

			return NULL;
		}
				
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				"meta_back_getconn: got target %d"
				" for ndn=\"%s\" from cache\n", 
				i, ndn->bv_val ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_CACHE,
	"==>meta_back_getconn: got target %d for ndn=\"%s\" from cache\n%s",
				i, ndn->bv_val, "" );
#endif /* !NEW_LOGGING */

		/*
		 * Clear all other candidates
		 */
		( void )meta_clear_unused_candidates( li, lc, i, 0 );

		/*
		 * The target is activated; if needed, it is
		 * also init'd. In case of error, init_one_conn
		 * sends the appropriate result.
		 */
		err = init_one_conn( conn, op, li->targets[ i ],
				vers, lc->conns[ i ] );
		if ( err != LDAP_SUCCESS ) {
		
			/*
			 * FIXME: in case one target cannot
			 * be init'd, should the other ones
			 * be tried?
			 */
			( void )meta_clear_one_candidate( lc->conns[ i ], 1 );
			if ( new_conn ) {
				metaconn_free( lc );
			}
			return NULL;
		}

		if ( candidate ) {
			*candidate = i;
		}

	/*
	 * require all connections ...
	 */
	} else if (op_type == META_OP_REQUIRE_ALL) {
		for ( i = 0; i < li->ntargets; i++ ) {

			/*
			 * The target is activated; if needed, it is
			 * also init'd
			 */
			int lerr = init_one_conn( conn, op, li->targets[ i ],
					vers, lc->conns[ i ] );
			if ( lerr != LDAP_SUCCESS ) {
				
				/*
				 * FIXME: in case one target cannot
				 * be init'd, should the other ones
				 * be tried?
				 */
				( void )meta_clear_one_candidate( lc->conns[ i ], 1 );
				err = lerr;
				continue;
			}
		}

	/*
	 * if no unique candidate ...
	 */
	} else {
		for ( i = 0; i < li->ntargets; i++ ) {
			if ( i == cached 
		|| meta_back_is_candidate( &li->targets[ i ]->suffix, ndn ) ) {

				/*
				 * The target is activated; if needed, it is
				 * also init'd
				 */
				int lerr = init_one_conn( conn, op,
						li->targets[ i ],
						vers, lc->conns[ i ] );
				if ( lerr != LDAP_SUCCESS ) {
				
					/*
					 * FIXME: in case one target cannot
					 * be init'd, should the other ones
					 * be tried?
					 */
					( void )meta_clear_one_candidate( lc->conns[ i ], 1 );
					err = lerr;
					continue;
				}
			}
		}
	}

	if ( new_conn ) {
		
		/*
		 * Inserts the newly created metaconn in the avl tree
		 */
		ldap_pvt_thread_mutex_lock( &li->conn_mutex );
		err = avl_insert( &li->conntree, ( caddr_t )lc,
			       	meta_back_conn_cmp, meta_back_conn_dup );

#if PRINT_CONNTREE > 0
		myprint( li->conntree );
#endif /* PRINT_CONNTREE */
		
		ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				"meta_back_getconn: conn %ld inserted\n",
				lc->conn->c_connid ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_getconn: conn %ld inserted\n%s%s",
			lc->conn->c_connid, "", "" );
#endif /* !NEW_LOGGING */
		
		/*
		 * Err could be -1 in case a duplicate metaconn is inserted
		 */
		if ( err != 0 ) {
			send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, "Internal server error", NULL, NULL );
			metaconn_free( lc );
			return NULL;
		}
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				"meta_back_getconn: conn %ld fetched\n",
				lc->conn->c_connid ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_getconn: conn %ld fetched\n%s%s",
			lc->conn->c_connid, "", "" );
#endif /* !NEW_LOGGING */
	}
	
	return lc;
}

