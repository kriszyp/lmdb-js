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
	
	return SLAP_PTRCMP( lc1->conn, lc2->conn );
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

	assert( ntargets > 0 );

	lc = ch_calloc( sizeof( struct metaconn ), 1 );
	if ( lc == NULL ) {
		return NULL;
	}
	
	/*
	 * make it a null-terminated array ...
	 */
	lc->conns = ch_calloc( sizeof( struct metasingleconn ), ntargets+1 );
	if ( lc->conns == NULL ) {
		free( lc );
		return NULL;
	}
	lc->conns[ ntargets ].candidate = META_LAST_CONN;

	for ( ; ntargets-- > 0; ) {
		lc->conns[ ntargets ].ld = NULL;
		lc->conns[ ntargets ].bound_dn.bv_val = NULL;
		lc->conns[ ntargets ].bound_dn.bv_len = 0;
		lc->conns[ ntargets ].cred.bv_val = NULL;
		lc->conns[ ntargets ].cred.bv_len = 0;
		lc->conns[ ntargets ].bound = META_UNBOUND;
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
		ch_free( lc->conns );
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
		Operation		*op,
		SlapReply		*rs,
		struct metatarget	*lt, 
		struct metasingleconn	*lsc
		)
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	int		vers;
	dncookie	dc;

	/*
	 * Already init'ed
	 */
	if ( lsc->ld != NULL ) {
		return LDAP_SUCCESS;
	}
       
	/*
	 * Attempts to initialize the connection to the target ds
	 */
	rs->sr_err = ldap_initialize( &lsc->ld, lt->uri );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		return slap_map_api2result( rs );
	}

	/*
	 * Set LDAP version. This will always succeed: If the client
	 * bound with a particular version, then so can we.
	 */
	vers = op->o_conn->c_protocol;
	ldap_set_option( lsc->ld, LDAP_OPT_PROTOCOL_VERSION, &vers );
	/* FIXME: configurable? */
	ldap_set_option(lsc->ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON);

	/*
	 * Set the network timeout if set
	 */
	if (li->network_timeout != 0){
		struct timeval network_timeout;

		network_timeout.tv_usec = 0;
		network_timeout.tv_sec = li->network_timeout;

		ldap_set_option( lsc->ld, LDAP_OPT_NETWORK_TIMEOUT, (void *) &network_timeout);
	}

	/*
	 * Sets a cookie for the rewrite session
	 */
	( void )rewrite_session_init( lt->rwmap.rwm_rw, op->o_conn );

	/*
	 * If the connection dn is not null, an attempt to rewrite it is made
	 */
	if ( op->o_conn->c_dn.bv_len != 0 ) {
		dc.rwmap = &lt->rwmap;
		dc.conn = op->o_conn;
		dc.rs = rs;
		dc.ctx = "bindDN";
		
		/*
		 * Rewrite the bind dn if needed
		 */
		if ( ldap_back_dn_massage( &dc, &op->o_conn->c_dn,
					&lsc->bound_dn) ) {
			send_ldap_result( op, rs );
			return rs->sr_err;
		}

		/* copy the DN idf needed */
		if ( lsc->bound_dn.bv_val == op->o_conn->c_dn.bv_val ) {
			ber_dupbv( &lsc->bound_dn, &op->o_conn->c_dn );
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
	       	Operation 	*op,
		SlapReply	*rs,
		int 		op_type,
		struct berval	*ndn,
		int 		*candidate )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn *lc, lc_curr;
	int cached = -1, i = -1, err = LDAP_SUCCESS;
	int new_conn = 0;

	/* Searches for a metaconn in the avl tree */
	lc_curr.conn = op->o_conn;
	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	lc = (struct metaconn *)avl_find( li->conntree, 
		(caddr_t)&lc_curr, meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	/* Looks like we didn't get a bind. Open a new session... */
	if ( !lc ) {
		lc = metaconn_alloc( li->ntargets );
		lc->conn = op->o_conn;
		new_conn = 1;
	}

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

			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			return NULL;
		}
				
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, INFO,
			"meta_back_getconn: got target %d for ndn=\"%s\" from cache\n", 
			i, ndn->bv_val, 0 );
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
		err = init_one_conn( op, rs, li->targets[ i ],
				&lc->conns[ i ] );
		if ( err != LDAP_SUCCESS ) {
		
			/*
			 * FIXME: in case one target cannot
			 * be init'd, should the other ones
			 * be tried?
			 */
			( void )meta_clear_one_candidate( &lc->conns[ i ], 1 );
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
			int lerr = init_one_conn( op, rs, li->targets[ i ],
					&lc->conns[ i ] );
			if ( lerr != LDAP_SUCCESS ) {
				
				/*
				 * FIXME: in case one target cannot
				 * be init'd, should the other ones
				 * be tried?
				 */
				( void )meta_clear_one_candidate( &lc->conns[ i ], 1 );
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
				int lerr = init_one_conn( op, rs,
						li->targets[ i ],
						&lc->conns[ i ] );
				if ( lerr != LDAP_SUCCESS ) {
				
					/*
					 * FIXME: in case one target cannot
					 * be init'd, should the other ones
					 * be tried?
					 */
					( void )meta_clear_one_candidate( &lc->conns[ i ], 1 );
					err = lerr;
					continue;
				}
			}
		}
	}

	/* clear out init_one_conn non-fatal errors */
	rs->sr_err = LDAP_SUCCESS;
	rs->sr_text = NULL;

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
		LDAP_LOG( BACK_META, INFO,
			"meta_back_getconn: conn %ld inserted\n", lc->conn->c_connid, 0, 0);
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_getconn: conn %ld inserted\n%s%s",
			lc->conn->c_connid, "", "" );
#endif /* !NEW_LOGGING */
		
		/*
		 * Err could be -1 in case a duplicate metaconn is inserted
		 */
		if ( err != 0 ) {
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "Internal server error";
			metaconn_free( lc );
			return NULL;
		}
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, INFO,
			"meta_back_getconn: conn %ld fetched\n", lc->conn->c_connid, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_getconn: conn %ld fetched\n%s%s",
			lc->conn->c_connid, "", "" );
#endif /* !NEW_LOGGING */
	}
	
	return lc;
}

