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
	
	return SLAP_PTRCMP( lc1->mc_conn, lc2->mc_conn );
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

	return( ( lc1->mc_conn == lc2->mc_conn ) ? -1 : 0 );
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
	
	ravl_print( root->avl_right, depth + 1 );
	
	for ( i = 0; i < depth; i++ ) {
		printf( "    " );
	}

	printf( "c(%d) %d\n", ( ( struct metaconn * )root->avl_data )->mc_conn->c_connid, root->avl_bf );
	
	ravl_print( root->avl_left, depth + 1 );
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
	lc->mc_conns = ch_calloc( sizeof( struct metasingleconn ), ntargets+1 );
	if ( lc->mc_conns == NULL ) {
		free( lc );
		return NULL;
	}
	lc->mc_conns[ ntargets ].msc_candidate = META_LAST_CONN;

	for ( ; ntargets-- > 0; ) {
		lc->mc_conns[ ntargets ].msc_ld = NULL;
		BER_BVZERO( &lc->mc_conns[ ntargets ].msc_bound_ndn );
		BER_BVZERO( &lc->mc_conns[ ntargets ].msc_cred );
		lc->mc_conns[ ntargets ].msc_bound = META_UNBOUND;
	}

	lc->mc_bound_target = META_BOUND_NONE;

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
	
	if ( lc->mc_conns ) {
		ch_free( lc->mc_conns );
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
		struct metasingleconn	*lsc,
		ldap_back_send_t	sendok )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	int		vers;
	dncookie	dc;

	/*
	 * Already init'ed
	 */
	if ( lsc->msc_ld != NULL ) {
		return LDAP_SUCCESS;
	}
       
	/*
	 * Attempts to initialize the connection to the target ds
	 */
	rs->sr_err = ldap_initialize( &lsc->msc_ld, lt->mt_uri );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto error_return;
	}

	/*
	 * Set LDAP version. This will always succeed: If the client
	 * bound with a particular version, then so can we.
	 */
	vers = op->o_conn->c_protocol;
	ldap_set_option( lsc->msc_ld, LDAP_OPT_PROTOCOL_VERSION, &vers );

	/* automatically chase referrals ("chase-referrals"/"dont-chase-referrals" statement) */
	if ( LDAP_BACK_CHASE_REFERRALS( li ) ) {
		ldap_set_option( lsc->msc_ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON );
	}

	/* start TLS ("start-tls"/"try-start-tls" statements) */
	if ( ( LDAP_BACK_USE_TLS( li ) || ( op->o_conn->c_is_tls && LDAP_BACK_PROPAGATE_TLS( li ) ) )
			&& !ldap_is_ldaps_url( lt->mt_uri ) )
	{
#if 0
		int		rc, msgid;
		LDAPMessage	*res;
		int		retries = 1;

retry:;
		rc = ldap_start_tls( lsc->msc_ld, NULL, NULL, &msgid );
		if ( rc == LDAP_SUCCESS ) {
			struct timeval	tv = { 0, 0 };

			rc = ldap_result( lsc->msc_ld, msgid, LDAP_MSG_ALL, &tv, &res );
			if ( rc < 0 ) {
				rs->sr_err = LDAP_OTHER;

			} else if ( rc == 0 ) {
				if ( retries ) {
					retries--;
					tv.tv_sec = 0;
					tv.tv_usec = 100000;
					goto retry;
				}
				rs->sr_err = LDAP_OTHER;

			} else {
				if ( rc == LDAP_RES_EXTENDED ) {
					rc = ldap_parse_result( lsc->msc_ld, res,
						&rs->sr_err, NULL, NULL, NULL, NULL, 1 );
					if ( rc != LDAP_SUCCESS ) {
						rs->sr_err = rc;

					/* FIXME: in case a referral 
					 * is returned, should we try
					 * using it instead of the 
					 * configured URI? */
					} else if ( rs->sr_err == LDAP_REFERRAL ) {
						rs->sr_err = LDAP_OTHER;
						rs->sr_text = "unwilling to chase referral returned by Start TLS exop";
					}

				} else {
					ldap_msgfree( res );
					rs->sr_err = LDAP_OTHER;
				}
			}
		}
#else
		rs->sr_err = ldap_start_tls_s( lsc->msc_ld, NULL, NULL );
#endif

		/* if StartTLS is requested, only attempt it if the URL
		 * is not "ldaps://"; this may occur not only in case
		 * of misconfiguration, but also when used in the chain 
		 * overlay, where the "uri" can be parsed out of a referral */
		if ( rs->sr_err == LDAP_SERVER_DOWN
				|| ( rs->sr_err != LDAP_SUCCESS && LDAP_BACK_TLS_CRITICAL( li ) ) )
		{
			ldap_unbind_ext_s( lsc->msc_ld, NULL, NULL );
			goto error_return;
		}
	}

	/*
	 * Set the network timeout if set
	 */
	if (li->network_timeout != 0){
		struct timeval	network_timeout;

		network_timeout.tv_usec = 0;
		network_timeout.tv_sec = li->network_timeout;

		ldap_set_option( lsc->msc_ld, LDAP_OPT_NETWORK_TIMEOUT,
				(void *)&network_timeout );
	}

	/*
	 * Sets a cookie for the rewrite session
	 */
	( void )rewrite_session_init( lt->mt_rwmap.rwm_rw, op->o_conn );

	/*
	 * If the connection DN is not null, an attempt to rewrite it is made
	 */
	if ( !BER_BVISEMPTY( &op->o_conn->c_dn ) ) {
		dc.rwmap = &lt->mt_rwmap;
		dc.conn = op->o_conn;
		dc.rs = rs;
		dc.ctx = "bindDN";
		
		/*
		 * Rewrite the bind dn if needed
		 */
		if ( ldap_back_dn_massage( &dc, &op->o_conn->c_dn,
					&lsc->msc_bound_ndn ) )
		{
			goto error_return;
		}

		/* copy the DN idf needed */
		if ( lsc->msc_bound_ndn.bv_val == op->o_conn->c_dn.bv_val ) {
			ber_dupbv( &lsc->msc_bound_ndn, &op->o_conn->c_dn );
		}

		assert( !BER_BVISNULL( &lsc->msc_bound_ndn ) );

	} else {
		ber_str2bv( "", 0, 1, &lsc->msc_bound_ndn );
	}

	lsc->msc_bound = META_UNBOUND;

error_return:;
	if ( rs->sr_err != LDAP_SUCCESS ) {
		rs->sr_err = slap_map_api2result( rs );
		if ( sendok & LDAP_BACK_SENDERR ) {
			send_ldap_result( op, rs );
			rs->sr_text = NULL;
		}

	} else {

		/*
		 * The candidate is activated
		 */
		lsc->msc_candidate = META_CANDIDATE;
	}

	return rs->sr_err;
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
	       	Operation 		*op,
		SlapReply		*rs,
		int 			op_type,
		struct berval		*ndn,
		int 			*candidate,
		ldap_back_send_t	sendok )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn	*lc, lc_curr;
	int		cached = META_TARGET_NONE,
			i = META_TARGET_NONE,
			err = LDAP_SUCCESS,
			new_conn = 0;

	/* Searches for a metaconn in the avl tree */
	lc_curr.mc_conn = op->o_conn;
	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	lc = (struct metaconn *)avl_find( li->conntree, 
		(caddr_t)&lc_curr, meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	/* Looks like we didn't get a bind. Open a new session... */
	if ( !lc ) {
		lc = metaconn_alloc( li->ntargets );
		lc->mc_conn = op->o_conn;
		new_conn = 1;
	}

	/*
	 * require all connections ...
	 */
	if ( op_type == META_OP_REQUIRE_ALL ) {
		for ( i = 0; i < li->ntargets; i++ ) {

			/*
			 * The target is activated; if needed, it is
			 * also init'd
			 */
			int lerr = init_one_conn( op, rs, li->targets[ i ],
					&lc->mc_conns[ i ], sendok );
			if ( lerr != LDAP_SUCCESS ) {
				
				/*
				 * FIXME: in case one target cannot
				 * be init'd, should the other ones
				 * be tried?
				 */
				( void )meta_clear_one_candidate( &lc->mc_conns[ i ], 1 );
				err = lerr;
				continue;
			}
		}
		goto done;
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
		if ( i == META_TARGET_NONE ) {
			i = meta_back_select_unique_candidate( li, ndn );
		}

		/*
		 * if any is found, inits the connection
		 */
		if ( i == META_TARGET_NONE ) {
			if ( new_conn ) {
				metaconn_free( lc );
			}

			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			return NULL;
		}
				
		Debug( LDAP_DEBUG_CACHE,
	"==>meta_back_getconn: got target %d for ndn=\"%s\" from cache\n",
				i, ndn->bv_val, 0 );

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
				&lc->mc_conns[ i ], sendok );
		if ( err != LDAP_SUCCESS ) {
		
			/*
			 * FIXME: in case one target cannot
			 * be init'd, should the other ones
			 * be tried?
			 */
			( void )meta_clear_one_candidate( &lc->mc_conns[ i ], 1 );
			if ( new_conn ) {
				metaconn_free( lc );
			}
			return NULL;
		}

		if ( candidate ) {
			*candidate = i;
		}

	/*
	 * if no unique candidate ...
	 */
	} else {
		for ( i = 0; i < li->ntargets; i++ ) {
			if ( i == cached 
				|| meta_back_is_candidate( &li->targets[ i ]->mt_nsuffix, ndn ) )
			{

				/*
				 * The target is activated; if needed, it is
				 * also init'd
				 */
				int lerr = init_one_conn( op, rs,
						li->targets[ i ],
						&lc->mc_conns[ i ], sendok );
				if ( lerr != LDAP_SUCCESS ) {
				
					/*
					 * FIXME: in case one target cannot
					 * be init'd, should the other ones
					 * be tried?
					 */
					( void )meta_clear_one_candidate( &lc->mc_conns[ i ], 1 );
					err = lerr;
					continue;
				}
			}
		}
	}

done:;
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

		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_getconn: conn %ld inserted\n",
			lc->mc_conn->c_connid, 0, 0 );
		
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
		Debug( LDAP_DEBUG_TRACE,
			"=>meta_back_getconn: conn %ld fetched\n",
			lc->mc_conn->c_connid, 0, 0 );
	}
	
	return lc;
}

