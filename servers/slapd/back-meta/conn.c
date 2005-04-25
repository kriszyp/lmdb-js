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
	const void *c2 )
{
	metaconn_t	*mc1 = ( metaconn_t * )c1;
        metaconn_t	*mc2 = ( metaconn_t * )c2;
	
	return SLAP_PTRCMP( mc1->mc_conn, mc2->mc_conn );
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
	void *c2 )
{
	metaconn_t	*mc1 = ( metaconn_t * )c1;
	metaconn_t	*mc2 = ( metaconn_t * )c2;

	return( ( mc1->mc_conn == mc2->mc_conn ) ? -1 : 0 );
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

	printf( "c(%d) %d\n", ( ( metaconn_t * )root->avl_data )->mc_conn->c_connid, root->avl_bf );
	
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
static metaconn_t *
metaconn_alloc(
	int		ntargets )
{
	metaconn_t	*mc;

	assert( ntargets > 0 );

	/* malloc once only; leave an extra one for one-past-end */
	mc = ( metaconn_t * )ch_malloc( sizeof( metaconn_t )
			+ sizeof( metasingleconn_t ) * ( ntargets + 1 ) );
	if ( mc == NULL ) {
		return NULL;
	}

	mc->mc_conns = ( metasingleconn_t * )&mc[ 1 ];

	/* FIXME: needed by META_LAST() */
	mc->mc_conns[ ntargets ].msc_candidate = META_LAST_CONN;

	for ( ; ntargets-- > 0; ) {
		mc->mc_conns[ ntargets ].msc_ld = NULL;
		BER_BVZERO( &mc->mc_conns[ ntargets ].msc_bound_ndn );
		BER_BVZERO( &mc->mc_conns[ ntargets ].msc_cred );
		mc->mc_conns[ ntargets ].msc_bound = META_UNBOUND;
	}

	mc->mc_auth_target = META_BOUND_NONE;
	ldap_pvt_thread_mutex_init( &mc->mc_mutex );

	return mc;
}

/*
 * meta_back_conn_free
 *
 * clears a metaconn
 */
void
meta_back_conn_free(
	metaconn_t	*mc )
{
	if ( mc == NULL ) {
		return;
	}

	ldap_pvt_thread_mutex_destroy( &mc->mc_mutex );
	
	free( mc );
}

/*
 * meta_back_init_one_conn
 * 
 * Initializes one connection
 */
int
meta_back_init_one_conn(
	Operation		*op,
	SlapReply		*rs,
	metatarget_t		*mt, 
	metasingleconn_t	*msc,
	ldap_back_send_t	sendok )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	int		vers;
	dncookie	dc;

	/*
	 * Already init'ed
	 */
	if ( msc->msc_ld != NULL ) {
		rs->sr_err = LDAP_SUCCESS;
		goto error_return;
	}
       
	/*
	 * Attempts to initialize the connection to the target ds
	 */
	rs->sr_err = ldap_initialize( &msc->msc_ld, mt->mt_uri );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto error_return;
	}

	/*
	 * Set LDAP version. This will always succeed: If the client
	 * bound with a particular version, then so can we.
	 */
	vers = op->o_conn->c_protocol;
	ldap_set_option( msc->msc_ld, LDAP_OPT_PROTOCOL_VERSION, &vers );

	/* automatically chase referrals ("chase-referrals"/"dont-chase-referrals" statement) */
	if ( LDAP_BACK_CHASE_REFERRALS( mi ) ) {
		ldap_set_option( msc->msc_ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON );
	}

#ifdef HAVE_TLS
	/* start TLS ("start-tls"/"try-start-tls" statements) */
	if ( ( LDAP_BACK_USE_TLS( mi ) || ( op->o_conn->c_is_tls && LDAP_BACK_PROPAGATE_TLS( mi ) ) )
			&& !ldap_is_ldaps_url( mt->mt_uri ) )
	{
#ifdef SLAP_STARTTLS_ASYNCHRONOUS
		/*
		 * use asynchronous StartTLS
		 * in case, chase referral (not implemented yet)
		 */
		int		msgid;

		rs->sr_err = ldap_start_tls( msc->msc_ld, NULL, NULL, &msgid );
		if ( rs->sr_err == LDAP_SUCCESS ) {
			LDAPMessage	*res = NULL;
			int		rc, nretries = mt->mt_nretries;
			struct timeval	tv = { 0, 0 };

retry:;
			rc = ldap_result( msc->msc_ld, msgid, LDAP_MSG_ALL, &tv, &res );
			if ( rc < 0 ) {
				rs->sr_err = LDAP_OTHER;

			} else if ( rc == 0 ) {
				if ( nretries != 0 ) {
					if ( nretries > 0 ) {
						nretries--;
					}
					tv.tv_sec = 0;
					tv.tv_usec = 100000;
					goto retry;
				}
				rs->sr_err = LDAP_OTHER;

			} else if ( rc == LDAP_RES_EXTENDED ) {
				struct berval	*data = NULL;

				rs->sr_err = ldap_parse_extended_result( msc->msc_ld, res,
						NULL, &data, 0 );
				if ( rs->sr_err == LDAP_SUCCESS ) {
					rs->sr_err = ldap_result2error( msc->msc_ld, res, 1 );
					res = NULL;
					
					/* FIXME: in case a referral 
					 * is returned, should we try
					 * using it instead of the 
					 * configured URI? */
					if ( rs->sr_err == LDAP_SUCCESS ) {
						ldap_install_tls( msc->msc_ld );

					} else if ( rs->sr_err == LDAP_REFERRAL ) {
						rs->sr_err = LDAP_OTHER;
						rs->sr_text = "unwilling to chase referral returned by Start TLS exop";
					}

					if ( data ) {
						if ( data->bv_val ) {
							ber_memfree( data->bv_val );
						}
						ber_memfree( data );
					}
				}

			} else {
				rs->sr_err = LDAP_OTHER;
			}

			if ( res != NULL ) {
				ldap_msgfree( res );
			}
		}
#else /* ! SLAP_STARTTLS_ASYNCHRONOUS */
		/*
		 * use synchronous StartTLS
		 */
		rs->sr_err = ldap_start_tls_s( msc->msc_ld, NULL, NULL );
#endif /* ! SLAP_STARTTLS_ASYNCHRONOUS */

		/* if StartTLS is requested, only attempt it if the URL
		 * is not "ldaps://"; this may occur not only in case
		 * of misconfiguration, but also when used in the chain 
		 * overlay, where the "uri" can be parsed out of a referral */
		if ( rs->sr_err == LDAP_SERVER_DOWN
				|| ( rs->sr_err != LDAP_SUCCESS && LDAP_BACK_TLS_CRITICAL( mi ) ) )
		{
			ldap_unbind_ext_s( msc->msc_ld, NULL, NULL );
			goto error_return;
		}
	}
#endif /* HAVE_TLS */

	/*
	 * Set the network timeout if set
	 */
	if ( mi->mi_network_timeout != 0 ) {
		struct timeval	network_timeout;

		network_timeout.tv_usec = 0;
		network_timeout.tv_sec = mi->mi_network_timeout;

		ldap_set_option( msc->msc_ld, LDAP_OPT_NETWORK_TIMEOUT,
				(void *)&network_timeout );
	}

	/*
	 * Sets a cookie for the rewrite session
	 */
	( void )rewrite_session_init( mt->mt_rwmap.rwm_rw, op->o_conn );

	/*
	 * If the connection DN is not null, an attempt to rewrite it is made
	 */
	if ( !BER_BVISEMPTY( &op->o_conn->c_dn ) ) {
		dc.rwmap = &mt->mt_rwmap;
		dc.conn = op->o_conn;
		dc.rs = rs;
		dc.ctx = "bindDN";
		
		/*
		 * Rewrite the bind dn if needed
		 */
		if ( ldap_back_dn_massage( &dc, &op->o_conn->c_dn,
					&msc->msc_bound_ndn ) )
		{
			goto error_return;
		}

		/* copy the DN idf needed */
		if ( msc->msc_bound_ndn.bv_val == op->o_conn->c_dn.bv_val ) {
			ber_dupbv( &msc->msc_bound_ndn, &op->o_conn->c_dn );
		}

		assert( !BER_BVISNULL( &msc->msc_bound_ndn ) );

	} else {
		ber_str2bv( "", 0, 1, &msc->msc_bound_ndn );
	}

	msc->msc_bound = META_UNBOUND;

error_return:;
	if ( rs->sr_err != LDAP_SUCCESS ) {
		rs->sr_err = slap_map_api2result( rs );
		if ( sendok & LDAP_BACK_SENDERR ) {
			send_ldap_result( op, rs );
			rs->sr_text = NULL;
		}
	}

	return rs->sr_err;
}

/*
 * meta_back_retry
 * 
 * Retries one connection
 */
int
meta_back_retry(
	Operation		*op,
	SlapReply		*rs,
	metaconn_t		*mc,
	int			candidate,
	ldap_back_send_t	sendok )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metatarget_t		*mt = mi->mi_targets[ candidate ];
	int			rc;
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

	ldap_pvt_thread_mutex_lock( &mc->mc_mutex );

	ldap_unbind_ext_s( msc->msc_ld, NULL, NULL );
        msc->msc_ld = NULL;
        msc->msc_bound = 0;

        /* mc here must be the regular mc, reset and ready for init */
        rc = meta_back_init_one_conn( op, rs, mt, msc, sendok );

	if ( rc == LDAP_SUCCESS ) {
        	rc = meta_back_single_dobind( op, rs, mc, candidate,
				sendok, mt->mt_nretries );
        }

	ldap_pvt_thread_mutex_unlock( &mc->mc_mutex );

	return rc == LDAP_SUCCESS ? 1 : 0;
}

/*
 * callback for unique candidate selection
 */
static int
meta_back_conn_cb( Operation *op, SlapReply *rs )
{
	assert( op->o_tag == LDAP_REQ_SEARCH );

	switch ( rs->sr_type ) {
	case REP_SEARCH:
		((int *)op->o_callback->sc_private)[0] = (int)op->o_private;
		break;

	case REP_SEARCHREF:
	case REP_RESULT:
		break;

	default:
		return rs->sr_err;
	}

	return 0;
}


static int
meta_back_get_candidate(
	Operation	*op,
	SlapReply	*rs,
	struct berval	*ndn )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	int		candidate;

	/*
	 * tries to get a unique candidate
	 * (takes care of default target)
	 */
	candidate = meta_back_select_unique_candidate( mi, ndn );

	/*
	 * if any is found, inits the connection
	 */
	if ( candidate == META_TARGET_NONE ) {
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		rs->sr_text = "no suitable candidate target found";

	} else if ( candidate == META_TARGET_MULTIPLE ) {
		Filter		f = { 0 };
		Operation	op2 = *op;
		SlapReply	rs2 = { 0 };
		slap_callback	cb2 = { 0 };
		int		rc;

		/* try to get a unique match for the request ndn
		 * among the multiple candidates available */
		op2.o_tag = LDAP_REQ_SEARCH;
		op2.o_req_dn = *ndn;
		op2.o_req_ndn = *ndn;
		op2.ors_scope = LDAP_SCOPE_BASE;
		op2.ors_deref = LDAP_DEREF_NEVER;
		op2.ors_attrs = slap_anlist_no_attrs;
		op2.ors_attrsonly = 0;
		op2.ors_limit = NULL;
		op2.ors_slimit = 1;
		op2.ors_tlimit = SLAP_NO_LIMIT;

		f.f_choice = LDAP_FILTER_PRESENT;
		f.f_desc = slap_schema.si_ad_objectClass;
		op2.ors_filter = &f;
		BER_BVSTR( &op2.ors_filterstr, "(objectClass=*)" );

		op2.o_callback = &cb2;
		cb2.sc_response = meta_back_conn_cb;
		cb2.sc_private = (void *)&candidate;

		rc = op->o_bd->be_search( &op2, &rs2 );

		switch ( rs2.sr_err ) {
		case LDAP_SUCCESS:
		default:
			rs->sr_err = rs2.sr_err;
			break;

		case LDAP_SIZELIMIT_EXCEEDED:
			/* if multiple candidates can serve the operation,
			 * and a default target is defined, and it is
			 * a candidate, try using it (FIXME: YMMV) */
			if ( mi->mi_defaulttarget != META_DEFAULT_TARGET_NONE
				&& meta_back_is_candidate( &mi->mi_targets[ mi->mi_defaulttarget ]->mt_nsuffix,
						ndn, op->o_tag == LDAP_REQ_SEARCH ? op->ors_scope : LDAP_SCOPE_BASE ) )
			{
				candidate = mi->mi_defaulttarget;
				rs->sr_err = LDAP_SUCCESS;
				rs->sr_text = NULL;

			} else {
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				rs->sr_text = "cannot select unique candidate target";
			}
			break;
		}
	}

	return candidate;
}

static void
meta_back_candidate_keyfree(
	void		*key,
	void		*data )
{
	ber_memfree_x( data, NULL );
}

SlapReply *
meta_back_candidates_get( Operation *op )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	void		*data = NULL;

	if ( op->o_threadctx ) {
		ldap_pvt_thread_pool_getkey( op->o_threadctx,
				meta_back_candidate_keyfree, &data, NULL );
	} else {
		data = (void *)mi->mi_candidates;
	}

	if ( data == NULL ) {
		data = ber_memalloc( sizeof( SlapReply ) * mi->mi_ntargets );
		if ( op->o_threadctx ) {
			ldap_pvt_thread_pool_setkey( op->o_threadctx,
					meta_back_candidate_keyfree, data,
					meta_back_candidate_keyfree );

		} else {
			mi->mi_candidates = (SlapReply *)data;
		}
	}

	return (SlapReply *)data;
}

/*
 * meta_back_getconn
 * 
 * Prepares the connection structure
 * 
 * RATIONALE:
 *
 * - determine what DN is being requested:
 *
 *	op	requires candidate	checks
 *
 *	add	unique			parent of o_req_ndn
 *	bind	unique^*[/all]		o_req_ndn [no check]
 *	compare	unique^+		o_req_ndn
 *	delete	unique			o_req_ndn
 *	modify	unique			o_req_ndn
 *	search	any			o_req_ndn
 *	modrdn	unique[, unique]	o_req_ndn[, orr_nnewSup]
 *
 * - for ops that require the candidate to be unique, in case of multiple
 *   occurrences an internal search with sizeLimit=1 is performed
 *   if a unique candidate can actually be determined.  If none is found,
 *   the operation aborts; if multiple are found, the default target
 *   is used if defined and candidate; otherwise the operation aborts.
 *
 * *^note: actually, the bind operation is handled much like a search;
 *   i.e. the bind is broadcast to all candidate targets.
 *
 * +^note: actually, the compare operation is handled much like a search;
 *   i.e. the compare is broadcast to all candidate targets, while checking
 *   that exactly none (noSuchObject) or one (TRUE/FALSE/UNDEFINED) is
 *   returned.
 */
metaconn_t *
meta_back_getconn(
       	Operation 		*op,
	SlapReply		*rs,
	int 			*candidate,
	ldap_back_send_t	sendok )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	metaconn_t	*mc, mc_curr;
	int		cached = META_TARGET_NONE,
			i = META_TARGET_NONE,
			err = LDAP_SUCCESS,
			new_conn = 0;

	meta_op_type	op_type = META_OP_REQUIRE_SINGLE;
	int		parent = 0,
			newparent = 0;
	struct berval	ndn = op->o_req_ndn,
			pndn;

	SlapReply	*candidates = meta_back_candidates_get( op );

	/* Searches for a metaconn in the avl tree */
	mc_curr.mc_conn = op->o_conn;
	ldap_pvt_thread_mutex_lock( &mi->mi_conn_mutex );
	mc = (metaconn_t *)avl_find( mi->mi_conntree, 
		(caddr_t)&mc_curr, meta_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &mi->mi_conn_mutex );

	switch ( op->o_tag ) {
	case LDAP_REQ_ADD:
		/* if we go to selection, the entry must not exist,
		 * and we must be able to resolve the parent */
		parent = 1;
		dnParent( &ndn, &pndn );
		break;

	case LDAP_REQ_MODRDN:
		/* if nnewSuperior is not NULL, it must resolve
		 * to the same candidate as the req_ndn */
		if ( op->orr_nnewSup ) {
			newparent = 1;
		}
		break;

	case LDAP_REQ_BIND:
		/* if bound as rootdn, the backend must bind to all targets
		 * with the administrative identity */
		if ( op->orb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op ) ) {
			op_type = META_OP_REQUIRE_ALL;
		}
		break;

	case LDAP_REQ_DELETE:
	case LDAP_REQ_MODIFY:
		/* just a unique candidate */
		break;

	case LDAP_REQ_COMPARE:
	case LDAP_REQ_SEARCH:
		/* allow multiple candidates for the searchBase */
		op_type = META_OP_ALLOW_MULTIPLE;
		break;

	default:
		/* right now, just break (exop?) */
		break;
	}

	/*
	 * require all connections ...
	 */
	if ( op_type == META_OP_REQUIRE_ALL ) {

		/* Looks like we didn't get a bind. Open a new session... */
		if ( !mc ) {
			mc = metaconn_alloc( mi->mi_ntargets );
			mc->mc_conn = op->o_conn;
			new_conn = 1;
		}

		for ( i = 0; i < mi->mi_ntargets; i++ ) {

			/*
			 * The target is activated; if needed, it is
			 * also init'd
			 */
			int lerr = meta_back_init_one_conn( op, rs, mi->mi_targets[ i ],
					&mc->mc_conns[ i ], sendok );
			if ( lerr == LDAP_SUCCESS ) {
				candidates[ i ].sr_tag = META_CANDIDATE;
				
			} else {
				
				/*
				 * FIXME: in case one target cannot
				 * be init'd, should the other ones
				 * be tried?
				 */
				candidates[ i ].sr_tag = META_NOT_CANDIDATE;
				err = lerr;
				continue;
			}
		}
		goto done;
	}
	
	/*
	 * looks in cache, if any
	 */
	if ( mi->mi_cache.ttl != META_DNCACHE_DISABLED ) {
		cached = i = meta_dncache_get_target( &mi->mi_cache, &op->o_req_ndn );
	}

	if ( op_type == META_OP_REQUIRE_SINGLE ) {
		int	j;

		for ( j = 0; j < mi->mi_ntargets; j++ ) {
			candidates[ j ].sr_tag = META_NOT_CANDIDATE;
		}

		/*
		 * tries to get a unique candidate
		 * (takes care of default target)
		 */
		if ( i == META_TARGET_NONE ) {
			i = meta_back_get_candidate( op, rs, &ndn );

			if ( rs->sr_err == LDAP_NO_SUCH_OBJECT && parent ) {
				i = meta_back_get_candidate( op, rs, &pndn );
			}
	
			if ( rs->sr_err != LDAP_SUCCESS ) {
				if ( sendok & LDAP_BACK_SENDERR ) {
					send_ldap_result( op, rs );
					rs->sr_text = NULL;
				}
				return NULL;
			}
		}

		if ( newparent && meta_back_get_candidate( op, rs, op->orr_nnewSup ) != i )
		{
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "cross-target rename not supported";
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
			}
			return NULL;
		}

		Debug( LDAP_DEBUG_CACHE,
	"==>meta_back_getconn: got target %d for ndn=\"%s\" from cache\n",
				i, op->o_req_ndn.bv_val, 0 );

		/* Retries searching for a metaconn in the avl tree */
		mc_curr.mc_conn = op->o_conn;
		ldap_pvt_thread_mutex_lock( &mi->mi_conn_mutex );
		mc = (metaconn_t *)avl_find( mi->mi_conntree, 
			(caddr_t)&mc_curr, meta_back_conn_cmp );
		ldap_pvt_thread_mutex_unlock( &mi->mi_conn_mutex );

		/* Looks like we didn't get a bind. Open a new session... */
		if ( !mc ) {
			mc = metaconn_alloc( mi->mi_ntargets );
			mc->mc_conn = op->o_conn;
			new_conn = 1;
		}

		/*
		 * Clear all other candidates
		 */
		( void )meta_clear_unused_candidates( op, i );

		/*
		 * The target is activated; if needed, it is
		 * also init'd. In case of error, meta_back_init_one_conn
		 * sends the appropriate result.
		 */
		err = meta_back_init_one_conn( op, rs, mi->mi_targets[ i ],
				&mc->mc_conns[ i ], sendok );
		if ( err == LDAP_SUCCESS ) {
			candidates[ i ].sr_tag = META_CANDIDATE;

		} else {
		
			/*
			 * FIXME: in case one target cannot
			 * be init'd, should the other ones
			 * be tried?
			 */
			candidates[ i ].sr_tag = META_NOT_CANDIDATE;
 			if ( new_conn ) {
				( void )meta_clear_one_candidate( &mc->mc_conns[ i ] );
				meta_back_conn_free( mc );
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

		int	ncandidates = 0;

		/* Looks like we didn't get a bind. Open a new session... */
		if ( !mc ) {
			mc = metaconn_alloc( mi->mi_ntargets );
			mc->mc_conn = op->o_conn;
			new_conn = 1;
		}

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			if ( i == cached 
				|| meta_back_is_candidate( &mi->mi_targets[ i ]->mt_nsuffix,
						&op->o_req_ndn, LDAP_SCOPE_SUBTREE ) )
			{

				/*
				 * The target is activated; if needed, it is
				 * also init'd
				 */
				int lerr = meta_back_init_one_conn( op, rs,
						mi->mi_targets[ i ],
						&mc->mc_conns[ i ], sendok );
				if ( lerr == LDAP_SUCCESS ) {
					candidates[ i ].sr_tag = META_CANDIDATE;
					ncandidates++;

				} else {
				
					/*
					 * FIXME: in case one target cannot
					 * be init'd, should the other ones
					 * be tried?
					 */
					if ( new_conn ) {
						( void )meta_clear_one_candidate( &mc->mc_conns[ i ] );
					}
					candidates[ i ].sr_tag = META_NOT_CANDIDATE;
					err = lerr;

					Debug( LDAP_DEBUG_ANY, "%s: meta_back_init_one_conn(%d) failed: %d\n",
						op->o_log_prefix, i, lerr );

					continue;
				}

			} else {
				if ( new_conn ) {
					( void )meta_clear_one_candidate( &mc->mc_conns[ i ] );
				}
				candidates[ i ].sr_tag = META_NOT_CANDIDATE;
			}
		}

		if ( ncandidates == 0 ) {
			if ( new_conn ) {
				meta_back_conn_free( mc );
			}

			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			rs->sr_text = "Unable to select valid candidates";

			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
			}

			return NULL;
		}
	}

done:;
	/* clear out meta_back_init_one_conn non-fatal errors */
	rs->sr_err = LDAP_SUCCESS;
	rs->sr_text = NULL;

	if ( new_conn ) {
		
		/*
		 * Inserts the newly created metaconn in the avl tree
		 */
		ldap_pvt_thread_mutex_lock( &mi->mi_conn_mutex );
		err = avl_insert( &mi->mi_conntree, ( caddr_t )mc,
			       	meta_back_conn_cmp, meta_back_conn_dup );

#if PRINT_CONNTREE > 0
		myprint( mi->mi_conntree );
#endif /* PRINT_CONNTREE */
		
		ldap_pvt_thread_mutex_unlock( &mi->mi_conn_mutex );

		/*
		 * Err could be -1 in case a duplicate metaconn is inserted
		 */
		if ( err == 0 ) {
			Debug( LDAP_DEBUG_TRACE,
				"%s meta_back_getconn: conn %ld inserted\n",
				op->o_log_prefix, mc->mc_conn->c_connid, 0 );

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"%s meta_back_getconn: conn %ld insert failed\n",
				op->o_log_prefix, mc->mc_conn->c_connid, 0 );
		
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "Internal server error";
			meta_back_conn_free( mc );
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
			}
			return NULL;
		}

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"%s meta_back_getconn: conn %ld fetched\n",
			op->o_log_prefix, mc->mc_conn->c_connid, 0 );
	}
	
	return mc;
}

