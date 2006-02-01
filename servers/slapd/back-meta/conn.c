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
	int		rc;
	
	/* If local DNs don't match, it is definitely not a match */
	rc = ber_bvcmp( &mc1->mc_local_ndn, &mc2->mc_local_ndn );
	if ( rc ) {
		return rc;
	}

	/* For shared sessions, conn is NULL. Only explicitly
	 * bound sessions will have non-NULL conn.
	 */
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

	/* Cannot have more than one shared session with same DN */
	if ( dn_match( &mc1->mc_local_ndn, &mc2->mc_local_ndn ) &&
       			mc1->mc_conn == mc2->mc_conn )
	{
		return -1;
	}
		
	return 0;
}

/*
 * Debug stuff (got it from libavl)
 */
#if PRINT_CONNTREE > 0
static void
ravl_print( Avlnode *root, int depth )
{
	int     	i;
	metaconn_t	*mc = (metaconn_t *)root->avl_data;
	
	if ( root == 0 ) {
		return;
	}
	
	ravl_print( root->avl_right, depth + 1 );
	
	for ( i = 0; i < depth; i++ ) {
		printf( "    " );
	}

	printf( "c(%d%s%s) %d\n",
		LDAP_BACK_PCONN_ID( mc->mc_conn ),
		BER_BVISNULL( &mc->mc_local_ndn ) ? "" : ": ",
		BER_BVISNULL( &mc->mc_local_ndn ) ? "" : mc->mc_local_ndn.bv_val,
		root->avl_bf );
	
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
       	Operation 		*op )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;
	metaconn_t	*mc;
	int		i, ntargets = mi->mi_ntargets;

	assert( ntargets > 0 );

	/* malloc all in one */
	mc = ( metaconn_t * )ch_malloc( sizeof( metaconn_t )
			+ sizeof( metasingleconn_t ) * ntargets );
	if ( mc == NULL ) {
		return NULL;
	}

	for ( i = 0; i < ntargets; i++ ) {
		mc->mc_conns[ i ].msc_ld = NULL;
		BER_BVZERO( &mc->mc_conns[ i ].msc_bound_ndn );
		BER_BVZERO( &mc->mc_conns[ i ].msc_cred );
		LDAP_BACK_CONN_ISBOUND_CLEAR( &mc->mc_conns[ i ] );
		mc->mc_conns[ i ].msc_info = mi;
	}

	BER_BVZERO( &mc->mc_local_ndn );
	mc->msc_mscflags = 0;
	mc->mc_authz_target = META_BOUND_NONE;
	ldap_pvt_thread_mutex_init( &mc->mc_mutex );
	mc->mc_refcnt = 1;
	mc->mc_tainted = 0;

	return mc;
}

static void
meta_back_freeconn(
	Operation	*op,
	metaconn_t	*mc )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;

	assert( mc != NULL );

	ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );

	if ( --mc->mc_refcnt == 0 ) {
		meta_back_conn_free( mc );
	}

	ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
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
	metaconn_t		*mc,
	int			candidate,
	int			ispriv,
	ldap_back_send_t	sendok )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];
	int			vers;
	dncookie		dc;
	int			isauthz = ( candidate == mc->mc_authz_target );

	/*
	 * Already init'ed
	 */
	if ( msc->msc_ld != NULL ) {
		int	doreturn = 1;

		if ( ( mt->mt_idle_timeout != 0 && op->o_time > msc->msc_time + mt->mt_idle_timeout )
			|| ( mt->mt_conn_ttl != 0 && op->o_time > msc->msc_create_time + mt->mt_conn_ttl ) )
		{
			Debug( LDAP_DEBUG_TRACE,
				"%s meta_back_init_one_conn[%d]: idle timeout/ttl.\n",
				op->o_log_prefix, candidate, 0 );
			if ( meta_back_retry( op, rs, mc, candidate, sendok ) ) {
				return rs->sr_err;
			}

			doreturn = 0;
		}

		if ( mt->mt_idle_timeout != 0 ) {
			msc->msc_time = op->o_time;
		}

		if ( doreturn ) {
			return rs->sr_err = LDAP_SUCCESS;
		}
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
	/* start TLS ("tls [try-]{start|propagate}" statement) */
	if ( ( LDAP_BACK_USE_TLS( mi ) || ( op->o_conn->c_is_tls && LDAP_BACK_PROPAGATE_TLS( mi ) ) )
			&& !ldap_is_ldaps_url( mt->mt_uri ) )
	{
#ifdef SLAP_STARTTLS_ASYNCHRONOUS
		/*
		 * use asynchronous StartTLS; in case, chase referral
		 * FIXME: OpenLDAP does not return referral on StartTLS yet
		 */
		int		msgid;

		rs->sr_err = ldap_start_tls( msc->msc_ld, NULL, NULL, &msgid );
		if ( rs->sr_err == LDAP_SUCCESS ) {
			LDAPMessage	*res = NULL;
			int		rc, nretries = mt->mt_nretries;
			struct timeval	tv;

			LDAP_BACK_TV_SET( &tv );

retry:;
			rc = ldap_result( msc->msc_ld, msgid, LDAP_MSG_ALL, &tv, &res );
			if ( rc < 0 ) {
				rs->sr_err = LDAP_OTHER;

			} else if ( rc == 0 ) {
				if ( nretries != 0 ) {
					if ( nretries > 0 ) {
						nretries--;
					}
					LDAP_BACK_TV_SET( &tv );
					goto retry;
				}
				rs->sr_err = LDAP_OTHER;

			} else if ( rc == LDAP_RES_EXTENDED ) {
				struct berval	*data = NULL;

				rs->sr_err = ldap_parse_extended_result( msc->msc_ld, res,
						NULL, &data, 0 );
				if ( rs->sr_err == LDAP_SUCCESS ) {
					int		err;

					rs->sr_err = ldap_parse_result( msc->msc_ld, res,
						&err, NULL, NULL, NULL, NULL, 1 );
					res = NULL;

					if ( rs->sr_err == LDAP_SUCCESS ) {
						rs->sr_err = err;
					}
					
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
	if ( mt->mt_network_timeout != 0 ) {
		struct timeval	network_timeout;

		network_timeout.tv_usec = 0;
		network_timeout.tv_sec = mt->mt_network_timeout;

		ldap_set_option( msc->msc_ld, LDAP_OPT_NETWORK_TIMEOUT,
				(void *)&network_timeout );
	}

	/*
	 * If the connection DN is not null, an attempt to rewrite it is made
	 */

	if ( ispriv ) {
		if ( !BER_BVISNULL( &mt->mt_pseudorootdn ) ) {
			ber_dupbv( &msc->msc_bound_ndn, &mt->mt_pseudorootdn );
			if ( !BER_BVISNULL( &mt->mt_pseudorootpw ) ) {
				ber_dupbv( &msc->msc_cred, &mt->mt_pseudorootpw );
			}

		} else {
			ber_str2bv( "", 0, 1, &msc->msc_bound_ndn );
		}

		LDAP_BACK_CONN_ISPRIV_SET( msc );

	} else {
		BER_BVZERO( &msc->msc_cred );
		BER_BVZERO( &msc->msc_bound_ndn );
		if ( !BER_BVISEMPTY( &op->o_ndn )
			&& SLAP_IS_AUTHZ_BACKEND( op )
			&& isauthz )
		{
			dc.target = mt;
			dc.conn = op->o_conn;
			dc.rs = rs;
			dc.ctx = "bindDN";
		
			/*
			 * Rewrite the bind dn if needed
			 */
			if ( ldap_back_dn_massage( &dc, &op->o_conn->c_dn,
						&msc->msc_bound_ndn ) )
			{
				ldap_unbind_ext_s( msc->msc_ld, NULL, NULL );
				goto error_return;
			}
			
			/* copy the DN idf needed */
			if ( msc->msc_bound_ndn.bv_val == op->o_conn->c_dn.bv_val ) {
				ber_dupbv( &msc->msc_bound_ndn, &op->o_conn->c_dn );
			}

		} else {
			ber_str2bv( "", 0, 1, &msc->msc_bound_ndn );
		}
	}

	assert( !BER_BVISNULL( &msc->msc_bound_ndn ) );

	LDAP_BACK_CONN_ISBOUND_CLEAR( msc );

error_return:;
	if ( rs->sr_err == LDAP_SUCCESS ) {
		/*
		 * Sets a cookie for the rewrite session
		 */
		( void )rewrite_session_init( mt->mt_rwmap.rwm_rw, op->o_conn );

		if ( mt->mt_idle_timeout ) {
			msc->msc_time = op->o_time;
		}

		if ( mt->mt_conn_ttl ) {
			msc->msc_create_time = op->o_time;
		}

	} else {
		rs->sr_err = slap_map_api2result( rs );
		if ( sendok & LDAP_BACK_SENDERR ) {
			send_ldap_result( op, rs );
			rs->sr_text = NULL;
		}
	}

	return rs->sr_err;
}

/*
 * meta_back_retry_lock
 * 
 * Retries one connection
 */
int
meta_back_retry_lock(
	Operation		*op,
	SlapReply		*rs,
	metaconn_t		*mc,
	int			candidate,
	ldap_back_send_t	sendok,
	int			dolock )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metatarget_t		*mt = &mi->mi_targets[ candidate ];
	int			rc = LDAP_UNAVAILABLE;
	metasingleconn_t	*msc = &mc->mc_conns[ candidate ];

retry_lock:;
	ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );

	assert( mc->mc_refcnt > 0 );

	if ( mc->mc_refcnt == 1 ) {
		char	buf[ SLAP_TEXT_BUFLEN ];

		while ( dolock && ldap_pvt_thread_mutex_trylock( &mc->mc_mutex ) ) {
			ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
			ldap_pvt_thread_yield();
			goto retry_lock;
		}

		snprintf( buf, sizeof( buf ),
			"retrying URI=\"%s\" DN=\"%s\"",
			mt->mt_uri,
			BER_BVISNULL( &msc->msc_bound_ndn ) ?
				"" : msc->msc_bound_ndn.bv_val );
		Debug( LDAP_DEBUG_ANY,
			"%s meta_back_retry[%d]: %s.\n",
			op->o_log_prefix, candidate, buf );

		meta_clear_one_candidate( msc );
		LDAP_BACK_CONN_ISBOUND_CLEAR( msc );

		( void )rewrite_session_delete( mt->mt_rwmap.rwm_rw, op->o_conn );

		/* mc here must be the regular mc, reset and ready for init */
		rc = meta_back_init_one_conn( op, rs, mt, mc, candidate,
			LDAP_BACK_CONN_ISPRIV( mc ), sendok );

		if ( rc == LDAP_SUCCESS ) {
			if ( be_isroot( op ) && !BER_BVISNULL( &mi->mi_targets[ candidate ].mt_pseudorootdn ) )
			{
				Operation	op2 = *op;

				op2.o_tag = LDAP_REQ_BIND;
				op2.o_req_dn = mi->mi_targets[ candidate ].mt_pseudorootdn;
				op2.o_req_ndn = mi->mi_targets[ candidate ].mt_pseudorootdn;
				op2.orb_cred = mi->mi_targets[ candidate ].mt_pseudorootpw;
				op2.orb_method = LDAP_AUTH_SIMPLE;

				rc = meta_back_single_bind( &op2, rs, mc, candidate, 0 );

			} else {
				rc = meta_back_single_dobind( op, rs, mc, candidate,
					sendok, mt->mt_nretries, 0 );
			}
        	}

		if ( dolock ) {
			ldap_pvt_thread_mutex_unlock( &mc->mc_mutex );
		}
	}

	if ( rc != LDAP_SUCCESS ) {
		mc->mc_tainted = 1;
	}

	ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );

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
		((long *)op->o_callback->sc_private)[0] = (long)op->o_private;
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
	long		candidate;

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
				&& meta_back_is_candidate( &mi->mi_targets[ mi->mi_defaulttarget ].mt_nsuffix,
						mi->mi_targets[ mi->mi_defaulttarget ].mt_scope,
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

	} else {
		rs->sr_err = LDAP_SUCCESS;
	}

	return candidate;
}

static void	*meta_back_candidates_dummy;

static void
meta_back_candidates_keyfree(
	void		*key,
	void		*data )
{
	metacandidates_t	*mc = (metacandidates_t *)data;

	ber_memfree_x( mc->mc_candidates, NULL );
	ber_memfree_x( data, NULL );
}

SlapReply *
meta_back_candidates_get( Operation *op )
{
	metainfo_t		*mi = ( metainfo_t * )op->o_bd->be_private;
	metacandidates_t	*mc;

	if ( op->o_threadctx ) {
		void		*data = NULL;

		ldap_pvt_thread_pool_getkey( op->o_threadctx,
				&meta_back_candidates_dummy, &data, NULL );
		mc = (metacandidates_t *)data;

	} else {
		mc = mi->mi_candidates;
	}

	if ( mc == NULL ) {
		mc = ch_calloc( sizeof( metacandidates_t ), 1 );
		mc->mc_ntargets = mi->mi_ntargets;
		mc->mc_candidates = ch_calloc( sizeof( SlapReply ), mc->mc_ntargets );
		if ( op->o_threadctx ) {
			void		*data = NULL;

			data = (void *)mc;
			ldap_pvt_thread_pool_setkey( op->o_threadctx,
					&meta_back_candidates_dummy, data,
					meta_back_candidates_keyfree );

		} else {
			mi->mi_candidates = mc;
		}

	} else if ( mc->mc_ntargets < mi->mi_ntargets ) {
		/* NOTE: in the future, may want to allow back-config
		 * to add/remove targets from back-meta... */
		mc->mc_ntargets = mi->mi_ntargets;
		mc->mc_candidates = ch_realloc( mc->mc_candidates,
				sizeof( SlapReply ) * mc->mc_ntargets );
	}

	return mc->mc_candidates;
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
	metaconn_t	*mc = NULL,
			mc_curr = { 0 };
	int		cached = META_TARGET_NONE,
			i = META_TARGET_NONE,
			err = LDAP_SUCCESS,
			new_conn = 0,
			ncandidates = 0;


	meta_op_type	op_type = META_OP_REQUIRE_SINGLE;
	int		parent = 0,
			newparent = 0;
	struct berval	ndn = op->o_req_ndn,
			pndn;

	SlapReply	*candidates = meta_back_candidates_get( op );

	/* Internal searches are privileged and shared. So is root. */
	/* FIXME: there seem to be concurrency issues */
	if ( op->o_do_not_cache || be_isroot( op ) ) {
		mc_curr.mc_local_ndn = op->o_bd->be_rootndn;
		LDAP_BACK_CONN_ISPRIV_SET( &mc_curr );
		mc_curr.mc_conn = LDAP_BACK_PCONN_SET( op );

	} else {
		mc_curr.mc_local_ndn = op->o_ndn;

		/* Explicit binds must not be shared */
		if ( op->o_tag == LDAP_REQ_BIND || SLAP_IS_AUTHZ_BACKEND( op ) ) {
			mc_curr.mc_conn = op->o_conn;
	
		} else {
			mc_curr.mc_conn = LDAP_BACK_PCONN_SET( op );
		}
	}

	/* Explicit Bind requests always get their own conn */
	if ( !( sendok & LDAP_BACK_BINDING ) ) {
		/* Searches for a metaconn in the avl tree */
retry_lock:
		ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
		mc = (metaconn_t *)avl_find( mi->mi_conninfo.lai_tree, 
			(caddr_t)&mc_curr, meta_back_conn_cmp );
		if ( mc ) {
			if ( mc->mc_tainted ) {
				rs->sr_err = LDAP_UNAVAILABLE;
				rs->sr_text = "remote server unavailable";
				ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
				return NULL;
			}
			
			/* Don't reuse connections while they're still binding */
			if ( LDAP_BACK_CONN_BINDING( mc ) ) {
				ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
				ldap_pvt_thread_yield();
				goto retry_lock;
			}
			mc->mc_refcnt++;
		}
		ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
	}

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
		if ( mc == NULL ) {
			mc = metaconn_alloc( op );
			mc->mc_conn = mc_curr.mc_conn;
			ber_dupbv( &mc->mc_local_ndn, &mc_curr.mc_local_ndn );
			new_conn = 1;
			if ( sendok & LDAP_BACK_BINDING ) {
				LDAP_BACK_CONN_BINDING_SET( mc );
			}
		}

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			metatarget_t		*mt = &mi->mi_targets[ i ];

			/*
			 * The target is activated; if needed, it is
			 * also init'd
			 */
			candidates[ i ].sr_err = meta_back_init_one_conn( op,
				rs, mt, mc, i,
				LDAP_BACK_CONN_ISPRIV( &mc_curr ), sendok );
			if ( candidates[ i ].sr_err == LDAP_SUCCESS ) {
				candidates[ i ].sr_tag = META_CANDIDATE;
				ncandidates++;
	
			} else {
				
				/*
				 * FIXME: in case one target cannot
				 * be init'd, should the other ones
				 * be tried?
				 */
				candidates[ i ].sr_tag = META_NOT_CANDIDATE;
				err = candidates[ i ].sr_err;
				continue;
			}
		}

		if ( ncandidates == 0 ) {
			if ( new_conn ) {
				meta_back_freeconn( op, mc );

			} else {
				meta_back_release_conn( op, mc );
			}

			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			rs->sr_text = "Unable to select valid candidates";

			if ( sendok & LDAP_BACK_SENDERR ) {
				if ( rs->sr_err == LDAP_NO_SUCH_OBJECT ) {
					rs->sr_matched = op->o_bd->be_suffix[ 0 ].bv_val;
				}
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
				rs->sr_matched = NULL;
			}

			return NULL;
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
		metatarget_t		*mt = NULL;
		metasingleconn_t	*msc = NULL;

		int			j;

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
				if ( mc != NULL ) {
					meta_back_release_conn( op, mc );
				}

				if ( sendok & LDAP_BACK_SENDERR ) {
					if ( rs->sr_err == LDAP_NO_SUCH_OBJECT ) {
						rs->sr_matched = op->o_bd->be_suffix[ 0 ].bv_val;
					}
					send_ldap_result( op, rs );
					rs->sr_text = NULL;
					rs->sr_matched = NULL;
				}
			
				return NULL;
			}
		}

		if ( newparent && meta_back_get_candidate( op, rs, op->orr_nnewSup ) != i )
		{
			if ( mc != NULL ) {
				meta_back_release_conn( op, mc );
			}

			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "cross-target rename not supported";
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
			}

			return NULL;
		}

		Debug( LDAP_DEBUG_TRACE,
	"==>meta_back_getconn: got target=%d for ndn=\"%s\" from cache\n",
				i, op->o_req_ndn.bv_val, 0 );

		if ( mc == NULL ) {
			/* Retries searching for a metaconn in the avl tree
			 * the reason is that the connection might have been
			 * created by meta_back_get_candidate() */
			if ( !( sendok & LDAP_BACK_BINDING ) ) {
				ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
				mc = (metaconn_t *)avl_find( mi->mi_conninfo.lai_tree, 
					(caddr_t)&mc_curr, meta_back_conn_cmp );
				if ( mc != NULL ) {
					mc->mc_refcnt++;
				}
				ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
			}

			/* Looks like we didn't get a bind. Open a new session... */
			if ( mc == NULL ) {
				mc = metaconn_alloc( op );
				mc->mc_conn = mc_curr.mc_conn;
				ber_dupbv( &mc->mc_local_ndn, &mc_curr.mc_local_ndn );
				new_conn = 1;
				if ( sendok & LDAP_BACK_BINDING ) {
					LDAP_BACK_CONN_BINDING_SET( mc );
				}
			}
		}

		/*
		 * Clear all other candidates
		 */
		( void )meta_clear_unused_candidates( op, i );

		mt = &mi->mi_targets[ i ];
		msc = &mc->mc_conns[ i ];

		/*
		 * The target is activated; if needed, it is
		 * also init'd. In case of error, meta_back_init_one_conn
		 * sends the appropriate result.
		 */
		err = meta_back_init_one_conn( op, rs, mt, mc, i,
			LDAP_BACK_CONN_ISPRIV( &mc_curr ), sendok );
		if ( err != LDAP_SUCCESS ) {
			/*
			 * FIXME: in case one target cannot
			 * be init'd, should the other ones
			 * be tried?
			 */
			candidates[ i ].sr_tag = META_NOT_CANDIDATE;
 			if ( new_conn ) {
				(void)meta_clear_one_candidate( msc );
				meta_back_freeconn( op, mc );

			} else {
				meta_back_release_conn( op, mc );
			}
			return NULL;
		}

		candidates[ i ].sr_err = LDAP_SUCCESS;
		candidates[ i ].sr_tag = META_CANDIDATE;
		ncandidates++;

		if ( candidate ) {
			*candidate = i;
		}

	/*
	 * if no unique candidate ...
	 */
	} else {

		/* Looks like we didn't get a bind. Open a new session... */
		if ( mc == NULL ) {
			mc = metaconn_alloc( op );
			mc->mc_conn = mc_curr.mc_conn;
			ber_dupbv( &mc->mc_local_ndn, &mc_curr.mc_local_ndn );
			new_conn = 1;
			if ( sendok & LDAP_BACK_BINDING ) {
				LDAP_BACK_CONN_BINDING_SET( mc );
			}
		}

		for ( i = 0; i < mi->mi_ntargets; i++ ) {
			metatarget_t		*mt = &mi->mi_targets[ i ];
			metasingleconn_t	*msc = &mc->mc_conns[ i ];

			if ( i == cached 
				|| meta_back_is_candidate( &mt->mt_nsuffix,
						mt->mt_scope,
						&op->o_req_ndn,
						LDAP_SCOPE_SUBTREE ) )
			{

				/*
				 * The target is activated; if needed, it is
				 * also init'd
				 */
				int lerr = meta_back_init_one_conn( op, rs,
						mt, mc, i,
						LDAP_BACK_CONN_ISPRIV( &mc_curr ),
						sendok );
				if ( lerr == LDAP_SUCCESS ) {
					candidates[ i ].sr_tag = META_CANDIDATE;
					candidates[ i ].sr_err = LDAP_SUCCESS;
					ncandidates++;

					Debug( LDAP_DEBUG_TRACE, "%s: meta_back_getconn[%d]\n",
						op->o_log_prefix, i, 0 );

				} else {
				
					/*
					 * FIXME: in case one target cannot
					 * be init'd, should the other ones
					 * be tried?
					 */
					if ( new_conn ) {
						( void )meta_clear_one_candidate( msc );
					}
					/* leave the target candidate, but record the error for later use */
					candidates[ i ].sr_err = lerr;
					err = lerr;

					Debug( LDAP_DEBUG_ANY, "%s: meta_back_getconn[%d] failed: %d\n",
						op->o_log_prefix, i, lerr );

					continue;
				}

			} else {
				if ( new_conn ) {
					( void )meta_clear_one_candidate( msc );
				}
				candidates[ i ].sr_tag = META_NOT_CANDIDATE;
			}
		}

		if ( ncandidates == 0 ) {
			if ( new_conn ) {
				meta_back_freeconn( op, mc );

			} else {
				meta_back_release_conn( op, mc );
			}

			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			rs->sr_text = "Unable to select valid candidates";

			if ( sendok & LDAP_BACK_SENDERR ) {
				if ( rs->sr_err == LDAP_NO_SUCH_OBJECT ) {
					rs->sr_matched = op->o_bd->be_suffix[ 0 ].bv_val;
				}
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
				rs->sr_matched = NULL;
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
		ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
		err = avl_insert( &mi->mi_conninfo.lai_tree, ( caddr_t )mc,
			       	meta_back_conn_cmp, meta_back_conn_dup );

#if PRINT_CONNTREE > 0
		myprint( mi->mi_conninfo.lai_tree );
#endif /* PRINT_CONNTREE */
		
		ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );

		/*
		 * Err could be -1 in case a duplicate metaconn is inserted
		 *
		 * FIXME: what if the same client issues more than one
		 * asynchronous operations?
		 */
		if ( err != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"%s meta_back_getconn: candidates=%d conn=%ld insert failed\n",
				op->o_log_prefix, ncandidates,
				LDAP_BACK_PCONN_ID( mc->mc_conn ) );
		
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "Internal server error";
			meta_back_freeconn( op, mc );
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
			}
			return NULL;
		}

		Debug( LDAP_DEBUG_TRACE,
			"%s meta_back_getconn: candidates=%d conn=%ld inserted\n",
			op->o_log_prefix, ncandidates,
			LDAP_BACK_PCONN_ID( mc->mc_conn ) );

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"%s meta_back_getconn: candidates=%d conn=%ld fetched\n",
			op->o_log_prefix, ncandidates,
			LDAP_BACK_PCONN_ID( mc->mc_conn ) );
	}
	
	return mc;
}

void
meta_back_release_conn(
       	Operation 		*op,
	metaconn_t		*mc )
{
	metainfo_t	*mi = ( metainfo_t * )op->o_bd->be_private;

	assert( mc != NULL );

	ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );
	assert( mc->mc_refcnt > 0 );
	mc->mc_refcnt--;
	LDAP_BACK_CONN_BINDING_CLEAR( mc );
	if ( mc->mc_refcnt == 0 && mc->mc_tainted ) {
		(void)avl_delete( &mi->mi_conninfo.lai_tree, ( caddr_t )mc,
				meta_back_conn_cmp );
		meta_back_conn_free( mc );
	}
	ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
}
