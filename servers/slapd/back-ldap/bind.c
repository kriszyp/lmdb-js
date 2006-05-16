/* bind.c - ldap backend bind function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
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
 * This work was initially developed by Howard Chu for inclusion
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
#include "back-ldap.h"

#include <lutil_ldap.h>

#ifndef PRINT_CONNTREE
#define PRINT_CONNTREE 0
#endif /* !PRINT_CONNTREE */

#define LDAP_CONTROL_OBSOLETE_PROXY_AUTHZ	"2.16.840.1.113730.3.4.12"

#if PRINT_CONNTREE > 0
static void
ravl_print( Avlnode *root, int depth )
{
	int		i;
	ldapconn_t	*lc;
	
	if ( root == 0 ) {
		return;
	}
	
	ravl_print( root->avl_right, depth+1 );
	
	for ( i = 0; i < depth; i++ ) {
		fprintf( stderr, "-" );
	}

	lc = root->avl_data;
	fprintf( stderr, "lc=%p local=\"%s\" conn=%p %s refcnt=%d\n",
		(void *)lc,
		lc->lc_local_ndn.bv_val ? lc->lc_local_ndn.bv_val : "",
		(void *)lc->lc_conn,
		avl_bf2str( root->avl_bf ), lc->lc_refcnt );
	
	ravl_print( root->avl_left, depth+1 );
}

static void
myprint( Avlnode *root, char *msg )
{
	fprintf( stderr, "========> %s\n", msg );
	
	if ( root == 0 ) {
		fprintf( stderr, "\tNULL\n" );

	} else {
		ravl_print( root, 0 );
	}
	
	fprintf( stderr, "<======== %s\n", msg );
}
#endif /* PRINT_CONNTREE */

static int
ldap_back_proxy_authz_bind( ldapconn_t *lc, Operation *op, SlapReply *rs, ldap_back_send_t sendok );

static int
ldap_back_prepare_conn( ldapconn_t **lcp, Operation *op, SlapReply *rs, ldap_back_send_t sendok );

static int
ldap_back_conndnlc_cmp( const void *c1, const void *c2 );

int
ldap_back_bind( Operation *op, SlapReply *rs )
{
	ldapinfo_t	*li = (ldapinfo_t *) op->o_bd->be_private;
	ldapconn_t	*lc;

	int rc = 0;
	ber_int_t msgid;

	lc = ldap_back_getconn( op, rs, LDAP_BACK_BIND_SERR );
	if ( !lc ) {
		return rs->sr_err;
	}

	if ( !BER_BVISNULL( &lc->lc_bound_ndn ) ) {
		ch_free( lc->lc_bound_ndn.bv_val );
		BER_BVZERO( &lc->lc_bound_ndn );
	}
	LDAP_BACK_CONN_ISBOUND_CLEAR( lc );

	/* method is always LDAP_AUTH_SIMPLE if we got here */
	rs->sr_err = ldap_sasl_bind( lc->lc_ld, op->o_req_dn.bv_val,
			LDAP_SASL_SIMPLE,
			&op->orb_cred, op->o_ctrls, NULL, &msgid );
	rc = ldap_back_op_result( lc, op, rs, msgid, 0, LDAP_BACK_SENDERR );

	if ( rc == LDAP_SUCCESS ) {
		/* If defined, proxyAuthz will be used also when
		 * back-ldap is the authorizing backend; for this
		 * purpose, a successful bind is followed by a
		 * bind with the configured identity assertion */
		/* NOTE: use with care */
		if ( li->li_idassert_flags & LDAP_BACK_AUTH_OVERRIDE ) {
			ldap_back_proxy_authz_bind( lc, op, rs, LDAP_BACK_SENDERR );
			if ( !LDAP_BACK_CONN_ISBOUND( lc ) ) {
				rc = 1;
			}
			goto done;
		}

		/* rebind is now done inside ldap_back_proxy_authz_bind()
		 * in case of success */
		LDAP_BACK_CONN_ISBOUND_SET( lc );
		ber_dupbv( &lc->lc_bound_ndn, &op->o_req_ndn );

		if ( LDAP_BACK_SAVECRED( li ) ) {
			if ( !BER_BVISNULL( &lc->lc_cred ) ) {
				memset( lc->lc_cred.bv_val, 0,
						lc->lc_cred.bv_len );
			}
			ber_bvreplace( &lc->lc_cred, &op->orb_cred );
			ldap_set_rebind_proc( lc->lc_ld, li->li_rebind_f, lc );
		}
	}
done:;

	assert( lc->lc_binding == 1 );
	lc->lc_binding = 0;

	/* must re-insert if local DN changed as result of bind */
	if ( !LDAP_BACK_CONN_ISBOUND( lc )
		|| ( LDAP_BACK_CONN_ISBOUND( lc )
			&& !dn_match( &op->o_req_ndn, &lc->lc_local_ndn ) ) )
	{
		int		lerr = -1;
		ldapconn_t	*tmplc;

		/* wait for all other ops to release the connection */
retry_lock:;
		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
		if ( lc->lc_refcnt > 1 ) {
			ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
			ldap_pvt_thread_yield();
			goto retry_lock;
		}

		assert( lc->lc_refcnt == 1 );
		tmplc = avl_delete( &li->li_conninfo.lai_tree, (caddr_t)lc,
				ldap_back_conndnlc_cmp );
		assert( tmplc == NULL || lc == tmplc );

		/* delete all cached connections with the current connection */
		if ( LDAP_BACK_SINGLECONN( li ) ) {
			while ( ( tmplc = avl_delete( &li->li_conninfo.lai_tree, (caddr_t)lc, ldap_back_conn_cmp ) ) != NULL )
			{
				Debug( LDAP_DEBUG_TRACE,
					"=>ldap_back_bind: destroying conn %ld (refcnt=%u)\n",
					LDAP_BACK_PCONN_ID( lc->lc_conn ), lc->lc_refcnt, 0 );

				if ( lc->lc_refcnt != 0 ) {
					/* taint it */
					LDAP_BACK_CONN_TAINTED_SET( tmplc );

				} else {
					/*
					 * Needs a test because the handler may be corrupted,
					 * and calling ldap_unbind on a corrupted header results
					 * in a segmentation fault
					 */
					ldap_back_conn_free( tmplc );
				}
			}
		}

		if ( LDAP_BACK_CONN_ISBOUND( lc ) ) {
			ber_bvreplace( &lc->lc_local_ndn, &op->o_req_ndn );
			if ( be_isroot_dn( op->o_bd, &op->o_req_ndn ) ) {
				lc->lc_conn = LDAP_BACK_PCONN_SET( op );
			}
			lerr = avl_insert( &li->li_conninfo.lai_tree, (caddr_t)lc,
				ldap_back_conndn_cmp, ldap_back_conndn_dup );
		}

#if PRINT_CONNTREE > 0
		myprint( li->li_conninfo.lai_tree, "ldap_back_bind" );
#endif /* PRINT_CONNTREE */
	
		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
		switch ( lerr ) {
		case 0:
			break;

		case -1:
			/* duplicate; someone else successfully bound
			 * on the same connection with the same identity;
			 * we can do this because lc_refcnt == 1 */
			ldap_back_conn_free( lc );
			lc = NULL;
		}
	}

	if ( lc != NULL ) {
		ldap_back_release_conn( op, rs, lc );
	}

	return( rc );
}

/*
 * ldap_back_conndn_cmp
 *
 * compares two ldapconn_t based on the value of the conn pointer
 * and of the local DN; used by avl stuff for insert, lookup
 * and direct delete
 */
int
ldap_back_conndn_cmp( const void *c1, const void *c2 )
{
	const ldapconn_t	*lc1 = (const ldapconn_t *)c1;
	const ldapconn_t	*lc2 = (const ldapconn_t *)c2;
	int rc;

	/* If local DNs don't match, it is definitely not a match */
	/* For shared sessions, conn is NULL. Only explicitly
	 * bound sessions will have non-NULL conn.
	 */
	rc = SLAP_PTRCMP( lc1->lc_conn, lc2->lc_conn );
	if ( rc == 0 ) {
		rc = ber_bvcmp( &lc1->lc_local_ndn, &lc2->lc_local_ndn );
	}

	return rc;
}

/*
 * ldap_back_conndnlc_cmp
 *
 * compares two ldapconn_t based on the value of the conn pointer,
 * the local DN and the lc pointer; used by avl stuff for insert, lookup
 * and direct delete
 */
static int
ldap_back_conndnlc_cmp( const void *c1, const void *c2 )
{
	const ldapconn_t	*lc1 = (const ldapconn_t *)c1;
	const ldapconn_t	*lc2 = (const ldapconn_t *)c2;
	int rc;

	/* If local DNs don't match, it is definitely not a match */
	/* For shared sessions, conn is NULL. Only explicitly
	 * bound sessions will have non-NULL conn.
	 */
	rc = SLAP_PTRCMP( lc1->lc_conn, lc2->lc_conn );
	if ( rc == 0 ) {
		rc = ber_bvcmp( &lc1->lc_local_ndn, &lc2->lc_local_ndn );
		if ( rc == 0 ) {
			rc = SLAP_PTRCMP( lc1, lc2 );
		}
	}

	return rc;
}

/*
 * ldap_back_conn_cmp
 *
 * compares two ldapconn_t based on the value of the conn pointer;
 * used by avl stuff for delete of all conns with the same connid
 */
int
ldap_back_conn_cmp( const void *c1, const void *c2 )
{
	const ldapconn_t	*lc1 = (const ldapconn_t *)c1;
	const ldapconn_t	*lc2 = (const ldapconn_t *)c2;

	/* For shared sessions, conn is NULL. Only explicitly
	 * bound sessions will have non-NULL conn.
	 */
	return SLAP_PTRCMP( lc1->lc_conn, lc2->lc_conn );
}

/*
 * ldap_back_conndn_dup
 *
 * returns -1 in case a duplicate ldapconn_t has been inserted;
 * used by avl stuff
 */
int
ldap_back_conndn_dup( void *c1, void *c2 )
{
	ldapconn_t	*lc1 = (ldapconn_t *)c1;
	ldapconn_t	*lc2 = (ldapconn_t *)c2;

	/* Cannot have more than one shared session with same DN */
	if ( lc1->lc_conn == lc2->lc_conn &&
		dn_match( &lc1->lc_local_ndn, &lc2->lc_local_ndn ) )
	{
		return -1;
	}
		
	return 0;
}

int
ldap_back_freeconn( Operation *op, ldapconn_t *lc, int dolock )
{
	ldapinfo_t	*li = (ldapinfo_t *) op->o_bd->be_private;
	ldapconn_t	*tmplc;

	if ( dolock ) {
		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
	}

	tmplc = avl_delete( &li->li_conninfo.lai_tree, (caddr_t)lc,
			ldap_back_conndnlc_cmp );
	assert( LDAP_BACK_CONN_TAINTED( lc ) || tmplc == lc );
	if ( lc->lc_refcnt == 0 ) {
		ldap_back_conn_free( (void *)lc );
	}

	if ( dolock ) {
		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
	}

	return 0;
}

#ifdef HAVE_TLS
static int
ldap_back_start_tls(
	LDAP		*ld,
	int		protocol,
	int		*is_tls,
	const char	*url,
	unsigned	flags,
	int		retries,
	const char	**text )
{
	int		rc = LDAP_SUCCESS;
	ldapinfo_t	dummy;

	/* this is ridiculous... */
	dummy.li_flags = flags;

	/* start TLS ("tls-[try-]{start,propagate}" statements) */
	if ( ( LDAP_BACK_USE_TLS( &dummy ) || ( *is_tls && LDAP_BACK_PROPAGATE_TLS( &dummy ) ) )
				&& !ldap_is_ldaps_url( url ) )
	{
#ifdef SLAP_STARTTLS_ASYNCHRONOUS
		/*
		 * use asynchronous StartTLS
		 * in case, chase referral (not implemented yet)
		 */
		int		msgid;

		if ( protocol == 0 ) {
			ldap_get_option( ld, LDAP_OPT_PROTOCOL_VERSION,
					(void *)&protocol );
		}

		if ( protocol < LDAP_VERSION3 ) {
			/* we should rather bail out... */
			rc = LDAP_UNWILLING_TO_PERFORM;
			*text = "invalid protocol version";
		}

		if ( rc == LDAP_SUCCESS ) {
			rc = ldap_start_tls( ld, NULL, NULL, &msgid );
		}

		if ( rc == LDAP_SUCCESS ) {
			LDAPMessage	*res = NULL;
			struct timeval	tv;

			LDAP_BACK_TV_SET( &tv );

retry:;
			rc = ldap_result( ld, msgid, LDAP_MSG_ALL, &tv, &res );
			if ( rc < 0 ) {
				rc = LDAP_UNAVAILABLE;

			} else if ( rc == 0 ) {
				if ( retries != LDAP_BACK_RETRY_NEVER ) {
					ldap_pvt_thread_yield();
					if ( retries > 0 ) {
						retries--;
					}
					LDAP_BACK_TV_SET( &tv );
					goto retry;
				}
				rc = LDAP_UNAVAILABLE;

			} else if ( rc == LDAP_RES_EXTENDED ) {
				struct berval	*data = NULL;

				rc = ldap_parse_extended_result( ld, res,
						NULL, &data, 0 );
				if ( rc == LDAP_SUCCESS ) {
					int err;
					rc = ldap_parse_result( ld, res, &err,
						NULL, NULL, NULL, NULL, 1 );
					if ( rc == LDAP_SUCCESS ) {
						rc = err;
					}
					res = NULL;
					
					/* FIXME: in case a referral 
					 * is returned, should we try
					 * using it instead of the 
					 * configured URI? */
					if ( rc == LDAP_SUCCESS ) {
						rc = ldap_install_tls( ld );

					} else if ( rc == LDAP_REFERRAL ) {
						rc = LDAP_UNWILLING_TO_PERFORM;
						*text = "unwilling to chase referral returned by Start TLS exop";
					}

					if ( data ) {
						if ( data->bv_val ) {
							ber_memfree( data->bv_val );
						}
						ber_memfree( data );
					}
				}

			} else {
				rc = LDAP_OTHER;
			}

			if ( res != NULL ) {
				ldap_msgfree( res );
			}
		}
#else /* ! SLAP_STARTTLS_ASYNCHRONOUS */
		/*
		 * use synchronous StartTLS
		 */
		rc = ldap_start_tls_s( ld, NULL, NULL );
#endif /* ! SLAP_STARTTLS_ASYNCHRONOUS */

		/* if StartTLS is requested, only attempt it if the URL
		 * is not "ldaps://"; this may occur not only in case
		 * of misconfiguration, but also when used in the chain 
		 * overlay, where the "uri" can be parsed out of a referral */
		switch ( rc ) {
		case LDAP_SUCCESS:
			*is_tls = 1;
			break;

		case LDAP_SERVER_DOWN:
			break;

		default:
			if ( LDAP_BACK_TLS_CRITICAL( &dummy ) ) {
				*text = "could not start TLS";
				break;
			}

			/* in case Start TLS is not critical */
			*is_tls = 0;
			rc = LDAP_SUCCESS;
			break;
		}

	} else {
		*is_tls = 0;
	}

	return rc;
}
#endif /* HAVE_TLS */

static int
ldap_back_prepare_conn( ldapconn_t **lcp, Operation *op, SlapReply *rs, ldap_back_send_t sendok )
{
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;
	int		version;
	LDAP		*ld = NULL;
#ifdef HAVE_TLS
	int		is_tls = op->o_conn->c_is_tls;
#endif /* HAVE_TLS */

	assert( lcp != NULL );

	ldap_pvt_thread_mutex_lock( &li->li_uri_mutex );
	rs->sr_err = ldap_initialize( &ld, li->li_uri );
	ldap_pvt_thread_mutex_unlock( &li->li_uri_mutex );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto error_return;
	}

	if ( li->li_urllist_f ) {
		ldap_set_urllist_proc( ld, li->li_urllist_f, li->li_urllist_p );
	}

	/* Set LDAP version. This will always succeed: If the client
	 * bound with a particular version, then so can we.
	 */
	if ( li->li_version != 0 ) {
		version = li->li_version;

	} else if ( op->o_protocol != 0 ) {
		version = op->o_protocol;

	} else {
		/* assume it's an internal op; set to LDAPv3 */
		version = LDAP_VERSION3;
	}
	ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, (const void *)&version );

	/* automatically chase referrals ("chase-referrals [{yes|no}]" statement) */
	ldap_set_option( ld, LDAP_OPT_REFERRALS,
		LDAP_BACK_CHASE_REFERRALS( li ) ? LDAP_OPT_ON : LDAP_OPT_OFF );

	if ( li->li_network_timeout > 0 ) {
		struct timeval		tv;

		tv.tv_sec = li->li_network_timeout;
		tv.tv_usec = 0;
		ldap_set_option( ld, LDAP_OPT_NETWORK_TIMEOUT, (const void *)&tv );
	}

#ifdef HAVE_TLS
	ldap_pvt_thread_mutex_lock( &li->li_uri_mutex );
	rs->sr_err = ldap_back_start_tls( ld, op->o_protocol, &is_tls,
			li->li_uri, li->li_flags, li->li_nretries, &rs->sr_text );
	ldap_pvt_thread_mutex_unlock( &li->li_uri_mutex );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		ldap_unbind_ext( ld, NULL, NULL );
		goto error_return;
	}
#endif /* HAVE_TLS */

	if ( *lcp == NULL ) {
		*lcp = (ldapconn_t *)ch_calloc( 1, sizeof( ldapconn_t ) );
		(*lcp)->lc_flags = li->li_flags;
	}
	(*lcp)->lc_ld = ld;
	(*lcp)->lc_refcnt = 1;
	(*lcp)->lc_binding = 1;
#ifdef HAVE_TLS
	if ( is_tls ) {
		LDAP_BACK_CONN_ISTLS_SET( *lcp );
	} else {
		LDAP_BACK_CONN_ISTLS_CLEAR( *lcp );
	}
#endif /* HAVE_TLS */

error_return:;
	if ( rs->sr_err != LDAP_SUCCESS ) {
		rs->sr_err = slap_map_api2result( rs );
		if ( sendok & LDAP_BACK_SENDERR ) {
			if ( rs->sr_text == NULL ) {
				rs->sr_text = "ldap_initialize() failed";
			}
			send_ldap_result( op, rs );
			rs->sr_text = NULL;
		}

	} else {
		if ( li->li_conn_ttl > 0 ) {
			(*lcp)->lc_create_time = op->o_time;
		}
	}

	return rs->sr_err;
}

ldapconn_t *
ldap_back_getconn( Operation *op, SlapReply *rs, ldap_back_send_t sendok )
{
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;
	ldapconn_t	*lc = NULL,
			lc_curr = { 0 };
	int		refcnt = 1, binding = 1;

	/* Internal searches are privileged and shared. So is root. */
	if ( op->o_do_not_cache || be_isroot( op ) ) {
		LDAP_BACK_CONN_ISPRIV_SET( &lc_curr );
		lc_curr.lc_local_ndn = op->o_bd->be_rootndn;
		lc_curr.lc_conn = LDAP_BACK_PCONN_SET( op );

	} else {
		lc_curr.lc_local_ndn = op->o_ndn;
		/* Explicit binds must not be shared */
		if ( op->o_tag == LDAP_REQ_BIND || SLAP_IS_AUTHZ_BACKEND( op ) ) {
			lc_curr.lc_conn = op->o_conn;
	
		} else {
			lc_curr.lc_conn = LDAP_BACK_PCONN_SET( op );
		}
	}

	/* Explicit Bind requests always get their own conn */
	if ( !( sendok & LDAP_BACK_BINDING ) ) {
		/* Searches for a ldapconn in the avl tree */
retry_lock:
		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );

		lc = (ldapconn_t *)avl_find( li->li_conninfo.lai_tree, 
				(caddr_t)&lc_curr, ldap_back_conndn_cmp );
		if ( lc != NULL ) {
			/* Don't reuse connections while they're still binding */
			if ( LDAP_BACK_CONN_BINDING( lc ) ) {
				ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
				ldap_pvt_thread_yield();
				goto retry_lock;
			}
			refcnt = ++lc->lc_refcnt;
			binding = ++lc->lc_binding;
		}
		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
	}

	/* Looks like we didn't get a bind. Open a new session... */
	if ( lc == NULL ) {
		if ( ldap_back_prepare_conn( &lc, op, rs, sendok ) != LDAP_SUCCESS ) {
			return NULL;
		}
		if ( sendok & LDAP_BACK_BINDING ) {
			LDAP_BACK_CONN_BINDING_SET( lc );
		}
		lc->lc_conn = lc_curr.lc_conn;
		ber_dupbv( &lc->lc_local_ndn, &lc_curr.lc_local_ndn );

		if ( LDAP_BACK_CONN_ISPRIV( &lc_curr ) ) {
			ber_dupbv( &lc->lc_cred, &li->li_acl_passwd );
			ber_dupbv( &lc->lc_bound_ndn, &li->li_acl_authcDN );
			LDAP_BACK_CONN_ISPRIV_SET( lc );

		} else {
			BER_BVZERO( &lc->lc_cred );
			BER_BVZERO( &lc->lc_bound_ndn );
			if ( !BER_BVISEMPTY( &op->o_ndn )
				&& SLAP_IS_AUTHZ_BACKEND( op ) )
			{
				ber_dupbv( &lc->lc_bound_ndn, &op->o_ndn );
			}
		}

#ifdef HAVE_TLS
		/* if start TLS failed but it was not mandatory,
		 * check if the non-TLS connection was already
		 * in cache; in case, destroy the newly created
		 * connection and use the existing one */
		if ( lc->lc_conn == LDAP_BACK_PCONN_TLS
				&& !ldap_tls_inplace( lc->lc_ld ) )
		{
			ldapconn_t *tmplc;
			
			lc_curr.lc_conn = LDAP_BACK_PCONN;
			ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
			tmplc = (ldapconn_t *)avl_find( li->li_conninfo.lai_tree, 
					(caddr_t)&lc_curr, ldap_back_conndn_cmp );
			if ( tmplc != NULL ) {
				refcnt = ++tmplc->lc_refcnt;
				binding = ++tmplc->lc_binding;
				ldap_back_conn_free( lc );
				lc = tmplc;
			}
			ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );

			if ( tmplc != NULL ) {
				goto done;
			}
		}
#endif /* HAVE_TLS */

		LDAP_BACK_CONN_ISBOUND_CLEAR( lc );

		/* Inserts the newly created ldapconn in the avl tree */
		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );

		assert( lc->lc_refcnt == 1 );
		assert( lc->lc_binding == 1 );
		rs->sr_err = avl_insert( &li->li_conninfo.lai_tree, (caddr_t)lc,
			ldap_back_conndn_cmp, ldap_back_conndn_dup );

#if PRINT_CONNTREE > 0
		myprint( li->li_conninfo.lai_tree, "ldap_back_getconn" );
#endif /* PRINT_CONNTREE */
	
		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );

		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_getconn: conn %p inserted refcnt=%u binding=%u\n",
			(void *)lc, refcnt, binding );
	
		/* Err could be -1 in case a duplicate ldapconn is inserted */
		switch ( rs->sr_err ) {
		case 0:
			break;

		case -1:
			if ( !( sendok & LDAP_BACK_BINDING ) ) {
				/* duplicate: free and try to get the newly created one */
				goto retry_lock;
			}
			/* taint connection, so that it'll be freed when released */
			ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
			(void *)avl_delete( &li->li_conninfo.lai_tree, (caddr_t)lc,
					ldap_back_conndnlc_cmp );
			ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
			LDAP_BACK_CONN_TAINTED_SET( lc );
			break;

		default:
			ldap_back_conn_free( lc );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "proxy bind collision";
			if ( op->o_conn && ( sendok & LDAP_BACK_SENDERR ) ) {
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
			}
			return NULL;
		}

	} else {
		char	buf[ SLAP_TEXT_BUFLEN ];
		int	expiring = 0;

		if ( ( li->li_idle_timeout != 0 && op->o_time > lc->lc_time + li->li_idle_timeout )
			|| ( li->li_conn_ttl != 0 && op->o_time > lc->lc_create_time + li->li_conn_ttl ) )
		{
			expiring = 1;

			/* let it be used, but taint/delete it so that 
			 * no-one else can look it up any further */
			ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
			(void *)avl_delete( &li->li_conninfo.lai_tree, (caddr_t)lc,
					ldap_back_conndnlc_cmp );
			ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
			LDAP_BACK_CONN_TAINTED_SET( lc );
		}

		if ( LogTest( LDAP_DEBUG_TRACE ) ) {
			snprintf( buf, sizeof( buf ),
				"conn %p fetched refcnt=%u binding=%u%s",
				(void *)lc, refcnt, binding, expiring ? " expiring" : "" );
			Debug( LDAP_DEBUG_TRACE,
				"=>ldap_back_getconn: %s.\n", buf, 0, 0 );
		}
	
	}

#ifdef HAVE_TLS
done:;
#endif /* HAVE_TLS */
	if ( li->li_idle_timeout && lc ) {
		lc->lc_time = op->o_time;
	}

	return lc;
}

void
ldap_back_release_conn_lock(
	Operation		*op,
	SlapReply		*rs,
	ldapconn_t		*lc,
	int			dolock )
{
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;

	if ( dolock ) {
		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
	}
	assert( lc->lc_refcnt > 0 );
	LDAP_BACK_CONN_BINDING_CLEAR( lc );
	lc->lc_refcnt--;
	if ( LDAP_BACK_CONN_TAINTED( lc ) ) {
		ldap_back_freeconn( op, lc, 0 );
	}
	if ( dolock ) {
		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
	}
}

/*
 * ldap_back_dobind
 *
 * Note: as the check for the value of lc->lc_bound was already here, I removed
 * it from all the callers, and I made the function return the flag, so
 * it can be used to simplify the check.
 *
 * Note: dolock indicates whether li->li_conninfo.lai_mutex must be locked or not
 */
static int
ldap_back_dobind_int(
	ldapconn_t		*lc,
	Operation		*op,
	SlapReply		*rs,
	ldap_back_send_t	sendok,
	int			retries,
	int			dolock )
{	
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;

	int		rc, binding = 0;
	ber_int_t	msgid;

	assert( retries >= 0 );

retry_lock:;
 	if ( dolock ) {
 		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
 	}

 	if ( binding == 0 ) {
		/* check if already bound */
		rc = LDAP_BACK_CONN_ISBOUND( lc );
		if ( rc ) {
			lc->lc_binding--;
 			if ( dolock ) {
 				ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
 			}
			return rc;
		}

		if ( LDAP_BACK_CONN_BINDING( lc ) ) {
			/* if someone else is about to bind it, give up and retry */
 			if ( dolock ) {
 				ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
 			}
			ldap_pvt_thread_yield();
			goto retry_lock;

		} else {
			/* otherwise this thread will bind it */
 			LDAP_BACK_CONN_BINDING_SET( lc );
			binding = 1;
		}
	}

	/* wait for pending operations to finish */
	/* FIXME: may become a bottleneck! */
	if ( lc->lc_refcnt != lc->lc_binding ) {
 		if ( dolock ) {
 			ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
 		}
		ldap_pvt_thread_yield();
		goto retry_lock;
	}

 	if ( dolock ) {
 		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
 	}

#if 0
	while ( lc->lc_refcnt > 1 ) {
		ldap_pvt_thread_yield();
		rc = LDAP_BACK_CONN_ISBOUND( lc );
		if ( rc ) {
			return rc;
		}
	}

 	if ( dolock ) {
 		ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
 	}
 	LDAP_BACK_CONN_BINDING_SET( lc );
 	if ( dolock ) {
 		ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
 	}
#endif

	/*
	 * FIXME: we need to let clients use proxyAuthz
	 * otherwise we cannot do symmetric pools of servers;
	 * we have to live with the fact that a user can
	 * authorize itself as any ID that is allowed
	 * by the authzTo directive of the "proxyauthzdn".
	 */
	/*
	 * NOTE: current Proxy Authorization specification
	 * and implementation do not allow proxy authorization
	 * control to be provided with Bind requests
	 */
	/*
	 * if no bind took place yet, but the connection is bound
	 * and the "idassert-authcDN" (or other ID) is set, 
	 * then bind as the asserting identity and explicitly 
	 * add the proxyAuthz control to every operation with the
	 * dn bound to the connection as control value.
	 * This is done also if this is the authrizing backend,
	 * but the "override" flag is given to idassert.
	 * It allows to use SASL bind and yet proxyAuthz users
	 */
	if ( op->o_conn != NULL &&
		!op->o_do_not_cache &&
		( BER_BVISNULL( &lc->lc_bound_ndn ) ||
			( li->li_idassert_flags & LDAP_BACK_AUTH_OVERRIDE ) ) )
	{
		(void)ldap_back_proxy_authz_bind( lc, op, rs, sendok );
		goto done;
	}

#ifdef HAVE_CYRUS_SASL
	if ( LDAP_BACK_CONN_ISPRIV( lc )
		&& li->li_acl_authmethod == LDAP_AUTH_SASL )
	{
		void		*defaults = NULL;

		if ( li->li_acl_secprops != NULL ) {
			rc = ldap_set_option( lc->lc_ld,
				LDAP_OPT_X_SASL_SECPROPS, li->li_acl_secprops);

			if ( rc != LDAP_OPT_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY, "Error: ldap_set_option "
					"(SECPROPS,\"%s\") failed!\n",
					li->li_acl_secprops, 0, 0 );
				goto done;
			}
		}

		defaults = lutil_sasl_defaults( lc->lc_ld,
				li->li_acl_sasl_mech.bv_val,
				li->li_acl_sasl_realm.bv_val,
				li->li_acl_authcID.bv_val,
				li->li_acl_passwd.bv_val,
				NULL );

		rs->sr_err = ldap_sasl_interactive_bind_s( lc->lc_ld,
				li->li_acl_authcDN.bv_val,
				li->li_acl_sasl_mech.bv_val, NULL, NULL,
				LDAP_SASL_QUIET, lutil_sasl_interact,
				defaults );

		lutil_sasl_freedefs( defaults );

		rs->sr_err = slap_map_api2result( rs );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			LDAP_BACK_CONN_ISBOUND_CLEAR( lc );
			send_ldap_result( op, rs );

		} else {
			LDAP_BACK_CONN_ISBOUND_SET( lc );
		}
		goto done;
	}
#endif /* HAVE_CYRUS_SASL */

retry:;
	rs->sr_err = ldap_sasl_bind( lc->lc_ld,
			BER_BVISNULL( &lc->lc_cred ) ? "" : lc->lc_bound_ndn.bv_val,
			LDAP_SASL_SIMPLE, &lc->lc_cred,
			NULL, NULL, &msgid );

	if ( rs->sr_err == LDAP_SERVER_DOWN ) {
		if ( retries != LDAP_BACK_RETRY_NEVER ) {
			if ( dolock ) {
				ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
			}

			assert( lc->lc_refcnt > 0 );
			if ( lc->lc_refcnt == 1 ) {
				ldap_unbind_ext( lc->lc_ld, NULL, NULL );
				lc->lc_ld = NULL;

				/* lc here must be the regular lc, reset and ready for init */
				rs->sr_err = ldap_back_prepare_conn( &lc, op, rs, sendok );
				if ( rs->sr_err != LDAP_SUCCESS ) {
					lc->lc_binding--;
					lc->lc_refcnt = 0;
				}
			}

			if ( dolock ) {
				ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
			}

			if ( rs->sr_err == LDAP_SUCCESS ) {
				if ( retries > 0 ) {
					retries--;
				}
				goto retry;
			}

		} else {
			if ( dolock ) {
				ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );
			}
			lc->lc_binding--;
			if ( dolock ) {
				ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );
			}
		}

		lc->lc_binding--;
		ldap_back_freeconn( op, lc, dolock );
		rs->sr_err = slap_map_api2result( rs );

		return 0;
	}

	rc = ldap_back_op_result( lc, op, rs, msgid, 0, sendok );
	if ( rc == LDAP_SUCCESS ) {
		LDAP_BACK_CONN_ISBOUND_SET( lc );
	}

done:;
	lc->lc_binding--;
	LDAP_BACK_CONN_BINDING_CLEAR( lc );
	rc = LDAP_BACK_CONN_ISBOUND( lc );
	if ( !rc ) {
		ldap_back_release_conn_lock( op, rs, lc, dolock );
	}

	return rc;
}

int
ldap_back_dobind( ldapconn_t *lc, Operation *op, SlapReply *rs, ldap_back_send_t sendok )
{
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;

	return ldap_back_dobind_int( lc, op, rs, sendok, li->li_nretries, 1 );
}

/*
 * ldap_back_default_rebind
 *
 * This is a callback used for chasing referrals using the same
 * credentials as the original user on this session.
 */
int 
ldap_back_default_rebind( LDAP *ld, LDAP_CONST char *url, ber_tag_t request,
	ber_int_t msgid, void *params )
{
	ldapconn_t	*lc = (ldapconn_t *)params;

#ifdef HAVE_TLS
	/* ... otherwise we couldn't get here */
	assert( lc != NULL );

	if ( !ldap_tls_inplace( ld ) ) {
		int		is_tls = LDAP_BACK_CONN_ISTLS( lc ),
				rc;
		const char	*text = NULL;

		rc = ldap_back_start_tls( ld, 0, &is_tls, url, lc->lc_flags,
			LDAP_BACK_RETRY_DEFAULT, &text );
		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}
	}
#endif /* HAVE_TLS */

	/* FIXME: add checks on the URL/identity? */

	return ldap_sasl_bind_s( ld,
			BER_BVISNULL( &lc->lc_cred ) ? "" : lc->lc_bound_ndn.bv_val,
			LDAP_SASL_SIMPLE, &lc->lc_cred, NULL, NULL, NULL );
}

/*
 * ldap_back_default_urllist
 */
int 
ldap_back_default_urllist(
	LDAP		*ld,
	LDAPURLDesc	**urllist,
	LDAPURLDesc	**url,
	void		*params )
{
	ldapinfo_t	*li = (ldapinfo_t *)params;
	LDAPURLDesc	**urltail;

	if ( urllist == url ) {
		return LDAP_SUCCESS;
	}

	for ( urltail = &(*url)->lud_next; *urltail; urltail = &(*urltail)->lud_next )
		/* count */ ;

	*urltail = *urllist;
	*urllist = *url;
	*url = NULL;

	ldap_pvt_thread_mutex_lock( &li->li_uri_mutex );
	if ( li->li_uri ) {
		ch_free( li->li_uri );
	}

	ldap_get_option( ld, LDAP_OPT_URI, (void *)&li->li_uri );
	ldap_pvt_thread_mutex_unlock( &li->li_uri_mutex );

	return LDAP_SUCCESS;
}

int
ldap_back_op_result(
		ldapconn_t		*lc,
		Operation		*op,
		SlapReply		*rs,
		ber_int_t		msgid,
		time_t			timeout,
		ldap_back_send_t	sendok )
{
	char		*match = NULL;
	LDAPMessage	*res = NULL;
	char		*text = NULL;

#define	ERR_OK(err) ((err) == LDAP_SUCCESS || (err) == LDAP_COMPARE_FALSE || (err) == LDAP_COMPARE_TRUE)

	rs->sr_text = NULL;
	rs->sr_matched = NULL;

	/* if the error recorded in the reply corresponds
	 * to a successful state, get the error from the
	 * remote server response */
	if ( ERR_OK( rs->sr_err ) ) {
		int		rc;
		struct timeval	tv;

		if ( timeout ) {
			tv.tv_sec = timeout;
			tv.tv_usec = 0;

		} else {
			LDAP_BACK_TV_SET( &tv );
		}

retry:;
		/* if result parsing fails, note the failure reason */
		rc = ldap_result( lc->lc_ld, msgid, LDAP_MSG_ALL, &tv, &res );
		switch ( rc ) {
		case 0:
			if ( timeout ) {
				(void)ldap_abandon_ext( lc->lc_ld, msgid, NULL, NULL );
				rs->sr_err = op->o_protocol >= LDAP_VERSION3 ?
					LDAP_ADMINLIMIT_EXCEEDED : LDAP_OPERATIONS_ERROR;
				rs->sr_text = "Operation timed out";
				break;
			}

			LDAP_BACK_TV_SET( &tv );
			ldap_pvt_thread_yield();
			goto retry;

		case -1:
			ldap_get_option( lc->lc_ld, LDAP_OPT_ERROR_NUMBER,
					&rs->sr_err );
			break;


		/* otherwise get the result; if it is not
		 * LDAP_SUCCESS, record it in the reply
		 * structure (this includes 
		 * LDAP_COMPARE_{TRUE|FALSE}) */
		default:
			rc = ldap_parse_result( lc->lc_ld, res, &rs->sr_err,
					&match, &text, NULL, NULL, 1 );
			rs->sr_text = text;
			if ( rc != LDAP_SUCCESS ) {
				rs->sr_err = rc;
			}
		}
	}

	/* if the error in the reply structure is not
	 * LDAP_SUCCESS, try to map it from client 
	 * to server error */
	if ( !ERR_OK( rs->sr_err ) ) {
		rs->sr_err = slap_map_api2result( rs );

		/* internal ops ( op->o_conn == NULL ) 
		 * must not reply to client */
		if ( op->o_conn && !op->o_do_not_cache && match ) {

			/* record the (massaged) matched
			 * DN into the reply structure */
			rs->sr_matched = match;
		}
	}
	if ( op->o_conn &&
			( ( sendok & LDAP_BACK_SENDOK ) 
			  || ( ( sendok & LDAP_BACK_SENDERR ) && rs->sr_err != LDAP_SUCCESS ) ) )
	{
		send_ldap_result( op, rs );
	}
	if ( match ) {
		if ( rs->sr_matched != match ) {
			free( (char *)rs->sr_matched );
		}
		rs->sr_matched = NULL;
		ldap_memfree( match );
	}
	if ( text ) {
		ldap_memfree( text );
	}
	rs->sr_text = NULL;
	return( ERR_OK( rs->sr_err ) ? LDAP_SUCCESS : rs->sr_err );
}

/* return true if bound, false if failed */
int
ldap_back_retry( ldapconn_t **lcp, Operation *op, SlapReply *rs, ldap_back_send_t sendok )
{
	int		rc = 0;
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;

	assert( lcp != NULL );
	assert( *lcp != NULL );

	ldap_pvt_thread_mutex_lock( &li->li_conninfo.lai_mutex );

	if ( (*lcp)->lc_refcnt == 1 ) {
		ldap_pvt_thread_mutex_lock( &li->li_uri_mutex );
		Debug( LDAP_DEBUG_ANY,
			"%s ldap_back_retry: retrying URI=\"%s\" DN=\"%s\"\n",
			op->o_log_prefix, li->li_uri,
			BER_BVISNULL( &(*lcp)->lc_bound_ndn ) ?
				"" : (*lcp)->lc_bound_ndn.bv_val );
		ldap_pvt_thread_mutex_unlock( &li->li_uri_mutex );

		ldap_unbind_ext( (*lcp)->lc_ld, NULL, NULL );
		(*lcp)->lc_ld = NULL;
		LDAP_BACK_CONN_ISBOUND_CLEAR( (*lcp) );

		/* lc here must be the regular lc, reset and ready for init */
		rc = ldap_back_prepare_conn( lcp, op, rs, sendok );
		if ( rc != LDAP_SUCCESS ) {
			rc = 0;
			*lcp = NULL;

		} else {
			rc = ldap_back_dobind_int( *lcp, op, rs, sendok, 0, 0 );
			if ( rc == 0 ) {
				*lcp = NULL;
			}
		}

	} else {
		Debug( LDAP_DEBUG_TRACE,
			"ldap_back_retry: conn %p refcnt=%u unable to retry.\n",
			(void *)(*lcp), (*lcp)->lc_refcnt, 0 );

		ldap_back_release_conn_lock( op, rs, *lcp, 0 );
		*lcp = NULL;

		if ( sendok ) {
			rs->sr_err = LDAP_UNAVAILABLE;
			rs->sr_text = "unable to retry";
			send_ldap_result( op, rs );
		}
	}

	ldap_pvt_thread_mutex_unlock( &li->li_conninfo.lai_mutex );

	return rc;
}

static int
ldap_back_proxy_authz_bind( ldapconn_t *lc, Operation *op, SlapReply *rs, ldap_back_send_t sendok )
{
	ldapinfo_t	*li = (ldapinfo_t *)op->o_bd->be_private;
	struct berval	binddn = slap_empty_bv;
	struct berval	bindcred = slap_empty_bv;
	struct berval	ndn;
	int		dobind = 0;
	int		msgid;
	int		rc;

	/* don't proxyAuthz if protocol is not LDAPv3 */
	switch ( li->li_version ) {
	case LDAP_VERSION3:
		break;

	case 0:
		if ( op->o_protocol == 0 || op->o_protocol == LDAP_VERSION3 ) {
			break;
		}
		/* fall thru */

	default:
		goto done;
	}

	if ( op->o_tag == LDAP_REQ_BIND ) {
		ndn = op->o_req_ndn;

	} else if ( !BER_BVISNULL( &op->o_conn->c_ndn ) ) {
		ndn = op->o_conn->c_ndn;

	} else {
		ndn = op->o_ndn;
	}

	/*
	 * FIXME: we need to let clients use proxyAuthz
	 * otherwise we cannot do symmetric pools of servers;
	 * we have to live with the fact that a user can
	 * authorize itself as any ID that is allowed
	 * by the authzTo directive of the "proxyauthzdn".
	 */
	/*
	 * NOTE: current Proxy Authorization specification
	 * and implementation do not allow proxy authorization
	 * control to be provided with Bind requests
	 */
	/*
	 * if no bind took place yet, but the connection is bound
	 * and the "proxyauthzdn" is set, then bind as 
	 * "proxyauthzdn" and explicitly add the proxyAuthz 
	 * control to every operation with the dn bound 
	 * to the connection as control value.
	 */

	/* bind as proxyauthzdn only if no idassert mode
	 * is requested, or if the client's identity
	 * is authorized */
	switch ( li->li_idassert_mode ) {
	case LDAP_BACK_IDASSERT_LEGACY:
		if ( !BER_BVISNULL( &ndn ) && !BER_BVISEMPTY( &ndn ) ) {
			if ( !BER_BVISNULL( &li->li_idassert_authcDN ) && !BER_BVISEMPTY( &li->li_idassert_authcDN ) )
			{
				binddn = li->li_idassert_authcDN;
				bindcred = li->li_idassert_passwd;
				dobind = 1;
			}
		}
		break;

	default:
		/* NOTE: rootdn can always idassert */
		if ( BER_BVISNULL( &ndn ) && li->li_idassert_authz == NULL ) {
			if ( li->li_idassert_flags & LDAP_BACK_AUTH_PRESCRIPTIVE ) {
				rs->sr_err = LDAP_INAPPROPRIATE_AUTH;
				if ( sendok & LDAP_BACK_SENDERR ) {
					send_ldap_result( op, rs );
				}
				LDAP_BACK_CONN_ISBOUND_CLEAR( lc );

			} else {
				rs->sr_err = LDAP_SUCCESS;
				binddn = slap_empty_bv;
				bindcred = slap_empty_bv;
				break;
			}

			goto done;

		} else if ( li->li_idassert_authz && !be_isroot( op ) ) {
			struct berval authcDN;

			if ( BER_BVISNULL( &ndn ) ) {
				authcDN = slap_empty_bv;

			} else {
				authcDN = ndn;
			}	
			rs->sr_err = slap_sasl_matches( op, li->li_idassert_authz,
					&authcDN, &authcDN );
			if ( rs->sr_err != LDAP_SUCCESS ) {
				if ( li->li_idassert_flags & LDAP_BACK_AUTH_PRESCRIPTIVE ) {
					if ( sendok & LDAP_BACK_SENDERR ) {
						send_ldap_result( op, rs );
					}
					LDAP_BACK_CONN_ISBOUND_CLEAR( lc );

				} else {
					rs->sr_err = LDAP_SUCCESS;
					binddn = slap_empty_bv;
					bindcred = slap_empty_bv;
					break;
				}

				goto done;
			}
		}

		binddn = li->li_idassert_authcDN;
		bindcred = li->li_idassert_passwd;
		dobind = 1;
		break;
	}

	if ( dobind && li->li_idassert_authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		void		*defaults = NULL;
		struct berval	authzID = BER_BVNULL;
		int		freeauthz = 0;

		/* if SASL supports native authz, prepare for it */
		if ( ( !op->o_do_not_cache || !op->o_is_auth_check ) &&
				( li->li_idassert_flags & LDAP_BACK_AUTH_NATIVE_AUTHZ ) )
		{
			switch ( li->li_idassert_mode ) {
			case LDAP_BACK_IDASSERT_OTHERID:
			case LDAP_BACK_IDASSERT_OTHERDN:
				authzID = li->li_idassert_authzID;
				break;

			case LDAP_BACK_IDASSERT_ANONYMOUS:
				BER_BVSTR( &authzID, "dn:" );
				break;

			case LDAP_BACK_IDASSERT_SELF:
				if ( BER_BVISNULL( &ndn ) ) {
					/* connection is not authc'd, so don't idassert */
					BER_BVSTR( &authzID, "dn:" );
					break;
				}
				authzID.bv_len = STRLENOF( "dn:" ) + ndn.bv_len;
				authzID.bv_val = slap_sl_malloc( authzID.bv_len + 1, op->o_tmpmemctx );
				AC_MEMCPY( authzID.bv_val, "dn:", STRLENOF( "dn:" ) );
				AC_MEMCPY( authzID.bv_val + STRLENOF( "dn:" ),
						ndn.bv_val, ndn.bv_len + 1 );
				freeauthz = 1;
				break;

			default:
				break;
			}
		}

		if ( li->li_idassert_secprops != NULL ) {
			rs->sr_err = ldap_set_option( lc->lc_ld,
				LDAP_OPT_X_SASL_SECPROPS,
				(void *)li->li_idassert_secprops );

			if ( rs->sr_err != LDAP_OPT_SUCCESS ) {
				rs->sr_err = LDAP_OTHER;
				if ( sendok & LDAP_BACK_SENDERR ) {
					send_ldap_result( op, rs );
				}
				LDAP_BACK_CONN_ISBOUND_CLEAR( lc );
				goto done;
			}
		}

		defaults = lutil_sasl_defaults( lc->lc_ld,
				li->li_idassert_sasl_mech.bv_val,
				li->li_idassert_sasl_realm.bv_val,
				li->li_idassert_authcID.bv_val,
				li->li_idassert_passwd.bv_val,
				authzID.bv_val );

		rs->sr_err = ldap_sasl_interactive_bind_s( lc->lc_ld, binddn.bv_val,
				li->li_idassert_sasl_mech.bv_val, NULL, NULL,
				LDAP_SASL_QUIET, lutil_sasl_interact,
				defaults );

		rs->sr_err = slap_map_api2result( rs );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			LDAP_BACK_CONN_ISBOUND_CLEAR( lc );
			if ( sendok & LDAP_BACK_SENDERR ) {
				send_ldap_result( op, rs );
			}

		} else {
			LDAP_BACK_CONN_ISBOUND_SET( lc );
		}

		lutil_sasl_freedefs( defaults );
		if ( freeauthz ) {
			slap_sl_free( authzID.bv_val, op->o_tmpmemctx );
		}

		goto done;
#endif /* HAVE_CYRUS_SASL */
	}

	switch ( li->li_idassert_authmethod ) {
	case LDAP_AUTH_NONE:
		rc = LDAP_SUCCESS;
		break;

	case LDAP_AUTH_SIMPLE:
		rs->sr_err = ldap_sasl_bind( lc->lc_ld,
				binddn.bv_val, LDAP_SASL_SIMPLE,
				&bindcred, NULL, NULL, &msgid );
		rc = ldap_back_op_result( lc, op, rs, msgid, 0, sendok );
		break;

	default:
		/* unsupported! */
		LDAP_BACK_CONN_ISBOUND_CLEAR( lc );
		rs->sr_err = LDAP_AUTH_METHOD_NOT_SUPPORTED;
		if ( sendok & LDAP_BACK_SENDERR ) {
			send_ldap_result( op, rs );
		}
		goto done;
	}

	if ( rc == LDAP_SUCCESS ) {
		/* set rebind stuff in case of successful proxyAuthz bind,
		 * so that referral chasing is attempted using the right
		 * identity */
		LDAP_BACK_CONN_ISBOUND_SET( lc );
		ber_dupbv( &lc->lc_bound_ndn, &binddn );

		if ( LDAP_BACK_SAVECRED( li ) ) {
			if ( !BER_BVISNULL( &lc->lc_cred ) ) {
				memset( lc->lc_cred.bv_val, 0,
						lc->lc_cred.bv_len );
			}
			ber_bvreplace( &lc->lc_cred, &bindcred );
			ldap_set_rebind_proc( lc->lc_ld, li->li_rebind_f, lc );
		}
	}
done:;
	return LDAP_BACK_CONN_ISBOUND( lc );
}

/*
 * ldap_back_proxy_authz_ctrl() prepends a proxyAuthz control
 * to existing server-side controls if required; if not,
 * the existing server-side controls are placed in *pctrls.
 * The caller, after using the controls in client API 
 * operations, if ( *pctrls != op->o_ctrls ), should
 * free( (*pctrls)[ 0 ] ) and free( *pctrls ).
 * The function returns success if the control could
 * be added if required, or if it did nothing; in the future,
 * it might return some error if it failed.
 * 
 * if no bind took place yet, but the connection is bound
 * and the "proxyauthzdn" is set, then bind as "proxyauthzdn" 
 * and explicitly add proxyAuthz the control to every operation
 * with the dn bound to the connection as control value.
 *
 * If no server-side controls are defined for the operation,
 * simply add the proxyAuthz control; otherwise, if the
 * proxyAuthz control is not already set, add it as
 * the first one
 *
 * FIXME: is controls order significant for security?
 * ANSWER: controls ordering and interoperability
 * must be indicated by the specs of each control; if none
 * is specified, the order is irrelevant.
 */
int
ldap_back_proxy_authz_ctrl(
		ldapconn_t	*lc,
		Operation	*op,
		SlapReply	*rs,
		LDAPControl	***pctrls )
{
	ldapinfo_t	*li = (ldapinfo_t *) op->o_bd->be_private;
	LDAPControl	**ctrls = NULL;
	int		i = 0,
			mode;
	struct berval	assertedID,
			ndn;

	*pctrls = NULL;

	rs->sr_err = LDAP_SUCCESS;

	/* don't proxyAuthz if protocol is not LDAPv3 */
	switch ( li->li_version ) {
	case LDAP_VERSION3:
		break;

	case 0:
		if ( op->o_protocol == 0 || op->o_protocol == LDAP_VERSION3 ) {
			break;
		}
		/* fall thru */

	default:
		goto done;
	}

	/* FIXME: SASL/EXTERNAL over ldapi:// doesn't honor the authcID,
	 * but if it is not set this test fails.  We need a different
	 * means to detect if idassert is enabled */
	if ( ( BER_BVISNULL( &li->li_idassert_authcID ) || BER_BVISEMPTY( &li->li_idassert_authcID ) )
			&& ( BER_BVISNULL( &li->li_idassert_authcDN ) || BER_BVISEMPTY( &li->li_idassert_authcDN ) ) )
	{
		goto done;
	}

	if ( !op->o_conn || op->o_do_not_cache || be_isroot( op ) ) {
		goto done;
	}

	if ( !BER_BVISNULL( &op->o_conn->c_ndn ) ) {
		ndn = op->o_conn->c_ndn;

	} else {
		ndn = op->o_ndn;
	}

	if ( li->li_idassert_mode == LDAP_BACK_IDASSERT_LEGACY ) {
		if ( op->o_proxy_authz ) {
			/*
			 * FIXME: we do not want to perform proxyAuthz
			 * on behalf of the client, because this would
			 * be performed with "proxyauthzdn" privileges.
			 *
			 * This might actually be too strict, since
			 * the "proxyauthzdn" authzTo, and each entry's
			 * authzFrom attributes may be crafted
			 * to avoid unwanted proxyAuthz to take place.
			 */
#if 0
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "proxyAuthz not allowed within namingContext";
#endif
			goto done;
		}

		if ( !BER_BVISNULL( &lc->lc_bound_ndn ) ) {
			goto done;
		}

		if ( BER_BVISNULL( &ndn ) ) {
			goto done;
		}

		if ( BER_BVISNULL( &li->li_idassert_authcDN ) ) {
			goto done;
		}

	} else if ( li->li_idassert_authmethod == LDAP_AUTH_SASL ) {
		if ( ( li->li_idassert_flags & LDAP_BACK_AUTH_NATIVE_AUTHZ )
				/* && ( !BER_BVISNULL( &ndn )
					|| LDAP_BACK_CONN_ISBOUND( lc ) ) */ )
		{
			/* already asserted in SASL via native authz */
			/* NOTE: the test on lc->lc_bound is used to trap
			 * native authorization of anonymous users,
			 * since in that case ndn is NULL */
			goto done;
		}

	} else if ( li->li_idassert_authz && !be_isroot( op ) ) {
		int		rc;
		struct berval authcDN;

		if ( BER_BVISNULL( &ndn ) ) {
			authcDN = slap_empty_bv;
		} else {
			authcDN = ndn;
		}
		rc = slap_sasl_matches( op, li->li_idassert_authz,
				&authcDN, & authcDN );
		if ( rc != LDAP_SUCCESS ) {
			if ( li->li_idassert_flags & LDAP_BACK_AUTH_PRESCRIPTIVE )
			{
				/* ndn is not authorized
				 * to use idassert */
				rs->sr_err = rc;
			}
			goto done;
		}
	}

	if ( op->o_proxy_authz ) {
		/*
		 * FIXME: we can:
		 * 1) ignore the already set proxyAuthz control
		 * 2) leave it in place, and don't set ours
		 * 3) add both
		 * 4) reject the operation
		 *
		 * option (4) is very drastic
		 * option (3) will make the remote server reject
		 * the operation, thus being equivalent to (4)
		 * option (2) will likely break the idassert
		 * assumptions, so we cannot accept it;
		 * option (1) means that we are contradicting
		 * the client's reques.
		 *
		 * I think (4) is the only correct choice.
		 */
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "proxyAuthz not allowed within namingContext";
	}

	if ( op->o_is_auth_check ) {
		mode = LDAP_BACK_IDASSERT_NOASSERT;

	} else {
		mode = li->li_idassert_mode;
	}

	switch ( mode ) {
	case LDAP_BACK_IDASSERT_SELF:
		if ( BER_BVISNULL( &ndn ) ) {
			goto done;
		}
		assertedID = ndn;
		break;

	case LDAP_BACK_IDASSERT_LEGACY:
		/* original behavior:
		 * assert the client's identity */
		if ( BER_BVISNULL( &ndn ) ) {
			assertedID = slap_empty_bv;
		} else {
			assertedID = ndn;
		}
		break;

	case LDAP_BACK_IDASSERT_ANONYMOUS:
		/* assert "anonymous" */
		assertedID = slap_empty_bv;
		break;

	case LDAP_BACK_IDASSERT_NOASSERT:
		/* don't assert; bind as proxyauthzdn */
		goto done;

	case LDAP_BACK_IDASSERT_OTHERID:
	case LDAP_BACK_IDASSERT_OTHERDN:
		/* assert idassert DN */
		assertedID = li->li_idassert_authzID;
		break;

	default:
		assert( 0 );
	}

	if ( BER_BVISNULL( &assertedID ) ) {
		assertedID = slap_empty_bv;
	}

	/* don't idassert the bound DN (ITS#4497) */
	if ( dn_match( &assertedID, &lc->lc_bound_ndn ) ) {
		goto done;
	}

	if ( op->o_ctrls ) {
		for ( i = 0; op->o_ctrls[ i ]; i++ )
			/* just count ctrls */ ;
	}

	ctrls = op->o_tmpalloc( sizeof( LDAPControl * ) * (i + 2) + sizeof( LDAPControl ),
			op->o_tmpmemctx );
	ctrls[ 0 ] = (LDAPControl *)&ctrls[ i + 2 ];
	
	ctrls[ 0 ]->ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
	ctrls[ 0 ]->ldctl_iscritical = 1;

	switch ( li->li_idassert_mode ) {
	/* already in u:ID or dn:DN form */
	case LDAP_BACK_IDASSERT_OTHERID:
	case LDAP_BACK_IDASSERT_OTHERDN:
		ber_dupbv_x( &ctrls[ 0 ]->ldctl_value, &assertedID, op->o_tmpmemctx );
		break;

	/* needs the dn: prefix */
	default:
		ctrls[ 0 ]->ldctl_value.bv_len = assertedID.bv_len + STRLENOF( "dn:" );
		ctrls[ 0 ]->ldctl_value.bv_val = op->o_tmpalloc( ctrls[ 0 ]->ldctl_value.bv_len + 1,
				op->o_tmpmemctx );
		AC_MEMCPY( ctrls[ 0 ]->ldctl_value.bv_val, "dn:", STRLENOF( "dn:" ) );
		AC_MEMCPY( &ctrls[ 0 ]->ldctl_value.bv_val[ STRLENOF( "dn:" ) ],
				assertedID.bv_val, assertedID.bv_len + 1 );
		break;
	}

	/* Older versions of <draft-weltman-ldapv3-proxy> required
	 * to encode the value of the authzID (and called it proxyDN);
	 * this hack provides compatibility with those DSAs that
	 * implement it this way */
	if ( li->li_idassert_flags & LDAP_BACK_AUTH_OBSOLETE_ENCODING_WORKAROUND ) {
		struct berval		authzID = ctrls[ 0 ]->ldctl_value;
		BerElementBuffer	berbuf;
		BerElement		*ber = (BerElement *)&berbuf;
		ber_tag_t		tag;

		ber_init2( ber, 0, LBER_USE_DER );
		ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

		tag = ber_printf( ber, "O", &authzID );
		if ( tag == LBER_ERROR ) {
			rs->sr_err = LDAP_OTHER;
			goto free_ber;
		}

		if ( ber_flatten2( ber, &ctrls[ 0 ]->ldctl_value, 1 ) == -1 ) {
			rs->sr_err = LDAP_OTHER;
			goto free_ber;
		}

free_ber:;
		op->o_tmpfree( authzID.bv_val, op->o_tmpmemctx );
		ber_free_buf( ber );

		if ( rs->sr_err != LDAP_SUCCESS ) {
			op->o_tmpfree( ctrls, op->o_tmpmemctx );
			ctrls = NULL;
			goto done;
		}

	} else if ( li->li_idassert_flags & LDAP_BACK_AUTH_OBSOLETE_PROXY_AUTHZ ) {
		struct berval		authzID = ctrls[ 0 ]->ldctl_value,
					tmp;
		BerElementBuffer	berbuf;
		BerElement		*ber = (BerElement *)&berbuf;
		ber_tag_t		tag;

		if ( strncasecmp( authzID.bv_val, "dn:", STRLENOF( "dn:" ) ) != 0 ) {
			op->o_tmpfree( ctrls[ 0 ]->ldctl_value.bv_val, op->o_tmpmemctx );
			op->o_tmpfree( ctrls, op->o_tmpmemctx );
			ctrls = NULL;
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			goto done;
		}

		tmp = authzID;
		tmp.bv_val += STRLENOF( "dn:" );
		tmp.bv_len -= STRLENOF( "dn:" );

		ber_init2( ber, 0, LBER_USE_DER );
		ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

		/* apparently, Mozilla API encodes this
		 * as "SEQUENCE { LDAPDN }" */
		tag = ber_printf( ber, "{O}", &tmp );
		if ( tag == LBER_ERROR ) {
			rs->sr_err = LDAP_OTHER;
			goto free_ber2;
		}

		if ( ber_flatten2( ber, &ctrls[ 0 ]->ldctl_value, 1 ) == -1 ) {
			rs->sr_err = LDAP_OTHER;
			goto free_ber2;
		}

free_ber2:;
		op->o_tmpfree( authzID.bv_val, op->o_tmpmemctx );
		ber_free_buf( ber );

		if ( rs->sr_err != LDAP_SUCCESS ) {
			op->o_tmpfree( ctrls, op->o_tmpmemctx );
			ctrls = NULL;
			goto done;
		}

		ctrls[ 0 ]->ldctl_oid = LDAP_CONTROL_OBSOLETE_PROXY_AUTHZ;
	}

	if ( op->o_ctrls ) {
		for ( i = 0; op->o_ctrls[ i ]; i++ ) {
			ctrls[ i + 1 ] = op->o_ctrls[ i ];
		}
	}
	ctrls[ i + 1 ] = NULL;

done:;
	if ( ctrls == NULL ) {
		ctrls = op->o_ctrls;
	}

	*pctrls = ctrls;
	
	return rs->sr_err;
}

int
ldap_back_proxy_authz_ctrl_free( Operation *op, LDAPControl ***pctrls )
{
	LDAPControl	**ctrls = *pctrls;

	/* we assume that the first control is the proxyAuthz
	 * added by back-ldap, so it's the only one we explicitly 
	 * free */
	if ( ctrls && ctrls != op->o_ctrls ) {
		assert( ctrls[ 0 ] != NULL );

		if ( !BER_BVISNULL( &ctrls[ 0 ]->ldctl_value ) ) {
			op->o_tmpfree( ctrls[ 0 ]->ldctl_value.bv_val, op->o_tmpmemctx );
		}

		op->o_tmpfree( ctrls, op->o_tmpmemctx );
	} 

	*pctrls = NULL;

	return 0;
}
