/* bind.c - ldap backend bind function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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
#include "back-ldap.h"

#define PRINT_CONNTREE 0

static LDAP_REBIND_PROC	ldap_back_rebind;

int
ldap_back_bind(
    Operation		*op,
    SlapReply		*rs )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;

	struct berval mdn = { 0, NULL };
	int rc = 0;
	ber_int_t msgid;
	dncookie dc;

	lc = ldap_back_getconn(op, rs);
	if ( !lc ) {
		return( -1 );
	}

	/*
	 * Rewrite the bind dn if needed
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "bindDN";
#else
	dc.tofrom = 1;
	dc.normalized = 0;
#endif
	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	if ( lc->bound_dn.bv_val ) {
		ch_free( lc->bound_dn.bv_val );
		lc->bound_dn.bv_len = 0;
		lc->bound_dn.bv_val = NULL;
	}
	lc->bound = 0;
	/* method is always LDAP_AUTH_SIMPLE if we got here */
	rs->sr_err = ldap_sasl_bind(lc->ld, mdn.bv_val, LDAP_SASL_SIMPLE,
		&op->oq_bind.rb_cred, op->o_ctrls, NULL, &msgid);
	rc = ldap_back_op_result( lc, op, rs, msgid, 1 );
	if (rc == LDAP_SUCCESS) {
		lc->bound = 1;
		if ( mdn.bv_val != op->o_req_dn.bv_val ) {
			lc->bound_dn = mdn;
		} else {
			ber_dupbv( &lc->bound_dn, &op->o_req_dn );
		}
		mdn.bv_val = NULL;

		if ( li->savecred ) {
			if ( lc->cred.bv_val ) {
				memset( lc->cred.bv_val, 0, lc->cred.bv_len );
				ch_free( lc->cred.bv_val );
			}
			ber_dupbv( &lc->cred, &op->oq_bind.rb_cred );
			ldap_set_rebind_proc( lc->ld, ldap_back_rebind, lc );
		}
	}

	/* must re-insert if local DN changed as result of bind */
	if ( lc->bound && !bvmatch(&op->o_req_ndn, &lc->local_dn ) ) {
		int lerr;

		ldap_pvt_thread_mutex_lock( &li->conn_mutex );
		lc = avl_delete( &li->conntree, (caddr_t)lc,
				ldap_back_conn_cmp );
		if ( lc->local_dn.bv_val )
			ch_free( lc->local_dn.bv_val );
		ber_dupbv( &lc->local_dn, &op->o_req_ndn );
		lerr = avl_insert( &li->conntree, (caddr_t)lc,
			ldap_back_conn_cmp, ldap_back_conn_dup );
		ldap_pvt_thread_mutex_unlock( &li->conn_mutex );
		if ( lerr == -1 ) {
			ldap_back_conn_free( lc );
		}
	}

	if ( mdn.bv_val && mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}

	return( rc );
}

/*
 * ldap_back_conn_cmp
 *
 * compares two struct ldapconn based on the value of the conn pointer;
 * used by avl stuff
 */
int
ldap_back_conn_cmp(
	const void *c1,
	const void *c2
	)
{
	const struct ldapconn *lc1 = (const struct ldapconn *)c1;
	const struct ldapconn *lc2 = (const struct ldapconn *)c2;
	int rc;
	
	/* If local DNs don't match, it is definitely not a match */
	if ( ( rc = ber_bvcmp( &lc1->local_dn, &lc2->local_dn )) )
		return rc;

	/* For shared sessions, conn is NULL. Only explicitly
	 * bound sessions will have non-NULL conn.
	 */
	return SLAP_PTRCMP(lc1->conn, lc2->conn);
}

/*
 * ldap_back_conn_dup
 *
 * returns -1 in case a duplicate struct ldapconn has been inserted;
 * used by avl stuff
 */
int
ldap_back_conn_dup(
	void *c1,
	void *c2
	)
{
	struct ldapconn *lc1 = (struct ldapconn *)c1;
	struct ldapconn *lc2 = (struct ldapconn *)c2;

	/* Cannot have more than one shared session with same DN */
	if ( dn_match( &lc1->local_dn, &lc2->local_dn ) &&
		 lc1->conn == lc2->conn ) return -1;
		
	return 0;
}

#if PRINT_CONNTREE > 0
static void ravl_print( Avlnode *root, int depth )
{
	int     i;
	struct ldapconn *lc;
	
	if ( root == 0 )
		return;
	
	ravl_print( root->avl_right, depth+1 );
	
	for ( i = 0; i < depth; i++ )
		printf( "   " );

	lc = root->avl_data;
	printf( "lc(%lx) local(%s) conn(%lx) %d\n",
			lc, lc->local_dn.bv_val, lc->conn, root->avl_bf );
	
	ravl_print( root->avl_left, depth+1 );
}

static void myprint( Avlnode *root )
{
	printf( "********\n" );
	
	if ( root == 0 )
		printf( "\tNULL\n" );

	else
		ravl_print( root, 0 );
	
	printf( "********\n" );
}
#endif /* PRINT_CONNTREE */

struct ldapconn *
ldap_back_getconn(Operation *op, SlapReply *rs)
{
	struct ldapinfo *li = (struct ldapinfo *)op->o_bd->be_private;
	struct ldapconn *lc, lc_curr;
	LDAP *ld;
	int is_priv = 0;

	/* Searches for a ldapconn in the avl tree */

	/* Explicit binds must not be shared */
	if ( op->o_tag == LDAP_REQ_BIND
		|| (op->o_conn
		  && (op->o_bd == op->o_conn->c_authz_backend ))) {
		lc_curr.conn = op->o_conn;
	} else {
		lc_curr.conn = NULL;
	}
	
	/* Internal searches are privileged and shared. So is root. */
	if ( op->o_do_not_cache || be_isroot_dn( li->be, &op->o_ndn ) ) {
		lc_curr.local_dn = li->be->be_rootndn;
		lc_curr.conn = NULL;
		is_priv = 1;
	} else {
		lc_curr.local_dn = op->o_ndn;
	}

	ldap_pvt_thread_mutex_lock( &li->conn_mutex );
	lc = (struct ldapconn *)avl_find( li->conntree, 
		(caddr_t)&lc_curr, ldap_back_conn_cmp );
	ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

	/* Looks like we didn't get a bind. Open a new session... */
	if (!lc) {
		int vers = op->o_protocol;
		rs->sr_err = ldap_initialize(&ld, li->url);
		
		if (rs->sr_err != LDAP_SUCCESS) {
			rs->sr_err = slap_map_api2result( rs );
			if (rs->sr_text == NULL) {
				rs->sr_text = "ldap_initialize() failed";
			}
			if (op->o_conn) send_ldap_result( op, rs );
			rs->sr_text = NULL;
			return( NULL );
		}
		/* Set LDAP version. This will always succeed: If the client
		 * bound with a particular version, then so can we.
		 */
		ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
				(const void *)&vers);
		/* FIXME: configurable? */
		ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON);

		lc = (struct ldapconn *)ch_malloc(sizeof(struct ldapconn));
		lc->conn = lc_curr.conn;
		lc->ld = ld;
		ber_dupbv( &lc->local_dn, &lc_curr.local_dn );

#ifdef ENABLE_REWRITE
		/*
		 * Sets a cookie for the rewrite session
		 *
		 * FIXME: the o_conn might be no longer valid,
		 * since we may have different entries
		 * for the same connection
		 */
		( void )rewrite_session_init( li->rwmap.rwm_rw, op->o_conn );
#endif /* ENABLE_REWRITE */

		ldap_pvt_thread_mutex_init( &lc->lc_mutex );

		if ( is_priv ) {
			ber_dupbv( &lc->cred, &li->bindpw );
			ber_dupbv( &lc->bound_dn, &li->binddn );
		} else {
			lc->cred.bv_len = 0;
			lc->cred.bv_val = NULL;
			lc->bound_dn.bv_val = NULL;
			lc->bound_dn.bv_len = 0;
			if ( op->o_conn && op->o_conn->c_dn.bv_len != 0
					&& ( op->o_bd == op->o_conn->c_authz_backend ) ) {
				
				dncookie dc;
				struct berval bv;

				/*
				 * Rewrite the bind dn if needed
				 */
				dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
				dc.conn = op->o_conn;
				dc.rs = rs;
				dc.ctx = "bindDN";
#else
				dc.tofrom = 1;
				dc.normalized = 0;
#endif

				if ( ldap_back_dn_massage( &dc, &op->o_conn->c_dn, &bv ) ) {
					send_ldap_result( op, rs );
					return NULL;
				}

				if ( bv.bv_val == op->o_conn->c_dn.bv_val ) {
					ber_dupbv( &lc->bound_dn, &bv );
				} else {
					lc->bound_dn = bv;
				}
			}
		}

		lc->bound = 0;

		/* Inserts the newly created ldapconn in the avl tree */
		ldap_pvt_thread_mutex_lock( &li->conn_mutex );
		rs->sr_err = avl_insert( &li->conntree, (caddr_t)lc,
			ldap_back_conn_cmp, ldap_back_conn_dup );

#if PRINT_CONNTREE > 0
		myprint( li->conntree );
#endif /* PRINT_CONNTREE */
	
		ldap_pvt_thread_mutex_unlock( &li->conn_mutex );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, INFO, 
			"ldap_back_getconn: conn %p inserted\n", (void *) lc, 0, 0);
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_getconn: conn %p inserted\n", (void *) lc, 0, 0 );
#endif /* !NEW_LOGGING */
	
		/* Err could be -1 in case a duplicate ldapconn is inserted */
		if ( rs->sr_err != 0 ) {
			ldap_back_conn_free( lc );
			if (op->o_conn) {
				send_ldap_error( op, rs, LDAP_OTHER,
				"internal server error" );
			}
			return( NULL );
		}
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, INFO, 
			"ldap_back_getconn: conn %p fetched\n", 
			(void *) lc, 0, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_TRACE,
			"=>ldap_back_getconn: conn %p fetched\n", (void *) lc, 0, 0 );
#endif /* !NEW_LOGGING */
	}
	
	return( lc );
}

/*
 * ldap_back_dobind
 *
 * Note: as the check for the value of lc->bound was already here, I removed
 * it from all the callers, and I made the function return the flag, so
 * it can be used to simplify the check.
 */
int
ldap_back_dobind( struct ldapconn *lc, Operation *op, SlapReply *rs )
{	
	struct ldapinfo *li = (struct ldapinfo *)op->o_bd->be_private;
	int rc;
	ber_int_t msgid;

	ldap_pvt_thread_mutex_lock( &lc->lc_mutex );
	if ( !lc->bound ) {
#ifdef LDAP_BACK_PROXY_AUTHZ
		int	gotit = 0;
#if 0
		/*
		 * FIXME: we need to let clients use proxyAuthz
		 * otherwise we cannot do symmetric pools of servers;
		 * we have to live with the fact that a user can
		 * authorize itself as any ID that is allowed
		 * by the saslAuthzTo directive of the "proxyauthzdn".
		 */
		/*
		 * NOTE: current Proxy Authorization specification
		 * and implementation do not allow proxy authorization
		 * control to be provided with Bind requests
		 */
		gotit = op->o_proxy_authz;
#endif

		/*
		 * if no bind took place yet, but the connection is bound
		 * and the "proxyauthzdn" is set, then bind as 
		 * "proxyauthzdn" and explicitly add the proxyAuthz 
		 * control to every operation with the dn bound 
		 * to the connection as control value.
		 */
		if ( ( lc->bound_dn.bv_val == NULL || lc->bound_dn.bv_len == 0 )
	      			&& ( op->o_conn && op->o_conn->c_dn.bv_val != NULL && op->o_conn->c_dn.bv_len != 0 )
	      			&& ( li->proxyauthzdn.bv_val != NULL && li->proxyauthzdn.bv_len != 0 ) 
	      			&& ! gotit ) {
			rs->sr_err = ldap_sasl_bind(lc->ld, li->proxyauthzdn.bv_val,
				LDAP_SASL_SIMPLE, &li->proxyauthzpw, NULL, NULL, &msgid);

		} else
#endif /* LDAP_BACK_PROXY_AUTHZ */
		{
			rs->sr_err = ldap_sasl_bind(lc->ld, lc->bound_dn.bv_val,
				LDAP_SASL_SIMPLE, &lc->cred, NULL, NULL, &msgid);
		}
		
		rc = ldap_back_op_result( lc, op, rs, msgid, 0 );
		if (rc == LDAP_SUCCESS) {
			lc->bound = 1;
		}
	}
	rc = lc->bound;
	ldap_pvt_thread_mutex_unlock( &lc->lc_mutex );
	return rc;
}

/*
 * ldap_back_rebind
 *
 * This is a callback used for chasing referrals using the same
 * credentials as the original user on this session.
 */
static int 
ldap_back_rebind( LDAP *ld, LDAP_CONST char *url, ber_tag_t request,
	ber_int_t msgid, void *params )
{
	struct ldapconn *lc = params;

	return ldap_bind_s( ld, lc->bound_dn.bv_val, lc->cred.bv_val, LDAP_AUTH_SIMPLE );
}

#if 0 /* deprecated in favour of slap_map_api2result() */
/* Map API errors to protocol errors... */
int
ldap_back_map_result( SlapReply *rs )
{
	switch(rs->sr_err)
	{
	case LDAP_SERVER_DOWN:
		return LDAP_UNAVAILABLE;
	case LDAP_LOCAL_ERROR:
		return LDAP_OTHER;
	case LDAP_ENCODING_ERROR:
	case LDAP_DECODING_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_TIMEOUT:
		return LDAP_UNAVAILABLE;
	case LDAP_AUTH_UNKNOWN:
		return LDAP_AUTH_METHOD_NOT_SUPPORTED;
	case LDAP_FILTER_ERROR:
		rs->sr_text = "Filter error";
		return LDAP_OTHER;
	case LDAP_USER_CANCELLED:
		rs->sr_text = "User cancelled";
		return LDAP_OTHER;
	case LDAP_PARAM_ERROR:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_MEMORY:
		return LDAP_OTHER;
	case LDAP_CONNECT_ERROR:
		return LDAP_UNAVAILABLE;
	case LDAP_NOT_SUPPORTED:
		return LDAP_UNWILLING_TO_PERFORM;
	case LDAP_CONTROL_NOT_FOUND:
		return LDAP_PROTOCOL_ERROR;
	case LDAP_NO_RESULTS_RETURNED:
		return LDAP_NO_SUCH_OBJECT;
	case LDAP_MORE_RESULTS_TO_RETURN:
		rs->sr_text = "More results to return";
		return LDAP_OTHER;
	case LDAP_CLIENT_LOOP:
	case LDAP_REFERRAL_LIMIT_EXCEEDED:
		return LDAP_LOOP_DETECT;
	default:
		if ( LDAP_API_ERROR(rs->sr_err) )
			return LDAP_OTHER;
		return rs->sr_err;
	}
}
#endif

int
ldap_back_op_result(struct ldapconn *lc, Operation *op, SlapReply *rs,
	ber_int_t msgid, int sendok)
{
	struct ldapinfo *li = (struct ldapinfo *)op->o_bd->be_private;
	char *match = NULL;
	LDAPMessage *res = NULL;
	char *text = NULL;

#define	ERR_OK(err) ((err) == LDAP_SUCCESS || (err) == LDAP_COMPARE_FALSE || (err) == LDAP_COMPARE_TRUE)

	rs->sr_text = NULL;
	rs->sr_matched = NULL;

	/* if the error recorded in the reply corresponds
	 * to a successful state, get the error from the
	 * remote server response */
	if ( ERR_OK( rs->sr_err ) ) {
		/* if result parsing fails, note the failure reason */
		if ( ldap_result( lc->ld, msgid, 1, NULL, &res ) == -1 ) {
			ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
					&rs->sr_err);

		/* otherwise get the result; if it is not
		 * LDAP_SUCCESS, record it in the reply
		 * structure (this includes 
		 * LDAP_COMPARE_{TRUE|FALSE}) */
		} else {
			int rc = ldap_parse_result(lc->ld, res, &rs->sr_err,
					&match, &text, NULL, NULL, 1);
			rs->sr_text = text;
			if ( rc != LDAP_SUCCESS ) rs->sr_err = rc;
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
			struct berval dn, mdn;
			dncookie dc;

			dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
			dc.conn = op->o_conn;
			dc.rs = rs;
			dc.ctx = "matchedDN";
#else
			dc.tofrom = 0;
			dc.normalized = 0;
#endif
			ber_str2bv(match, 0, 0, &dn);
			ldap_back_dn_massage(&dc, &dn, &mdn);

			/* record the (massaged) matched
			 * DN into the reply structure */
			rs->sr_matched = mdn.bv_val;
				
		}
	}
	if ( op->o_conn && ( sendok || rs->sr_err != LDAP_SUCCESS ) ) {
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
	return( ERR_OK( rs->sr_err ) ? 0 : -1 );
}

#ifdef LDAP_BACK_PROXY_AUTHZ
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
 * the first one (FIXME: is controls order significant
 * for security?).
 */
int
ldap_back_proxy_authz_ctrl(
		struct ldapconn	*lc,
		Operation	*op,
		SlapReply	*rs,
		LDAPControl	***pctrls )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	LDAPControl	**ctrls = NULL;

	*pctrls = NULL;

	if ( ( lc->bound_dn.bv_val == NULL || lc->bound_dn.bv_len == 0 )
	      		&& ( op->o_conn && op->o_conn->c_dn.bv_val != NULL && op->o_conn->c_dn.bv_len != 0 )
	      		&& ( li->proxyauthzdn.bv_val != NULL && li->proxyauthzdn.bv_len != 0 ) ) {
		int	i = 0;

		if ( !op->o_proxy_authz ) {
			ctrls = ch_malloc( sizeof( LDAPControl * ) * (i + 2) );
			ctrls[ 0 ] = ch_malloc( sizeof( LDAPControl ) );
			
			ctrls[ 0 ]->ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
			ctrls[ 0 ]->ldctl_iscritical = 1;
			ctrls[ 0 ]->ldctl_value.bv_len = op->o_conn->c_dn.bv_len + 3;
			ctrls[ 0 ]->ldctl_value.bv_val = ch_malloc( ctrls[ 0 ]->ldctl_value.bv_len + 1 );
			AC_MEMCPY( ctrls[ 0 ]->ldctl_value.bv_val, "dn:", sizeof( "dn:" ) - 1 );
			AC_MEMCPY( ctrls[ 0 ]->ldctl_value.bv_val + sizeof( "dn:") - 1,
					op->o_conn->c_dn.bv_val, op->o_conn->c_dn.bv_len + 1 );

			if ( op->o_ctrls ) {
				for ( i = 0; op->o_ctrls[ i ]; i++ ) {
					ctrls[ i + 1 ] = op->o_ctrls[ i ];
				}
			}
			ctrls[ i + 1 ] = NULL;

		} else {
			/*
			 * FIXME: we do not want to perform proxyAuthz
			 * on behalf of the client, because this would
			 * be performed with "proxyauthzdn" privileges.
			 *
			 * This might actually be too strict, since
			 * the "proxyauthzdn" saslAuthzTo, and each entry's
			 * saslAuthzFrom attributes may be crafted
			 * to avoid unwanted proxyAuthz to take place.
			 */
#if 0
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "proxyAuthz not allowed within namingContext";
#endif
		}
	}

	if ( ctrls == NULL ) {
		ctrls = op->o_ctrls;
	}

	*pctrls = ctrls;
	
	return rs->sr_err;
}
#endif /* LDAP_BACK_PROXY_AUTHZ */
