/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 */
/* This notice applies to changes, created by or for Novell, Inc.,
 * to preexisting works for which notices appear elsewhere in this file.
 *
 * Copyright (C) 1999, 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
 * USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT TO VERSION
 * 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS AVAILABLE AT
 * HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE" IN THE
 * TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION OF THIS
 * WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP PUBLIC
 * LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT THE
 * PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY. 
 *---
 * Modification to OpenLDAP source by Novell, Inc.
 * April 2000 sfs  Added code to chase V3 referrals
 *  request.c - sending of ldap requests; handling of referrals
 *---
 * Note: A verbatim copy of version 2.0.1 of the OpenLDAP Public License 
 * can be found in the file "build/LICENSE-2.0.1" in this distribution
 * of OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap-int.h"
#include "lber.h"

static LDAPConn *find_connection LDAP_P(( LDAP *ld, LDAPURLDesc *srv, int any ));
static void use_connection LDAP_P(( LDAP *ld, LDAPConn *lc ));

static BerElement *
re_encode_request( LDAP *ld,
	BerElement *origber,
	ber_int_t msgid,
	int sref,
	LDAPURLDesc *srv,
	int *type );

BerElement *
ldap_alloc_ber_with_options( LDAP *ld )
{
	BerElement	*ber;

    if (( ber = ber_alloc_t( ld->ld_lberoptions )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
	}

	return( ber );
}


void
ldap_set_ber_options( LDAP *ld, BerElement *ber )
{
	ber->ber_options = ld->ld_lberoptions;
}


ber_int_t
ldap_send_initial_request(
	LDAP *ld,
	ber_tag_t msgtype,
	const char *dn,
	BerElement *ber,
	ber_int_t msgid)
{
	LDAPURLDesc	*servers;
	int rc;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_send_initial_request\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_send_initial_request\n", 0, 0, 0 );
#endif

	if ( ber_sockbuf_ctrl( ld->ld_sb, LBER_SB_OPT_GET_FD, NULL ) == -1 ) {
		/* not connected yet */
		int rc = ldap_open_defconn( ld );

		if( rc < 0 ) {
			ber_free( ber, 1 );
			return( -1 );
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"ldap_send_initial_request: ldap_open_defconn: successful\n" , 
			0, 0, 0);
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldap_open_defconn: successful\n",
			0, 0, 0 );
#endif
	}

	{
		/*
		 * use of DNS is turned off or this is an X.500 DN...
		 * use our default connection
		 */
		servers = NULL;
	}	

#ifdef LDAP_CONNECTIONLESS
	if (LDAP_IS_UDP(ld)) {
		if (msgtype == LDAP_REQ_BIND) {
			if (ld->ld_options.ldo_cldapdn)
				ldap_memfree(ld->ld_options.ldo_cldapdn);
			ld->ld_options.ldo_cldapdn = ldap_strdup(dn);
			return 0;
		}
		if (msgtype != LDAP_REQ_ABANDON && msgtype != LDAP_REQ_SEARCH)
			return LDAP_PARAM_ERROR;
	}
#endif
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	rc = ldap_send_server_request( ld, ber, msgid, NULL,
									servers, NULL, NULL );
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
	if (servers)
		ldap_free_urllist(servers);
	return(rc);
}


int
ldap_int_flush_request(
	LDAP *ld,
	LDAPRequest *lr
)
{
	LDAPConn *lc = lr->lr_conn;

	if ( ber_flush( lc->lconn_sb, lr->lr_ber, 0 ) != 0 ) {
		if ( errno == EAGAIN ) {
			/* need to continue write later */
			lr->lr_status = LDAP_REQST_WRITING;
			ldap_mark_select_write( ld, lc->lconn_sb );
			ld->ld_errno = LDAP_BUSY;
			return -2;
		} else {
			ld->ld_errno = LDAP_SERVER_DOWN;
			ldap_free_request( ld, lr );
			ldap_free_connection( ld, lc, 0, 0 );
			return( -1 );
		}
	} else {
		if ( lr->lr_parent == NULL ) {
			lr->lr_ber->ber_end = lr->lr_ber->ber_ptr;
			lr->lr_ber->ber_ptr = lr->lr_ber->ber_buf;
		}
		lr->lr_status = LDAP_REQST_INPROGRESS;

		/* sent -- waiting for a response */
		ldap_mark_select_read( ld, lc->lconn_sb );
	}
	return 0;
}

int
ldap_send_server_request(
	LDAP *ld,
	BerElement *ber,
	ber_int_t msgid,
	LDAPRequest *parentreq,
	LDAPURLDesc *srvlist,
	LDAPConn *lc,
	LDAPreqinfo *bind )
{
	LDAPRequest	*lr;
	int incparent, rc;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_send_server_request\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_send_server_request\n", 0, 0, 0 );
#endif

	incparent = 0;
	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */

	if ( lc == NULL ) {
		if ( srvlist == NULL ) {
			lc = ld->ld_defconn;
		} else {
			if (( lc = find_connection( ld, srvlist, 1 )) ==
			    NULL ) {
				if ( (bind != NULL) && (parentreq != NULL) ) {
					/* Remember the bind in the parent */
					incparent = 1;
					++parentreq->lr_outrefcnt;
				}
				lc = ldap_new_connection( ld, srvlist, 0, 1, bind );
			}
		}
	}

	if ( lc == NULL || lc->lconn_status != LDAP_CONNST_CONNECTED ) {
		ber_free( ber, 1 );
		if ( ld->ld_errno == LDAP_SUCCESS ) {
			ld->ld_errno = LDAP_SERVER_DOWN;
		}
		if ( incparent ) {
			/* Forget about the bind */
			--parentreq->lr_outrefcnt; 
		}
		return( -1 );
	}

	use_connection( ld, lc );

	/* If we still have an incomplete write, try to finish it before
	 * dealing with the new request. If we don't finish here, return
	 * LDAP_BUSY and let the caller retry later. We only allow a single
	 * request to be in WRITING state.
	 */
	rc = 0;
	if ( ld->ld_requests &&
		ld->ld_requests->lr_status == LDAP_REQST_WRITING &&
		ldap_int_flush_request( ld, ld->ld_requests ) < 0 ) {
		rc = -1;
	}
	if ( rc ) return rc;

	if (( lr = (LDAPRequest *)LDAP_CALLOC( 1, sizeof( LDAPRequest ))) ==
	    NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		ldap_free_connection( ld, lc, 0, 0 );
		ber_free( ber, 1 );
		if ( incparent ) {
			/* Forget about the bind */
			--parentreq->lr_outrefcnt; 
		}
		return( -1 );
	} 
	lr->lr_msgid = msgid;
	lr->lr_status = LDAP_REQST_INPROGRESS;
	lr->lr_res_errno = LDAP_SUCCESS;	/* optimistic */
	lr->lr_ber = ber;
	lr->lr_conn = lc;
	if ( parentreq != NULL ) {	/* sub-request */
		if ( !incparent ) { 
			/* Increment if we didn't do it before the bind */
			++parentreq->lr_outrefcnt;
		}
		lr->lr_origid = parentreq->lr_origid;
		lr->lr_parentcnt = parentreq->lr_parentcnt + 1;
		lr->lr_parent = parentreq;
		lr->lr_refnext = parentreq->lr_child;
		parentreq->lr_child = lr;
	} else {			/* original request */
		lr->lr_origid = lr->lr_msgid;
	}

	if (( lr->lr_next = ld->ld_requests ) != NULL ) {
		lr->lr_next->lr_prev = lr;
	}
	ld->ld_requests = lr;
	lr->lr_prev = NULL;

	ld->ld_errno = LDAP_SUCCESS;
	if ( ldap_int_flush_request( ld, lr ) == -1 ) {
		msgid = -1;
	}

	return( msgid );
}

LDAPConn *
ldap_new_connection( LDAP *ld, LDAPURLDesc *srvlist, int use_ldsb,
	int connect, LDAPreqinfo *bind )
{
	LDAPConn	*lc;
	LDAPURLDesc	*srv;
	Sockbuf		*sb = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_new_connection\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_new_connection\n", 0, 0, 0 );
#endif
	/*
	 * make a new LDAP server connection
	 * XXX open connection synchronously for now
	 */
	if (( lc = (LDAPConn *)LDAP_CALLOC( 1, sizeof( LDAPConn ))) == NULL ||
	    ( !use_ldsb && ( (sb = ber_sockbuf_alloc()) == NULL ))) {
		if ( lc != NULL ) {
			LDAP_FREE( (char *)lc );
		}
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULL );
	}

	lc->lconn_sb = ( use_ldsb ) ? ld->ld_sb : sb;

	if ( connect ) {
		for ( srv = srvlist; srv != NULL; srv = srv->lud_next ) {
			if ( ldap_int_open_connection( ld, lc, srv, 0 ) != -1 ) {
				break;
			}
		}

		if ( srv == NULL ) {
			if ( !use_ldsb ) {
				ber_sockbuf_free( lc->lconn_sb );
			}
		    LDAP_FREE( (char *)lc );
		    ld->ld_errno = LDAP_SERVER_DOWN;
		    return( NULL );
		}

		lc->lconn_server = ldap_url_dup(srv);
	}

	lc->lconn_status = LDAP_CONNST_CONNECTED;
	lc->lconn_next = ld->ld_conns;
	ld->ld_conns = lc;

	/*
	 * XXX for now, we always do a synchronous bind.  This will have
	 * to change in the long run...
	 */
	if ( bind != NULL) {
		int		err = 0;
		LDAPConn	*savedefconn;

		/* Set flag to prevent additional referrals from being processed on this
		 * connection until the bind has completed
		 */
		lc->lconn_rebind_inprogress = 1;
		/* V3 rebind function */
		if ( ld->ld_rebind_proc != NULL) {
			LDAPURLDesc	*srvfunc;
			if( ( srvfunc = ldap_url_dup( srvlist)) == NULL) {
				ld->ld_errno = LDAP_NO_MEMORY;
				err = -1;
			} else {
				savedefconn = ld->ld_defconn;
				++lc->lconn_refcnt;	/* avoid premature free */
				ld->ld_defconn = lc;

#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"ldap_new_connection: Call application rebind_proc\n", 
					0, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE, "Call application rebind_proc\n", 0, 0, 0);
#endif
#ifdef LDAP_R_COMPILE
		ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
		ldap_pvt_thread_mutex_unlock( &ld->ld_res_mutex );
#endif
				err = (*ld->ld_rebind_proc)( ld,
					bind->ri_url, bind->ri_request, bind->ri_msgid,
					ld->ld_rebind_params );
#ifdef LDAP_R_COMPILE
		ldap_pvt_thread_mutex_lock( &ld->ld_res_mutex );
		ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif

				ld->ld_defconn = savedefconn;
				--lc->lconn_refcnt;

				if( err != 0) {
				err = -1;
					ldap_free_connection( ld, lc, 1, 0 );
					lc = NULL;
			}
				ldap_free_urldesc( srvfunc);
		}
		} else {
			savedefconn = ld->ld_defconn;
			++lc->lconn_refcnt;	/* avoid premature free */
			ld->ld_defconn = lc;

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"ldap_new_connection: anonymous rebind via ldap_bind_s\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "anonymous rebind via ldap_bind_s\n", 0, 0, 0);
#endif
#ifdef LDAP_R_COMPILE
			ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
			ldap_pvt_thread_mutex_unlock( &ld->ld_res_mutex );
#endif
			if ( ldap_bind_s( ld, "", "", LDAP_AUTH_SIMPLE ) != LDAP_SUCCESS ) {
				err = -1;
			}
#ifdef LDAP_R_COMPILE
			ldap_pvt_thread_mutex_lock( &ld->ld_res_mutex );
			ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
			ld->ld_defconn = savedefconn;
			--lc->lconn_refcnt;

		if ( err != 0 ) {
			ldap_free_connection( ld, lc, 1, 0 );
			lc = NULL;
		}
	}
		if( lc != NULL)
			lc->lconn_rebind_inprogress = 0;
	}

	return( lc );
}


static LDAPConn *
find_connection( LDAP *ld, LDAPURLDesc *srv, int any )
/*
 * return an existing connection (if any) to the server srv
 * if "any" is non-zero, check for any server in the "srv" chain
 */
{
	LDAPConn	*lc;
	LDAPURLDesc	*ls;

	for ( lc = ld->ld_conns; lc != NULL; lc = lc->lconn_next ) {
		for ( ls = srv; ls != NULL; ls = ls->lud_next ) {
			if ( lc->lconn_server->lud_host != NULL &&
				*lc->lconn_server->lud_host != '\0' &&
			    ls->lud_host != NULL && *ls->lud_host != '\0' &&
				strcasecmp( ls->lud_host, lc->lconn_server->lud_host ) == 0
			    && ls->lud_port == lc->lconn_server->lud_port ) {
				return lc;
			}
			if ( !any ) {
				break;
			}
		}
	}

	return NULL;
}



static void
use_connection( LDAP *ld, LDAPConn *lc )
{
	++lc->lconn_refcnt;
	lc->lconn_lastused = time( NULL );
}


void
ldap_free_connection( LDAP *ld, LDAPConn *lc, int force, int unbind )
{
	LDAPConn	*tmplc, *prevlc;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_free_connection\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_free_connection\n", 0, 0, 0 );
#endif

	if ( force || --lc->lconn_refcnt <= 0 ) {
		if ( lc->lconn_status == LDAP_CONNST_CONNECTED ) {
			ldap_mark_select_clear( ld, lc->lconn_sb );
			if ( unbind ) {
				ldap_send_unbind( ld, lc->lconn_sb, NULL, NULL );
			}
		}

		if( lc->lconn_ber != NULL ) {
			ber_free( lc->lconn_ber, 1 );
		}

		ldap_int_sasl_close( ld, lc );

		prevlc = NULL;
		for ( tmplc = ld->ld_conns; tmplc != NULL;
		    tmplc = tmplc->lconn_next ) {
			if ( tmplc == lc ) {
				if ( prevlc == NULL ) {
				    ld->ld_conns = tmplc->lconn_next;
				} else {
				    prevlc->lconn_next = tmplc->lconn_next;
				}
				break;
			}
			prevlc = tmplc;
		}
		ldap_free_urllist( lc->lconn_server );
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		if ( lc->lconn_krbinstance != NULL ) {
			LDAP_FREE( lc->lconn_krbinstance );
		}
#endif
		if ( lc->lconn_sb != ld->ld_sb ) {
			ber_sockbuf_free( lc->lconn_sb );
		}
		if( lc->lconn_rebind_queue != NULL) {
			int i;
			for( i = 0; lc->lconn_rebind_queue[i] != NULL; i++) {
				LDAP_VFREE(lc->lconn_rebind_queue[i]);
			}
			LDAP_FREE( lc->lconn_rebind_queue);
		}
		LDAP_FREE( lc );
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"ldap_free_connection: actually freed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "ldap_free_connection: actually freed\n",
		    0, 0, 0 );
#endif
	} else {
		lc->lconn_lastused = time( NULL );
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, "ldap_free_connection: refcnt %d\n", 
			lc->lconn_refcnt, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "ldap_free_connection: refcnt %d\n",
		    lc->lconn_refcnt, 0, 0 );
#endif
	}
}


#ifdef LDAP_DEBUG
void
ldap_dump_connection( LDAP *ld, LDAPConn *lconns, int all )
{
	LDAPConn	*lc;
   	char		timebuf[32];

	fprintf( stderr, "** Connection%s:\n", all ? "s" : "" );
	for ( lc = lconns; lc != NULL; lc = lc->lconn_next ) {
		if ( lc->lconn_server != NULL ) {
			fprintf( stderr, "* host: %s  port: %d%s\n",
			    ( lc->lconn_server->lud_host == NULL ) ? "(null)"
			    : lc->lconn_server->lud_host,
			    lc->lconn_server->lud_port, ( lc->lconn_sb ==
			    ld->ld_sb ) ? "  (default)" : "" );
		}
		fprintf( stderr, "  refcnt: %d  status: %s\n", lc->lconn_refcnt,
		    ( lc->lconn_status == LDAP_CONNST_NEEDSOCKET ) ?
		    "NeedSocket" : ( lc->lconn_status ==
		    LDAP_CONNST_CONNECTING ) ? "Connecting" : "Connected" );
		fprintf( stderr, "  last used: %s",
		    ldap_pvt_ctime( &lc->lconn_lastused, timebuf ));
		if( lc->lconn_rebind_inprogress ) {
			fprintf( stderr, "  rebind in progress\n");
			if( lc->lconn_rebind_queue != NULL) {
				int i = 0;
				for( ;lc->lconn_rebind_queue[i] != NULL; i++) {
					int j = 0;
					for( ;lc->lconn_rebind_queue[i][j] != 0; j++) {
						fprintf( stderr, "    queue %d entry %d - %s\n",
							i, j, lc->lconn_rebind_queue[i][j]);
					}
				}
			} else {
				fprintf( stderr, "    queue is empty\n");
			}
		}
		fprintf(stderr, "\n");
		if ( !all ) {
			break;
		}
	}
}


void
ldap_dump_requests_and_responses( LDAP *ld )
{
	LDAPRequest	*lr;
	LDAPMessage	*lm, *l;

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	fprintf( stderr, "** Outstanding Requests:\n" );
	if (( lr = ld->ld_requests ) == NULL ) {
		fprintf( stderr, "   Empty\n" );
	}
	for ( ; lr != NULL; lr = lr->lr_next ) {
	    fprintf( stderr, " * msgid %d,  origid %d, status %s\n",
		lr->lr_msgid, lr->lr_origid,
		( lr->lr_status == LDAP_REQST_INPROGRESS ) ? "InProgress" :
		( lr->lr_status == LDAP_REQST_CHASINGREFS ) ? "ChasingRefs" :
		( lr->lr_status == LDAP_REQST_NOTCONNECTED ) ? "NotConnected" :
		( lr->lr_status == LDAP_REQST_WRITING) ? "Writing" :
		( lr->lr_status == LDAP_REQST_COMPLETED ? "Request Completed" : "Invalid Status"));
	    fprintf( stderr, "   outstanding referrals %d, parent count %d\n",
		    lr->lr_outrefcnt, lr->lr_parentcnt );
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
	fprintf( stderr, "** Response Queue:\n" );
	if (( lm = ld->ld_responses ) == NULL ) {
		fprintf( stderr, "   Empty\n" );
	}
	for ( ; lm != NULL; lm = lm->lm_next ) {
		fprintf( stderr, " * msgid %d,  type %lu\n",
		    lm->lm_msgid, (unsigned long) lm->lm_msgtype );
		if (( l = lm->lm_chain ) != NULL ) {
			fprintf( stderr, "   chained responses:\n" );
			for ( ; l != NULL; l = l->lm_chain ) {
				fprintf( stderr,
				    "  * msgid %d,  type %lu\n",
				    l->lm_msgid,
				    (unsigned long) l->lm_msgtype );
			}
		}
	}
}
#endif /* LDAP_DEBUG */

void
ldap_free_request_int( LDAP *ld, LDAPRequest *lr )
{
	if ( lr->lr_prev == NULL ) {
		ld->ld_requests = lr->lr_next;
	} else {
		lr->lr_prev->lr_next = lr->lr_next;
	}

	if ( lr->lr_next != NULL ) {
		lr->lr_next->lr_prev = lr->lr_prev;
	}

	if ( lr->lr_ber != NULL ) {
		ber_free( lr->lr_ber, 1 );
	}

	if ( lr->lr_res_error != NULL ) {
		LDAP_FREE( lr->lr_res_error );
	}

	if ( lr->lr_res_matched != NULL ) {
		LDAP_FREE( lr->lr_res_matched );
	}

	LDAP_FREE( lr );
}

void
ldap_free_request( LDAP *ld, LDAPRequest *lr )
{
	LDAPRequest     **ttmplr;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, "ldap_free_request (origid %d, msgid %d)\n",
		lr->lr_origid, lr->lr_msgid, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_free_request (origid %d, msgid %d)\n",
		lr->lr_origid, lr->lr_msgid, 0 );
#endif

	/* free all referrals (child requests) */
	while ( lr->lr_child )
		ldap_free_request( ld, lr->lr_child );

	if ( lr->lr_parent != NULL ) {
		--lr->lr_parent->lr_outrefcnt;
		for ( ttmplr = &lr->lr_parent->lr_child; *ttmplr && *ttmplr != lr; ttmplr = &(*ttmplr)->lr_refnext ); 
		if ( *ttmplr == lr )  
			*ttmplr = lr->lr_refnext;
	}
	ldap_free_request_int( ld, lr );
}


/*
 * Chase v3 referrals
 *
 * Parameters:
 *  (IN) ld = LDAP connection handle
 *  (IN) lr = LDAP Request structure
 *  (IN) refs = array of pointers to referral strings that we will chase
 *              The array will be free'd by this function when no longer needed
 *  (IN) sref != 0 if following search reference
 *  (OUT) errstrp = Place to return a string of referrals which could not be followed
 *  (OUT) hadrefp = 1 if sucessfully followed referral
 *
 * Return value - number of referrals followed
 */
int
ldap_chase_v3referrals( LDAP *ld, LDAPRequest *lr, char **refs, int sref, char **errstrp, int *hadrefp )
{
	char		*unfollowed;
	int			 unfollowedcnt = 0;
	LDAPRequest	*origreq;
	LDAPURLDesc	*srv = NULL;
	BerElement	*ber;
	char		**refarray = NULL;
	LDAPConn	*lc;
	int			 rc, count, i, j, id;
	LDAPreqinfo  rinfo;

	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */
	*hadrefp = 0;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_chase_v3referrals\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_chase_v3referrals\n", 0, 0, 0 );
#endif

	unfollowed = NULL;
	rc = count = 0;

	/* If no referrals in array, return */
	if ( (refs == NULL) || ( (refs)[0] == NULL) ) {
		rc = 0;
		goto done;
	}

	/* Check for hop limit exceeded */
	if ( lr->lr_parentcnt >= ld->ld_refhoplimit ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"ldap_chase_v3referrals: more than %d referral hops (dropping)\n",
			ld->ld_refhoplimit, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "more than %d referral hops (dropping)\n", ld->ld_refhoplimit, 0, 0 );
#endif
		ld->ld_errno = LDAP_REFERRAL_LIMIT_EXCEEDED;
	    rc = -1;
		goto done;
	}

	/* find original request */
	for ( origreq = lr;
		origreq->lr_parent != NULL;
		origreq = origreq->lr_parent )
	{
		/* empty */ ;
	}

	refarray = refs;
	refs = NULL;
	/* parse out & follow referrals */
	for( i=0; refarray[i] != NULL; i++) {
		/* Parse the referral URL */
		if (( rc = ldap_url_parse_ext( refarray[i], &srv)) != LDAP_SUCCESS) {
			ld->ld_errno = rc;
			rc = -1;
			goto done;
		}

		if( srv->lud_crit_exts ) {
			/* we do not support any extensions */
			ld->ld_errno = LDAP_NOT_SUPPORTED;
			rc = -1;
			goto done;
		}

		/* treat ldap://hostpart and ldap://hostpart/ the same */
		if ( srv->lud_dn && srv->lud_dn[0] == '\0' ) {
			LDAP_FREE( srv->lud_dn );
			srv->lud_dn = NULL;
		}

		/* check connection for re-bind in progress */
		if (( lc = find_connection( ld, srv, 1 )) != NULL ) {
			if( lc->lconn_rebind_inprogress) {
				/* We are already chasing a referral or search reference and a
				 * bind on that connection is in progress.  We must queue
				 * referrals on that connection, so we don't get a request
				 * going out before the bind operation completes. This happens
				 * if two search references come in one behind the other
				 * for the same server with different contexts.
				 */
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, DETAIL1, 
					"ldap_chase_v3referrals: queue referral \"%s\"\n",
					refarray[i], 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"ldap_chase_v3referrals: queue referral \"%s\"\n",
					refarray[i], 0, 0);
#endif
				if( lc->lconn_rebind_queue == NULL ) {
					/* Create a referral list */
					lc->lconn_rebind_queue =
						(char ***) LDAP_MALLOC( sizeof(void *) * 2);

					if( lc->lconn_rebind_queue == NULL) {
						ld->ld_errno = LDAP_NO_MEMORY;
						rc = -1;
						goto done;
					}

					lc->lconn_rebind_queue[0] = refarray;
					lc->lconn_rebind_queue[1] = NULL;
					refarray = NULL;

				} else {
					/* Count how many referral arrays we already have */
					for( j = 0; lc->lconn_rebind_queue[j] != NULL; j++) {
						/* empty */;
					}

					/* Add the new referral to the list */
					lc->lconn_rebind_queue = (char ***) LDAP_REALLOC(
						lc->lconn_rebind_queue, sizeof(void *) * (j + 2));

					if( lc->lconn_rebind_queue == NULL ) {
						ld->ld_errno = LDAP_NO_MEMORY;
						rc = -1;
						goto done;
					}
					lc->lconn_rebind_queue[j] = refarray;
					lc->lconn_rebind_queue[j+1] = NULL;
					refarray = NULL;
				}

				/* We have queued the referral/reference, now just return */
				rc = 0;
				*hadrefp = 1;
				count = 1; /* Pretend we already followed referral */
				goto done;
			}
		} 
		/* Re-encode the request with the new starting point of the search.
		 * Note: In the future we also need to replace the filter if one
		 * was provided with the search reference
		 */

		/* For references we don't want old dn if new dn empty */
		if ( sref && srv->lud_dn == NULL ) {
			srv->lud_dn = LDAP_STRDUP( "" );
		}

		LDAP_NEXT_MSGID( ld, id );
		ber = re_encode_request( ld, origreq->lr_ber, id,
			sref, srv, &rinfo.ri_request );

		if( ber == NULL ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			rc = -1;
			goto done;
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"ldap_chase_v3referrals: msgid %d, url \"%s\"\n",
			lr->lr_msgid, refarray[i], 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldap_chase_v3referral: msgid %d, url \"%s\"\n",
			lr->lr_msgid, refarray[i], 0);
#endif

		/* Send the new request to the server - may require a bind */
		rinfo.ri_msgid = origreq->lr_origid;
		rinfo.ri_url = refarray[i];
#ifdef LDAP_R_COMPILE
		ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
		rc = ldap_send_server_request( ld, ber, id,
		    	origreq, srv, NULL, &rinfo );
#ifdef LDAP_R_COMPILE
		ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
		if ( rc < 0 ) {
			/* Failure, try next referral in the list */
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
			"ldap_chase_v3referrals: Unable to chase referral \"%s\" (%s)\n",
			refarray[i], ldap_err2string( ld->ld_errno ), 0 );
#else
			Debug( LDAP_DEBUG_ANY, "Unable to chase referral \"%s\" (%s)\n", 
				refarray[i], ldap_err2string( ld->ld_errno ), 0);
#endif
			unfollowedcnt += ldap_append_referral( ld, &unfollowed, refarray[i]);
			ldap_free_urllist(srv);
			srv = NULL;
		} else {
			/* Success, no need to try this referral list further */
			rc = 0;
			++count;
			*hadrefp = 1;

			/* check if there is a queue of referrals that came in during bind */
			if( lc == NULL) {
				if (( lc = find_connection( ld, srv, 1 )) == NULL ) {
					ld->ld_errno = LDAP_OPERATIONS_ERROR;
					rc = -1;
					goto done;
				}
			}

			if( lc->lconn_rebind_queue != NULL) {
				/* Release resources of previous list */
				LDAP_VFREE(refarray);
				refarray = NULL;
				ldap_free_urllist(srv);
				srv = NULL;

				/* Pull entries off end of queue so list always null terminated */
				for( j = 0; lc->lconn_rebind_queue[j] != NULL; j++) {
					;
				}
				refarray = lc->lconn_rebind_queue[j-1];
				lc->lconn_rebind_queue[j-1] = NULL;
				/* we pulled off last entry from queue, free queue */
				if ( j == 1 ) {
					LDAP_FREE( lc->lconn_rebind_queue);
					lc->lconn_rebind_queue = NULL;
				}
				/* restart the loop the with new referral list */
				i = -1;
				continue;
			}
			break; /* referral followed, break out of for loop */
		}
	} /* end for loop */
done:
	LDAP_VFREE(refarray);
	ldap_free_urllist(srv);
	LDAP_FREE( *errstrp );
	
	if( rc == 0) {
		*errstrp = NULL;
		LDAP_FREE( unfollowed );
		return count;
	} else {
		ld->ld_errno = LDAP_REFERRAL;
		*errstrp = unfollowed;
		return rc;
	}
}

/*
 * XXX merging of errors in this routine needs to be improved
 */
int
ldap_chase_referrals( LDAP *ld,
	LDAPRequest *lr,
	char **errstrp,
	int sref,
	int *hadrefp )
{
	int		rc, count, id;
	unsigned	len;
	char		*p, *ref, *unfollowed;
	LDAPRequest	*origreq;
	LDAPURLDesc	*srv;
	BerElement	*ber;
	LDAPreqinfo  rinfo;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_chase_referrals\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_chase_referrals\n", 0, 0, 0 );
#endif

	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */
	*hadrefp = 0;

	if ( *errstrp == NULL ) {
		return( 0 );
	}

	len = strlen( *errstrp );
	for ( p = *errstrp; len >= LDAP_REF_STR_LEN; ++p, --len ) {
		if ( strncasecmp( p, LDAP_REF_STR, LDAP_REF_STR_LEN ) == 0 ) {
			*p = '\0';
			p += LDAP_REF_STR_LEN;
			break;
		}
	}

	if ( len < LDAP_REF_STR_LEN ) {
		return( 0 );
	}

	if ( lr->lr_parentcnt >= ld->ld_refhoplimit ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ENTRY, 
			"ldap_chase_referrals: more than %d referral hops (dropping)\n",
			ld->ld_refhoplimit, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "more than %d referral hops (dropping)\n",
		    ld->ld_refhoplimit, 0, 0 );
#endif
		    /* XXX report as error in ld->ld_errno? */
		    return( 0 );
	}

	/* find original request */
	for ( origreq = lr; origreq->lr_parent != NULL;
	     origreq = origreq->lr_parent ) {
		/* empty */;
	}

	unfollowed = NULL;
	rc = count = 0;

	/* parse out & follow referrals */
	for ( ref = p; rc == 0 && ref != NULL; ref = p ) {
		if (( p = strchr( ref, '\n' )) != NULL ) {
			*p++ = '\0';
		} else {
			p = NULL;
		}

		rc = ldap_url_parse_ext( ref, &srv );

		if ( rc != LDAP_URL_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"ldap_chase_referrals: ignoring unknown referral <%s>\n",
				ref, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
			    "ignoring unknown referral <%s>\n", ref, 0, 0 );
#endif
			rc = ldap_append_referral( ld, &unfollowed, ref );
			*hadrefp = 1;
			continue;
		}

		if( srv->lud_dn != NULL && srv->lud_dn == '\0' ) {
			LDAP_FREE( srv->lud_dn );
			srv->lud_dn = NULL;
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"ldap_chase_referrals: chasing LDAP referral <%s>\n", ref, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		    "chasing LDAP referral: <%s>\n", ref, 0, 0 );
#endif

		*hadrefp = 1;

		LDAP_NEXT_MSGID( ld, id );
		ber = re_encode_request( ld, origreq->lr_ber,
		    id, sref, srv, &rinfo.ri_request );

		if( ber == NULL ) {
			return -1 ;
		}

		/* copy the complete referral for rebind process */
		rinfo.ri_url = LDAP_STRDUP( ref );

		rinfo.ri_msgid = origreq->lr_origid;

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
		rc = ldap_send_server_request( ld, ber, id,
		    lr, srv, NULL, &rinfo );
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif

		LDAP_FREE( rinfo.ri_url );

		if( rc >= 0 ) {
			++count;
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"ldap_chase_referrals: Unable to chase referral <%s>\n", 
				ldap_err2string( ld->ld_errno), 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
			    "Unable to chase referral (%s)\n", 
			    ldap_err2string( ld->ld_errno ), 0, 0 );
#endif
			rc = ldap_append_referral( ld, &unfollowed, ref );
		}

		ldap_free_urllist(srv);
	}

	LDAP_FREE( *errstrp );
	*errstrp = unfollowed;

	return(( rc == 0 ) ? count : rc );
}


int
ldap_append_referral( LDAP *ld, char **referralsp, char *s )
{
	int	first;

	if ( *referralsp == NULL ) {
		first = 1;
		*referralsp = (char *)LDAP_MALLOC( strlen( s ) + LDAP_REF_STR_LEN
		    + 1 );
	} else {
		first = 0;
		*referralsp = (char *)LDAP_REALLOC( *referralsp,
		    strlen( *referralsp ) + strlen( s ) + 2 );
	}

	if ( *referralsp == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}

	if ( first ) {
		strcpy( *referralsp, LDAP_REF_STR );
	} else {
		strcat( *referralsp, "\n" );
	}
	strcat( *referralsp, s );

	return( 0 );
}



static BerElement *
re_encode_request( LDAP *ld,
	BerElement *origber,
	ber_int_t msgid,
	int sref,
	LDAPURLDesc *srv,
	int *type )
{
	/*
	 * XXX this routine knows way too much about how the lber library works!
	 */
	ber_int_t	along;
	ber_tag_t	tag;
	ber_tag_t	rtag;
	ber_int_t	ver;
	ber_int_t	scope;
	int		rc;
	BerElement	tmpber, *ber;
	char		*orig_dn;
	char		*dn;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, 
		"re_encode_request: new msgid %ld, new dn <%s>\n",
		(long) msgid, 
		( srv == NULL || srv->lud_dn == NULL ) ? "NONE" : srv->lud_dn, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	    "re_encode_request: new msgid %ld, new dn <%s>\n",
	    (long) msgid,
		( srv == NULL || srv->lud_dn == NULL) ? "NONE" : srv->lud_dn, 0 );
#endif

	tmpber = *origber;

	/*
	 * all LDAP requests are sequences that start with a message id.
	 * For all except delete, this is followed by a sequence that is
	 * tagged with the operation code.  For delete, the provided DN
	 * is not wrapped by a sequence.
	 */
	rtag = ber_scanf( &tmpber, "{it", /*}*/ &along, &tag );

	if ( rtag == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

	assert( tag != 0);
	if ( tag == LDAP_REQ_BIND ) {
		/* bind requests have a version number before the DN & other stuff */
		rtag = ber_scanf( &tmpber, "{ia" /*}*/, &ver, &orig_dn );

	} else if ( tag == LDAP_REQ_DELETE ) {
		/* delete requests don't have a DN wrapping sequence */
		rtag = ber_scanf( &tmpber, "a", &orig_dn );

	} else if ( tag == LDAP_REQ_SEARCH ) {
		/* search requests need to be re-scope-ed */
		rtag = ber_scanf( &tmpber, "{ae" /*"}"*/, &orig_dn, &scope );

		if( srv->lud_scope != LDAP_SCOPE_DEFAULT ) {
			/* use the scope provided in reference */
			scope = srv->lud_scope;

		} else if ( sref ) {
			/* use scope implied by previous operation
			 *   base -> base
			 *   one -> base
			 *   subtree -> subtree
			 *   subordinate -> subtree
			 */
			switch( scope ) {
			default:
			case LDAP_SCOPE_BASE:
			case LDAP_SCOPE_ONELEVEL:
				scope = LDAP_SCOPE_BASE;
				break;
			case LDAP_SCOPE_SUBTREE:
#ifdef LDAP_FEATURE_SUBORDINATE_SCOPE
			case LDAP_SCOPE_SUBORDINATE:
#endif
				scope = LDAP_SCOPE_SUBTREE;
				break;
			}
		}

	} else {
		rtag = ber_scanf( &tmpber, "{a" /*}*/, &orig_dn );
	}

	if( rtag == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return NULL;
	}

	if (( ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		return NULL;
	}

	if ( srv->lud_dn == NULL ) {
		dn = orig_dn;
	} else {
		dn = srv->lud_dn;
	}

	if ( tag == LDAP_REQ_BIND ) {
		rc = ber_printf( ber, "{it{is" /*}}*/, msgid, tag, ver, dn );
	} else if ( tag == LDAP_REQ_DELETE ) {
		rc = ber_printf( ber, "{itsN}", msgid, tag, dn );
	} else if ( tag == LDAP_REQ_SEARCH ) {
		rc = ber_printf( ber, "{it{se" /*}}*/, msgid, tag, dn, scope );
	} else {
		rc = ber_printf( ber, "{it{s" /*}}*/, msgid, tag, dn );
	}

	LDAP_FREE( orig_dn );

	if ( rc == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return NULL;
	}

	if ( tag != LDAP_REQ_DELETE && (
		ber_write(ber, tmpber.ber_ptr, ( tmpber.ber_end - tmpber.ber_ptr ), 0)
		!= ( tmpber.ber_end - tmpber.ber_ptr ) ||
	    ber_printf( ber, /*{{*/ "N}N}" ) == -1 ) )
	{
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return NULL;
	}

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_PACKETS ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"re_encode_request: new request is:\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "re_encode_request new request is:\n",
		    0, 0, 0 );
#endif
		ber_log_dump( LDAP_DEBUG_BER, ldap_debug, ber, 0 );
	}
#endif /* LDAP_DEBUG */

	*type = tag;	/* return request type */
	return ber;
}


LDAPRequest *
ldap_find_request_by_msgid( LDAP *ld, ber_int_t msgid )
{
	LDAPRequest	*lr;

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if( lr->lr_status == LDAP_REQST_COMPLETED ) {
			continue;	/* Skip completed requests */
		}
		if ( msgid == lr->lr_msgid ) {
			break;
		}
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif

	return( lr );
}


