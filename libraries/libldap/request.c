/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  request.c - sending of ldap requests; handling of referrals
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

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
static LDAPURLDesc *dn2servers LDAP_P(( LDAP *ld, const char *dn ));
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */

static BerElement *re_encode_request LDAP_P((
	LDAP *ld,
	BerElement *origber,
    ber_int_t msgid,
	char **dnp ));


BerElement *
ldap_alloc_ber_with_options( LDAP *ld )
{
	BerElement	*ber;

    if (( ber = ber_alloc_t( ld->ld_lberoptions )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
#ifdef STR_TRANSLATION
	} else {
		ldap_set_ber_options( ld, ber );
#endif /* STR_TRANSLATION */
	}

	return( ber );
}


void
ldap_set_ber_options( LDAP *ld, BerElement *ber )
{
	ber->ber_options = ld->ld_lberoptions;
#ifdef STR_TRANSLATION
	if (( ld->ld_lberoptions & LBER_TRANSLATE_STRINGS ) != 0 ) {
		ber_set_string_translators( ber,
		    ld->ld_lber_encode_translate_proc,
		    ld->ld_lber_decode_translate_proc );
	}
#endif /* STR_TRANSLATION */
}


ber_int_t
ldap_send_initial_request(
	LDAP *ld,
	ber_tag_t msgtype,
	const char *dn,
	BerElement *ber )
{
	LDAPURLDesc	*servers;
	int rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_send_initial_request\n", 0, 0, 0 );

	if ( ! ber_pvt_sb_in_use(&ld->ld_sb ) ) {
		/* not connected yet */
		int rc = ldap_open_defconn( ld );

		if( rc < 0 ) {
			ber_free( ber, 1 );
			return( -1 );
		}

		Debug( LDAP_DEBUG_TRACE,
			"ldap_delayed_open successful, ld_host is %s\n",
			( ld->ld_host == NULL ) ? "(null)" : ld->ld_host, 0, 0 );
	}


#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
	if ( LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_DNS )
		&& ldap_is_dns_dn( dn ) )
	{
		if (( servers = dn2servers( ld, dn )) == NULL ) {
			ber_free( ber, 1 );
			return( -1 );
		}

#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_TRACE ) {
			LDAPURLDesc	*srv;

			for (	srv = servers;
					srv != NULL;
			    	srv = srv->lud_next )
			{
				fprintf( stderr,
				    "LDAP server %s:  dn %s, port %d\n",
				    srv->lud_host, ( srv->lud_dn == NULL ) ?
				    "(default)" : srv->lud_dn,
				    srv->lud_port );
			}
		}
#endif /* LDAP_DEBUG */
	} else
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */
	{
		/*
		 * use of DNS is turned off or this is an X.500 DN...
		 * use our default connection
		 */
		servers = NULL;
	}	

	rc = ldap_send_server_request( ld, ber, ld->ld_msgid, NULL,
									servers, NULL, 0 );
	if (servers)
		ldap_free_urllist(servers);
	return(rc);
}



int
ldap_send_server_request(
	LDAP *ld,
	BerElement *ber,
	ber_int_t msgid,
	LDAPRequest *parentreq,
	LDAPURLDesc *srvlist,
	LDAPConn *lc,
	int bind )
{
	LDAPRequest	*lr;
	int incparent;

	Debug( LDAP_DEBUG_TRACE, "ldap_send_server_request\n", 0, 0, 0 );

	incparent = 0;
	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */

	if ( lc == NULL ) {
		if ( srvlist == NULL ) {
			lc = ld->ld_defconn;
		} else {
			if (( lc = find_connection( ld, srvlist, 1 )) ==
			    NULL ) {
				if ( bind && (parentreq != NULL) ) {
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
		lr->lr_refnext = parentreq->lr_refnext;
		parentreq->lr_refnext = lr;
	} else {			/* original request */
		lr->lr_origid = lr->lr_msgid;
	}

	if (( lr->lr_next = ld->ld_requests ) != NULL ) {
		lr->lr_next->lr_prev = lr;
	}
	ld->ld_requests = lr;
	lr->lr_prev = NULL;

	if ( ber_flush( lc->lconn_sb, ber, 0 ) != 0 ) {
#ifdef notyet
		if ( errno == EWOULDBLOCK ) {
			/* need to continue write later */
			lr->lr_status = LDAP_REQST_WRITING;
			ldap_mark_select_write( ld, lc->lconn_sb );
		} else {
#else /* notyet */
			ld->ld_errno = LDAP_SERVER_DOWN;
			ldap_free_request( ld, lr );
			ldap_free_connection( ld, lc, 0, 0 );
			return( -1 );
#endif /* notyet */
#ifdef notyet
		}
#endif /* notyet */
	} else {
		if ( parentreq == NULL ) {
			ber->ber_end = ber->ber_ptr;
			ber->ber_ptr = ber->ber_buf;
		}

		/* sent -- waiting for a response */
		ldap_mark_select_read( ld, lc->lconn_sb );
	}

	ld->ld_errno = LDAP_SUCCESS;
	return( msgid );
}


LDAPConn *
ldap_new_connection( LDAP *ld, LDAPURLDesc *srvlist, int use_ldsb,
	int connect, int bind )
{
	LDAPConn	*lc;
	LDAPURLDesc	*srv;
	Sockbuf		*sb;

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

	lc->lconn_sb = ( use_ldsb ) ? &ld->ld_sb : sb;

	if ( connect ) {
		for ( srv = srvlist; srv != NULL; srv = srv->lud_next ) {
			if ( open_ldap_connection( ld, lc->lconn_sb,
			    		srv, &lc->lconn_krbinstance, 0 ) != -1 )
			{
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
	if ( bind ) {
		int		err, freepasswd, authmethod;
		char		*binddn, *passwd;
		LDAPConn	*savedefconn;

		freepasswd = err = 0;

		if ( ld->ld_rebindproc == 0 ) {
			binddn = passwd = "";
			authmethod = LDAP_AUTH_SIMPLE;
		} else {
			if (( err = (*ld->ld_rebindproc)( ld, &binddn, &passwd,
			    &authmethod, 0 )) == LDAP_SUCCESS ) {
				freepasswd = 1;
			} else {
				ld->ld_errno = err;
				err = -1;
			}
		}


		if ( err == 0 ) {
			savedefconn = ld->ld_defconn;
			ld->ld_defconn = lc;
			++lc->lconn_refcnt;	/* avoid premature free */

			if ( ldap_bind_s( ld, binddn, passwd, authmethod ) !=
			    LDAP_SUCCESS ) {
				err = -1;
			}
			--lc->lconn_refcnt;
			ld->ld_defconn = savedefconn;
		}

		if ( freepasswd ) {
			(*ld->ld_rebindproc)( ld, &binddn, &passwd,
				&authmethod, 1 );
		}

		if ( err != 0 ) {
			ldap_free_connection( ld, lc, 1, 0 );
			lc = NULL;
		}
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
			    ls->lud_host != NULL && strcasecmp(
			    ls->lud_host, lc->lconn_server->lud_host ) == 0
			    && ls->lud_port == lc->lconn_server->lud_port ) {
				return( lc );
			}
			if ( !any ) {
				break;
			}
		}
	}

	return( NULL );
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

	Debug( LDAP_DEBUG_TRACE, "ldap_free_connection\n", 0, 0, 0 );

	if ( force || --lc->lconn_refcnt <= 0 ) {
		if ( lc->lconn_status == LDAP_CONNST_CONNECTED ) {
			ldap_mark_select_clear( ld, lc->lconn_sb );
			if ( unbind ) {
				ldap_send_unbind( ld, lc->lconn_sb, NULL, NULL );
			}
		}

		/* force closure */
		ldap_close_connection( lc->lconn_sb );
		ber_pvt_sb_destroy( lc->lconn_sb );

		if( lc->lconn_ber != NULL ) {
			ber_free( lc->lconn_ber, 1 );
		}

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
		if ( lc->lconn_krbinstance != NULL ) {
			LDAP_FREE( lc->lconn_krbinstance );
		}
		if ( lc->lconn_sb != &ld->ld_sb ) {
			ber_sockbuf_free( lc->lconn_sb );
		}
		LDAP_FREE( lc );
		Debug( LDAP_DEBUG_TRACE, "ldap_free_connection: actually freed\n",
		    0, 0, 0 );
	} else {
		lc->lconn_lastused = time( NULL );
		Debug( LDAP_DEBUG_TRACE, "ldap_free_connection: refcnt %d\n",
		    lc->lconn_refcnt, 0, 0 );
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
			    &ld->ld_sb ) ? "  (default)" : "" );
		}
		fprintf( stderr, "  refcnt: %d  status: %s\n", lc->lconn_refcnt,
		    ( lc->lconn_status == LDAP_CONNST_NEEDSOCKET ) ?
		    "NeedSocket" : ( lc->lconn_status ==
		    LDAP_CONNST_CONNECTING ) ? "Connecting" : "Connected" );
		fprintf( stderr, "  last used: %s\n",
		    ldap_pvt_ctime( &lc->lconn_lastused, timebuf ));
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

	fprintf( stderr, "** Outstanding Requests:\n" );
	if (( lr = ld->ld_requests ) == NULL ) {
		fprintf( stderr, "   Empty\n" );
	}
	for ( ; lr != NULL; lr = lr->lr_next ) {
	    fprintf( stderr, " * msgid %d,  origid %d, status %s\n",
		lr->lr_msgid, lr->lr_origid, ( lr->lr_status ==
		LDAP_REQST_INPROGRESS ) ? "InProgress" :
		( lr->lr_status == LDAP_REQST_CHASINGREFS ) ? "ChasingRefs" :
		( lr->lr_status == LDAP_REQST_NOTCONNECTED ) ? "NotConnected" :
		"Writing" );
	    fprintf( stderr, "   outstanding referrals %d, parent count %d\n",
		    lr->lr_outrefcnt, lr->lr_parentcnt );
	}

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
ldap_free_request( LDAP *ld, LDAPRequest *lr )
{
	LDAPRequest	*tmplr, *nextlr;

	Debug( LDAP_DEBUG_TRACE, "ldap_free_request (origid %d, msgid %d)\n",
		lr->lr_origid, lr->lr_msgid, 0 );

	if ( lr->lr_parent != NULL ) {
		--lr->lr_parent->lr_outrefcnt;
	} else {
		/* free all referrals (child requests) */
		for ( tmplr = lr->lr_refnext; tmplr != NULL; tmplr = nextlr ) {
			nextlr = tmplr->lr_refnext;
			ldap_free_request( ld, tmplr );
		}
	}

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


/*
 * XXX merging of errors in this routine needs to be improved
 */
int
ldap_chase_referrals( LDAP *ld, LDAPRequest *lr, char **errstrp, int *hadrefp )
{
	int		rc, count, len, newdn = 0;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
	int		ldapref;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */
	char		*p, *ports, *ref, *tmpref, *refdn, *unfollowed;
	LDAPRequest	*origreq;
	LDAPURLDesc	*srv;
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_chase_referrals\n", 0, 0, 0 );

	ld->ld_errno = LDAP_SUCCESS;	/* optimistic */
	*hadrefp = 0;

	if ( *errstrp == NULL ) {
		return( 0 );
	}

	len = strlen( *errstrp );
	for ( p = *errstrp; len >= LDAP_REF_STR_LEN; ++p, --len ) {
		if (( *p == 'R' || *p == 'r' ) && strncasecmp( p,
		    LDAP_REF_STR, LDAP_REF_STR_LEN ) == 0 ) {
			*p = '\0';
			p += LDAP_REF_STR_LEN;
			break;
		}
	}

	if ( len < LDAP_REF_STR_LEN ) {
		return( 0 );
	}

	if ( lr->lr_parentcnt >= ld->ld_refhoplimit ) {
		Debug( LDAP_DEBUG_ANY,
		    "more than %d referral hops (dropping)\n",
		    ld->ld_refhoplimit, 0, 0 );
		    /* XXX report as error in ld->ld_errno? */
		    return( 0 );
	}

	/* find original request */
	for ( origreq = lr; origreq->lr_parent != NULL;
	     origreq = origreq->lr_parent ) {
		;
	}

	unfollowed = NULL;
	rc = count = 0;

	/* parse out & follow referrals */
	for ( ref = p; rc == 0 && ref != NULL; ref = p ) {
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
		ldapref = 0;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */

		if (( p = strchr( ref, '\n' )) != NULL ) {
			*p++ = '\0';
		} else {
			p = NULL;
		}

		len = strlen( ref );
		if ( len > LDAP_LDAP_REF_STR_LEN && strncasecmp( ref,
		    LDAP_LDAP_REF_STR, LDAP_LDAP_REF_STR_LEN ) == 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "chasing LDAP referral: <%s>\n", ref, 0, 0 );
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
			ldapref = 1;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */
			tmpref = ref + LDAP_LDAP_REF_STR_LEN;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
		} else if ( len > LDAP_DX_REF_STR_LEN && strncasecmp( ref,
		    LDAP_DX_REF_STR, LDAP_DX_REF_STR_LEN ) == 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "chasing DX referral: <%s>\n", ref, 0, 0 );
			tmpref = ref + LDAP_DX_REF_STR_LEN;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */
		} else {
			Debug( LDAP_DEBUG_TRACE,
			    "ignoring unknown referral <%s>\n", ref, 0, 0 );
			rc = ldap_append_referral( ld, &unfollowed, ref );
			*hadrefp = 1;
			continue;
		}

		*hadrefp = 1;
		if (( refdn = strchr( tmpref, '/' )) != NULL ) {
			*refdn++ = '\0';
			if ( *refdn != '\0' )
			{
				newdn = 1;
			} else
			{
				refdn = NULL;
			}
		}

		if (( ber = re_encode_request( ld, origreq->lr_ber,
		    ++ld->ld_msgid, &refdn )) == NULL ) {
			return( -1 );
		}

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
		if ( ldapref ) {
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */
			if (( srv = (LDAPURLDesc *)LDAP_CALLOC( 1,
			    sizeof( LDAPURLDesc ))) == NULL ) {
				ber_free( ber, 1 );
				ld->ld_errno = LDAP_NO_MEMORY;
				return( -1 );
			}

			if (( srv->lud_host = LDAP_STRDUP( tmpref )) == NULL ) {
				LDAP_FREE( (char *)srv );
				ber_free( ber, 1 );
				ld->ld_errno = LDAP_NO_MEMORY;
				return( -1 );
			}

			if (( ports = strchr( srv->lud_host, ':' )) != NULL ) {
				*ports++ = '\0';
				srv->lud_port = atoi( ports );
			} else {
				srv->lud_port = ldap_int_global_options.ldo_defport;
			}
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
		} else {
			srv = dn2servers( ld, tmpref );
		}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */

		if ( srv != NULL && ldap_send_server_request( ld, ber, ld->ld_msgid,
		    lr, srv, NULL, 1 ) >= 0 ) {
			++count;
		} else {
			Debug( LDAP_DEBUG_ANY,
			    "Unable to chase referral (%s)\n", 
			    ldap_err2string( ld->ld_errno ), 0, 0 );
			rc = ldap_append_referral( ld, &unfollowed, ref );
		}

		if (srv != NULL)
			ldap_free_urllist(srv);

		if ( !newdn && refdn != NULL ) {
			LDAP_FREE( refdn );
		}
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
re_encode_request( LDAP *ld, BerElement *origber, ber_int_t msgid, char **dnp )
{
/*
 * XXX this routine knows way too much about how the lber library works!
 */
	ber_int_t	along;
	ber_len_t	len;
	ber_tag_t	tag;
	ber_int_t	ver;
	int		rc;
	BerElement	tmpber, *ber;
	char		*orig_dn;

	Debug( LDAP_DEBUG_TRACE,
	    "re_encode_request: new msgid %ld, new dn <%s>\n",
	    (long) msgid, ( *dnp == NULL ) ? "NONE" : *dnp, 0 );

	tmpber = *origber;

	/*
	 * all LDAP requests are sequences that start with a message id,
	 * followed by a sequence that is tagged with the operation code
	 */
	if ( ber_scanf( &tmpber, "{i", /*}*/ &along ) != LDAP_TAG_MSGID ||
	    ( tag = ber_skip_tag( &tmpber, &len )) == LBER_DEFAULT ) {
                ld->ld_errno = LDAP_DECODING_ERROR;
		return( NULL );
	}

        if (( ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
                return( NULL );
        }

	/* bind requests have a version number before the DN & other stuff */
	if ( tag == LDAP_REQ_BIND && ber_get_int( &tmpber, &ver ) ==
	    LBER_DEFAULT ) {
                ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	/* the rest of the request is the DN followed by other stuff */
	if ( ber_get_stringa( &tmpber, &orig_dn ) == LBER_DEFAULT ) {
		ber_free( ber, 1 );
		return( NULL );
	}

	if ( *dnp == NULL ) {
		*dnp = orig_dn;
	} else {
		LDAP_FREE( orig_dn );
	}

	if ( tag == LDAP_REQ_BIND ) {
		rc = ber_printf( ber, "{it{is" /*}}*/, msgid, tag, ver, *dnp );
	} else {
		rc = ber_printf( ber, "{it{s" /*}}*/, msgid, tag, *dnp );
	}

	if ( rc == -1 ) {
		ber_free( ber, 1 );
		return( NULL );
	}

	if ( ber_write( ber, tmpber.ber_ptr, ( tmpber.ber_end -
	    tmpber.ber_ptr ), 0 ) != ( tmpber.ber_end - tmpber.ber_ptr ) ||
	    ber_printf( ber, /*{{*/ "}}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_PACKETS ) {
		Debug( LDAP_DEBUG_ANY, "re_encode_request new request is:\n",
		    0, 0, 0 );
		ber_log_dump( LDAP_DEBUG_BER, ldap_debug, ber, 0 );
	}
#endif /* LDAP_DEBUG */

	return( ber );
}


LDAPRequest *
ldap_find_request_by_msgid( LDAP *ld, ber_int_t msgid )
{
    	LDAPRequest	*lr;

	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if ( msgid == lr->lr_msgid ) {
			break;
		}
	}

	return( lr );
}


#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_DNS
static LDAPURLDesc *
dn2servers( LDAP *ld, const char *dn )	/* dn can also be a domain.... */
{
	char		*p, *host, *server_dn, **dxs;
	const char *domain;
	int		i, port;
	LDAPURLDesc	*srvlist, *prevsrv, *srv;

	if (( domain = strrchr( dn, '@' )) != NULL ) {
		++domain;
	} else {
		domain = dn;
	}

	if (( dxs = ldap_getdxbyname( domain )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULL );
	}

	srvlist = NULL;
	for ( i = 0; dxs[ i ] != NULL; ++i ) {
		if (ldap_url_parselist(&srv, dxs[i]) == LDAP_SUCCESS
			|| ldap_url_parsehosts(&srv, dxs[i]) == LDAP_SUCCESS)
		{
			/* add to end of list of servers */
			if ( srvlist == NULL ) {
				srvlist = srv;
			} else {
				prevsrv->lud_next = srv;
			}
			prevsrv = srv;
		}
	}

	ldap_value_free( dxs );

	if ( srvlist == NULL ) {
		ld->ld_errno = LDAP_SERVER_DOWN;
	}

	return( srvlist );
}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_DNS */
