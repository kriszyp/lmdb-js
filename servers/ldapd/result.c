/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/syslog.h>

#include <quipu/dsap.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

/*
 * dsa_response - called by do_queries() when there is activity on one of
 * the DSA associations.  It is passed the association descriptor on which
 * the activity occurred, and the client socket.  It figures out what kind
 * of activity it was (e.g., result of a previously initiated operation,
 * error return, etc), and calls the appropriate routine to send a response
 * to the client, or to continue the operation in some cases (e.g., modify),
 * or to chase a referral and retry an operation.
 *
 * If the client is actually given a response, dsa_response() removes the
 * corresponding request from the queue of outstanding requests.  If the
 * activity was an error referral, a connection is made to the referred to
 * DSA (if possible), and do_request() is called to retry the request.
 */

void
dsa_response(
    struct conn	*dsaconn,
    Sockbuf	*clientsb
)
{
	struct DAPindication	di;
	struct DSResult		*dr;
	struct DSError		*de;
	struct DAPpreject	*dp;
	struct DAPabort		*da;
	struct msg		*m = NULL;
	BerElement		*bercopy;
	char			*matched;
	int			incr, delete, rc, ldaperr;

	Debug( LDAP_DEBUG_TRACE, "dsa_response on ad %d\n", dsaconn->c_ad, 0,
	    0 );
	di.di_type = -1;
	if ( (rc = DapInitWaitRequest( dsaconn->c_ad, OK, &di )) == DONE ) {
		Debug( LDAP_DEBUG_ANY, "DapInitWaitRequest: DONE\n", 0, 0, 0 );
		return;
	}

	Debug( LDAP_DEBUG_ARGS, "DapInitWaitRequest: result %d type %d\n", rc,
	    di.di_type, 0 );

	delete = 1;
	switch ( di.di_type ) {
	case DI_RESULT:
		dr = &di.di_result.dr_res;
		if ( (m = get_msg( di.di_result.dr_id )) == NULL ) {
			Debug( LDAP_DEBUG_ANY, "DI_RESULT: can't find msg %d\n",
			    di.di_result.dr_id, 0, 0 );
			return;
		}

		Debug( LDAP_DEBUG_ARGS, "DI_RESULT: type %d\n",
		    dr->result_type, 0, 0 );

		switch ( dr->result_type ) {
		case OP_COMPARE:
			compare_result( clientsb, m, &dr->res_cm );
			break;

		case OP_SEARCH:
			search_result( clientsb, m, &dr->res_sr );
			break;

		case OP_ADDENTRY:
			add_result( clientsb, m );
			break;

		case OP_REMOVEENTRY:
			delete_result( clientsb, m );
			break;

		case OP_MODIFYENTRY:
			modify_result( clientsb, m );
			break;

		case OP_READ:
			if ( do_modify2( clientsb, m, &dr->res_rd ) != 0 )
				delete = 0;
			break;

		case OP_MODIFYRDN:
			modrdn_result( clientsb, m );
			break;

		default:
			break;
		}
		ds_res_free( dr );
		break;

	case DI_ERROR:
		de = &di.di_error.de_err;
		if ( (m = get_msg( di.di_error.de_id )) == NULL ) {
			Debug( LDAP_DEBUG_ANY, "DI_ERROR: can't find msg %d\n",
			    di.di_error.de_id, 0, 0 );
			return;
		}
		if ( m->m_msgtype == LDAP_REQ_SEARCH 
#ifdef LDAP_COMPAT20
		    || m->m_msgtype == OLD_LDAP_REQ_SEARCH
#endif
		    )
			incr = 2;
		else if ( m->m_msgtype == LDAP_REQ_DELETE )
			incr = (LDAP_RES_DELETE - LDAP_REQ_DELETE);
		else
			incr = 1;

		Debug( LDAP_DEBUG_ARGS, "DI_ERROR\n", 0, 0, 0 );

		/* 
		 * chase down referrals, retry operation there.  only do
		 * this for modify-like operations, since we assume the
		 * dsa should have been able to chase anything else that
		 * wasn't really down.
		 */

		if ( de->dse_type == DSE_REFERRAL ) {
			int	bound, rc;

			switch ( m->m_msgtype ) {
#ifdef LDAP_COMPAT20
			case OLD_LDAP_REQ_ADD:
			case OLD_LDAP_REQ_MODIFY:
			case OLD_LDAP_REQ_MODRDN:
			case OLD_LDAP_REQ_DELETE:
			case OLD_LDAP_REQ_COMPARE:
			case OLD_LDAP_REQ_SEARCH:
#endif
#ifdef LDAP_COMPAT30
			case LDAP_REQ_DELETE_30:
#endif
			case LDAP_REQ_ADD:
			case LDAP_REQ_MODIFY:
			case LDAP_REQ_MODRDN:
			case LDAP_REQ_DELETE:
			case LDAP_REQ_COMPARE:
			case LDAP_REQ_SEARCH:
				/* chase down the referral */
				if ( (rc = chase_referral( clientsb, m, de,
				    &matched )) != LDAP_SUCCESS ) {
					send_ldap_msgresult( clientsb,
					    m->m_msgtype + incr, m, rc,
					    matched, "Can't chase referral" );
					free( matched );
					break;
				}

				/* now retry the operation */
				bercopy = ber_dup( m->m_ber );
				if ( do_request( clientsb, m, bercopy, &bound )
				    == 0 ) {
					del_msg( m );
				}
				ber_free( bercopy, 0 );
				return;
				break;

			default:
				send_ldap_msgresult( clientsb, m->m_msgtype +
				    incr, m, LDAP_UNAVAILABLE, NULL, "" );
				break;
			}
			break;
		} else if ( de->dse_type == DSE_ABANDONED ) {
			return;
		}
		

		/* not a referral - convert the error and return to client */
		ldaperr = x500err2ldaperr( de, &matched );
#ifdef LDAP_DEBUG
		if ( ldap_debug )
			print_error( de );	/* prints, then calls free */
		else
#endif
			ds_error_free( de );

		send_ldap_msgresult( clientsb, m->m_msgtype + incr, m,
		    ldaperr, matched, "" );
		free( matched );
		break;

	case DI_PREJECT:
		dp = &di.di_preject;
		if ( (m = get_msg( dp->dp_id )) == NULL ) {
			Debug(LDAP_DEBUG_ANY, "DI_PREJECT: can't find msg %d\n",
			    dp->dp_id, 0, 0 );
			return;
		}

		Debug( LDAP_DEBUG_ARGS, "DI_PREJECT src %d rson %d inf (%s)\n",
		    dp->dp_source, dp->dp_reason, dp->dp_cc ? dp->dp_data
		    : "" );

		send_ldap_msgresult( clientsb, m->m_msgtype, m,
		    LDAP_UNAVAILABLE, NULL, "Got PREJECT from X.500" );

		dsaconn->c_ad = -1;
		break;

	case DI_ABORT:
		da = &di.di_abort;

		Debug( LDAP_DEBUG_ARGS, "DI_ABORT src %d rson %d inf (%s)\n",
		    da->da_source, da->da_reason, da->da_cc ? da->da_data
		    : "" );

		/* assume this always means more stuff coming... */
		if ( da->da_reason == DA_ROS )
			return;

		/* moby hack - but how else do you tell the difference? */
		if ( isclosed( dsaconn->c_ad ) ) {
			send_msg( dsaconn, clientsb, LDAP_UNAVAILABLE,
			    "Got ABORT from X.500" );
			return;
		}

		/* notify outstanding requests of the failure */
		send_msg( dsaconn, clientsb, LDAP_OPERATIONS_ERROR,
		    "Got unknown ABORT from X.500" );

		dsaconn->c_ad = -1;
		return;
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "unknown result type %d\n", di.di_type,
		    0, 0 );

		dsaconn->c_ad = -1;	/* better safe... */
		return;
		break;
	}

	if ( delete && m != NULL )
		del_msg( m );
}

int
send_ldap_msgresult(
    Sockbuf		*sb,
    unsigned long	tag,
    struct msg		*m,
    int			err,
    char		*matched,
    char		*text
)
{
#ifdef LDAP_CONNECTIONLESS
	if ( m->m_cldap ) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_UDP_SET_DST,
		    (void *)&m->m_clientaddr );

		Debug( LDAP_DEBUG_TRACE, "UDP response to %s port %d\n", 
		    inet_ntoa(((struct sockaddr_in *)
		    &m->m_clientaddr)->sin_addr ),
		    ((struct sockaddr_in *)&m->m_clientaddr)->sin_port, 0 );
	}
#endif
	return( send_ldap_result( sb, tag, m->m_msgid, err, matched, text ) );
}

int
send_ldap_result(
    Sockbuf		*sb,
    unsigned long	tag,
    int			msgid,
    int			err,
    char		*matched,
    char		*text
)
{
	BerElement	*ber;
	int		rc;
#ifdef LDAP_CONNECTIONLESS
	int		cldap;
	cldap = ber_sockbuf_ctrl( sb, LBER_SB_OPT_HAS_IO, &ber_sockbuf_io_udp );
#endif

	Debug( LDAP_DEBUG_TRACE, "send_ldap_result\n", 0, 0, 0 );

	if ( tag == LBER_DEFAULT )
#ifdef LDAP_COMPAT20
		tag = ldap_compat == 20 ? OLD_LBER_SEQUENCE : LBER_SEQUENCE;
#else
		tag = LBER_SEQUENCE;
#endif

	if ( (ber = der_alloc()) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "der_alloc failed\n", 0, 0, 0 );
		return( -1 );
	}

	if ( version != 1 ) {
#ifdef LDAP_COMPAT20
		if ( ldap_compat == 20 ) {
			rc = ber_printf( ber, "t{it{tess}}", OLD_LBER_SEQUENCE,
			    msgid, tag, LBER_INTEGER, err,
			    matched ? matched : "", text );
		} else
#endif
#ifdef LDAP_COMPAT30
		if ( ldap_compat == 30 ) {
			rc = ber_printf( ber, "{it{{ess}}}", msgid, tag, err,
			    matched ? matched : "", text );
		} else
#endif
#ifdef LDAP_CONNECTIONLESS
		if ( cldap ) {
			rc = ber_printf( ber, "{is{t{ess}}}", msgid, "", tag,
			    err, matched ? matched : "", text );
		} else
#endif
		rc = ber_printf( ber, "{it{ess}}", msgid, tag, err, matched ?
		    matched : "", text );
	} else {
		/* version 1 always uses the broken stuff */
		rc = ber_printf( ber, "t{it{is}}", OLD_LBER_SEQUENCE, msgid,
		    tag, err, text );
	}

	if ( rc == -1 ) {
		Debug( LDAP_DEBUG_ANY, "ber_printf failed\n", 0, 0, 0 );
		return( -1 );
	}

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_BER )
		trace_ber( 0, ber->ber_ptr - ber->ber_buf, ber->ber_buf,
		    stderr, 0, 0 );
#endif

	if ( ber_flush( sb, ber, 1 ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "ber_flush failed\n", 0, 0, 0 );
		return( -1 );
	}

	return( 0 );
}
