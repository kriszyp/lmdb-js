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

#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/syslog.h>
#include <ac/time.h>
#include <ac/wait.h>

#include <quipu/commonarg.h>
#include <quipu/ds_error.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef PEPSY_DUMP
#ifndef DEBUG
#define DEBUG
#endif
#include "LDAP-types.h"
#if ISODEPACKAGE == IC
#include <compat/logger.h>
#else
#include <logger.h>
#endif
#endif

/*
 * client_request - called by do_queries() when there is activity on the
 * client socket.  It expects to be able to get an LDAP message from the
 * client socket, parses the first couple of fields, and then calls
 * do_request() to handle the request.  If do_request() (or something
 * called by it) returns a response to the client (e.g., in the case of
 * an error), then client_request() is done.  If the request is not
 * responded to (and needs a response), it is added to the queue of
 * outstanding requests.  It will be responded to later via dsa_response(),
 * once the DSA operation completes.
 */

void
client_request(
    Sockbuf	*clientsb,
    struct conn	*dsaconn,
    int 	udp
)
{
	unsigned long	tag;
	unsigned long	len;
	long		msgid;
	BerElement	ber, *copyofber;
	struct msg	*m;
	static int	bound;
#ifdef LDAP_CONNECTIONLESS
	struct sockaddr_in *sai;
#endif   
	Debug( LDAP_DEBUG_TRACE, "client_request%s\n",
	    udp ? " udp" : "", 0, 0 );

	/*
	 * Get the ldap message, which is a sequence of message id

	 * and then the actual request choice.
	 */

	ber_init_w_nullc( &ber, 0 );
	if ( (tag = ber_get_next( clientsb, &len, &ber )) == LBER_DEFAULT ) {
		Debug( LDAP_DEBUG_ANY, "ber_get_next failed\n", 0, 0, 0 );
		log_and_exit( 1 );
	}

#ifdef LDAP_CONNECTIONLESS
	if ( udp && dosyslog ) {
		ber_sockbuf_ctrl( clientsb, LBER_SB_OPT_UDP_GET_SRC,
			(void *)&sai );
		syslog( LOG_INFO, "UDP request from unknown (%s)",
			inet_ntoa( sai->sin_addr ) );
	}
#endif

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_BER )
		trace_ber( tag, len, ber.ber_buf, stderr, 1, 1 );
#endif

#ifdef LDAP_COMPAT
	/*
	 * This tag should be a normal SEQUENCE tag.  In release 2.0 this
	 * tag is 0x10.  In the new stuff this is 0x30.  To distinguish
	 * between 3.0 and the "correct" stuff, we look for an extra
	 * sequence tag after the bind tag.
	 */

	Debug( LDAP_DEBUG_ANY, "bound %d\n", bound, 0, 0 );
	if ( bound == 0 ) {
		/* check for 2.0 */
		if ( tag == OLD_LDAP_TAG_MESSAGE ) {
			Debug( LDAP_DEBUG_ANY, "version 2.0 detected\n", 0,
			    0, 0 );
			if ( dosyslog ) {
				syslog( LOG_INFO, "old version 2.0 detected" );
			}
			ldap_compat = 20;
		/* check for 3.0 */
		} else {
			BerElement	tber;
			unsigned long	tlen;
			unsigned long	ttag;

			tber = ber;	/* struct copy */
			/* msgid */
			ttag = ber_skip_tag( &tber, &tlen );
			tber.ber_ptr += tlen;
			/* bind sequence header */
			ttag = ber_skip_tag( &tber, &tlen );
			ttag = ber_peek_tag( &tber, &tlen );

			Debug( LDAP_DEBUG_ANY, "checking for 3.0 tag 0x%lx\n",
			       ttag, 0, 0 );
			if ( ttag == LBER_SEQUENCE ) {
				Debug( LDAP_DEBUG_ANY, "version 3.0 detected\n",
				    0, 0, 0 );
				if ( dosyslog ) {
					syslog( LOG_INFO,
					    "old version 3.0 detected" );
				}
				ldap_compat = 30;
			}
		}
	}
#endif

	if ( ber_get_int( &ber, &msgid ) != LDAP_TAG_MSGID ) {
		send_ldap_result( clientsb, LBER_DEFAULT, msgid,
		    LDAP_PROTOCOL_ERROR, NULL, "Not an LDAP message" );
		free( ber.ber_buf );
		return;
	}

#ifdef LDAP_CONNECTIONLESS
	if ( udp ) {
		char	*logdn = NULL;

		ber_get_stringa( &ber, &logdn );
		if ( logdn != NULL ) {
		    if ( dosyslog ) {
			    syslog( LOG_INFO, "UDP requestor: %s", logdn );
		    }
		    Debug( LDAP_DEBUG_ANY, "UDP requestor: %s\n", logdn, 0, 0 );
		    free( logdn );
		}
	}
#endif /* LDAP_CONNECTIONLESS */

#ifdef LDAP_COMPAT30
	if ( ldap_compat == 30 )
		tag = ber_skip_tag( &ber, &len );
	else
#endif
		tag = ber_peek_tag( &ber, &len );
	if ( !udp && bound == 0 && tag != LDAP_REQ_BIND
#ifdef LDAP_COMPAT20
	    && tag != OLD_LDAP_REQ_BIND
#endif
	    ) {
		send_ldap_result( clientsb, tag, msgid, LDAP_OPERATIONS_ERROR,
		    NULL, "Bind operation must come first" );
		free( ber.ber_buf );
		return;
	}

#ifdef LDAP_CONNECTIONLESS
	if (udp && tag != LDAP_REQ_SEARCH && tag != LDAP_REQ_ABANDON ) {
		send_ldap_result( clientsb, tag, msgid, LDAP_OPERATIONS_ERROR,
		    NULL, "Only search is supported over UDP/CLDAP" );
		free( ber.ber_buf );
		return;
	}
	ber_sockbuf_ctrl( clientsb, LBER_SB_OPT_UDP_GET_SRC, (void *)&sai );
   
	if ( get_cldap_msg( msgid, tag,
	    (struct sockaddr *)sai ) != NULL ) {
		/*
		 * duplicate request: toss this one
		 */
		Debug( LDAP_DEBUG_TRACE,
		    "client_request tossing dup request id %ld from %s\n",
		    msgid, inet_ntoa( sai->sin_addr ), 0 );
	   
		free( ber.ber_buf );
		return;
	}
#endif

	copyofber = ber_dup( &ber );

	m = add_msg( msgid, tag, copyofber, dsaconn, udp,
#ifdef LDAP_CONNECTIONLESS
		(struct sockaddr *)sai );
#else
		NULL );
#endif

	/* 
	 * Call the appropriate routine to handle the request.  If it
	 * returns a nonzero result, the message requires a response, and
	 * so it's left in the queue of outstanding requests, otherwise
	 * it's deleted.
	 */

	if ( do_request( clientsb, m, &ber, &bound ) == 0 ) {
		del_msg( m );
	}

	return;
}

/*
 * do_request - called when a client makes a request, or when a referral
 * error is returned.  In the latter case, a connection is made to the
 * referred to DSA, and do_request() is called to retry the operation over
 * that connection.  In the former case, do_request() is called to try
 * the operation over the default association.
 */

int
do_request(
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber,
    int		*bound
)
{
	int		resp_required = 0;

	Debug( LDAP_DEBUG_TRACE, "do_request\n", 0, 0, 0 );

	switch ( m->m_msgtype ) {
#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_BIND:
#endif
	case LDAP_REQ_BIND:
		resp_required = do_bind( clientsb, m, ber, bound );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_UNBIND:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_REQ_UNBIND_30:
#endif
	case LDAP_REQ_UNBIND:
		conn_close();
		log_and_exit( 0 );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_ADD:
#endif
	case LDAP_REQ_ADD:
		resp_required = do_add( clientsb, m, ber );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_DELETE:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_REQ_DELETE_30:
#endif
	case LDAP_REQ_DELETE:
		resp_required = do_delete( clientsb, m, ber );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_MODRDN:
#endif
	case LDAP_REQ_MODRDN:
		resp_required = do_modrdn( clientsb, m, ber );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_MODIFY:
#endif
	case LDAP_REQ_MODIFY:
		resp_required = do_modify( clientsb, m, ber );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_COMPARE:
#endif
	case LDAP_REQ_COMPARE:
		resp_required = do_compare( clientsb, m, ber );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_SEARCH:
#endif
	case LDAP_REQ_SEARCH:
		resp_required = do_search( clientsb, m, ber );
		break;

#ifdef LDAP_COMPAT20
	case OLD_LDAP_REQ_ABANDON:
#endif
#ifdef LDAP_COMPAT30
	case LDAP_REQ_ABANDON_30:
#endif
	case LDAP_REQ_ABANDON:
		resp_required = do_abandon( m->m_conn, ber, m->m_uniqid );
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "unknown operation %d\n", m->m_msgtype,
		    0, 0 );

		send_ldap_msgresult( clientsb, m->m_msgtype, m,
		    LDAP_PROTOCOL_ERROR, NULL, "Unknown request type" );
		break;
	}

	return( resp_required );
}

/* 
 * initiate_dap_operation - initiate a dap operation, rebinding and retrying
 * the request if necessary.  If the request is successfully initiated, 0 is
 * returned.  Otherwise, an indication of the error is returned.
 */

int
initiate_dap_operation(
    int		op,
    struct msg	*m,
    void	*arg
)
{
	char			*matched;
	int			i, rc, bound = 0;
	struct DAPindication	di;

	Debug( LDAP_DEBUG_TRACE, "initiate_dap_operation\n", 0, 0, 0 );

	if ( m->m_conn->c_ad == -1 && do_bind_real( m->m_conn, &bound,
	    &matched ) != LDAP_SUCCESS )
		return( LDAP_UNAVAILABLE );

	for ( i = 0; i < 2; i++ ) {
		switch ( op ) {
		case OP_COMPARE:
			rc = DapCompare( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_compare_arg *) arg, &di, ROS_ASYNC );
			break;

		case OP_SEARCH:
			rc = DapSearch( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_search_arg *) arg, &di, ROS_ASYNC );
			break;

		case OP_ADDENTRY:
			rc = DapAddEntry( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_addentry_arg *) arg, &di, ROS_ASYNC );
			break;

		case OP_REMOVEENTRY:
			rc = DapRemoveEntry( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_removeentry_arg *) arg, &di, ROS_ASYNC );
			break;

		case OP_MODIFYENTRY:
			rc = DapModifyEntry( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_modifyentry_arg *) arg, &di, ROS_ASYNC );
			break;

		case OP_READ:
			rc = DapRead( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_read_arg *) arg, &di, ROS_ASYNC );
			break;

		case OP_MODIFYRDN:
			rc = DapModifyRDN( m->m_conn->c_ad, m->m_uniqid,
			    (struct ds_modifyrdn_arg *) arg, &di, ROS_ASYNC );
			break;

		default:
			break;
		}

		Debug( LDAP_DEBUG_TRACE, "operation initiated %d\n", rc, 0,
		    0 );

		if ( rc == OK )
			return( 0 );

		/* 
		 * the operation was not invoked - try rebinding, then 
		 * try it again.
		 */

		(void) dap_unbind( m->m_conn->c_ad );

		if ( do_bind_real( m->m_conn, &bound, &matched )
		    != LDAP_SUCCESS )
			break;
	}

	m->m_conn->c_ad = -1;

	return( LDAP_UNAVAILABLE );	/* DSA was unreachable */
}

#ifdef LDAP_DEBUG
int
trace_ber(
    int   tag,
    int   len,
    char  *ber,
    FILE  *trace_file,
    int	  prepend,
    int   read_pdu	/* If non-zero, PDU was read from client.  0 == PDU is being written */
)
{
	unsigned char   *buf;
	PS              input_ps  = NULLPS;
	PE              pe;
	int             result = -1;

	Debug( LDAP_DEBUG_TRACE, "trace_ber(tag=%#x, ber=%#lx, len=%d)\n", tag,
	    (unsigned long) ber, len );

	if ( (buf = (unsigned char *) malloc( len + 6 )) == NULL ) {
		fprintf( trace_file, "Unable to allocate memory\n" );
	} else {
		if ( prepend ) {
			buf[0] = tag;
			buf[1] = 0x84;
			buf[2] = len >> 24;
			buf[3] = len >> 16;
			buf[4] = len >> 8;
			buf[5] = len;
			SAFEMEMCPY( buf + 6, ber, len );
		} else {
			SAFEMEMCPY( buf, ber, len );
		}
		if ( (input_ps = ps_alloc( str_open )) == NULLPS )
			fprintf( trace_file, "ps_alloc failed\n" );
		else if ( str_setup( input_ps, (char *)buf, len + 6, 1 ) != OK )
			fprintf( trace_file, "str_setup\n" );
		else if ( (pe = ps2pe( input_ps )) == NULLPE ) {
			fprintf(trace_file, "ps2pe: %s\n",
			    ps_error( input_ps->ps_errno ) );
			ber_bprint( (char *) buf, len + 6 );
		} else {
#ifdef PEPSY_DUMP
			int				failed = 0;
			static LLog			log = {
    				"-", NULLCP, NULLCP, LLOG_PDUS,
    				LLOG_NONE, -1, 0, NOTOK
			};
			struct type_LDAP_LDAPMessage	*ldap_msg = NULL;

			if ( decode_LDAP_LDAPMessage(pe, 1, 0, NULL, &ldap_msg)
			    == -1 ) {
				failed = 1;
				fprintf( trace_file,
				    "Error decoding LDAPMessage:\n  [%s]\n",
				    PY_pepy );
				fprintf( trace_file, "Here is the PDU:\n" );
				vsetfp( trace_file, NULL );
				vunknown( pe );
			}
			if (log.ll_events & LLOG_PDUS) {
				pvpdu (&log, print_LDAP_LDAPMessage_P, pe,
				    failed ?
				    "<Bad LDAPMessage>" : "<LDAPMessage>",
				    read_pdu);
			}
/*
			PLOGP(&log, LDAP_LDAPMessage, pe, failed ? "<Bad LDAPMessage>" : "<LDAPMessage>", read_pdu);
*/
			if (ldap_msg)
				free_LDAP_LDAPMessage(ldap_msg);
#else
			vsetfp( trace_file, NULL );
			vunknown( pe );
#endif
			pe_free( pe );
			result = 0;
		}
		free( buf );
	}

      if ( input_ps )
              ps_free( input_ps );

      return( result );
}
#endif
