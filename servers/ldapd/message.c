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

#include <quipu/commonarg.h>
#include <quipu/ds_error.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

static struct msg	*messages;

struct msg *add_msg(
    int			msgid,
    int			msgtype,
    BerElement		*ber,
    struct conn		*dsaconn,
    int			udp,
    struct sockaddr	*clientaddr
)
{
	struct msg		*new;
	static int		uniqid = 0;

	/* make a new message */
	if ( (new = (struct msg *) malloc( sizeof(struct msg) )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "addmsg: malloc failed\n", 0, 0, 0 );
		return( NULL );
	}
	new->m_msgid = msgid;
	new->m_uniqid = ++uniqid;
	new->m_msgtype = msgtype;
	new->m_ber = ber;
	new->m_mods = NULL;
	new->m_conn = dsaconn;
	new->m_conn->c_refcnt++;
	new->m_next = NULL;

#ifdef LDAP_CONNECTIONLESS
	new->m_cldap = udp;
	new->m_searchbase = NULLDN;

	if ( udp ) {
		new->m_clientaddr = *clientaddr;
		Debug( LDAP_DEBUG_TRACE, "udp message from %s port %d\n", 
		    inet_ntoa( ((struct sockaddr_in *)clientaddr)->sin_addr ),
		    ((struct sockaddr_in *)clientaddr)->sin_port, 0 );
	}
#endif

	/* add it to the front of the queue */
	new->m_next = messages;
	messages = new;

	return( new );
}

struct msg *get_msg( int uniqid )
{
	struct msg	*tmp;

	for ( tmp = messages; tmp != NULL; tmp = tmp->m_next ) {
		if ( tmp->m_uniqid == uniqid )
			return( tmp );
	}

	return( NULL );
}

int
del_msg( struct msg *m )
{
	struct msg	*cur, *prev;

	prev = NULL;
	for ( cur = messages; cur != NULL; cur = cur->m_next ) {
		if ( cur == m )
			break;
		prev = cur;
	}

	if ( cur == NULL ) {
		Debug( LDAP_DEBUG_ANY, "delmsg: cannot find msg %lx\n",
		       (unsigned long) m, 0, 0 );
		return( -1 );
	}

	if ( prev == NULL ) {
		messages = cur->m_next;
	} else {
		prev->m_next = cur->m_next;
	}
	conn_free( cur->m_conn );
	modlist_free( cur->m_mods );
	ber_free( cur->m_ber, 1 );
#ifdef LDAP_CONNECTIONLESS
	if ( cur->m_searchbase != NULLDN ) {
	    dn_free( cur->m_searchbase );
	}
#endif /* LDAP_CONNECTIONLESS */
	free( (char *) cur );

	return( 0 );
}

/*
 * send_msg - Send a messge in response to every outstanding request on
 * a given connection.  This is used, for example, when an association to
 * a dsa fails.  It deletes messages to which it responds.
 */

void
send_msg(
    struct conn	*conn,
    Sockbuf	*clientsb,
    int		err,
    char	*str
)
{
	struct msg	*tmp, *next;

	next = NULL;
	for ( tmp = messages; tmp != NULL; tmp = next ) {
		next = tmp->m_next;

		if ( tmp->m_conn == conn ) {
			send_ldap_msgresult( clientsb, tmp->m_msgtype, tmp,
			    err, NULL, str );
		}

		del_msg( tmp );
	}
}


#ifdef LDAP_CONNECTIONLESS
struct msg *
get_cldap_msg(
    int			msgid,
    int			msgtype,
    struct sockaddr	*fromaddr
)
{
    	struct msg	*tmp;

	for ( tmp = messages; tmp != NULL; tmp = tmp->m_next ) {
		if ( tmp->m_cldap && tmp->m_msgid == msgid &&
		    tmp->m_msgtype == msgtype &&
		    ((struct sockaddr_in *)&tmp->m_clientaddr)->sin_port ==
		    ((struct sockaddr_in *)fromaddr)->sin_port &&
		    ((struct sockaddr_in *)&tmp->m_clientaddr)->sin_addr
		    == ((struct sockaddr_in *)fromaddr)->sin_addr ) {
			break;
		}
	}

	return( tmp );
}
#endif /* LDAP_CONNECTIONLESS */
