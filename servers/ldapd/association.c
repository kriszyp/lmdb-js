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

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <quipu/commonarg.h>
#include <quipu/ds_error.h>
#include <quipu/dap.h>			/* get dap_unbind() */
#if ISODEPACKAGE == IC
#include <ll/isoaddrs.h>
#else
#include <isoaddrs.h>
#endif

#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef HAVE_SYS_IOCTL_H 
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_FILIO_H 
#include <sys/filio.h>
#endif

#ifdef __hpux
#define FIOGETOWN	FIOGSAIOOWN
#endif

struct conn	*conns;

struct conn *
conn_dup( struct conn *cn )
{
	struct conn	*new;
	if ( (new = (struct conn *) malloc( sizeof(struct conn) )) == NULL )
		return( NULL );

	*new = *cn;
	new->c_next = NULL;
	new->c_time = 0L;
	new->c_paddr = psap_cpy( cn->c_paddr );
	new->c_dn = strdup( cn->c_dn );
	if ( new->c_credlen > 0 ) {
		new->c_cred = (char *) malloc( cn->c_credlen );
		SAFEMEMCPY( new->c_cred, cn->c_cred, cn->c_credlen );
	} else {
		new->c_cred = "";
	}
	new->c_credlen = cn->c_credlen;
	new->c_refcnt = 1;

	return( new );
}

int
conn_init( void )
{
	struct PSAPaddr	*addr;

	if ( (conns = (struct conn *) malloc( sizeof(struct conn) )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "conn_init: malloc failed\n", 0, 0, 0 );
		return( -1 );
	}

	conns->c_ad = -1;
	conns->c_dn = NULL;
	conns->c_cred = NULL;
	conns->c_credlen = 0;

	if ( dsa_address == NULL || (addr = str2paddr( dsa_address ))
	    == NULLPA ) {
		conns->c_paddr = NULLPA;
		Debug( LDAP_DEBUG_ANY, "conn_init: bad DSA address (%s)\n",
		    dsa_address ? dsa_address : "NULL", 0, 0 );
	} else {
	    conns->c_paddr = psap_cpy( addr );
	}

	conns->c_refcnt = 1;	/* this conn is never deleted */
	conns->c_next = NULL;

	return( 0 );
}

void
conn_free( struct conn *conn )
{
	struct timeval	tv;

	Debug( LDAP_DEBUG_TRACE, "conn_free (%s): refcnt is %d\n",
	    paddr2str( conn->c_paddr, NULLNA ), conn->c_refcnt, 0 );

	if ( --conn->c_refcnt > 0 )
		return;

	gettimeofday( &tv, (struct timezone *)NULL );
	if ( conn->c_time != 0L && (tv.tv_sec - conn->c_time)
	    < referral_connection_timeout ) {
		Debug( LDAP_DEBUG_TRACE, "conn_free: referral conn ttl is %d\n",
		    referral_connection_timeout - (tv.tv_sec - conn->c_time),
		    0, 0 );
		return;
	}


	conn_del( conn );

	if ( conn->c_paddr )
		free( (char *) conn->c_paddr );
	if ( conn->c_dn )
		free( conn->c_dn );
	if ( conn->c_credlen > 0 )
		free( conn->c_cred );
	free( conn );
}

void
conn_del( struct conn *conn )
{
	struct conn	*tmp, *prev;

	Debug( LDAP_DEBUG_TRACE, "conn_del (%s)\n",
	    paddr2str( conn->c_paddr, NULLNA ), 0, 0 );

	prev = NULL;
	for ( tmp = conns; tmp != NULL; tmp = tmp->c_next ) {
		if ( tmp == conn )
			break;
		prev = tmp;
	}

	if ( tmp == NULL ) {
		Debug( LDAP_DEBUG_ANY, "conn_del: cannot find conn\n", 0, 0,
		    0 );
		return;
	}

	if ( prev == NULL ) {
		conns = conns->c_next;	/* delete head of list */
	} else {
		prev->c_next = tmp->c_next;
	}
}

void
conn_setfds( fd_set *fds )
{
	struct conn	*tmp;

	for ( tmp = conns; tmp != NULL; tmp = tmp->c_next ) {
		if ( tmp->c_ad != -1 )
			FD_SET( tmp->c_ad, fds );
	}
}

void
conn_badfds( void )
{
	struct conn	*tmp;

	for ( tmp = conns; tmp != NULL; tmp = tmp->c_next ) {
		if ( isclosed( tmp->c_ad ) ) {
			Debug( LDAP_DEBUG_ANY, "conn_badfds: fd %d is bad\n",
			    tmp->c_ad, 0, 0 );
			tmp->c_ad = -1;
		}
	}
}

struct conn *
conn_getfd( fd_set *fds )
{
	struct conn	*tmp;

	for ( tmp = conns; tmp != NULL; tmp = tmp->c_next ) {
		if ( tmp->c_ad != -1 )
			if ( FD_ISSET( tmp->c_ad, fds ) )
				return( tmp );
	}

	return( NULL );
}

void
conn_add( struct conn *new )
{
	struct timeval	tv;

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_CONNS ) {
		char	*str;

		str = paddr2str( new->c_paddr, NULLNA );
		Debug( LDAP_DEBUG_CONNS, "conn_add: (%s)\n", str, 0, 0 );
	}
#endif

	gettimeofday( &tv, (struct timezone *)NULL );
	new->c_time = tv.tv_sec;
	new->c_next = conns;
	new->c_refcnt = 1;
	conns = new;
}

static int
psap_cmp( struct PSAPaddr *a, struct PSAPaddr *b )
{
	return( bcmp( (char *) a, (char *) b, sizeof(struct PSAPaddr) ) );
}

struct conn *
conn_find( struct conn *c )
{
	struct conn	*tmp;

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_CONNS ) {
		char	*str;

		str = paddr2str( c->c_paddr, NULLNA );
		Debug( LDAP_DEBUG_CONNS, "conn_find: (%s)\n", str, 0, 0 );
	}
#endif
	for ( tmp = conns; tmp != NULL; tmp = tmp->c_next ) {
#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_CONNS ) {
			char	*str;

			str = paddr2str( tmp->c_paddr, NULLNA );
			Debug( LDAP_DEBUG_CONNS, "conn_find: compare to (%s)\n",
			    str, 0, 0 );
		}
#endif
		if ( psap_cmp( tmp->c_paddr, c->c_paddr ) == 0
		    && strcmp( tmp->c_dn, c->c_dn ) == 0
		    && tmp->c_credlen == c->c_credlen
		    && bcmp( tmp->c_cred, c->c_cred, c->c_credlen ) == 0 ) {
			Debug( LDAP_DEBUG_CONNS, "conn_find: found\n", 0,
			    0, 0 );
			return( tmp );
		}
	}

	Debug( LDAP_DEBUG_CONNS, "conn_find: not found\n", 0, 0, 0 );
	return( NULL );
}

void
conn_close( void )
{
	struct conn	*tmp;

	for ( tmp = conns; tmp != NULL; tmp = tmp->c_next ) {
		if ( tmp->c_ad != -1 )
			dap_unbind( tmp->c_ad );
	}
}

int
isclosed( int ad )
{
	int		o;

	if ( ioctl( ad, FIOGETOWN, &o ) < 0 )
		return( errno == EBADF ? 1 : 0 );
	else
		return( 0 );
}
