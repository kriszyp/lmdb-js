/*
 *  Copyright (c) 1993 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  open-wsa.c -- libldap ldap_open routine that assumes Winsock API
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1993 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include "lber.h"
#include "ldap.h"
#include <stdio.h>
#include <string.h>
#include "msdos.h"
#ifdef WSHELPER
#include "wshelper.h"
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	((u_long) 0x7f000001)
#endif

#ifdef LDAP_DEBUG
int	ldap_debug;
#endif

/*
 * ldap_open - initialize and connect to an ldap server.  A magic cookie to
 * be used for future communication is returned on success, NULL on failure.
 *
 * Example:
 *	LDAP	*ld;
 *	ld = ldap_open( hostname, port );
 */

LDAP *ldap_open( host, port )
char	*host;
int	port;
{
	SOCKET			s;
	struct sockaddr_in 	sock;
	struct hostent FAR	*hp;
	LDAP			*ld;
	unsigned long		address;
	int			i, connected;
	char			*p, hostname[64];
	WSADATA 		wsadata;

	Debug( LDAP_DEBUG_TRACE, "ldap_open\n", 0, 0, 0 );

	if ( WSAStartup( 0x0101, &wsadata ) != 0 ) {
	    return( NULL );
	}

	hp = NULL;

	if ( host != NULL ) {
	    if (( address = inet_addr( host )) == INADDR_NONE ) {
		if (( hp = gethostbyname( host )) == NULL ) {
		    WSACleanup();
		    return( NULL );
		}
	    }
	} else {
	    address = htonl( INADDR_LOOPBACK );
	}

	if ( port == 0 )
		port = LDAP_PORT;

	if ( (s = socket( AF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET ) {
		WSACleanup();
		return( NULL );
	}

	connected = 0;
	for ( i = 0; i == 0 || ( hp != NULL && hp->h_addr_list[ i ] != 0L );
		++i ) {
	    if ( hp != NULL ) {
		SAFEMEMCPY( &sock.sin_addr.s_addr, hp->h_addr_list[ i ],
		    sizeof( sock.sin_addr.s_addr ));
	    } else {
		sock.sin_addr.s_addr = address;
	    }
	    sock.sin_family = AF_INET;
	    sock.sin_port = htons( port );

	    if ( connect( s, (struct sockaddr *) &sock, sizeof(sock) ) != SOCKET_ERROR ) {
		connected = 1;
		break;
	    }
	}

	if ( !connected ) {
	    closesocket( s );
	    WSACleanup();
	    return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */

	hostname[0] = '\0';
#ifdef WSHELPER
	if ( (hp = rgethostbyaddr( (char *)&sock.sin_addr.s_addr,
#else
	if ( (hp = gethostbyaddr( (char *)&sock.sin_addr.s_addr,
#endif
	     sizeof(sock.sin_addr.s_addr), AF_INET )) != NULL ) {
	    if ( hp->h_name != NULL ) {
		if ( (p = strchr( hp->h_name, '.' )) != NULL ) {
		    *p = '\0';
		}
		strcpy( hostname, hp->h_name );
	    }
	}

	if ( (ld = (LDAP *) calloc( sizeof(LDAP), 1 )) == NULL ) {
		closesocket( s );
		WSACleanup();
		return( NULL );
	}
	ld->ld_sb.sb_sd = s;
	ld->ld_host = strdup( hostname );
	ld->ld_version = LDAP_VERSION;

	return( ld );
}
