/*
 *  Copyright (c) 1992 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  open-dos.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1992 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include "lber.h"
#include "ldap.h"
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#ifdef PCNFS
#include <tklib.h>
#include <sys/tk_types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#else /* PCNFS */
#include "hostform.h"
#include "externs.h"
#endif /* PCNFS */
#include "msdos.h"

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	((u_long) 0x7f000001)
#endif

#ifdef LDAP_DEBUG
int	ldap_debug;
#endif

#ifndef PCNFS
u_long *lookup_addrs( char *host );
extern long inet_addr( char *addr );
extern struct machinfo *lookup( char *host );
#endif /* PCNFS */

/*
 * ldap_open - initialize and connect to an ldap server.  A magic cookie to
 * be used for future communication is returned on success, NULL on failure.
 *
 * Example:
 *	LDAP	*ld;
 *	ld = ldap_open( hostname, port );
 */

#ifdef PCNFS
LDAP *ldap_open( host, port )
    char	*host;
    int		port;
{
	int                     s;
	unsigned long           address;
	struct sockaddr_in      sock;
	struct hostent          *hp;
	LDAP                    *ld;
	char                    *p, hostname[BUFSIZ];

	Debug( LDAP_DEBUG_TRACE, "ldap_open\n", 0, 0, 0 );

	if ( host == NULL ) {
		fprintf(stderr, "No hostname!\n");
		return( NULL );
	}
	if ( (hp = gethostbyname( host )) == NULL ) {
		perror( "gethostbyname" );
		return( NULL );
	}
	SAFEMEMCPY( (char *) &address, (char *) hp->h_addr, hp->h_length );
	strcpy( hostname, hp->h_name );
	if ( (p = strchr( hostname, '.' )) != NULL )
		*p = '\0';
	if ( port == 0 )
		port = LDAP_PORT;

	if ( (s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
		tk_perror( "socket" );
		return( NULL );
	}

	memset( (char *)&sock, 0, sizeof(sock));
	SAFEMEMCPY( &sock.sin_addr, hp->h_addr, hp->h_length );
	sock.sin_family = hp->h_addrtype;
	sock.sin_port = htons( (u_short) port);

	if (connect( s, (struct sockaddr *)&sock, sizeof(sock) ) < 0 ) {
		tk_perror( "connect" );
		return( NULL );
	}

	if ( (ld = (LDAP *) calloc( sizeof(LDAP), 1 )) == NULL ) {
		close( s );
		return( NULL );
	}
	ld->ld_sb.sb_sd = s;
	ld->ld_host = strdup( hostname );
	ld->ld_version = LDAP_VERSION;

	return( ld );
}
#else /* PCNFS */

LDAP *ldap_open( host, port )
char	*host;
int	port;
{
	int 			s, i;
	unsigned long		tmpaddr[2], *addrs;
	LDAP			*ld;
	char			*p, hostname[BUFSIZ];

	Debug( LDAP_DEBUG_TRACE, "ldap_open\n", 0, 0, 0 );

	ncsainit();
	tmpaddr[ 1 ] = 0;
	addrs = tmpaddr;
	if ( host != NULL ) {
		strcpy( hostname, host );
		if ( (tmpaddr[0] = inet_addr( host )) == -1 ) {
	    		if (( addrs = lookup_addrs( host )) == NULL ) {
				netshut();
				return( NULL );
	    		}
		}
	} else {
		tmpaddr[0] = INADDR_LOOPBACK;
		strcpy( hostname, "localhost" );
	}
	if ( (p = strchr( hostname, '.' )) != NULL )
		*p = '\0';
	if ( port == 0 )
		port = LDAP_PORT;

	for ( i = 0; addrs[ i ] != 0; ++i ) {
		if ( (s = ncsaopen( addrs[ i ], port )) >= 0 ) {
			break;
		}
	}

	if ( addrs[ i ] == 0 ) {
		netshut();
		return( NULL );
	}

	if ( (ld = (LDAP *) calloc( sizeof(LDAP), 1 )) == NULL ) {
		netclose( s );
		netshut();
		return( NULL );
	}
	ld->ld_sb.sb_sd = s;
	ld->ld_host = strdup( hostname );
	ld->ld_version = LDAP_VERSION;

	return( ld );
}


u_long *
lookup_addrs( host )
    char	*host;
{
    struct machinfo	*mr;
    int			numaddrs, i;
    char		*ipp;
    u_long		*addrs, along;

    if (( mr = lookup( host )) == NULL ) {
	return( NULL );
    }

    ipp = mr->hostip;
#ifdef NCSADOMAINFIX
    numaddrs = 0;
    while ( numaddrs < 4 ) {	/* maximum of 4 addresses */
        SAFEMEMCPY( (char *)&along, (char *)ipp, sizeof( u_long ));
	if ( along == 0 ) {
		break;
	}
	++numaddrs;
	ipp += 4;
    }
#else /* NCSADOMAINFIX */
    numaddrs = 1;
#endif /* NCSADOMAINFIX */

    if (( addrs = (u_long *)malloc(( numaddrs + 1 ) * sizeof( u_long )))
		== NULL ) {
	return( NULL );
    }
    addrs[ numaddrs ] = 0;

    for ( i = 0, ipp = mr->hostip; i < numaddrs; ++i, ipp += 4 ) {
    	SAFEMEMCPY( (char *)&addrs[ i ], (char *)ipp, sizeof( u_long ));
    }

    return( addrs );
}

/*
 * Stand alone inet_addr derived from BSD 4.3 Networking Release 2 by MCS
 *
 *  Copyright (c) 1992 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  inet_addr.c
 */

/*
 * Copyright (c) 1983, 1990 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)inet_addr.c	5.10 (Berkeley) 2/24/91";
#endif /* LIBC_SCCS and not lint */

#define STANDALONE	1

#ifdef STANDALONE
#define	INADDR_NONE	0xffffffff		/* -1 return */
#define const
int inet_aton( char *cp, u_long *addr);

#else STANDALONE
#include <netinet/in.h>
#include <arpa/inet.h>
#endif STANDALONE

#include <ctype.h>

#ifndef isascii
#define isascii(c)	((unsigned)(c)<=0177)	/* for broken machines */
#endif isascii

/*
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 */
long
inet_addr(cp)
	register const char *cp;
{
#ifdef STANDALONE
	u_long val;
#else STANDALONE
	struct in_addr val;
#endif STANDALONE

	if (inet_aton(cp, &val))
#ifdef STANDALONE
		return (val);
#else STANDALONE
		return (val.s_addr);
#endif STANDALONE
	return (INADDR_NONE);
}

/* 
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */

inet_aton(cp, addr)
	register char *cp;
#ifdef STANDALONE
	u_long *addr;
#else STANDALONE
	struct in_addr *addr;
#endif STANDALONE
{
	register u_long val, base, n;
	register char c;
	u_long parts[4], *pp = parts;

	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, other=decimal.
		 */
		val = 0; base = 10;
		if (*cp == '0') {
			if (*++cp == 'x' || *cp == 'X')
				base = 16, cp++;
			else
				base = 8;
		}
		while ((c = *cp) != '\0') {
			if (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				cp++;
				continue;
			}
			if (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) + 
					(c + 10 - (islower(c) ? 'a' : 'A'));
				cp++;
				continue;
			}
			break;
		}
		if (*cp == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16-bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3 || val > 0xff)
				return (0);
			*pp++ = val, cp++;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (*cp && (!isascii(*cp) || !isspace(*cp)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if (val > 0xffffff)
			return (0);
		val |= parts[0] << 24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if (val > 0xffff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if (val > 0xff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		break;
	}
	if (addr)
#ifdef STANDALONE
		*addr = htonl(val);
#else STANDALONE
		addr->s_addr = htonl(val);
#endif STANDALONE
	return (1);
}

#endif /* PCNFS */
