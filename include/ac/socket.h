/*
 * Generic socket.h
 */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_SOCKET_H_
#define _AC_SOCKET_H_

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <netinet/in.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif

#include <netdb.h>

#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif

#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_WINSOCK2
#include <winsock2.h>
#elif HAVE_WINSOCK
#include <winsock.h>
#else
#define WSACleanup()
#endif

#ifdef HAVE_PCNFS
#include <tklib.h>
#endif /* HAVE_PCNFS */

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	((unsigned long) 0x7f000001)
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN  64
#endif

#ifdef MACOS
#define tcp_close( s )		tcpclose( s )
#else /* MACOS */
#ifdef DOS
#ifdef PCNFS
#define tcp_close( s )		close( s )
#endif /* PCNFS */
#ifdef NCSA
#define tcp_close( s )		netclose( s ); netshut()
#endif /* NCSA */
#ifdef WINSOCK
#define tcp_close( s )		closesocket( s );
#endif /* WINSOCK */
#else /* DOS */
#define tcp_close( s )		close( s )
#endif /* DOS */
#endif /* MACOS */

#if !defined(__alpha) || defined(VMS)
#define AC_HTONL( l ) htonl( l )
#define AC_NTOHL( l ) ntohl( l )
#else /* __alpha && !VMS */
/*
 * htonl and ntohl on the DEC Alpha under OSF 1 seem to only swap the
 * lower-order 32-bits of a (64-bit) long, so we define correct versions
 * here.
 */ 
#define AC_HTONL( l )	(((long)htonl( (l) & 0x00000000FFFFFFFF )) << 32 \
	| htonl( ( (l) & 0xFFFFFFFF00000000 ) >> 32 ))

#define AC_NTOHL( l ) (((long)ntohl( (l) & 0x00000000FFFFFFFF )) << 32 \
	| ntohl( ( (l) & 0xFFFFFFFF00000000 ) >> 32 ))

#endif /* __alpha && !VMS */

#endif /* _AC_SOCKET_H_ */
