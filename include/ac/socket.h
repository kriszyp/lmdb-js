/*
 * Generic socket.h
 */

#ifndef _AC_SOCKET_H_
#define _AC_SOCKET_H_

#ifdef HAVE_SYS_SOCKET_H
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#endif

#ifdef HAVE_WINSOCK2
#include <sys/types.h>
#include <winsock2.h>
#endif

#ifdef HAVE_WINSOCK
#include <winsock.h>
#endif

#ifdef HAVE_PCNFS
#include <tklib.h>
#endif /* HAVE_PCNFS */

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	((unsigned long) 0x7f000001)
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
#define tcp_close( s )		closesocket( s ); WSACleanup();
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
