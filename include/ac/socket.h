/*
 * Generic socket.h
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
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#endif

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

#ifndef BYTE_ORDER
/*    
 * Definitions for byte order, according to byte significance from low
 * address to high.
 */
#define LITTLE_ENDIAN   1234	/* LSB first: i386, vax */
#define BIG_ENDIAN  4321		/* MSB first: 68000, ibm, net */
#define PDP_ENDIAN  3412		/* LSB first in word, MSW first in long */

/* assume autoconf's AC_C_BIGENDIAN has been run */
/* if it hasn't, we assume (maybe falsely) the order is LITTLE ENDIAN */
#ifdef WORDS_BIGENDIAN
#define BYTE_ORDER  BIG_ENDIAN
#else
#define BYTE_ORDER  LITTLE_ENDIAN
#endif

#endif /* BYTE_ORDER */

#endif /* _AC_SOCKET_H_ */
