/* os-ip.c -- platform-specific TCP & UDP related code */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * Portions Copyright 1999 Lars Uffmann.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 */
/* Significant additional contributors include:
 *    Lars Uffman
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif /* HAVE_IO_H */

#include "ldap-int.h"

int ldap_int_tblsize = 0;

#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
#  ifdef LDAP_PF_INET6
int ldap_int_inet4or6 = AF_UNSPEC;
#  else
int ldap_int_inet4or6 = AF_INET;
#  endif
#endif

#ifdef LDAP_DEBUG

#define osip_debug(ld,fmt,arg1,arg2,arg3) \
do { \
	ldap_log_printf(NULL, LDAP_DEBUG_TRACE, fmt, arg1, arg2, arg3); \
} while(0)

#else

#define osip_debug(ld,fmt,arg1,arg2,arg3) ((void)0)

#endif /* LDAP_DEBUG */

static void
ldap_pvt_set_errno(int err)
{
	errno = err;
}

int
ldap_int_timeval_dup( struct timeval **dest, const struct timeval *src )
{
	struct timeval *new;

	assert( dest != NULL );

	if (src == NULL) {
		*dest = NULL;
		return 0;
	}

	new = (struct timeval *) LDAP_MALLOC(sizeof(struct timeval));

	if( new == NULL ) {
		*dest = NULL;
		return 1;
	}

	AC_MEMCPY( (char *) new, (const char *) src, sizeof(struct timeval));

	*dest = new;
	return 0;
}

static int
ldap_pvt_ndelay_on(LDAP *ld, int fd)
{
	osip_debug(ld, "ldap_ndelay_on: %d\n",fd,0,0);
	return ber_pvt_socket_set_nonblock( fd, 1 );
}
   
static int
ldap_pvt_ndelay_off(LDAP *ld, int fd)
{
	osip_debug(ld, "ldap_ndelay_off: %d\n",fd,0,0);
	return ber_pvt_socket_set_nonblock( fd, 0 );
}

static ber_socket_t
ldap_int_socket(LDAP *ld, int family, int type )
{
	ber_socket_t s = socket(family, type, 0);
	osip_debug(ld, "ldap_new_socket: %d\n",s,0,0);
	return ( s );
}

static int
ldap_pvt_close_socket(LDAP *ld, int s)
{
	osip_debug(ld, "ldap_close_socket: %d\n",s,0,0);
	return tcp_close(s);
}

static int
ldap_int_prepare_socket(LDAP *ld, int s, int proto )
{
	osip_debug(ld, "ldap_prepare_socket: %d\n", s,0,0);

#ifdef TCP_NODELAY
	if( proto == LDAP_PROTO_TCP ) {
		int dummy = 1;
		if ( setsockopt( s, IPPROTO_TCP, TCP_NODELAY,
			(char*) &dummy, sizeof(dummy) ) == AC_SOCKET_ERROR )
		{
			osip_debug(ld, "ldap_prepare_socket: "
				"setsockopt(%d, TCP_NODELAY) failed (ignored).\n",
				s, 0, 0);
		}
	}
#endif

	return 0;
}

#ifndef HAVE_WINSOCK

#undef TRACE
#define TRACE do { \
	osip_debug(ld, \
		"ldap_is_socket_ready: error on socket %d: errno: %d (%s)\n", \
		s, \
		errno, \
		sock_errstr(errno) ); \
} while( 0 )

/*
 * check the socket for errors after select returned.
 */
static int
ldap_pvt_is_socket_ready(LDAP *ld, int s)
{
	osip_debug(ld, "ldap_is_sock_ready: %d\n",s,0,0);

#if defined( notyet ) /* && defined( SO_ERROR ) */
{
	int so_errno;
	socklen_t dummy = sizeof(so_errno);
	if ( getsockopt( s, SOL_SOCKET, SO_ERROR, &so_errno, &dummy )
		== AC_SOCKET_ERROR )
	{
		return -1;
	}
	if ( so_errno ) {
		ldap_pvt_set_errno(so_errno);
		TRACE;
		return -1;
	}
	return 0;
}
#else
{
	/* error slippery */
#ifdef LDAP_PF_INET6
	struct sockaddr_storage sin;
#else
	struct sockaddr_in sin;
#endif
	char ch;
	socklen_t dummy = sizeof(sin);
	if ( getpeername( s, (struct sockaddr *) &sin, &dummy )
		== AC_SOCKET_ERROR )
	{
		/* XXX: needs to be replace with ber_stream_read() */
		read(s, &ch, 1);
		TRACE;
		return -1;
	}
	return 0;
}
#endif
	return -1;
}
#undef TRACE

#endif /* HAVE_WINSOCK */

static int
ldap_pvt_connect(LDAP *ld, ber_socket_t s,
	struct sockaddr *sin, socklen_t addrlen,
	int async)
{
	int rc;
	struct timeval	tv, *opt_tv=NULL;
	fd_set		wfds, *z=NULL;
#ifdef HAVE_WINSOCK
	fd_set		efds;
#endif

#ifdef LDAP_CONNECTIONLESS
	/* We could do a connect() but that would interfere with
	 * attempts to poll a broadcast address
	 */
	if (LDAP_IS_UDP(ld)) {
		if (ld->ld_options.ldo_peer)
			ldap_memfree(ld->ld_options.ldo_peer);
		ld->ld_options.ldo_peer=ldap_memalloc(sizeof(struct sockaddr));
		AC_MEMCPY(ld->ld_options.ldo_peer,sin,sizeof(struct sockaddr));
		return ( 0 );
	}
#endif
	if ( (opt_tv = ld->ld_options.ldo_tm_net) != NULL ) {
		tv.tv_usec = opt_tv->tv_usec;
		tv.tv_sec = opt_tv->tv_sec;
	}

	osip_debug(ld, "ldap_connect_timeout: fd: %d tm: %ld async: %d\n",
			s, opt_tv ? tv.tv_sec : -1L, async);

	if ( ldap_pvt_ndelay_on(ld, s) == -1 )
		return ( -1 );

	if ( connect(s, sin, addrlen) != AC_SOCKET_ERROR ) {
		if ( ldap_pvt_ndelay_off(ld, s) == -1 )
			return ( -1 );
		return ( 0 );
	}

#ifdef HAVE_WINSOCK
	ldap_pvt_set_errno( WSAGetLastError() );
#endif

	if ( errno != EINPROGRESS && errno != EWOULDBLOCK ) {
		return ( -1 );
	}
	
#ifdef notyet
	if ( async ) return ( -2 );
#endif

	FD_ZERO(&wfds);
	FD_SET(s, &wfds );

#ifdef HAVE_WINSOCK
	FD_ZERO(&efds);
	FD_SET(s, &efds );
#endif

	do {
		rc = select(ldap_int_tblsize, z, &wfds,
#ifdef HAVE_WINSOCK
			&efds,
#else
			z,
#endif
			opt_tv ? &tv : NULL);
	} while( rc == AC_SOCKET_ERROR && errno == EINTR &&
		LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_RESTART ));

	if( rc == AC_SOCKET_ERROR ) return rc;

#ifdef HAVE_WINSOCK
	/* This means the connection failed */
	if ( FD_ISSET(s, &efds) ) {
	    int so_errno;
	    int dummy = sizeof(so_errno);
	    if ( getsockopt( s, SOL_SOCKET, SO_ERROR,
			(char *) &so_errno, &dummy ) == AC_SOCKET_ERROR || !so_errno )
	    {
	    	/* impossible */
	    	so_errno = WSAGetLastError();
	    }
	    ldap_pvt_set_errno(so_errno);
	    osip_debug(ld, "ldap_pvt_connect: error on socket %d: "
		       "errno: %d (%s)\n", s, errno, sock_errstr(errno));
	    return -1;
	}
#endif
	if ( FD_ISSET(s, &wfds) ) {
#ifndef HAVE_WINSOCK
		if ( ldap_pvt_is_socket_ready(ld, s) == -1 )
			return ( -1 );
#endif
		if ( ldap_pvt_ndelay_off(ld, s) == -1 )
			return ( -1 );
		return ( 0 );
	}
	osip_debug(ld, "ldap_connect_timeout: timed out\n",0,0,0);
	ldap_pvt_set_errno( ETIMEDOUT );
	return ( -1 );
}

#ifndef HAVE_INET_ATON
int
ldap_pvt_inet_aton( const char *host, struct in_addr *in)
{
	unsigned long u = inet_addr( host );
	if ( u != 0xffffffff || u != (unsigned long) -1 ) {
		in->s_addr = u;
		return 1;
	}
	return 0;
}
#endif


int
ldap_connect_to_host(LDAP *ld, Sockbuf *sb,
	int proto,
	const char *host, int port,
	int async )
{
	int	rc;
	int	socktype;
	ber_socket_t		s = AC_SOCKET_INVALID;

#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
	char serv[7];
	int err;
	struct addrinfo hints, *res, *sai;
#else
	int i;
	int use_hp = 0;
	struct hostent *hp = NULL;
	struct hostent he_buf;
	struct in_addr in;
	char *ha_buf=NULL;
#endif

	if( host == NULL ) host = "localhost";
	
	switch(proto) {
	case LDAP_PROTO_TCP: socktype = SOCK_STREAM;
		osip_debug( ld,
			"ldap_connect_to_host: TCP %s:%d\n",
			host, port, 0);
		break;
	case LDAP_PROTO_UDP: socktype = SOCK_DGRAM;
		osip_debug( ld,
			"ldap_connect_to_host: UDP %s:%d\n",
			host, port, 0);
		break;
	default:
		osip_debug( ld, "ldap_connect_to_host: unknown proto: %d\n",
			proto, 0, 0 );
		return -1;
	}

#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
	memset( &hints, '\0', sizeof(hints) );
#ifdef AI_ADDRCONFIG
	hints.ai_flags = AI_ADDRCONFIG;
#endif	
	hints.ai_family = ldap_int_inet4or6;
	hints.ai_socktype = socktype;
	snprintf(serv, sizeof serv, "%d", port );

#ifdef LDAP_R_COMPILE
	/* most getaddrinfo(3) use non-threadsafe resolver libraries */
	ldap_pvt_thread_mutex_lock(&ldap_int_resolv_mutex);
#endif

	err = getaddrinfo( host, serv, &hints, &res );

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock(&ldap_int_resolv_mutex);
#endif

	if ( err != 0 ) {
		osip_debug(ld, "ldap_connect_to_host: getaddrinfo failed: %s\n",
			AC_GAI_STRERROR(err), 0, 0);
		return -1;
	}
	rc = -1;

	for( sai=res; sai != NULL; sai=sai->ai_next) {
		if( sai->ai_addr == NULL ) {
			osip_debug(ld, "ldap_connect_to_host: getaddrinfo "
				"ai_addr is NULL?\n", 0, 0, 0);
			continue;
		}

		/* we assume AF_x and PF_x are equal for all x */
		s = ldap_int_socket( ld, sai->ai_family, socktype );
		if ( s == AC_SOCKET_INVALID ) {
			continue;
		}

		if ( ldap_int_prepare_socket(ld, s, proto ) == -1 ) {
			ldap_pvt_close_socket(ld, s);
			break;
		}

		switch (sai->ai_family) {
#ifdef LDAP_PF_INET6
			case AF_INET6: {
				char addr[INET6_ADDRSTRLEN];
				inet_ntop( AF_INET6,
					&((struct sockaddr_in6 *)sai->ai_addr)->sin6_addr,
					addr, sizeof addr);
				osip_debug(ld, "ldap_connect_to_host: Trying %s %s\n", 
					addr, serv, 0);
			} break;
#endif
			case AF_INET: {
				char addr[INET_ADDRSTRLEN];
				inet_ntop( AF_INET,
					&((struct sockaddr_in *)sai->ai_addr)->sin_addr,
					addr, sizeof addr);
				osip_debug(ld, "ldap_connect_to_host: Trying %s:%s\n", 
					addr, serv, 0);
			} break;
		}

		rc = ldap_pvt_connect( ld, s,
			sai->ai_addr, sai->ai_addrlen, async );
		if ( (rc == 0) || (rc == -2) ) {
			ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_FD, &s );
			break;
		}
		ldap_pvt_close_socket(ld, s);
	}
	freeaddrinfo(res);

#else
	if (! inet_aton( host, &in ) ) {
		int local_h_errno;
		rc = ldap_pvt_gethostbyname_a( host, &he_buf, &ha_buf,
			&hp, &local_h_errno );

		if ( (rc < 0) || (hp == NULL) ) {
#ifdef HAVE_WINSOCK
			ldap_pvt_set_errno( WSAGetLastError() );
#else
			/* not exactly right, but... */
			ldap_pvt_set_errno( EHOSTUNREACH );
#endif
			if (ha_buf) LDAP_FREE(ha_buf);
			return -1;
		}

		use_hp = 1;
	}

	rc = s = -1;
	for ( i = 0; !use_hp || (hp->h_addr_list[i] != 0); ++i, rc = -1 ) {
		struct sockaddr_in	sin;

		s = ldap_int_socket( ld, PF_INET, socktype );
		if ( s == AC_SOCKET_INVALID ) {
			/* use_hp ? continue : break; */
			break;
		}
	   
		if ( ldap_int_prepare_socket( ld, s, proto ) == -1 ) {
			ldap_pvt_close_socket(ld, s);
			break;
		}

		(void)memset((char *)&sin, '\0', sizeof sin);
		sin.sin_family = AF_INET;
		sin.sin_port = htons((short) port);

		if( use_hp ) {
			AC_MEMCPY( &sin.sin_addr, hp->h_addr_list[i],
				sizeof(sin.sin_addr) );
		} else {
			AC_MEMCPY( &sin.sin_addr, &in.s_addr,
				sizeof(sin.sin_addr) );
		}

		osip_debug(ld, "ldap_connect_to_host: Trying %s:%d\n", 
			inet_ntoa(sin.sin_addr), port, 0);

		rc = ldap_pvt_connect(ld, s,
			(struct sockaddr *)&sin, sizeof(sin),
			async);
   
		if ( (rc == 0) || (rc == -2) ) {
			ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_FD, &s );
			break;
		}

		ldap_pvt_close_socket(ld, s);

		if (!use_hp) break;
	}
	if (ha_buf) LDAP_FREE(ha_buf);
#endif

	return rc;
}

#if defined( LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND ) || \
	defined( HAVE_CYRUS_SASL )
char *
ldap_host_connected_to( Sockbuf *sb, const char *host )
{
	socklen_t		len;
#ifdef LDAP_PF_INET6
	struct sockaddr_storage sabuf;
#else
	struct sockaddr sabuf;
#endif
	struct sockaddr	*sa = (struct sockaddr *) &sabuf;
	int rc;
	ber_socket_t	sd;

	(void)memset( (char *)sa, '\0', sizeof sabuf );
	len = sizeof sabuf;

	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	if ( getpeername( sd, sa, &len ) == -1 ) {
		return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */

	switch (sa->sa_family) {
#ifdef LDAP_PF_LOCAL
	case AF_LOCAL:
		return LDAP_STRDUP( ldap_int_hostname );
#endif
#ifdef LDAP_PF_INET6
	case AF_INET6:
		{
			struct in6_addr localhost = IN6ADDR_LOOPBACK_INIT;
			if( memcmp ( &((struct sockaddr_in6 *)sa)->sin6_addr,
				&localhost, sizeof(localhost)) == 0 )
			{
				return LDAP_STRDUP( ldap_int_hostname );
			}
		}
		break;
#endif
	case AF_INET:
		{
			struct in_addr localhost;
			localhost.s_addr = htonl( INADDR_ANY );

			if( memcmp ( &((struct sockaddr_in *)sa)->sin_addr,
				&localhost, sizeof(localhost) ) == 0 )
			{
				return LDAP_STRDUP( ldap_int_hostname );
			}

#ifdef INADDR_LOOPBACK
			localhost.s_addr = htonl( INADDR_LOOPBACK );

			if( memcmp ( &((struct sockaddr_in *)sa)->sin_addr,
				&localhost, sizeof(localhost) ) == 0 )
			{
				return LDAP_STRDUP( ldap_int_hostname );
			}
#endif
		}
		break;

	default:
		return( NULL );
		break;
	}

#if 0
	{
		char *herr;
		char hbuf[NI_MAXHOST];
		hbuf[0] = 0;

		if (ldap_pvt_get_hname( sa, len, hbuf, sizeof(hbuf), &herr ) == 0
			&& hbuf[0] ) 
		{
			return LDAP_STRDUP( hbuf );   
		}
	}
#endif

	return host ? LDAP_STRDUP( host ) : NULL;
}
#endif


/* for UNIX */
struct selectinfo {
	fd_set	si_readfds;
	fd_set	si_writefds;
	fd_set	si_use_readfds;
	fd_set	si_use_writefds;
};


void
ldap_mark_select_write( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	ber_socket_t		sd;

	sip = (struct selectinfo *)ld->ld_selectinfo;
	
	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	if ( !FD_ISSET( sd, &sip->si_writefds )) {
		FD_SET( sd, &sip->si_writefds );
	}
}


void
ldap_mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	ber_socket_t		sd;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	if ( !FD_ISSET( sd, &sip->si_readfds )) {
		FD_SET( sd, &sip->si_readfds );
	}
}


void
ldap_mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	ber_socket_t		sd;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	FD_CLR( sd, &sip->si_writefds );
	FD_CLR( sd, &sip->si_readfds );
}


int
ldap_is_write_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	ber_socket_t		sd;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	return( FD_ISSET( sd, &sip->si_use_writefds ));
}


int
ldap_is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	ber_socket_t		sd;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	return( FD_ISSET( sd, &sip->si_use_readfds ));
}


void *
ldap_new_select_info( void )
{
	struct selectinfo	*sip;

	if (( sip = (struct selectinfo *)LDAP_CALLOC( 1,
	    sizeof( struct selectinfo ))) != NULL ) {
		FD_ZERO( &sip->si_readfds );
		FD_ZERO( &sip->si_writefds );
	}

	return( (void *)sip );
}


void
ldap_free_select_info( void *sip )
{
	LDAP_FREE( sip );
}


void
ldap_int_ip_init( void )
{
	int tblsize;
#if defined( HAVE_SYSCONF )
	tblsize = sysconf( _SC_OPEN_MAX );
#elif defined( HAVE_GETDTABLESIZE )
	tblsize = getdtablesize();
#else
	tblsize = FD_SETSIZE;
#endif /* !USE_SYSCONF */

#ifdef FD_SETSIZE
	if( tblsize > FD_SETSIZE )
		tblsize = FD_SETSIZE;
#endif	/* FD_SETSIZE*/
	ldap_int_tblsize = tblsize;
}


int
ldap_int_select( LDAP *ld, struct timeval *timeout )
{
	struct selectinfo	*sip;

#ifdef NEW_LOGGING
	LDAP_LOG ( CONNECTION, ENTRY, "ldap_int_select\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_int_select\n", 0, 0, 0 );
#endif

	if ( ldap_int_tblsize == 0 )
		ldap_int_ip_init();

	sip = (struct selectinfo *)ld->ld_selectinfo;
	sip->si_use_readfds = sip->si_readfds;
	sip->si_use_writefds = sip->si_writefds;
	
	return( select( ldap_int_tblsize,
	                &sip->si_use_readfds, &sip->si_use_writefds,
	                NULL, timeout ));
}
