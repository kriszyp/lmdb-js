/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  os-ip.c -- platform-specific TCP & UDP related code
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

/*
 * nonblock connect code
 * written by Lars Uffmann, <lars.uffmann@mediaway.net>.
 *
 * Copyright 1999, Lars Uffmann, All rights reserved.
 * This software is not subject to any license of my employer
 * mediaWays GmbH.
 *
 * OpenLDAP COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * Read about the rationale in ldap_connect_timeout: 
 * ftp://koobera.math.uic.edu/www/docs/connect.html.
 */

#define osip_debug(ld,fmt,arg1,arg2,arg3) \
do { \
	ldap_log_printf(NULL, LDAP_DEBUG_TRACE, fmt, arg1, arg2, arg3); \
} while(0)

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
	int dummy = sizeof(so_errno);
	if ( getsockopt( s, SOL_SOCKET, SO_ERROR, &so_errno, &dummy ) == -1 ) {
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
	struct sockaddr_in sin;
	char ch;
	int dummy = sizeof(sin);
	if ( getpeername( s, (struct sockaddr *) &sin, &dummy ) == -1 ) {
		/* XXX: needs to be replace with ber_stream_read() */
		read(s, &ch, 1);
#ifdef HAVE_WINSOCK
		ldap_pvt_set_errno( WSAGetLastError() );
#endif
		TRACE;
		return -1;
	}
	return 0;
}
#endif
	return -1;
}
#undef TRACE

static int
ldap_pvt_connect(LDAP *ld, ber_socket_t s,
	struct sockaddr *sin, socklen_t addrlen,
	int async)
{
	struct timeval	tv, *opt_tv=NULL;
	fd_set		wfds, *z=NULL;
#ifdef HAVE_WINSOCK
	fd_set		efds;
#endif

	if ( (opt_tv = ld->ld_options.ldo_tm_net) != NULL ) {
		tv.tv_usec = opt_tv->tv_usec;
		tv.tv_sec = opt_tv->tv_sec;
	}

	osip_debug(ld, "ldap_connect_timeout: fd: %d tm: %ld async: %d\n",
			s, opt_tv ? tv.tv_sec : -1L, async);

	if ( ldap_pvt_ndelay_on(ld, s) == -1 )
		return ( -1 );

	if ( connect(s, sin, addrlen) == 0 )
	{
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

	if ( select(ldap_int_tblsize, z, &wfds,
#ifdef HAVE_WINSOCK
		    &efds,
#else
		    z,
#endif
		    opt_tv ? &tv : NULL) == -1)
		return ( -1 );

#ifdef HAVE_WINSOCK
	/* This means the connection failed */
	if (FD_ISSET(s, &efds))
	{
	    ldap_pvt_set_errno(WSAECONNREFUSED);
	    osip_debug(ld, "ldap_pvt_connect: error on socket %d: "
		       "errno: %d (%s)\n", s, errno, sock_errstr(errno));
	    return -1;
	}
#endif
	if ( FD_ISSET(s, &wfds) ) {
		if ( ldap_pvt_is_socket_ready(ld, s) == -1 )
			return ( -1 );
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
	const char *host,
	unsigned long address, int port, int async)
{
	struct sockaddr_in	sin;
	ber_socket_t		s = AC_SOCKET_INVALID;
	int			rc, i, use_hp = 0;
	struct hostent		*hp = NULL;
	char   			*ha_buf=NULL, *p, *q;

	osip_debug(ld, "ldap_connect_to_host\n",0,0,0);
	
	if (host != NULL) {
#ifdef HAVE_GETADDRINFO
		char serv[7];
		struct addrinfo hints, *res, *sai;

		memset( &hints, '\0', sizeof(hints) );
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		snprintf(serv, sizeof serv, "%d", ntohs(port));
		if ( getaddrinfo(host, serv, &hints, &res) ) {
			osip_debug(ld, "ldap_connect_to_host:getaddrinfo failed\n",0,0,0);
			return -1;
		}
		sai = res;
		rc = -1;
		do {
			/* we assume AF_x and PF_x are equal for all x */
			s = ldap_int_socket( ld, sai->ai_family, SOCK_STREAM );
			if ( s == -1 ) {
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

			rc = ldap_pvt_connect(ld, s, sai->ai_addr, sai->ai_addrlen, async);
			if ( (rc == 0) || (rc == -2) ) {
				ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_FD, &s );
				break;
			}
			ldap_pvt_close_socket(ld, s);
		} while ((sai = sai->ai_next) != NULL);
		freeaddrinfo(res);
		return rc;
#else
		struct in_addr in;
		if (! inet_aton( host, &in) ) {
			int local_h_errno;
			struct hostent he_buf;
			rc = ldap_pvt_gethostbyname_a(host, &he_buf, &ha_buf,
					&hp, &local_h_errno);

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
		address = in.s_addr;
#endif
	}

	rc = s = -1;
	for ( i = 0; !use_hp || (hp->h_addr_list[i] != 0); ++i, rc = -1 ) {

		s = ldap_int_socket( ld, PF_INET, SOCK_STREAM );
		if ( s == -1 ) {
			/* use_hp ? continue : break; */
			break;
		}
	   
		if ( ldap_int_prepare_socket( ld, s, proto ) == -1 ) {
			ldap_pvt_close_socket(ld, s);
			break;
		}

		(void)memset((char *)&sin, '\0', sizeof(struct sockaddr_in));
		sin.sin_family = AF_INET;
		sin.sin_port = port;
		p = (char *)&sin.sin_addr;
		q = use_hp ? (char *)hp->h_addr_list[i] : (char *)&address;
		AC_MEMCPY(p, q, sizeof(sin.sin_addr) );

		osip_debug(ld, "ldap_connect_to_host: Trying %s:%d\n", 
				inet_ntoa(sin.sin_addr),ntohs(sin.sin_port),0);

		rc = ldap_pvt_connect(ld, s,
			(struct sockaddr *)&sin, sizeof(struct sockaddr_in),
			async);
   
		if ( (rc == 0) || (rc == -2) ) {
			ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_FD, &s );
			break;
		}

		ldap_pvt_close_socket(ld, s);

		if (!use_hp)
			break;
	}
	if (ha_buf) LDAP_FREE(ha_buf);
	return rc;
}

#if defined( LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND ) \
	|| defined( HAVE_TLS ) || defined( HAVE_CYRUS_SASL )
char *
ldap_host_connected_to( Sockbuf *sb )
{
	struct hostent	*hp;
	socklen_t		len;
	struct sockaddr	sa;
	char			*addr;
	char			*host;

   	/* buffers for gethostbyaddr_r */
   	struct hostent	he_buf;
	int				local_h_errno;
   	char			*ha_buf=NULL;
	ber_socket_t	sd;

	(void)memset( (char *)&sa, '\0', sizeof( struct sockaddr ));
	len = sizeof( sa );

	ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_FD, &sd );
	if ( getpeername( sd, &sa, &len ) == -1 ) {
		return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */

	switch (sa.sa_family) {
#ifdef LDAP_PF_LOCAL
	case AF_LOCAL:
		return LDAP_STRDUP( ldap_int_hostname );
#endif
#ifdef LDAP_PF_INET6
	case AF_INET6:
		addr = (char *) &((struct sockaddr_in6 *)&sa)->sin6_addr;
		len = sizeof( struct in6_addr );
		break;
#endif
	case AF_INET:
		addr = (char *) &((struct sockaddr_in *)&sa)->sin_addr;
		len = sizeof( struct in_addr );

		{
			struct sockaddr_in localhost;
			localhost.sin_addr.s_addr = htonl( INADDR_ANY );

			if( memcmp ( &localhost.sin_addr,
				&((struct sockaddr_in *)&sa)->sin_addr,
				sizeof(localhost.sin_addr) ) == 0 )
			{
				return LDAP_STRDUP( ldap_int_hostname );
			}

#ifdef INADDR_LOOPBACK
			localhost.sin_addr.s_addr = htonl( INADDR_LOOPBACK );

			if( memcmp ( &localhost.sin_addr,
				&((struct sockaddr_in *)&sa)->sin_addr,
				sizeof(localhost.sin_addr) ) == 0 )
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

	host = NULL;
	if ((ldap_pvt_gethostbyaddr_a( addr, len,
		sa.sa_family, &he_buf, &ha_buf,
		&hp,&local_h_errno ) == 0 ) &&
		(hp != NULL) && ( hp->h_name != NULL ) )
	{
		host = LDAP_STRDUP( hp->h_name );   
	}

	LDAP_FREE( ha_buf );
	return host;
}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND || HAVE_TLS */


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
do_ldap_select( LDAP *ld, struct timeval *timeout )
{
	struct selectinfo	*sip;

	Debug( LDAP_DEBUG_TRACE, "do_ldap_select\n", 0, 0, 0 );

	if ( ldap_int_tblsize == 0 )
		ldap_int_ip_init();

	sip = (struct selectinfo *)ld->ld_selectinfo;
	sip->si_use_readfds = sip->si_readfds;
	sip->si_use_writefds = sip->si_writefds;
	
	return( select( ldap_int_tblsize,
	                &sip->si_use_readfds, &sip->si_use_writefds,
	                NULL, timeout ));
}
