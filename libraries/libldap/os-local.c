/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *  Copyright (c) 1999 PADL Software Pty Ltd.
 *  os-ip.c -- platform-specific domain socket code
 */


#include "portable.h"

#ifdef LDAP_PF_LOCAL

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

/* XXX non-portable */
#include <sys/stat.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif /* HAVE_IO_H */

#include "ldap-int.h"

/* int ldap_int_tblsize = 0; */

#define oslocal_debug(ld,fmt,arg1,arg2,arg3) \
do { \
	ldap_log_printf(ld, LDAP_DEBUG_TRACE, fmt, arg1, arg2, arg3); \
} while(0)

static void
ldap_pvt_set_errno(int err)
{
	errno = err;
}

static int
ldap_pvt_ndelay_on(LDAP *ld, int fd)
{
	oslocal_debug(ld, "ldap_ndelay_on: %d\n",fd,0,0);
	return ber_pvt_socket_set_nonblock( fd, 1 );
}
   
static int
ldap_pvt_ndelay_off(LDAP *ld, int fd)
{
	oslocal_debug(ld, "ldap_ndelay_off: %d\n",fd,0,0);
	return ber_pvt_socket_set_nonblock( fd, 0 );
}

static ber_socket_t
ldap_pvt_socket(LDAP *ld)
{
	ber_socket_t s = socket(AF_UNIX, SOCK_STREAM, 0);
	oslocal_debug(ld, "ldap_new_socket: %d\n",s,0,0);
	return ( s );
}

static int
ldap_pvt_close_socket(LDAP *ld, int s)
{
	oslocal_debug(ld, "ldap_close_socket: %d\n",s,0,0);
	return tcp_close(s);
}

#undef TRACE
#define TRACE do { \
	oslocal_debug(ld, \
		"ldap_is_socket_ready: errror on socket %d: errno: %d (%s)\n", \
		s, \
		errno, \
		strerror(errno) ); \
} while( 0 )

/*
 * check the socket for errors after select returned.
 */
static int
ldap_pvt_is_socket_ready(LDAP *ld, int s)
{
	oslocal_debug(ld, "ldap_is_sock_ready: %d\n",s,0,0);

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
	struct sockaddr_un sun;
	char ch;
	int dummy = sizeof(sun);
	if ( getpeername( s, (struct sockaddr *) &sun, &dummy ) == -1 ) {
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

static int
ldap_pvt_connect(LDAP *ld, ber_socket_t s, struct sockaddr_un *sun, int async)
{
	struct timeval	tv, *opt_tv=NULL;
	fd_set		wfds, *z=NULL;

	if ( (opt_tv = ld->ld_options.ldo_tm_net) != NULL ) {
		tv.tv_usec = opt_tv->tv_usec;
		tv.tv_sec = opt_tv->tv_sec;
	}

	oslocal_debug(ld, "ldap_connect_timeout: fd: %d tm: %ld async: %d\n",
			s, opt_tv ? tv.tv_sec : -1L, async);

	if ( ldap_pvt_ndelay_on(ld, s) == -1 )
		return ( -1 );

	if ( connect(s, (struct sockaddr *) sun, sizeof(struct sockaddr_un)) == 0 )
	{
		if ( ldap_pvt_ndelay_off(ld, s) == -1 )
			return ( -1 );
		return ( 0 );
	}

	if ( errno != EINPROGRESS && errno != EWOULDBLOCK ) {
		return ( -1 );
	}
	
#ifdef notyet
	if ( async ) return ( -2 );
#endif

	FD_ZERO(&wfds);
	FD_SET(s, &wfds );

	if ( select(ldap_int_tblsize, z, &wfds, z, opt_tv ? &tv : NULL) == -1)
		return ( -1 );

	if ( FD_ISSET(s, &wfds) ) {
		if ( ldap_pvt_is_socket_ready(ld, s) == -1 )
			return ( -1 );
		if ( ldap_pvt_ndelay_off(ld, s) == -1 )
			return ( -1 );
		return ( 0 );
	}
	oslocal_debug(ld, "ldap_connect_timeout: timed out\n",0,0,0);
	ldap_pvt_set_errno( ETIMEDOUT );
	return ( -1 );
}

int
ldap_connect_to_path(LDAP *ld, Sockbuf *sb, const char *path, int async)
{
	struct sockaddr_un	server;
	ber_socket_t		s = AC_SOCKET_INVALID;
	int			rc, i, len;
	char   			*ha_buf=NULL, *p, *q;

	oslocal_debug(ld, "ldap_connect_to_path\n",0,0,0);

	if ( (s = ldap_pvt_socket( ld )) == -1 ) {
		return -1;
	}

	if ( path == NULL || path[0] == '\0' ) {
		path = "/tmp/.ldap-sock";
	} else {
		if ( strlen(path) > (sizeof( server.sun_path ) - 1) ) {
			ldap_pvt_set_errno( ENAMETOOLONG );
			return -1;
		}
	}

	oslocal_debug(ld, "ldap_connect_to_path: Trying %s\n", path, 0, 0);

	memset( &server, 0, sizeof(server) );
	server.sun_family = AF_UNIX;
	strcpy( server.sun_path, path );

	rc = ldap_pvt_connect(ld, s, &server, async);

	if (rc == 0) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_FD, (void *)&s );
	} else {
		ldap_pvt_close_socket(ld, s);
	}
	return rc;
}
#else
static int dummy;
#endif /* LDAP_PF_LOCAL */
