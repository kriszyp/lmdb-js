/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

#if defined( HAVE_SYS_FILIO_H )
#include <sys/filio.h>
#elif defined( HAVE_SYS_IOCTL_H )
#include <sys/ioctl.h>
#endif

#include "ldap-int.h"

int
ldap_connect_to_host( Sockbuf *sb, const char *host, unsigned long address,
	int port, int async )
/*
 * if host == NULL, connect using address
 * "address" and "port" must be in network byte order
 * zero is returned upon success, -1 if fatal error, -2 EINPROGRESS
 * async is only used ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS (non-0 means don't wait for connect)
 * XXX async is not used yet!
 */
{
	int			rc, i;
	ber_socket_t s = AC_SOCKET_INVALID;
	int			connected, use_hp;
	struct sockaddr_in	sin;
	struct hostent		*hp = NULL;
#ifdef notyet
	ioctl_t			status;	/* for ioctl call */
#endif /* notyet */
   
   	/* buffers for ldap_pvt_gethostbyname_a */
   	struct hostent		he_buf;
   	int			local_h_errno;
   	char   			*ha_buf=NULL;
#define DO_RETURN(x) if (ha_buf) LDAP_FREE(ha_buf); return (x);
   
	Debug( LDAP_DEBUG_TRACE, "ldap_connect_to_host: %s:%d\n",
	    ( host == NULL ) ? "(by address)" : host, (int) ntohs( (short) port ), 0 );

	connected = use_hp = 0;

	if ( host != NULL ) {
	    address = inet_addr( host );
	    /* This was just a test for -1 until OSF1 let inet_addr return
	       unsigned int, which is narrower than 'unsigned long address' */
	    if ( address == 0xffffffff || address == (unsigned long) -1 ) {
		if ( ( ldap_pvt_gethostbyname_a( host, &he_buf, &ha_buf,
			&hp, &local_h_errno) < 0) || (hp==NULL))
		{
#ifdef HAVE_WINSOCK
			errno = WSAGetLastError();
#else
			errno = EHOSTUNREACH;	/* not exactly right, but... */
#endif
			DO_RETURN( -1 );
		}
		use_hp = 1;
	    }
	}

	rc = -1;
	for ( i = 0; !use_hp || ( hp->h_addr_list[ i ] != 0 ); i++ ) {
		if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
			DO_RETURN( -1 );
		}
#ifdef notyet
		status = 1;
		if ( async && ioctl( s, FIONBIO, (caddr_t)&status ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "FIONBIO ioctl failed on %d\n",
			    s, 0, 0 );
		}
#endif /* notyet */
		(void)memset( (char *)&sin, 0, sizeof( struct sockaddr_in ));
		sin.sin_family = AF_INET;
		sin.sin_port = port;
		SAFEMEMCPY( (char *) &sin.sin_addr.s_addr,
		    ( use_hp ? (char *) hp->h_addr_list[ i ] :
		    (char *) &address ), sizeof( sin.sin_addr.s_addr) );

		if ( connect( s, (struct sockaddr *)&sin,
		    sizeof( struct sockaddr_in )) >= 0 ) {
			connected = 1;
			rc = 0;
			break;
		} else {
#ifdef HAVE_WINSOCK
		        errno = WSAGetLastError();
#endif
#ifdef notyet
#ifdef EAGAIN
			if ( errno == EINPROGRESS || errno == EAGAIN ) {
#else /* EAGAIN */
			if ( errno == EINPROGRESS ) {
#endif /* EAGAIN */
				Debug( LDAP_DEBUG_TRACE,
					"connect would block...\n", 0, 0, 0 );
				rc = -2;
				break;
			}
#endif /* notyet */

#ifdef LDAP_DEBUG		
			if ( ldap_debug & LDAP_DEBUG_TRACE ) {
				perror( (char *)inet_ntoa( sin.sin_addr ));
			}
#endif
			tcp_close( s );
			if ( !use_hp ) {
				break;
			}
		}
	}

	ber_pvt_sb_set_desc( sb, s );		

	if ( connected ) {
	   
#ifdef notyet
		status = 0;
		if ( !async && ioctl( s, FIONBIO, (caddr_t)&on ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "FIONBIO ioctl failed on %d\n",
			    s, 0, 0 );
		}
#endif /* notyet */

		Debug( LDAP_DEBUG_TRACE, "sd %d connected to: %s\n",
		    s, (char *) inet_ntoa( sin.sin_addr ), 0 );
	}

	DO_RETURN( rc );
}
   
#undef DO_RETURN


void
ldap_close_connection( Sockbuf *sb )
{
	ber_pvt_sb_close( sb );
}


#if defined( HAVE_KERBEROS ) || defined( HAVE_TLS )
char *
ldap_host_connected_to( Sockbuf *sb )
{
	struct hostent		*hp;
	char			*p;
	int			len;
	struct sockaddr_in	sin;

   	/* buffers for gethostbyaddr_r */
   	struct hostent		he_buf;
        int			local_h_errno;
   	char			*ha_buf=NULL;
#define DO_RETURN(x) if (ha_buf) LDAP_FREE(ha_buf); return (x);
   
	(void)memset( (char *)&sin, 0, sizeof( struct sockaddr_in ));
	len = sizeof( sin );

	if ( getpeername( ber_pvt_sb_get_desc(sb), (struct sockaddr *)&sin, &len ) == -1 ) {
		return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */
	if ((ldap_pvt_gethostbyaddr_a( (char *) &sin.sin_addr,
		sizeof( sin.sin_addr ), 
		AF_INET, &he_buf, &ha_buf,
		&hp,&local_h_errno ) ==0 ) && (hp != NULL) )
	{
		if ( hp->h_name != NULL ) {
			char *host = LDAP_STRDUP( hp->h_name );   
			DO_RETURN( host );
		}
	}

	DO_RETURN( NULL );
}
#undef DO_RETURN   
   
#endif /* HAVE_KERBEROS || HAVE_TLS */


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

	sip = (struct selectinfo *)ld->ld_selectinfo;
	
	if ( !FD_ISSET( ber_pvt_sb_get_desc(sb), &sip->si_writefds )) {
		FD_SET( (u_int) sb->sb_sd, &sip->si_writefds );
	}
}


void
ldap_mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	if ( !FD_ISSET( ber_pvt_sb_get_desc(sb), &sip->si_readfds )) {
		FD_SET( (u_int) sb->sb_sd, &sip->si_readfds );
	}
}


void
ldap_mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	FD_CLR( (u_int) ber_pvt_sb_get_desc(sb), &sip->si_writefds );
	FD_CLR( (u_int) ber_pvt_sb_get_desc(sb), &sip->si_readfds );
}


int
ldap_is_write_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( ber_pvt_sb_get_desc(sb), &sip->si_use_writefds ));
}


int
ldap_is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( ber_pvt_sb_get_desc(sb), &sip->si_use_readfds ));
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


int
do_ldap_select( LDAP *ld, struct timeval *timeout )
{
	struct selectinfo	*sip;
	static int		tblsize;

	Debug( LDAP_DEBUG_TRACE, "do_ldap_select\n", 0, 0, 0 );

	if ( tblsize == 0 ) {
#if defined( HAVE_SYSCONF )
		tblsize = sysconf( _SC_OPEN_MAX );
#elif defined( HAVE_GETDTABLESIZE )
		tblsize = getdtablesize();
#else
		tblsize = FD_SETSIZE;
#endif /* !USE_SYSCONF */

#ifdef FD_SETSIZE
		if( tblsize > FD_SETSIZE ) {
			tblsize = FD_SETSIZE;
		}
#endif	/* FD_SETSIZE*/
	}

	sip = (struct selectinfo *)ld->ld_selectinfo;
	sip->si_use_readfds = sip->si_readfds;
	sip->si_use_writefds = sip->si_writefds;
	
	return( select( tblsize, &sip->si_use_readfds, &sip->si_use_writefds,
	    NULL, timeout ));
}
