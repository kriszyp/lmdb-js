/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  os-ip.c -- platform-specific TCP & UDP related code
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

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
ldap_connect_to_host( Sockbuf *sb, char *host, unsigned long address,
	int port, int async )
/*
 * if host == NULL, connect using address
 * "address" and "port" must be in network byte order
 * zero is returned upon success, -1 if fatal error, -2 EINPROGRESS
 * async is only used ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS (non-0 means don't wait for connect)
 * XXX async is not used yet!
 */
{
	int			rc, i, s = 0;
	int			connected, use_hp;
	struct sockaddr_in	sin;
	struct hostent		*hp = NULL;
#ifdef notyet
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	int			status;	/* for ioctl call */
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
#endif /* notyet */

	Debug( LDAP_DEBUG_TRACE, "ldap_connect_to_host: %s:%d\n",
	    ( host == NULL ) ? "(by address)" : host, (int) ntohs( (short) port ), 0 );

	connected = use_hp = 0;

	if ( host != NULL ) {
	    address = inet_addr( host );
	    /* This was just a test for -1 until OSF1 let inet_addr return
	       unsigned int, which is narrower than 'unsigned long address' */
	    if ( address == 0xffffffff || address == (unsigned long) -1 ) {
		if ( (hp = gethostbyname( host )) == NULL ) {
#ifdef HAVE_WINSOCK
			errno = WSAGetLastError();
#else
			errno = EHOSTUNREACH;	/* not exactly right, but... */
#endif
			return( -1 );
		}
		use_hp = 1;
	    }
	}

	rc = -1;
	for ( i = 0; !use_hp || ( hp->h_addr_list[ i ] != 0 ); i++ ) {
		if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
			return( -1 );
		}
#ifdef notyet
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
		status = 1;
		if ( async && ioctl( s, FIONBIO, (caddr_t)&status ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "FIONBIO ioctl failed on %d\n",
			    s, 0, 0 );
		}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
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
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
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
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
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

	sb->sb_sd = s;

	if ( connected ) {
#ifdef notyet
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
		status = 0;
		if ( !async && ioctl( s, FIONBIO, (caddr_t)&on ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "FIONBIO ioctl failed on %d\n",
			    s, 0, 0 );
		}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
#endif /* notyet */

		Debug( LDAP_DEBUG_TRACE, "sd %d connected to: %s\n",
		    s, (char *) inet_ntoa( sin.sin_addr ), 0 );
	}

	return( rc );
}


void
ldap_close_connection( Sockbuf *sb )
{
    tcp_close( sb->sb_sd );
}


#ifdef HAVE_KERBEROS
char *
ldap_host_connected_to( Sockbuf *sb )
{
	struct hostent		*hp;
	char			*p;
	int			len;
	struct sockaddr_in	sin;

	(void)memset( (char *)&sin, 0, sizeof( struct sockaddr_in ));
	len = sizeof( sin );
	if ( getpeername( sb->sb_sd, (struct sockaddr *)&sin, &len ) == -1 ) {
		return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */
	if (( hp = gethostbyaddr( (char *) &sin.sin_addr,
	    sizeof( sin.sin_addr ), AF_INET )) != NULL ) {
		if ( hp->h_name != NULL ) {
			return( strdup( hp->h_name ));
		}
	}

	return( NULL );
}
#endif /* HAVE_KERBEROS */


#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
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

	if ( !FD_ISSET( sb->sb_sd, &sip->si_writefds )) {
		FD_SET( (u_int) sb->sb_sd, &sip->si_writefds );
	}
}


void
ldap_mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	if ( !FD_ISSET( sb->sb_sd, &sip->si_readfds )) {
		FD_SET( (u_int) sb->sb_sd, &sip->si_readfds );
	}
}


void
ldap_mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	FD_CLR( (u_int) sb->sb_sd, &sip->si_writefds );
	FD_CLR( (u_int) sb->sb_sd, &sip->si_readfds );
}


int
ldap_is_write_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( sb->sb_sd, &sip->si_use_writefds ));
}


int
ldap_is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( sb->sb_sd, &sip->si_use_readfds ));
}


void *
ldap_new_select_info( void )
{
	struct selectinfo	*sip;

	if (( sip = (struct selectinfo *)calloc( 1,
	    sizeof( struct selectinfo ))) != NULL ) {
		FD_ZERO( &sip->si_readfds );
		FD_ZERO( &sip->si_writefds );
	}

	return( (void *)sip );
}


void
ldap_free_select_info( void *sip )
{
	free( sip );
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
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
