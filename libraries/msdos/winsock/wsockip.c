/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  os-ip.c -- platform-specific TCP & UDP related code
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1995 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#if defined(WINSOCK) || defined(_WIN32)
#include <io.h>
#include "msdos.h"
#include "stdarg.h"
#ifdef 	 KERBEROS
#include "wshelper.h"
#endif	 /* KERBEROS */
#endif 	 /* WINSOCK */
#include <errno.h>

#ifdef 	 _WIN32
#include <io.h>
#else 	 /* _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif 	 /* _WIN32 */
#ifdef 	 _AIX
#include <sys/select.h>
#endif 	 /* _AIX */
#include "portable.h"
#include "lber.h"
#include "ldap.h"

#ifdef 	 NEED_FILIO
#ifdef 	 WINSOCK
#include <_sys/filio.h>
#else  	 /* WINSOCK */
#include <sys/filio.h>
#endif 	 /* WINSOCK */
#else 	 /* NEED_FILIO */
#ifdef 	 WINSOCK
#include <_sys/ioctl.h>
#else 	 /* WINSOCK */
#include <sys/ioctl.h>
#endif 	 /* WINSOCK */
#endif 	 /* NEED_FILIO */
#ifdef 	 USE_SYSCONF
#include <unistd.h>
#endif 	 /* USE_SYSCONF */


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


#ifdef WINSOCK
	static WSADATA 		wsadata;
	
#ifdef LDAP_DEBUG
void
Debug( int level, char* fmt, ... )
{
	char buf[BUFSIZ];
	va_list DbgArgs;
	int i = 0;
	char* arg[3] = { NULL, NULL, NULL };

	va_start( DbgArgs, fmt );
	for ( i= 0; i < 3; i++ )
	{
		arg[i] = va_arg( DbgArgs, va_list );
	}
	va_end( DbgArgs );              /* Reset variable arguments.      */


	wsprintf( buf, fmt, arg[0], arg[1], arg[2] );
	OutputDebugString( buf );
}

#define BPLEN	48
#include <ctype.h>

void
lber_bprint( char *data, int len )
{
    static char	hexdig[] = "0123456789abcdef";
    char	out[ BPLEN ];
    int		i = 0;
    char	buf[BUFSIZ];

    memset( out, 0, BPLEN );
    buf[0] = '\0';
    for ( ;; ) {
	if ( len < 1 ) {
	    wsprintf( buf, "\t%s\n", ( i == 0 ) ? "(end)" : out );
	    OutputDebugString( buf );
	    break;
	}

#ifndef HEX
	if ( isgraph( (unsigned char)*data )) {
	    out[ i ] = ' ';
	    out[ i+1 ] = *data;
	} else {
#endif
	    out[ i ] = hexdig[ ( *data & 0xf0 ) >> 4 ];
	    out[ i+1 ] = hexdig[ *data & 0x0f ];
#ifndef HEX
	}
#endif
	i += 2;
	len--;
	data++;

	if ( i > BPLEN - 2 ) {
	    wsprintf( buf, "\t%s\n", out );
	    OutputDebugString( buf );
	    memset( out, 0, BPLEN );
	    i = 0;
	    continue;
	}
	out[ i++ ] = ' ';
    }
}
#endif /* LDAP_DEBUG */
#endif /* WINSOCK */

int
connect_to_host( Sockbuf *sb, char *host, unsigned long address,
	int port, int async )
/*
 * if host == NULL, connect using address
 * "address" and "port" must be in network byte order
 * zero is returned upon success, -1 if fatal error, -2 EINPROGRESS
 * async is only used ifdef LDAP_REFERRALS (non-0 means don't wait for connect)
 * XXX async is not used yet!
 */
{
	int			rc, i, s, connected, use_hp;
	struct sockaddr_in	sin;
	struct hostent		*hp;

#ifdef notyet
#ifdef LDAP_REFERRALS
	int			status;	/* for ioctl call */
#endif /* LDAP_REFERRALS */
#endif /* notyet */

	Debug( LDAP_DEBUG_TRACE, "connect_to_host: %s:%d\n",
	    ( host == NULL ) ? "(by address)" : host, ntohs( port ), 0 );

#ifdef WINSOCK
	if ( WSAStartup( 0x0101, &wsadata ) != 0 ) {
	    return( (int)NULL );
	}
#endif

	hp = NULL;
	connected = use_hp = 0;

	if ( host != NULL && ( address = inet_addr( host )) == -1 ) {
		if ( (hp = gethostbyname( host )) == NULL ) {
#ifdef WINSOCK
			errno = WSAGetLastError();
#else
			errno = EHOSTUNREACH;	/* not exactly right, but... */
#endif
			return( -1 );
		}
		use_hp = 1;
	}

	rc = -1;
	for ( i = 0; !use_hp || ( hp->h_addr_list[ i ] != 0 ); i++ ) {
		if (( s = socket( AF_INET, SOCK_STREAM, 0 )) < 0 ) {
			return( -1 );
		}
#ifdef notyet
#ifdef LDAP_REFERRALS
		status = 1;
		if ( async && ioctl( s, FIONBIO, (caddr_t)&status ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "FIONBIO ioctl failed on %d\n",
			    s, 0, 0 );
		}
#endif /* LDAP_REFERRALS */
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
#ifdef notyet
#ifdef LDAP_REFERRALS
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
#endif /* LDAP_REFERRALS */
#endif /* notyet */

			Debug( LDAP_DEBUG_TRACE, "%s", (char *)inet_ntoa( sin.sin_addr ), 0, 0 );

			close( s );
			if ( !use_hp ) {
				break;
			}
		}
	}

	sb->sb_sd = s;

	if ( connected ) {
#ifdef notyet
#ifdef LDAP_REFERRALS
		status = 0;
		if ( !async && ioctl( s, FIONBIO, (caddr_t)&on ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "FIONBIO ioctl failed on %d\n",
			    s, 0, 0 );
		}
#endif /* LDAP_REFERRALS */
#endif /* notyet */

		Debug( LDAP_DEBUG_TRACE, "sd %d connected to: %s\n",
		    s, inet_ntoa( sin.sin_addr ), 0 );
	}
    
	return( rc );	/* Do NOT call WSACleanup. We want to use socket and various routines */
}


void
close_connection( Sockbuf *sb )
{
    tcp_close( sb->sb_sd );
}


#ifdef KERBEROS
char *
host_connected_to( Sockbuf *sb )
{
	struct hostent		*hp = NULL;
	int			len;
	struct sockaddr_in	sin;

#ifdef WINSOCK
	struct hostent		lhp;
	char hName[BUFSIZ/2];
    unsigned int prevMode;

	// Create a function pointer type that can be type-checked
	// by an ANSI-C compiler.
	typedef struct hostent FAR * (PASCAL FAR * LPGHBA)(const char FAR * addr, int len, int type);
	HINSTANCE hDLLInst;
	LPGHBA ghba = NULL;    // Declare pointer to functions that can be type-checked.

	memset(&lhp, 0x00, sizeof(struct hostent));
	hName[0] = '\0';
#endif	
	(void)memset( (char *)&sin, 0, sizeof( struct sockaddr_in ));
	len = sizeof( sin );
	if ( getpeername( sb->sb_sd, (struct sockaddr*) &sin, &len ) == -1 ) {
		return( NULL );
	}

	/*
	 * do a reverse lookup on the addr to get the official hostname.
	 * this is necessary for kerberos to work right, since the official
	 * hostname is used as the kerberos instance.
	 */
#ifdef WINSOCK
	/*
	 * Dynamically detect and use wshelper.dll if available. If not use 
	 * winsock's gethostbyaddr and cross your fingers.
	 */
    prevMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hDLLInst = LoadLibrary ("WSHELPER.DLL");
	SetErrorMode( prevMode );
	if (hDLLInst >= HINSTANCE_ERROR) {
	     ghba = (LPGHBA)GetProcAddress (hDLLInst, "rgethostbyaddr");
	
	     if (ghba) {
			hp = (*ghba)( (char *)&sin.sin_addr, 
				sizeof( sin.sin_addr.s_addr ), AF_INET );
			if ( hp && hp->h_name ) {
				/* copy name, put in our fake hp, make hp point to it
				 * because this hp disappears when FreeLibrary is called */
				strcpy(hName, hp->h_name);
				lhp.h_name = &hName;
				hp = &lhp;
			}
	     } else {
			hp = gethostbyaddr( (char *)&sin.sin_addr,
	    		sizeof( sin.sin_addr.s_addr ), AF_INET );
	     }
	     FreeLibrary (hDLLInst);
	} else {
		hp = gethostbyaddr( (char *)&sin.sin_addr,
    		sizeof( sin.sin_addr.s_addr ), AF_INET );
	}
#else
	hp = gethostbyaddr( (char *)&sin.sin_addr,
    		sizeof( sin.sin_addr.s_addr ), AF_INET );
#endif
	if ( hp != NULL ) {
		if ( hp->h_name != NULL ) {
			return( strdup( hp->h_name ));
		}
	}

	return( NULL );
}
#endif /* KERBEROS */


#ifdef LDAP_REFERRALS
/* for UNIX */
struct selectinfo {
	fd_set	si_readfds;
	fd_set	si_writefds;
	fd_set	si_use_readfds;
	fd_set	si_use_writefds;
};


void
mark_select_write( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	if ( !FD_ISSET( sb->sb_sd, &sip->si_writefds ))
		FD_SET( sb->sb_sd, &sip->si_writefds );
}


void
mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	if ( !FD_ISSET( sb->sb_sd, &sip->si_readfds ))
		FD_SET( sb->sb_sd, &sip->si_readfds );
}


void
mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	FD_CLR( sb->sb_sd, &sip->si_writefds );
	FD_CLR( sb->sb_sd, &sip->si_readfds );
}


int
is_write_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( sb->sb_sd, &sip->si_use_writefds ));
}


int
is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;

	sip = (struct selectinfo *)ld->ld_selectinfo;

	return( FD_ISSET( sb->sb_sd, &sip->si_use_readfds ));
}


void *
new_select_info()
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
free_select_info( void *sip )
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
#ifdef FD_SETSIZE
		/*
		 * It is invalid to use a set size in excess of the type
		 * scope, as defined for the fd_set in sys/types.h.  This
		 * is true for any OS.
		 */
		tblsize = FD_SETSIZE;
#else	/* !FD_SETSIZE*/
#ifdef USE_SYSCONF
		tblsize = sysconf( _SC_OPEN_MAX );
#else /* USE_SYSCONF */
#ifdef WINSOCK
		tblsize = FD_SETSIZE;
#else
		tblsize = getdtablesize();
#endif
#endif /* USE_SYSCONF */
#endif	/* !FD_SETSIZE*/
	}

	sip = (struct selectinfo *)ld->ld_selectinfo;
	sip->si_use_readfds = sip->si_readfds;
	sip->si_use_writefds = sip->si_writefds;
	
	return( select( tblsize, &sip->si_use_readfds, &sip->si_use_writefds,
	    NULL, timeout ));
}
#endif /* LDAP_REFERRALS */
