#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldapconfig.h"
#include "slap.h"

#ifdef HAVE_TCPD
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* TCP Wrappers */

/* globals */
int dtblsize;

#ifdef HAVE_WINSOCK2
/* forward reference */
void hit_socket();
/* In wsa_err.c */
char *WSAGetLastErrorString();

#define WAKE_LISTENER \
    if( wake ) {\
        ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );\
        hit_socket();\
    }
#else
#define WAKE_LISTENER \
    if( wake ) {\
        ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );\
    }
#endif

static int daemon_initialized = 0;
static ldap_pvt_thread_t	listener_tid;
static volatile sig_atomic_t slapd_shutdown = 0;
static volatile sig_atomic_t slapd_listener = 0;
void sockinit();

struct slap_daemon {
	ldap_pvt_thread_mutex_t	sd_mutex;

	int sd_nactives;

#ifndef HAVE_WINSOCK
	/* In winsock, accept() returns values higher than dtblsize
		so don't bother with this optimization */
	int sd_nfds;
#endif

	fd_set sd_actives;
	fd_set sd_readers;
	fd_set sd_writers;
} slap_daemon; 

/*
 * Add a descriptor to daemon control
 */
static void slapd_add(int s) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( !FD_ISSET( s, &slap_daemon.sd_actives ));
	assert( !FD_ISSET( s, &slap_daemon.sd_readers ));
	assert( !FD_ISSET( s, &slap_daemon.sd_writers ));

#ifndef HAVE_WINSOCK
	if (s >= slap_daemon.sd_nfds) {
		slap_daemon.sd_nfds = s + 1;
	}
#endif

	FD_SET( s, &slap_daemon.sd_actives );
	FD_SET( s, &slap_daemon.sd_readers );

	Debug( LDAP_DEBUG_CONNS, "daemon: added %d%s%s\n", s,
	    FD_ISSET(s, &slap_daemon.sd_readers) ? "r" : "",
		FD_ISSET(s, &slap_daemon.sd_writers) ? "w" : "" );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
}

/*
 * Remove the descriptor from daemon control
 */
void slapd_remove(int s) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives ));

	Debug( LDAP_DEBUG_CONNS, "daemon: removing %d%s%s\n", s,
	    FD_ISSET(s, &slap_daemon.sd_readers) ? "r" : "",
		FD_ISSET(s, &slap_daemon.sd_writers) ? "w" : "" );

	FD_CLR( s, &slap_daemon.sd_actives );
	FD_CLR( s, &slap_daemon.sd_readers );
	FD_CLR( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
}

void slapd_clr_write(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	WAKE_LISTENER;
}

void slapd_set_write(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_SET( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

    WAKE_LISTENER;
}

void slapd_clr_read(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

    WAKE_LISTENER;
}

void slapd_set_read(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_SET( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

    WAKE_LISTENER;
}

static void slapd_close(int s) {
	slapd_remove(s);

	Debug( LDAP_DEBUG_CONNS, "daemon: closing %d\n", s, 0, 0 );
	tcp_close(s);
}

int
set_socket( struct sockaddr_in *addr )
{
	int	tcps = -1;
    if ( !daemon_initialized ) sockinit();

#ifdef HAVE_SYSCONF
	dtblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	dtblsize = getdtablesize();
#else
	dtblsize = FD_SETSIZE;
#endif

#ifdef FD_SETSIZE
	if(dtblsize > FD_SETSIZE) {
		dtblsize = FD_SETSIZE;
	}
#endif	/* !FD_SETSIZE */

	if( addr != NULL ) {
		int	tmp;

		if ( (tcps = socket( AF_INET, SOCK_STREAM, 0 )) == -1 ) {
#ifndef WIN32
			int err = errno;
			Debug( LDAP_DEBUG_ANY,
				"daemon: socket() failed errno %d (%s)\n", err,
		    	err > -1 && err < sys_nerr ? sys_errlist[err] :
		    	"unknown", 0 );
#endif
#ifdef WIN32
			Debug( LDAP_DEBUG_ANY, 
				"daemon: socket() failed errno %d (%s)\n", WSAGetLastError(),
		    	WSAGetLastErrorString(), 0 );
#endif
			exit( 1 );
		}

#ifndef HAVE_WINSOCK
		if ( tcps >= dtblsize ) {
			Debug( LDAP_DEBUG_ANY,
				"daemon: listener descriptor %d is too great\n",
				tcps, dtblsize, 0 );
			exit( 1 );
		}
#endif

		tmp = 1;
		if ( setsockopt( tcps, SOL_SOCKET, SO_REUSEADDR,
			(char *) &tmp, sizeof(tmp) ) == -1 )
		{
			int err = errno;
			Debug( LDAP_DEBUG_ANY,
			       "slapd(%d): setsockopt() failed errno %d (%s)\n",
		    	tcps, err,
				err > -1 && err < sys_nerr
					? sys_errlist[err] : "unknown" );
		}

		if ( bind( tcps, (struct sockaddr *) addr, sizeof(*addr) ) == -1 ) {
			int err = errno;
			Debug( LDAP_DEBUG_ANY, "daemon: bind(%d) failed errno %d (%s)\n",
		    	tcps, err,
				err > -1 && err < sys_nerr
					? sys_errlist[err] : "unknown" );
			exit( 1 );
		}
	}

	return tcps;
}

static void *
slapd_daemon_task(
	void *ptr
)
{
	int inetd = ((int *)ptr) [0];
	int tcps  = ((int *)ptr) [1];
	free( ptr );

    if ( !daemon_initialized ) sockinit();

	slapd_listener=1;

	ldap_pvt_thread_mutex_init( &slap_daemon.sd_mutex );
	FD_ZERO( &slap_daemon.sd_readers );
	FD_ZERO( &slap_daemon.sd_writers );

	if( !inetd ) {
		if ( listen( tcps, 5 ) == -1 ) {
			int err = errno;
			Debug( LDAP_DEBUG_ANY,
				"daemon: listen(%d, 5) failed errno %d (%s)\n",
			    tcps, err,
				err > -1 && err < sys_nerr
					? sys_errlist[err] : "unknown" );
			exit( 1 );
		}

		slapd_add( tcps );

	} else {
		if( connection_init( 0, NULL, NULL ) ) {
			Debug( LDAP_DEBUG_ANY,
				"connection_init(%d) failed.\n",
				0, 0, 0 );

			exit( 1 );
		}

		slapd_add( 0 );
	}

	while ( !slapd_shutdown ) {
		unsigned int i;
		int ns, nfds;

		fd_set			readfds;
		fd_set			writefds;

		struct sockaddr_in	from;
#if defined(SLAPD_RLOOKUPS) || defined(HAVE_TCPD)
        struct hostent		*hp;
#endif
        struct timeval		zero;
		struct timeval		*tvp;

		char	*client_name;
		char	*client_addr;

		FD_ZERO( &writefds );
		FD_ZERO( &readfds );

		zero.tv_sec = 0;
		zero.tv_usec = 0;

		ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

#ifdef FD_SET_MANUAL_COPY
		for( s = 0; s < nfds; s++ ) {
			if(FD_ISSET( &slap_sd_writers, s )) {
				FD_SET( &writefds, s );
			}
			if(FD_ISSET( &slap_sd_writers, s )) {
				FD_SET( &writefds, s );
			}
		}
#else
		memcpy( &readfds, &slap_daemon.sd_readers, sizeof(fd_set) );
		memcpy( &writefds, &slap_daemon.sd_writers, sizeof(fd_set) );
#endif

		FD_SET( tcps, &readfds );

#ifndef HAVE_WINSOCK
		nfds = slap_daemon.sd_nfds;
#else
		nfds = dtblsize;
#endif

		ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

		ldap_pvt_thread_mutex_lock( &active_threads_mutex );
#if defined( HAVE_YIELDING_SELECT ) || defined( NO_THREADS )
		tvp = NULL;
#else
		tvp = active_threads ? &zero : NULL;
#endif

		Debug( LDAP_DEBUG_CONNS,
			"daemon: select: tcps=%d active_threads=%d tvp=%s\n",
		    tcps, active_threads,
			tvp == NULL ? "NULL" : "zero" );
	   

		ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

		switch(ns = select( nfds, &readfds, &writefds, 0, tvp )) {
		case -1: {	/* failure - try again */
				int err = errno;
				if( err != EINTR ) {
					Debug( LDAP_DEBUG_CONNS,
						"daemon: select failed (%d): %s\n",
						err,
						err >= 0 && err < sys_nerr
							? sys_errlist[err] : "unknown",
						0 );

					slapd_shutdown = -1;
				}
			}
			continue;

		case 0:		/* timeout - let threads run */
			Debug( LDAP_DEBUG_CONNS, "daemon: select timeout - yielding\n",
			    0, 0, 0 );
	     	ldap_pvt_thread_yield();
			continue;

		default:	/* something happened - deal with it */
			Debug( LDAP_DEBUG_CONNS, "daemon: activity on %d descriptors\n",
				ns, 0, 0 );
			/* FALL THRU */
		}

		if ( FD_ISSET( tcps, &readfds ) ) {
			int s;
			int len = sizeof(from);
			long id;

			if ( (s = accept( tcps,
				(struct sockaddr *) &from, &len )) == -1 )
			{
				int err = errno;
				Debug( LDAP_DEBUG_ANY,
				    "daemon: accept(%d) failed errno %d (%s)\n", err,
				    tcps, err >= 0 && err < sys_nerr ?
				    sys_errlist[err] : "unknown");
				continue;
			}

			assert( !FD_ISSET( 0, &slap_daemon.sd_actives) );
			assert( !FD_ISSET( 0, &slap_daemon.sd_readers) );
			assert( !FD_ISSET( 0, &slap_daemon.sd_writers) );

#ifndef HAVE_WINSOCK
			/* make sure descriptor number isn't too great */
			if ( s >= dtblsize ) {
				Debug( LDAP_DEBUG_ANY,
					"daemon: %d beyond descriptor table size %d\n",
					s, dtblsize, 0 );
				tcp_close(s);
				continue;
			}
#endif
		   
			Debug( LDAP_DEBUG_CONNS, "daemon: new connection on %d\n",
				s, 0, 0 );

			len = sizeof(from);
			if ( getpeername( s, (struct sockaddr *) &from, &len ) == 0 ) {
				client_addr = inet_ntoa( from.sin_addr );

#if defined(SLAPD_RLOOKUPS) || defined(HAVE_TCPD)
				hp = gethostbyaddr( (char *)
				    &(from.sin_addr.s_addr),
				    sizeof(from.sin_addr.s_addr), AF_INET );

				if(hp) {
					char *p;
					client_name = hp->h_name;

					/* normalize the domain */
					for ( p = client_name; *p; p++ ) {
						*p = TOLOWER( (unsigned char) *p );
					}

				} else {
					client_name = NULL;
				}
#else
				client_name = NULL;
#endif

			} else {
				client_name = NULL;;
				client_addr = NULL;
			}

#ifdef HAVE_TCPD
			if(!hosts_ctl("slapd",
				client_name != NULL ? client_name : STRING_UNKNOWN,
				client_addr != NULL ? client_addr : STRING_UNKNOWN,
				STRING_UNKNOWN))
			{
				/* DENY ACCESS */
				Statslog( LDAP_DEBUG_ANY,
			   	 "fd=%d connection from %s (%s) denied.\n",
			   	 	s,
					client_name == NULL ? "unknown" : client_name,
					client_addr == NULL ? "unknown" : client_addr,
			   	  0, 0 );

				tcp_close(s);
				continue;
			}
#endif /* HAVE_TCPD */

			if( (id = connection_init(s, client_name, client_addr)) < 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"daemon: connection_init(%d, %s, %s) failed.\n",
					s,
					client_name == NULL ? "unknown" : client_name,
					client_addr == NULL ? "unknown" : client_addr);
				tcp_close(s);
				continue;
			}

			Statslog( LDAP_DEBUG_STATS,
				"daemon: conn=%d fd=%d connection from %s (%s) accepted.\n",
				id, s,
				client_name == NULL ? "unknown" : client_name,
				client_addr == NULL ? "unknown" : client_addr,
				0 );

			slapd_add( s );
			continue;
		}

#ifdef LDAP_DEBUG
		Debug( LDAP_DEBUG_CONNS, "daemon: activity on:", 0, 0, 0 );
#ifdef HAVE_WINSOCK
		for ( i = 0; i < readfds.fd_count; i++ )
		{
			Debug( LDAP_DEBUG_CONNS, " %d%s", readfds.fd_array[i], "r" );
		}
		for ( i = 0; i < writefds.fd_count; i++ )
		{
			Debug( LDAP_DEBUG_CONNS, " %d%s", writefds.fd_array[i], "w" );
		}
#else
		for ( i = 0; i < nfds; i++ ) {
			int	a, r, w;

			r = FD_ISSET( i, &readfds );
			w = FD_ISSET( i, &writefds );
			if ( i != tcps && (r || w) ) {
				Debug( LDAP_DEBUG_CONNS, " %d%s%s", i,
				    r ? "r" : "", w ? "w" : "" );
			}
		}
#endif
		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );
#endif

		/* loop through the writers */
#ifdef HAVE_WINSOCK
		for ( i = 0; i < writefds.fd_count; i++ ) {
			int wd = writefds.fd_array[i];

			if ( wd == tcps ) {
				continue;
			}

			Debug( LDAP_DEBUG_CONNS,
				"daemon: signalling write waiter on %d\n",
				wd, 0, 0 );

			assert( FD_ISSET( wd, &slap_daemon.sd_actives) );

			slapd_clr_write( wd, 0 );
			if ( connection_write( wd ) < 0 ) {
				FD_CLR( wd, &readfds );
				slapd_close( wd );
			}
		}
#else
		for ( i = 0; i < nfds; i++ ) {
			if ( i == tcps ) {
				continue;
			}
			if ( FD_ISSET( i, &writefds ) ) {
				Debug( LDAP_DEBUG_CONNS,
				    "daemon: signaling write waiter on %d\n", i, 0, 0 );

				assert( FD_ISSET( i, &slap_daemon.sd_actives) );

				/* clear the write flag */
				slapd_clr_write( i, 0 );
				
				if( connection_write( i ) < 0 ) { 
					FD_CLR( i, &readfds );
					slapd_close( i );
				}
			}
		}
#endif

#ifdef HAVE_WINSOCK
		for ( i = 0; i < readfds.fd_count; i++ ) {
			int rd = readfds.fd_array[i];
			if ( rd == tcps ) {
				continue;
			}
			Debug ( LDAP_DEBUG_CONNS,
				"daemon: read activity on %d\n", rd, 0, 0 );
			assert( FD_ISSET( rd, &slap_daemon.sd_actives) );

			if ( connection_read( rd ) < 0 ) {
				slapd_close( rd );
			}
		}
#else
		for ( i = 0; i < nfds; i++ ) {
			if ( i == tcps ) {
				continue;
			}

			if ( FD_ISSET( i, &readfds ) ) {
				Debug( LDAP_DEBUG_CONNS,
				    "daemon: read activity on %d\n", i, 0, 0 );

				assert( FD_ISSET( i, &slap_daemon.sd_actives) );

				if( connection_read( i ) < 0) {
					slapd_close( i );
				}
			}
		}
#endif
		ldap_pvt_thread_yield();
	}

	if( slapd_shutdown > 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: shutdown requested (%d) and initiated.\n",
			(int) slapd_shutdown, 0, 0 );

	} else if ( slapd_shutdown < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: abnormal condition (%d), shutdown initiated.\n",
			(int) slapd_shutdown, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: no active streams, shutdown initiated.\n",
			0, 0, 0 );
	}

	if( tcps >= 0 ) {
		tcp_close( tcps );
	}

	/* we only implement "quick" shutdown */
	connections_shutdown();

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	Debug( LDAP_DEBUG_ANY,
	    "slapd shutdown: waiting for %d threads to terminate\n",
	    active_threads, 0, 0 );
	while ( active_threads > 0 ) {
		ldap_pvt_thread_cond_wait(&active_threads_cond, &active_threads_mutex);
	}
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

	slapd_listener = 0;
	return NULL;
}

int slapd_daemon( int inetd, int tcps )
{
	int rc;
	int *args = ch_malloc( sizeof( int[2] ) );
	args[0] = inetd;
	args[1] = tcps;

    if ( !daemon_initialized ) sockinit();

	connections_init();

#define SLAPD_LISTENER_THREAD 1
#if SLAPD_LISTENER_THREAD
	/* listener as a separate THREAD */
	rc = ldap_pvt_thread_create( &listener_tid,
		0, slapd_daemon_task, args );

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "listener ldap_pvt_thread_create failed (%d)\n", rc, 0, 0 );
		goto destory;
	}

	/* wait for the listener thread to complete */
	ldap_pvt_thread_join( listener_tid, (void *) NULL );
#else
	/* expermimental code */
	listener_tid = pthread_self();
	slapd_daemon_task( args );
#endif

	rc = 0;

destory:
	connections_destroy();

#ifdef HAVE_WINSOCK
    WSACleanup( );
#endif

	return rc;
}

#ifdef HAVE_WINSOCK2
void sockinit()
{
    WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	wVersionRequested = MAKEWORD( 2, 0 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		/* Tell the user that we couldn't find a usable */
		/* WinSock DLL.                                  */
		return;
	}
 
	/* Confirm that the WinSock DLL supports 2.0.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.0 in addition to 2.0, it will still return */
	/* 2.0 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 0 )
	{
	    /* Tell the user that we couldn't find a usable */
	    /* WinSock DLL.                                  */
	    WSACleanup( );
	    return; 
	}
    daemon_initialized = 1;
}	/* The WinSock DLL is acceptable. Proceed. */

void hit_socket( void )
{
	int s, on = 1;
	extern struct sockaddr_in	bind_addr;

	/* throw something at the socket to terminate the select() in the daemon thread. */
	if (( s = socket( AF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET )
		Debug( LDAP_DEBUG_TRACE, "slap_set_shutdown: socket failed\n\tWSAGetLastError=%d (%s)\n", WSAGetLastError(), WSAGetLastErrorString(), 0 );
	if ( ioctlsocket( s, FIONBIO, &on ) == -1 ) 
		Debug( LDAP_DEBUG_TRACE, "slap_set_shutdown:FIONBIO ioctl on %d faled\n\tWSAGetLastError=%d (%s)\n", s, WSAGetLastError(), WSAGetLastError() );

	bind_addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
	if ( connect( s, (struct sockaddr *)&bind_addr, sizeof( struct sockaddr_in )) == SOCKET_ERROR ) {
		/* we can probably expect some error to occur here, mostly WSAEWOULDBLOCK */
	}
}
#elif HAVE_WINSOCK
void sockinit()
{	WSADATA wsaData;
	if ( WSAStartup( 0x0101, &wsaData ) != 0 ) {
	    return( NULL );
	}
    daemon_initialized = 1;
}
#else
void sockinit()
{
    daemon_initialized = 1;
    return;
}
#endif

void
slap_set_shutdown( int sig )
{
	slapd_shutdown = sig;
#ifndef WIN32
	if(slapd_listener) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
#else
	hit_socket();
#endif
	/* reinstall self */
	(void) SIGNAL( sig, slap_set_shutdown );
}

void
slap_do_nothing( int sig )
{
	/* reinstall self */
	(void) SIGNAL( sig, slap_do_nothing );
}
