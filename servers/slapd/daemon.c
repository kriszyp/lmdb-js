#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap_defaults.h"
#include "slap.h"

#ifdef HAVE_TCPD
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* TCP Wrappers */

/* globals */
ber_socket_t dtblsize;
#ifdef HAVE_TLS
#define N_LISTENERS 2
#else
#define N_LISTENERS 1
#endif
struct listener_rec {
	ber_socket_t		tcps;
	struct sockaddr_in	*addr;
	int			use_tls;
} listeners[N_LISTENERS];

#ifdef HAVE_WINSOCK2
/* in nt_main.c */
extern ldap_pvt_thread_cond_t			started_event;

/* forward reference */
void hit_socket();
/* In wsa_err.c */
char *WSAGetLastErrorString();
static ldap_pvt_thread_t hit_tid;

#define WAKE_LISTENER(w) \
do {\
    if( w ) {\
        ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );\
        hit_socket(); \
    }\
} while(0)
#else
#define WAKE_LISTENER(w) \
do {\
    if( w ) {\
        ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );\
    }\
} while(0)
#endif

#ifndef HAVE_WINSOCK
static 
#endif
volatile sig_atomic_t slapd_shutdown = 0;

static int daemon_initialized = 0;
static ldap_pvt_thread_t	listener_tid;
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
static void slapd_add(ber_socket_t s) {
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

	Debug( LDAP_DEBUG_CONNS, "daemon: added %ld%s%s\n",
		(long) s,
	    FD_ISSET(s, &slap_daemon.sd_readers) ? "r" : "",
		FD_ISSET(s, &slap_daemon.sd_writers) ? "w" : "" );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
}

/*
 * Remove the descriptor from daemon control
 */
void slapd_remove(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);

	Debug( LDAP_DEBUG_CONNS, "daemon: removing %ld%s%s\n",
		(long) s,
	    FD_ISSET(s, &slap_daemon.sd_readers) ? "r" : "",
		FD_ISSET(s, &slap_daemon.sd_writers) ? "w" : "" );

	FD_CLR( s, &slap_daemon.sd_actives );
	FD_CLR( s, &slap_daemon.sd_readers );
	FD_CLR( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
}

void slapd_clr_write(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

void slapd_set_write(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
    WAKE_LISTENER(wake);

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_SET( (unsigned) s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

void slapd_clr_read(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
    WAKE_LISTENER(wake);

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

void slapd_set_read(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
    WAKE_LISTENER(wake);

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_SET( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

static void slapd_close(ber_socket_t s) {
	Debug( LDAP_DEBUG_CONNS, "daemon: closing %ld\n",
		(long) s, 0, 0 );
	tcp_close(s);
}



int
set_socket( struct sockaddr_in *addr )
{
	ber_socket_t	tcps = AC_SOCKET_INVALID;

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

		if ( (tcps = socket( AF_INET, SOCK_STREAM, 0 )) == AC_SOCKET_INVALID ) {
#ifndef HAVE_WINSOCK
			int err = errno;
			Debug( LDAP_DEBUG_ANY,
				"daemon: socket() failed errno %d (%s)\n", err,
		    	err > -1 && err < sys_nerr ? sys_errlist[err] :
		    	"unknown", 0 );
#else
			Debug( LDAP_DEBUG_ANY, 
				"daemon: socket() failed errno %d (%s)\n",
				WSAGetLastError(),
		    	WSAGetLastErrorString(), 0 );
#endif
			return( -1 );
		}

#ifndef HAVE_WINSOCK
		if ( tcps >= dtblsize ) {
			Debug( LDAP_DEBUG_ANY,
				"daemon: listener descriptor %ld is too great %ld\n",
				(long) tcps, (long) dtblsize, 0 );
			return( -1);
		}
#endif

#ifdef SO_REUSEADDR
		tmp = 1;
		if ( setsockopt( tcps, SOL_SOCKET, SO_REUSEADDR,
			(char *) &tmp, sizeof(tmp) ) == -1 )
		{
			int err = errno;
			Debug( LDAP_DEBUG_ANY,
			       "slapd(%ld): setsockopt() failed errno %d (%s)\n",
		    	(long) tcps, err,
				err > -1 && err < sys_nerr
					? sys_errlist[err] : "unknown" );
		}
#endif
#ifdef SO_KEEPALIVE
		tmp = 1;
		if ( setsockopt( tcps, SOL_SOCKET, SO_KEEPALIVE,
			(char *) &tmp, sizeof(tmp) ) == -1 )
		{
			int err = errno;
			Debug( LDAP_DEBUG_ANY,
				"slapd(%ld): setsockopt(KEEPALIVE) failed errno %d (%s)\n",
		    	(long) tcps, err,
				err > -1 && err < sys_nerr
					? sys_errlist[err] : "unknown" );
		}
#endif


		if ( bind( tcps, (struct sockaddr *) addr, sizeof(*addr) ) == -1 ) {
			int err = errno;
			Debug( LDAP_DEBUG_ANY, "daemon: bind(%ld) failed errno %d (%s)\n",
		    	(long) tcps, err,
				err > -1 && err < sys_nerr
					? sys_errlist[err] : "unknown" );
			return -1;
		}
	}

	return tcps;
}

static void *
slapd_daemon_task(
	void *ptr
)
{
	int inetd;
	struct slapd_args *args = (struct slapd_args *) ptr;
	int l;

	listeners[0].tcps = args->tcps;
	listeners[0].addr = args->addr;
	listeners[0].use_tls = 0;
#ifdef HAVE_TLS
	listeners[1].tcps = args->tls_tcps;
	listeners[1].addr = args->tls_addr;
	listeners[1].use_tls = 1;
#endif

	inetd = ( listeners[0].addr == NULL);
    if ( !daemon_initialized ) sockinit();

	slapd_listener=1;

	ldap_pvt_thread_mutex_init( &slap_daemon.sd_mutex );
	FD_ZERO( &slap_daemon.sd_readers );
	FD_ZERO( &slap_daemon.sd_writers );

	if( !inetd ) {
		for ( l = 0; l < N_LISTENERS; l++ ) {
			if ( listeners[l].tcps < 0 )
				continue;
			if ( listen( listeners[l].tcps, 5 ) == -1 ) {
				int err = errno;
				Debug( LDAP_DEBUG_ANY,
				"daemon: listen(%ld, 5) failed errno %d (%s)\n",
				       (long) listeners[l].tcps, err,
				       err > -1 && err < sys_nerr
				       ? sys_errlist[err] : "unknown" );
				return( (void*)-1 );
			}

			slapd_add( listeners[l].tcps );
		}

	} else {
		if( connection_init( (ber_socket_t) 0, NULL, NULL, 0 ) ) {
			Debug( LDAP_DEBUG_ANY,
				"connection_init(%d) failed.\n",
				0, 0, 0 );
			return( (void*)-1 );
		}

		slapd_add( 0 );
	}

#ifdef HAVE_WINSOCK
	if ( started_event != NULL )
		ldap_pvt_thread_cond_signal( &started_event );
#endif
	/* initialization complete. Here comes the loop. */

	while ( !slapd_shutdown ) {
		ber_socket_t i;
		int ns;
		int at;
		ber_socket_t nfds;
#define SLAPD_EBADF_LIMIT 10
		int ebadf = 0;

#define SLAPD_IDLE_CHECK_LIMIT 4
		time_t	last_idle_check = slap_get_time();
		time_t	now;


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

		if( global_idletimeout > 0 && difftime(
			last_idle_check+global_idletimeout/SLAPD_IDLE_CHECK_LIMIT,
			now ) < 0 )
		{
			connections_timeout_idle(now);
		}

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

		for ( l = 0; l < N_LISTENERS; l++ ) {
			if ( listeners[l].tcps < 0 )
				continue;
			FD_SET( (unsigned) listeners[l].tcps, &readfds );
		}

#ifndef HAVE_WINSOCK
		nfds = slap_daemon.sd_nfds;
#else
		nfds = dtblsize;
#endif

		ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

		ldap_pvt_thread_mutex_lock( &active_threads_mutex );
		at = active_threads;
		ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

#if defined( HAVE_YIELDING_SELECT ) || defined( NO_THREADS )
		tvp = NULL;
#else
		tvp = at ? &zero : NULL;
#endif

		for ( i = 0; i < N_LISTENERS; i++ ) {
			if ( listeners[l].tcps < 0 )
				continue;
			Debug( LDAP_DEBUG_CONNS,
			"daemon: select: tcps=%d active_threads=%d tvp=%s\n",
			       listeners[i].tcps, at,
			       tvp == NULL ? "NULL" : "zero" );
		}

		switch(ns = select( nfds, &readfds,
#ifdef HAVE_WINSOCK
			/* don't pass empty fd_set */
			( writefds.fd_count > 0 ? &writefds : NULL ),
#else
			&writefds,
#endif
			NULL, tvp ))
		{
		case -1: {	/* failure - try again */
#ifdef HAVE_WINSOCK
				int err = WSAGetLastError();
#else
				int err = errno;
#endif

				if( err == EBADF && ++ebadf < SLAPD_EBADF_LIMIT) {
					continue;
				}

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
			ebadf = 0;
			Debug( LDAP_DEBUG_CONNS, "daemon: select timeout - yielding\n",
			    0, 0, 0 );
	     	ldap_pvt_thread_yield();
			continue;

		default:	/* something happened - deal with it */
			ebadf = 0;
			Debug( LDAP_DEBUG_CONNS, "daemon: activity on %d descriptors\n",
				ns, 0, 0 );
			/* FALL THRU */
		}

		for ( l = 0; l < N_LISTENERS; l++ ) {
			ber_int_t s;
			int len = sizeof(from);
			long id;

			if ( listeners[l].tcps < 0 )
				continue;
			if ( !FD_ISSET( listeners[l].tcps, &readfds ) )
				continue;

			if ( (s = accept( listeners[l].tcps,
				(struct sockaddr *) &from, &len )) == AC_SOCKET_INVALID )
			{
				int err = errno;
				Debug( LDAP_DEBUG_ANY,
				    "daemon: accept(%ld) failed errno %d (%s)\n", err,
				    (long) listeners[l].tcps,
				    err >= 0 && err < sys_nerr ?
				    sys_errlist[err] : "unknown");
				continue;
			}

#ifdef LDAP_DEBUG
			ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

			/* newly accepted stream should not be in any of the FD SETS */

			assert( !FD_ISSET( s, &slap_daemon.sd_actives) );
			assert( !FD_ISSET( s, &slap_daemon.sd_readers) );
			assert( !FD_ISSET( s, &slap_daemon.sd_writers) );

			ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
#endif

#ifndef HAVE_WINSOCK
			/* make sure descriptor number isn't too great */
			if ( s >= dtblsize ) {
				Debug( LDAP_DEBUG_ANY,
					"daemon: %ld beyond descriptor table size %ld\n",
					(long) s, (long) dtblsize, 0 );
				slapd_close(s);
				continue;
			}
#endif
		   
			Debug( LDAP_DEBUG_CONNS, "daemon: new connection on %ld\n",
				(long) s, 0, 0 );

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
			   	 "fd=%ld connection from %s (%s) denied.\n",
			   	 	(long) s,
					client_name == NULL ? "unknown" : client_name,
					client_addr == NULL ? "unknown" : client_addr,
			   	  0, 0 );

				slapd_close(s);
				continue;
			}
#endif /* HAVE_TCPD */

			if( (id = connection_init(s, client_name, client_addr,
						  listeners[l].use_tls)) < 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"daemon: connection_init(%ld, %s, %s) failed.\n",
					(long) s,
					client_name == NULL ? "unknown" : client_name,
					client_addr == NULL ? "unknown" : client_addr);
				slapd_close(s);
				continue;
			}

			Statslog( LDAP_DEBUG_STATS,
				"daemon: conn=%d fd=%ld connection from %s (%s) accepted.\n",
				id, (long) s,
				client_name == NULL ? "unknown" : client_name,
				client_addr == NULL ? "unknown" : client_addr,
				0 );

			slapd_add( s );
			continue;
		}

#ifdef LDAP_DEBUG
		Debug( LDAP_DEBUG_CONNS, "daemon: activity on:", 0, 0, 0 );
#ifdef HAVE_WINSOCK
		for ( i = 0; i < readfds.fd_count; i++ ) {
			Debug( LDAP_DEBUG_CONNS, " %d%s",
				readfds.fd_array[i], "r", 0 );
		}
		for ( i = 0; i < writefds.fd_count; i++ ) {
			Debug( LDAP_DEBUG_CONNS, " %d%s",
				writefds.fd_array[i], "w", 0 );
		}
#else
		for ( i = 0; i < nfds; i++ ) {
			int	a, r, w;
			int	is_listener = 0;

			for ( l = 0; l < N_LISTENERS; l++ ) {
				if ( i == listeners[l].tcps ) {
					is_listener = 1;
					break;
				}
			}
			if ( is_listener ) {
				continue;
			}
			r = FD_ISSET( i, &readfds );
			w = FD_ISSET( i, &writefds );
			if ( r || w ) {
				Debug( LDAP_DEBUG_CONNS, " %d%s%s", i,
				    r ? "r" : "", w ? "w" : "" );
			}
		}
#endif
		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );
#endif

		/* loop through the writers */
#ifdef HAVE_WINSOCK
		for ( i = 0; i < writefds.fd_count; i++ )
#else
		for ( i = 0; i < nfds; i++ )
#endif
		{
			ber_socket_t wd;
			int is_listener = 0;
#ifdef HAVE_WINSOCK
			wd = writefds.fd_array[i];
#else
			if( ! FD_ISSET( i, &writefds ) ) {
				continue;
			}
			wd = i;
#endif

			for ( l = 0; l < N_LISTENERS; l++ ) {
				if ( wd == listeners[l].tcps ) {
					is_listener = 1;
					break;
				}
			}
			if ( is_listener ) {
				continue;
			}
			Debug( LDAP_DEBUG_CONNS,
				"daemon: write active on %d\n",
				wd, 0, 0 );

			/*
			 * NOTE: it is possible that the connection was closed
			 * and that the stream is now inactive.
			 * connection_write() must valid the stream is still
			 * active.
			 */

			if ( connection_write( wd ) < 0 ) {
				FD_CLR( (unsigned) wd, &readfds );
				slapd_close( wd );
			}
		}

#ifdef HAVE_WINSOCK
		for ( i = 0; i < readfds.fd_count; i++ )
#else
		for ( i = 0; i < nfds; i++ )
#endif
		{
			ber_socket_t rd;
			int is_listener = 0;

#ifdef HAVE_WINSOCK
			rd = readfds.fd_array[i];
#else
			if( ! FD_ISSET( i, &readfds ) ) {
				continue;
			}
			rd = i;
#endif

			for ( l = 0; l < N_LISTENERS; l++ ) {
				if ( rd == listeners[l].tcps ) {
					is_listener = 1;
					break;
				}
			}
			if ( is_listener ) {
				continue;
			}

			Debug ( LDAP_DEBUG_CONNS,
				"daemon: read activity on %d\n", rd, 0, 0 );

			/*
			 * NOTE: it is possible that the connection was closed
			 * and that the stream is now inactive.
			 * connection_read() must valid the stream is still
			 * active.
			 */

			if ( connection_read( rd ) < 0 ) {
				slapd_close( rd );
			}
		}
		ldap_pvt_thread_yield();
	}

	if( slapd_shutdown > 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: shutdown requested and initiated.\n",
			0, 0, 0 );

	} else if ( slapd_shutdown < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: abnormal condition, shutdown initiated.\n",
			0, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: no active streams, shutdown initiated.\n",
			0, 0, 0 );
	}

	for ( l = 0; l < N_LISTENERS; l++ ) {
		if ( listeners[l].tcps >= 0 ) {
			slapd_close( listeners[l].tcps );
		}
	}

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	Debug( LDAP_DEBUG_ANY,
	    "slapd shutdown: waiting for %d threads to terminate\n",
	    active_threads, 0, 0 );
	while ( active_threads > 0 ) {
		ldap_pvt_thread_cond_wait(&active_threads_cond, &active_threads_mutex);
	}
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

	return NULL;
}


int slapd_daemon( struct slapd_args *args )
{
	int rc;

    if ( !daemon_initialized ) sockinit();

	connections_init();

#define SLAPD_LISTENER_THREAD 1
#if defined( SLAPD_LISTENER_THREAD ) || !defined(HAVE_PTHREADS)

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

void hit_socket()
{
	ber_socket_t s;
	int on = 1;
	extern struct sockaddr_in	bind_addr;

	/* throw something at the socket to terminate the select() in the daemon thread. */
	if (( s = socket( AF_INET, SOCK_STREAM, 0 )) == AC_SOCKET_INVALID )
		Debug( LDAP_DEBUG_ANY,
			"slap_set_shutdown: socket failed\n\tWSAGetLastError=%d (%s)\n",
			WSAGetLastError(), WSAGetLastErrorString(), 0 );

	if ( ioctlsocket( s, FIONBIO, &on ) == -1 ) 
		Debug( LDAP_DEBUG_ANY,
			"slap_set_shutdown:FIONBIO ioctl on %d faled\n\tWSAGetLastError=%d (%s)\n",
			s, WSAGetLastError(), WSAGetLastError() );
	
	bind_addr.sin_addr.s_addr = htonl( INADDR_LOOPBACK );

	if ( connect( s, (struct sockaddr *)&bind_addr, sizeof( struct sockaddr_in )) == SOCKET_ERROR ) {
		Debug( LDAP_DEBUG_ANY,
			"hit_socket: error on connect: %d\n",
			WSAGetLastError(), 0, 0 );
		/* we can probably expect some error to occur here, mostly WSAEWOULDBLOCK */
	}

	tcp_close(s);
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
}
#endif

void
slap_set_shutdown( int sig )
{
	int l;
	slapd_shutdown = sig;
#ifndef HAVE_WINSOCK
	if(slapd_listener) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
#else
	Debug( LDAP_DEBUG_TRACE, "Shutdown %d ordered", sig, 0, 0 );
	/* trying to "hit" the socket seems to always get a */
	/* EWOULDBLOCK error, so just close the listen socket to */
	/* break out of the select since we're shutting down anyway */
	for ( l = 0; l < N_LISTENERS; l++ ) {
		if ( listeners[l].tcps >= 0 ) {
			tcp_close( listeners[l].tcps );
		}
	}
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
