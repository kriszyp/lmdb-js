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

#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#elif HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_TCPD
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* TCP Wrappers */

/* globals */
int dtblsize;

static ldap_pvt_thread_t	listener_tid;
static volatile sig_atomic_t slapd_shutdown = 0;

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

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

void slapd_set_write(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_SET( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

void slapd_clr_read(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

void slapd_set_read(int s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_SET( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

	if( wake ) {
		ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );
	}
}

static void slapd_close(int s) {
	slapd_remove(s);

	Debug( LDAP_DEBUG_CONNS, "daemon: closing %d\n", s, 0, 0 );
	tcp_close(s);
}

static void *
slapd_daemon_task(
	void *ptr
)
{
	struct sockaddr_in *addr = ptr;
	int	tcps = -1;

#ifdef HAVE_SYSCONF
	dtblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	dtblsize = getdtablesize();
#else
	dtblsize = FD_SETSIZE
#endif

#ifdef FD_SETSIZE
	if(dtblsize > FD_SETSIZE) {
		dtblsize = FD_SETSIZE;
	}
#endif	/* !FD_SETSIZE */

	connections_init();

	ldap_pvt_thread_mutex_init( &slap_daemon.sd_mutex );
	FD_ZERO( &slap_daemon.sd_readers );
	FD_ZERO( &slap_daemon.sd_writers );

	if( addr != NULL ) {
		int	tmp;

		if ( (tcps = socket( AF_INET, SOCK_STREAM, 0 )) == -1 ) {
			Debug( LDAP_DEBUG_ANY,
				"daemon: socket() failed errno %d (%s)", errno,
		    	errno > -1 && errno < sys_nerr ? sys_errlist[errno] :
		    	"unknown", 0 );
			exit( 1 );
		}

#ifndef HAVE_WINSOCK
		if ( tcps >= dtblsize ) {
			Debug( LDAP_DEBUG_ANY,
				"daemon: listener descriptor %d is too great",
				tcps, dtblsize, 0 );
			exit( 1 );
		}
#endif

		tmp = 1;
		if ( setsockopt( tcps, SOL_SOCKET, SO_REUSEADDR,
			(char *) &tmp, sizeof(tmp) ) == -1 )
		{
			Debug( LDAP_DEBUG_ANY,
				"slapd(%d): setsockopt() failed errno %d (%s)",
		    	tcps, errno,
				errno > -1 && errno < sys_nerr
					? sys_errlist[errno] : "unknown" );

			errno = 0;
		}

		if ( bind( tcps, (struct sockaddr *) addr, sizeof(*addr) ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "daemon: bind(%d) failed errno %d (%s)\n",
		    	tcps, errno,
				errno > -1 && errno < sys_nerr
					? sys_errlist[errno] : "unknown" );
			exit( 1 );
		}

		if ( listen( tcps, 5 ) == -1 ) {
			Debug( LDAP_DEBUG_ANY,
				"daemon: listen(%d, 5) failed errno %d (%s)\n",
			    tcps, errno,
				errno > -1 && errno < sys_nerr
					? sys_errlist[errno] : "unknown" );
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
		int i, ns, nfds;

		fd_set			readfds;
		fd_set			writefds;

		struct sockaddr_in	from;
		struct hostent		*hp;
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
		case -1:	/* failure - try again */
			if( errno != EINTR ) {
				Debug( LDAP_DEBUG_CONNS,
					"daemon: select failed (%d): %s\n",
					errno,
					errno >= 0 && errno < sys_nerr
						? sys_errlist[errno] : "unknown",
					0 );

				slapd_shutdown = -1;
			}
			errno = 0;
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
				Debug( LDAP_DEBUG_ANY,
				    "daemon: accept(%d) failed errno %d (%s)", errno,
				    tcps, errno >= 0 && errno < sys_nerr ?
				    sys_errlist[errno] : "unknown");
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

		for ( i = 0; i < nfds; i++ ) {
			int	a, r, w;

			r = FD_ISSET( i, &readfds );
			w = FD_ISSET( i, &writefds );
			if ( i != tcps && (r || w) ) {
				Debug( LDAP_DEBUG_CONNS, " %d%s%s", i,
				    r ? "r" : "", w ? "w" : "" );
			}
		}

		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );
#endif

		/* loop through the writers */
		for ( i = 0; i < nfds; i++ ) {
			if ( i == tcps ) {
				continue;
			}

			if ( FD_ISSET( i, &writefds ) ) {
				Debug( LDAP_DEBUG_CONNS,
				    "daemon: signaling write waiter on %d\n", i, 0, 0 );

				assert( FD_ISSET( 0, &slap_daemon.sd_actives) );

				/* clear the write flag */
				slapd_clr_write( i, 0 );
				
				if( connection_write( i ) < 0 ) { 
					FD_CLR( i, &readfds );
					slapd_close( i );
				}
			}
		}

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

	if( tcps >= 0 ) {
		tcp_close( tcps );
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

int slapd_daemon( struct sockaddr_in *addr )
{
	int status;

	status = ldap_pvt_thread_create( &listener_tid, 0,
		 slapd_daemon_task, addr );

	if ( status != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "listener ldap_pvt_thread_create failed (%d)\n", status, 0, 0 );
		return -1;
	} else {
		/* wait for the listener thread to complete */
		ldap_pvt_thread_join( listener_tid, (void *) NULL );
	}

	return 0;
}

void
slap_set_shutdown( int sig )
{
	slapd_shutdown = 1;
	ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );

	/* reinstall self */
	(void) SIGNAL( sig, slap_set_shutdown );
}

void
slap_do_nothing( int sig )
{
	/* reinstall self */
	(void) SIGNAL( sig, slap_do_nothing );
}
