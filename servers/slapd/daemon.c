#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#ifdef _AIX
#include <sys/select.h>
#endif
#include "slap.h"
#include "portable.h"
#include "ldapconfig.h"
#ifdef NEED_FILIO
#include <sys/filio.h>
#else /* NEED_FILIO */
#include <sys/ioctl.h>
#endif /* NEED_FILIO */
#ifdef USE_SYSCONF
#include <unistd.h>
#endif /* USE_SYSCONF */

extern Operation	*op_add();

#ifndef SYSERRLIST_IN_STDIO
extern int		sys_nerr;
extern char		*sys_errlist[];
#endif
extern time_t		currenttime;
extern pthread_mutex_t	currenttime_mutex;
extern int		active_threads;
extern pthread_mutex_t	active_threads_mutex;
extern pthread_mutex_t	new_conn_mutex;
extern int		slapd_shutdown;
extern pthread_t	listener_tid;
extern int		num_conns;
extern pthread_mutex_t	ops_mutex;
extern int		g_argc;
extern char		**g_argv;

int		dtblsize;
Connection	*c;

static void	set_shutdown();
static void	do_nothing();

void
daemon(
    int	port
)
{
	Operation		*o;
	BerElement		ber;
	unsigned long		len, tag, msgid;
	int			i;
	int			tcps, ns;
	struct sockaddr_in	addr;
	fd_set			readfds;
	fd_set			writefds;
	FILE			*fp;
	int			on = 1;

#ifdef USE_SYSCONF
        dtblsize = sysconf( _SC_OPEN_MAX );
#else /* USE_SYSCONF */
        dtblsize = getdtablesize();
#endif /* USE_SYSCONF */
	/*
	 * Add greg@greg.rim.or.jp
	 */
	if(dtblsize > FD_SETSIZE) {
		dtblsize = FD_SETSIZE;
	}
	c = (Connection *) ch_calloc( 1, dtblsize * sizeof(Connection) );

	for ( i = 0; i < dtblsize; i++ ) {
		c[i].c_dn = NULL;
		c[i].c_addr = NULL;
		c[i].c_domain = NULL;
		c[i].c_ops = NULL;
		c[i].c_sb.sb_sd = -1;
		c[i].c_sb.sb_options = LBER_NO_READ_AHEAD;
		c[i].c_sb.sb_naddr = 0;
		c[i].c_sb.sb_ber.ber_buf = NULL;
		c[i].c_sb.sb_ber.ber_ptr = NULL;
		c[i].c_sb.sb_ber.ber_end = NULL;
		c[i].c_writewaiter = 0;
		c[i].c_connid = 0;
		pthread_mutex_init( &c[i].c_dnmutex,
		    pthread_mutexattr_default );
		pthread_mutex_init( &c[i].c_opsmutex,
		    pthread_mutexattr_default );
		pthread_mutex_init( &c[i].c_pdumutex,
		    pthread_mutexattr_default );
		pthread_cond_init( &c[i].c_wcv, pthread_condattr_default );
	}

	if ( (tcps = socket( AF_INET, SOCK_STREAM, 0 )) == -1 ) {
		Debug( LDAP_DEBUG_ANY, "socket() failed errno %d (%s)", errno,
		    errno > -1 && errno < sys_nerr ? sys_errlist[errno] :
		    "unknown", 0 );
		exit( 1 );
	}

	i = 1;
	if ( setsockopt( tcps, SOL_SOCKET, SO_REUSEADDR, (char *) &i,
	    sizeof(i) ) == -1 ) {
		Debug( LDAP_DEBUG_ANY, "setsockopt() failed errno %d (%s)",
		    errno, errno > -1 && errno < sys_nerr ? sys_errlist[errno] :
		    "unknown", 0 );
	}

	(void) memset( (void *) &addr, '\0', sizeof(addr) );
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons( port );
	if ( bind( tcps, (struct sockaddr *) &addr, sizeof(addr) ) == -1 ) {
		Debug( LDAP_DEBUG_ANY, "bind() failed errno %d (%s)\n",
		    errno, errno > -1 && errno < sys_nerr ? sys_errlist[errno] :
		    "unknown", 0 );
		exit( 1 );
	}

	if ( listen( tcps, 5 ) == -1 ) {
		Debug( LDAP_DEBUG_ANY, "listen() failed errno %d (%s)",
		    errno, errno > -1 && errno < sys_nerr ? sys_errlist[errno] :
		    "unknown", 0 );
		exit( 1 );
	}

	(void) SIGNAL( SIGPIPE, SIG_IGN );
	(void) SIGNAL( SIGUSR1, (void *) do_nothing );
	(void) SIGNAL( SIGUSR2, (void *) set_shutdown );
	(void) SIGNAL( SIGTERM, (void *) set_shutdown );
	(void) SIGNAL( SIGINT, (void *) set_shutdown );
	(void) SIGNAL( SIGHUP, (void *) set_shutdown );

	Debug( LDAP_DEBUG_ANY, "slapd starting\n", 0, 0, 0 );
#ifdef SLAPD_PIDFILE
	if ( (fp = fopen( SLAPD_PIDFILE, "w" )) != NULL ) {
		fprintf( fp, "%d\n", getpid() );
		fclose( fp );
	}
#endif
#ifdef SLAPD_ARGSFILE
	if ( (fp = fopen( SLAPD_ARGSFILE, "w" )) != NULL ) {
		for ( i = 0; i < g_argc; i++ ) {
			fprintf( fp, "%s ", g_argv[i] );
		}
		fprintf( fp, "\n" );
		fclose( fp );
	}
#endif

	while ( !slapd_shutdown ) {
		struct sockaddr_in	from;
		struct hostent		*hp;
		struct timeval		zero;
		struct timeval		*tvp;
		int			len, pid;

		FD_ZERO( &writefds );
		FD_ZERO( &readfds );
		FD_SET( tcps, &readfds );

		pthread_mutex_lock( &active_threads_mutex );
		Debug( LDAP_DEBUG_CONNS,
		    "listening for connections on %d, activity on:",
		    tcps, 0, 0 );
		for ( i = 0; i < dtblsize; i++ ) {
			if ( c[i].c_sb.sb_sd != -1 ) {
				FD_SET( c[i].c_sb.sb_sd, &readfds );

				if ( c[i].c_writewaiter ) {
					FD_SET( c[i].c_sb.sb_sd, &writefds );
				}
				Debug( LDAP_DEBUG_CONNS, " %dr%s", i,
				    c[i].c_writewaiter ? "w" : "", 0 );
			}
		}
		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );

		zero.tv_sec = 0;
		zero.tv_usec = 0;
		Debug( LDAP_DEBUG_CONNS, "before select active_threads %d\n",
		    active_threads, 0, 0 );
#ifdef PTHREAD_PREEMPTIVE
		tvp = NULL;
#else
		tvp = active_threads ? &zero : NULL;
#endif
		pthread_mutex_unlock( &active_threads_mutex );

		switch ( select( dtblsize, &readfds, &writefds, 0, tvp ) ) {
		case -1:	/* failure - try again */
			Debug( LDAP_DEBUG_CONNS,
			    "select failed errno %d (%s)\n",
			    errno, errno > -1 && errno < sys_nerr ?
			    sys_errlist[errno] : "unknown", 0 );
			continue;

		case 0:		/* timeout - let threads run */
			Debug( LDAP_DEBUG_CONNS, "select timeout - yielding\n",
			    0, 0, 0 );
			pthread_yield();
			continue;

		default:	/* something happened - deal with it */
			Debug( LDAP_DEBUG_CONNS, "select activity\n", 0, 0, 0 );
			;	/* FALL */
		}
		pthread_mutex_lock( &currenttime_mutex );
		time( &currenttime );
		pthread_mutex_unlock( &currenttime_mutex );

		/* new connection */
		pthread_mutex_lock( &new_conn_mutex );
		if ( FD_ISSET( tcps, &readfds ) ) {
			len = sizeof(from);
			if ( (ns = accept( tcps, (struct sockaddr *) &from,
			    &len )) == -1 ) {
				Debug( LDAP_DEBUG_ANY,
				    "accept() failed errno %d (%s)", errno,
				    errno > -1 && errno < sys_nerr ?
				    sys_errlist[errno] : "unknown", 0 );
				pthread_mutex_unlock( &new_conn_mutex );
				continue;
			}
			if ( ioctl( ns, FIONBIO, (caddr_t) &on ) == -1 ) {
				Debug( LDAP_DEBUG_ANY,
				    "FIONBIO ioctl on %d faled\n", ns, 0, 0 );
			}
			c[ns].c_sb.sb_sd = ns;
			Debug( LDAP_DEBUG_CONNS, "new connection on %d\n", ns,
			    0, 0 );

			pthread_mutex_lock( &ops_mutex );
			c[ns].c_connid = num_conns++;
			pthread_mutex_unlock( &ops_mutex );
			len = sizeof(from);
			if ( getpeername( ns, (struct sockaddr *) &from, &len )
			    == 0 ) {
				char	*s;
#ifdef REVERSE_LOOKUP
				hp = gethostbyaddr( (char *)
				    &(from.sin_addr.s_addr),
				    sizeof(from.sin_addr.s_addr), AF_INET );
#else
				hp = NULL;
#endif

				Statslog( LDAP_DEBUG_STATS,
				    "conn=%d fd=%d connection from %s (%s)\n",
				    c[ns].c_connid, ns, hp == NULL ? "unknown"
				    : hp->h_name, inet_ntoa( from.sin_addr ),
				    0 );

				if ( c[ns].c_addr != NULL ) {
					free( c[ns].c_addr );
				}
				c[ns].c_addr = strdup( inet_ntoa(
				    from.sin_addr ) );
				if ( c[ns].c_domain != NULL ) {
					free( c[ns].c_domain );
				}
				c[ns].c_domain = strdup( hp == NULL ? "" :
				    hp->h_name );
				/* normalize the domain */
				for ( s = c[ns].c_domain; *s; s++ ) {
					*s = TOLOWER( *s );
				}
			} else {
				Statslog( LDAP_DEBUG_STATS,
				    "conn=%d fd=%d connection from unknown\n",
				    c[ns].c_connid, ns, 0, 0, 0 );
			}
			pthread_mutex_lock( &c[ns].c_dnmutex );
			if ( c[ns].c_dn != NULL ) {
				free( c[ns].c_dn );
				c[ns].c_dn = NULL;
			}
			pthread_mutex_unlock( &c[ns].c_dnmutex );
			c[ns].c_starttime = currenttime;
			c[ns].c_opsinitiated = 0;
			c[ns].c_opscompleted = 0;
		}
		pthread_mutex_unlock( &new_conn_mutex );

		Debug( LDAP_DEBUG_CONNS, "activity on:", 0, 0, 0 );
		for ( i = 0; i < dtblsize; i++ ) {
			int	r, w;

			r = FD_ISSET( i, &readfds );
			w = FD_ISSET( i, &writefds );
			if ( i != tcps && (r || w) ) {
				Debug( LDAP_DEBUG_CONNS, " %d%s%s", i,
				    r ? "r" : "", w ? "w" : "" );
			}
		}
		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );

		for ( i = 0; i < dtblsize; i++ ) {
			if ( i == tcps || (! FD_ISSET( i, &readfds ) &&
			    ! FD_ISSET( i, &writefds )) ) {
				continue;
			}

			if ( FD_ISSET( i, &writefds ) ) {
				Debug( LDAP_DEBUG_CONNS,
				    "signaling write waiter on %d\n", i, 0, 0 );

				pthread_mutex_lock( &active_threads_mutex );
				pthread_cond_signal( &c[i].c_wcv );
				c[i].c_writewaiter = 0;
				active_threads++;
				pthread_mutex_unlock( &active_threads_mutex );
			}

			if ( FD_ISSET( i, &readfds ) ) {
				Debug( LDAP_DEBUG_CONNS,
				    "read activity on %d\n", i, 0, 0 );

				connection_activity( &c[i] );
			}
		}

		pthread_yield();
	}

	close( tcps );
	pthread_mutex_lock( &active_threads_mutex );
	Debug( LDAP_DEBUG_ANY,
	    "slapd shutting down - waiting for %d threads to terminate\n",
	    active_threads, 0, 0 );
	while ( active_threads > 0 ) {
		pthread_mutex_unlock( &active_threads_mutex );
		pthread_yield();
		pthread_mutex_lock( &active_threads_mutex );
	}
	pthread_mutex_unlock( &active_threads_mutex );

	/* let backends do whatever cleanup they need to do */
	Debug( LDAP_DEBUG_TRACE,
	    "slapd shutting down - waiting for backends to close down\n", 0, 0,
	    0 );
	be_close();
	Debug( LDAP_DEBUG_ANY, "slapd stopping\n", 0, 0, 0 );
}

static void
set_shutdown()
{
	Debug( LDAP_DEBUG_ANY, "slapd got shutdown signal\n", 0, 0, 0 );
	slapd_shutdown = 1;
	pthread_kill( listener_tid, SIGUSR1 );
	(void) SIGNAL( SIGUSR2, (void *) set_shutdown );
	(void) SIGNAL( SIGTERM, (void *) set_shutdown );
	(void) SIGNAL( SIGINT, (void *) set_shutdown );
	(void) SIGNAL( SIGHUP, (void *) set_shutdown );
}

static void
do_nothing()
{
	Debug( LDAP_DEBUG_TRACE, "slapd got SIGUSR1\n", 0, 0, 0 );
	(void) SIGNAL( SIGUSR1, (void *) do_nothing );
}
