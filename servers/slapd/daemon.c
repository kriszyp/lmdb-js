
/* Revision history
 *
 * 5-Jun-96	hodges
 *	Added locking of new_conn_mutex when traversing the c[] array.
 */

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

int		dtblsize;
Connection	*c;

static volatile sig_atomic_t slapd_shutdown = 0;

/* a link to the slapd.conf configuration parameters */
extern char *slapd_pid_file;
extern char *slapd_args_file;

void *
slapd_daemon(
	void *ptr
)
{
	struct sockaddr_in *addr = ptr;
	int			i;
	int			tcps, ns;
	fd_set			readfds;
	fd_set			writefds;
	FILE			*fp;

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

	c = (Connection *) ch_calloc( (size_t) dtblsize, sizeof(Connection) );

	for ( i = 0; i < dtblsize; i++ ) {
		c[i].c_dn = NULL;
		c[i].c_cdn = NULL;
		c[i].c_addr = NULL;
		c[i].c_domain = NULL;
		c[i].c_ops = NULL;
		lber_pvt_sb_init( &c[i].c_sb );
		ldap_pvt_thread_mutex_init( &c[i].c_dnmutex );
		ldap_pvt_thread_mutex_init( &c[i].c_opsmutex );
		ldap_pvt_thread_mutex_init( &c[i].c_pdumutex );
		ldap_pvt_thread_cond_init( &c[i].c_wcv );
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

	if ( bind( tcps, (struct sockaddr *) addr, sizeof(*addr) ) == -1 ) {
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

	Debug( LDAP_DEBUG_ANY, "slapd starting\n", 0, 0, 0 );

	if (( slapd_pid_file != NULL ) &&
			(( fp = fopen( slapd_pid_file, "w" )) != NULL )) {
		fprintf( fp, "%d\n", (int) getpid() );
		fclose( fp );
	}

	if (( slapd_args_file != NULL ) &&
			(( fp = fopen( slapd_args_file, "w" )) != NULL )) {
		for ( i = 0; i < g_argc; i++ ) {
			fprintf( fp, "%s ", g_argv[i] );
		}
		fprintf( fp, "\n" );
		fclose( fp );
	}

	while ( !slapd_shutdown ) {
		struct sockaddr_in	from;
		struct hostent		*hp;
		struct timeval		zero;
		struct timeval		*tvp;
		int			len;
	   	int			data_ready;

		char	*client_name;
		char	*client_addr;

		FD_ZERO( &writefds );
		FD_ZERO( &readfds );
		FD_SET( tcps, &readfds );

		zero.tv_sec = 0;
		zero.tv_usec = 0;

		ldap_pvt_thread_mutex_lock( &active_threads_mutex );
		Debug( LDAP_DEBUG_CONNS,
		    "listening for connections on %d, activity on:",
		    tcps, 0, 0 );
	   
	   	data_ready = 0;

		ldap_pvt_thread_mutex_lock( &new_conn_mutex );
		for ( i = 0; i < dtblsize; i++ ) {
			if ( (c[i].c_state != SLAP_C_INACTIVE)  
				&& (c[i].c_state != SLAP_C_CLOSING) )
			{
				assert(lber_pvt_sb_in_use( &c[i].c_sb ));

				FD_SET( lber_pvt_sb_get_desc(&c[i].c_sb),
					&readfds );
				if (lber_pvt_sb_data_ready(&c[i].c_sb))
			     		data_ready = 1;
				if ( c[i].c_writewaiter ) {
					FD_SET( lber_pvt_sb_get_desc(&c[i].c_sb),
						&writefds );
				}
				Debug( LDAP_DEBUG_CONNS, " %dr%s", i,
				    c[i].c_writewaiter ? "w" : "", 0 );
			}
		}

		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );
		ldap_pvt_thread_mutex_unlock( &new_conn_mutex );

		Debug( LDAP_DEBUG_CONNS, "before select active_threads %d\n",
		    active_threads, 0, 0 );
#if defined( HAVE_YIELDING_SELECT ) || defined( NO_THREADS )
		tvp = (data_ready) ? &zero : NULL;
#else
		tvp = (active_threads || data_ready) ? &zero : NULL;
#endif
		ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

		switch ( i = select( dtblsize, &readfds, &writefds, 0, tvp ) ) {
		case -1:	/* failure - try again */
			Debug( LDAP_DEBUG_CONNS,
			    "select failed errno %d (%s)\n",
			    errno, errno > -1 && errno < sys_nerr ?
			    sys_errlist[errno] : "unknown", 0 );
			continue;

		case 0:		/* timeout - let threads run */
			Debug( LDAP_DEBUG_CONNS, "select timeout - yielding\n",
			    0, 0, 0 );
		   	if (!data_ready)
		     		ldap_pvt_thread_yield();
			continue;

		default:	/* something happened - deal with it */
			Debug( LDAP_DEBUG_CONNS, "select activity on %d descriptors\n", i, 0, 0 );
			;	/* FALL */
		}
		ldap_pvt_thread_mutex_lock( &currenttime_mutex );
		time( &currenttime );
		ldap_pvt_thread_mutex_unlock( &currenttime_mutex );

		/* new connection */
		ldap_pvt_thread_mutex_lock( &new_conn_mutex );
		if ( FD_ISSET( tcps, &readfds ) ) {
			len = sizeof(from);
			if ( (ns = accept( tcps, (struct sockaddr *) &from,
			    &len )) == -1 ) {
				Debug( LDAP_DEBUG_ANY,
				    "accept() failed errno %d (%s)", errno,
				    errno > -1 && errno < sys_nerr ?
				    sys_errlist[errno] : "unknown", 0 );
				ldap_pvt_thread_mutex_unlock( &new_conn_mutex );
				continue;
			}

			/* make sure descriptor number isn't too great */
			if ( ns >= dtblsize ) {
				Debug( LDAP_DEBUG_ANY,
					"new connection on %d beyond descriptor table size %d\n",
					ns, dtblsize, 0 );
				close(ns);
				ldap_pvt_thread_mutex_unlock( &new_conn_mutex );
				continue;
			}
		   
			Debug( LDAP_DEBUG_CONNS, "new connection on %d\n", ns,
			    0, 0 );

			len = sizeof(from);

			if ( getpeername( ns, (struct sockaddr *) &from, &len )
			    == 0 ) {
				char *s;
				client_addr = inet_ntoa( from.sin_addr );

#if defined(SLAPD_RLOOKUPS) || defined(HAVE_TCPD)
				hp = gethostbyaddr( (char *)
				    &(from.sin_addr.s_addr),
				    sizeof(from.sin_addr.s_addr), AF_INET );

				if(hp) {
					client_name = hp->h_name;

					/* normalize the domain */
					for ( s = client_name; *s; s++ ) {
						*s = TOLOWER( (unsigned char) *s );
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
			   	 	ns,
						client_name == NULL ? "unknown" : client_name,
						client_addr == NULL ? "unknown" : client_addr,
			   	  0, 0 );

				ldap_pvt_thread_mutex_unlock( &new_conn_mutex );
				continue;
			}
#endif /* HAVE_TCPD */


			ldap_pvt_thread_mutex_lock( &ops_mutex );
			c[ns].c_connid = num_conns++;
			ldap_pvt_thread_mutex_unlock( &ops_mutex );

			Statslog( LDAP_DEBUG_STATS,
			    "conn=%d fd=%d connection from %s (%s) accepted.\n",
			    	c[ns].c_connid, ns,
					client_name == NULL ? "unknown" : client_name,
					client_addr == NULL ? "unknown" : client_addr,
			     0 );

			if ( c[ns].c_addr != NULL ) {
				free( c[ns].c_addr );
			}
			c[ns].c_addr = ch_strdup( client_addr );

			if ( c[ns].c_domain != NULL ) {
				free( c[ns].c_domain );
			}

			c[ns].c_domain = ch_strdup( client_name == NULL
				? "" : client_name );

			ldap_pvt_thread_mutex_lock( &c[ns].c_dnmutex );
			if ( c[ns].c_dn != NULL ) {
				free( c[ns].c_dn );
				c[ns].c_dn = NULL;
			}
			if ( c[ns].c_cdn != NULL ) {
				free( c[ns].c_cdn );
				c[ns].c_cdn = NULL;
			}
			ldap_pvt_thread_mutex_unlock( &c[ns].c_dnmutex );

			c[ns].c_starttime = currenttime;
			c[ns].c_ops_received = 0;
			c[ns].c_ops_executing = 0;
			c[ns].c_ops_pending = 0;
			c[ns].c_ops_completed = 0;

			lber_pvt_sb_set_desc( &c[ns].c_sb, ns );
			lber_pvt_sb_set_io( &c[ns].c_sb, &lber_pvt_sb_io_tcp, NULL );
		   
			if (lber_pvt_sb_set_nonblock( &c[ns].c_sb, 1)<0) {			   
				Debug( LDAP_DEBUG_ANY,
				    "FIONBIO ioctl on %d failed\n", ns, 0, 0 );
			}

			c[ns].c_state = SLAP_C_ACTIVE;
		}
		ldap_pvt_thread_mutex_unlock( &new_conn_mutex );

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

				ldap_pvt_thread_mutex_lock( &active_threads_mutex );
				active_threads++;
				c[i].c_writewaiter = 0;
				ldap_pvt_thread_cond_signal( &c[i].c_wcv );
				ldap_pvt_thread_mutex_unlock( &active_threads_mutex );
			}

			if ( FD_ISSET( i, &readfds ) || 
				lber_pvt_sb_data_ready( &c[i].c_sb ) ) {
				Debug( LDAP_DEBUG_CONNS,
				    "read activity on %d\n", i, 0, 0 );

				connection_activity( &c[i] );
			}
		}

		ldap_pvt_thread_yield();
	}

	Debug( LDAP_DEBUG_TRACE,
	    "slapd shutdown: shutdown initiated.\n",
	    0, 0, 0 );

	close( tcps );

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

void
slap_set_shutdown( int sig )
{
	Debug( LDAP_DEBUG_ANY, "slapd got shutdown signal %d\n", sig, 0, 0 );
	slapd_shutdown = 1;
	ldap_pvt_thread_kill( listener_tid, LDAP_SIGUSR1 );

	/* reinstall self */
	(void) SIGNAL( sig, slap_set_shutdown );
}

void
slap_do_nothing( int sig )
{
	Debug( LDAP_DEBUG_TRACE, "slapd got do_nothing signal %d\n", sig, 0, 0 );

	/* reinstall self */
	(void) SIGNAL( sig, slap_do_nothing );
}
