/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"

#ifdef HAVE_TCPD
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* TCP Wrappers */

#ifdef LDAP_PF_LOCAL
#include <sys/stat.h>
#endif /* LDAP_PF_LOCAL */

/* globals */
time_t starttime;
ber_socket_t dtblsize;

#ifdef LDAP_PF_LOCAL
typedef union slap_sockaddr {
	struct sockaddr sa_addr;
	struct sockaddr_in sa_in_addr;
	struct sockaddr_un sa_un_addr;
} Sockaddr;
#endif /* LDAP_PF_LOCAL */

typedef struct slap_listener {
	char* sl_url;
	char* sl_name;
#ifdef HAVE_TLS
	int		sl_is_tls;
#endif
	ber_socket_t		sl_sd;
#ifdef LDAP_PF_LOCAL
	Sockaddr sl_sa;
#define sl_addr	sl_sa.sa_in_addr
#else	
	struct sockaddr_in	sl_addr;
#endif /* LDAP_PF_LOCAL */
} Listener;

Listener **slap_listeners = NULL;

static ber_socket_t wake_sds[2];

#ifdef NO_THREADS
static int waking;
#define WAKE_LISTENER(w) \
((w && !waking) ? tcp_write( wake_sds[1], "0", 1 ), waking=1 : 0)
#else
#define WAKE_LISTENER(w) \
do { if (w) tcp_write( wake_sds[1], "0", 1 ); } while(0)
#endif

#ifdef HAVE_NT_SERVICE_MANAGER
/* in nt_main.c */
extern ldap_pvt_thread_cond_t			started_event;
extern int	  is_NT_Service;
#endif

#ifndef HAVE_WINSOCK
static 
#endif
volatile sig_atomic_t slapd_shutdown = 0;

static ldap_pvt_thread_t	listener_tid;

static struct slap_daemon {
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

	Debug( LDAP_DEBUG_CONNS, "daemon: removing %ld%s%s\n",
		(long) s,
	    FD_ISSET(s, &slap_daemon.sd_readers) ? "r" : "",
		FD_ISSET(s, &slap_daemon.sd_writers) ? "w" : "" );

	FD_CLR( s, &slap_daemon.sd_actives );
	FD_CLR( s, &slap_daemon.sd_readers );
	FD_CLR( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_clr_write(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_set_write(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	if (!FD_ISSET(s, &slap_daemon.sd_writers))
	    FD_SET( (unsigned) s, &slap_daemon.sd_writers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_clr_read(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	FD_CLR( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_set_read(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( FD_ISSET( s, &slap_daemon.sd_actives) );
	if (!FD_ISSET(s, &slap_daemon.sd_readers))
	    FD_SET( s, &slap_daemon.sd_readers );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

static void slapd_close(ber_socket_t s) {
	Debug( LDAP_DEBUG_CONNS, "daemon: closing %ld\n",
		(long) s, 0, 0 );
	tcp_close(s);
}


static Listener * open_listener( const char* url )
{
	int	tmp, rc;
	Listener l;
	Listener *li;
	LDAPURLDesc *lud;
	char *s;
	int port;

	rc = ldap_url_parse( url, &lud );

	if( rc != LDAP_URL_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: listen URL \"%s\" parse error=%d\n",
			url, rc, 0 );
		return NULL;
	}

#ifndef HAVE_TLS
	if( lud->lud_properties & LDAP_URL_USE_SSL ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: TLS not supported (%s)\n",
			url, 0, 0 );
		ldap_free_urldesc( lud );
		return NULL;
	}

	if(! lud->lud_port ) {
		lud->lud_port = LDAP_PORT;
	}

#else
	l.sl_is_tls = (lud->lud_properties & LDAP_URL_USE_SSL);

	if(! lud->lud_port ) {
		lud->lud_port = (lud->lud_properties & LDAP_URL_USE_SSL) ? LDAPS_PORT : LDAP_PORT;
	}
#endif

#ifdef LDAP_PF_LOCAL
	if (lud->lud_protocol == LDAP_PROTO_LOCAL) {
		port = 0;
		(void) memset( (void *)&l.sl_sa.sa_un_addr, '\0', sizeof(l.sl_sa.sa_un_addr) );

		l.sl_sa.sa_un_addr.sun_family = AF_UNIX;

		/* hack: overload the host to be the path */
		if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
			strcpy( l.sl_sa.sa_un_addr.sun_path, "/tmp/.ldap-sock" );
		} else {
			if ( strlen(lud->lud_host) > (sizeof(l.sl_sa.sa_un_addr.sun_path) - 1) ) {
				Debug( LDAP_DEBUG_ANY, "domain socket path (%s) too long in URL: %s",
					lud->lud_host, url, 0);
				ldap_free_urldesc( lud );
				return NULL;
			}
			strcpy( l.sl_sa.sa_un_addr.sun_path, lud->lud_host );
		}
		unlink( l.sl_sa.sa_un_addr.sun_path ); 
#if 0
		/* I don't think we need to set this. */
		l.sl_sa.sa_un_addr.sun_len = sizeof( l.sl_sa.sa_un_addr.sun_len ) +
			sizeof( l.sl_sa.sa_un_addr.sun_family ) +
			strlen( l.sl_sa.sa_un_addr.sun_path ) + 1;
#endif
	} else {
#endif /* LDAP_PF_LOCAL */

	port = lud->lud_port;

	(void) memset( (void*) &l.sl_addr, '\0', sizeof(l.sl_addr) );

	l.sl_addr.sin_family = AF_INET;
	l.sl_addr.sin_port = htons( (unsigned short) lud->lud_port );

	if( lud->lud_host == NULL || lud->lud_host[0] == '\0'
		|| strcmp(lud->lud_host, "*") == 0 )
	{
		l.sl_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	} else {
		/* host or address was specified */
		if( !inet_aton( lud->lud_host, &l.sl_addr.sin_addr ) ) {
			struct hostent *he = gethostbyname( lud->lud_host );
			if( he == NULL ) {
				Debug( LDAP_DEBUG_ANY, "invalid host (%s) in URL: %s",
					lud->lud_host, url, 0);
				ldap_free_urldesc( lud );
				return NULL;
			}

			memcpy( &l.sl_addr.sin_addr, he->h_addr,
			       sizeof( l.sl_addr.sin_addr ) );
		}
	}
#ifdef LDAP_PF_LOCAL
	}
#endif /* LDAP_PF_LOCAL */

	ldap_free_urldesc( lud );

#ifdef LDAP_PF_LOCAL
	l.sl_sd = socket( l.sl_sa.sa_addr.sa_family, SOCK_STREAM, 0 );
	if ( l.sl_sd == AC_SOCKET_INVALID ) {
#else
	if ( (l.sl_sd = socket( AF_INET, SOCK_STREAM, 0 )) == AC_SOCKET_INVALID ) {
#endif /* LDAP_PF_LOCAL */
		int err = sock_errno();
		Debug( LDAP_DEBUG_ANY,
			"daemon: socket() failed errno=%d (%s)\n", err,
			sock_errstr(err), 0 );
		return NULL;
	}

#ifndef HAVE_WINSOCK
	if ( l.sl_sd >= dtblsize ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: listener descriptor %ld is too great %ld\n",
			(long) l.sl_sd, (long) dtblsize, 0 );
		tcp_close( l.sl_sd );
		return NULL;
	}
#endif

#ifdef LDAP_PF_LOCAL
	/* for IP sockets only */
	if ( l.sl_sa.sa_addr.sa_family == AF_INET ) {
#endif /* LDAP_PF_LOCAL */

#ifdef SO_REUSEADDR
	/* enable address reuse */
	tmp = 1;
	rc = setsockopt( l.sl_sd, SOL_SOCKET, SO_REUSEADDR,
		(char *) &tmp, sizeof(tmp) );
	if ( rc == AC_SOCKET_ERROR ) {
		int err = sock_errno();
		Debug( LDAP_DEBUG_ANY,
	       "slapd(%ld): setsockopt(SO_REUSEADDR) failed errno=%d (%s)\n",
	    	(long) l.sl_sd, err, sock_errstr(err) );
	}
#endif
#ifdef SO_KEEPALIVE
	/* enable keep alives */
	tmp = 1;
	rc = setsockopt( l.sl_sd, SOL_SOCKET, SO_KEEPALIVE,
		(char *) &tmp, sizeof(tmp) );
	if ( rc == AC_SOCKET_ERROR ) {
		int err = sock_errno();
		Debug( LDAP_DEBUG_ANY,
			"slapd(%ld): setsockopt(SO_KEEPALIVE) failed errno=%d (%s)\n",
	    	(long) l.sl_sd, err, sock_errstr(err) );
	}
#endif
#ifdef TCP_NODELAY
	/* enable no delay */
	tmp = 1;
	rc = setsockopt( l.sl_sd, IPPROTO_TCP, TCP_NODELAY,
		(char *)&tmp, sizeof(tmp) );
	if ( rc == AC_SOCKET_ERROR ) {
		int err = sock_errno();
		Debug( LDAP_DEBUG_ANY,
			"slapd(%ld): setsockopt(TCP_NODELAY) failed errno=%d (%s)\n",
	    	(long) l.sl_sd, err, sock_errstr(err) );
	}
#endif

#ifdef LDAP_PF_LOCAL
	/* close conditional */
	}

	switch ( l.sl_sa.sa_addr.sa_family ) {
		case AF_UNIX:
			rc = bind( l.sl_sd, (struct sockaddr *)&l.sl_sa,
				sizeof(l.sl_sa.sa_un_addr) );
			break;
		case AF_INET:
			rc = bind( l.sl_sd, (struct sockaddr *)&l.sl_sa,
				sizeof(l.sl_sa.sa_in_addr) );
			break;
		default:
			rc = AC_SOCKET_ERROR;
			errno = EINVAL;
			break;
	}
#else
	rc = bind( l.sl_sd, (struct sockaddr *) &l.sl_addr, sizeof(l.sl_addr) );
#endif /* LDAP_PF_LOCAL */
	if ( rc == AC_SOCKET_ERROR ) {
		int err = sock_errno();
		Debug( LDAP_DEBUG_ANY, "daemon: bind(%ld) failed errno=%d (%s)\n",
	    	(long) l.sl_sd, err, sock_errstr(err) );
		tcp_close( l.sl_sd );
		return NULL;
	}
#ifdef LDAP_PF_LOCAL
	if ( l.sl_sa.sa_addr.sa_family == AF_UNIX ) {
		if ( chmod( l.sl_sa.sa_un_addr.sun_path, S_IRWXU ) < 0 ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY, "daemon: fchmod(%ld) failed errno=%d (%s)",
				(long) l.sl_sd, err, sock_errstr(err) );
			tcp_close( l.sl_sd );
			return NULL;
		}
	}
#endif /* LDAP_PF_LOACL */
	l.sl_url = ch_strdup( url );
#ifdef LDAP_PF_LOCAL
	switch ( l.sl_sa.sa_addr.sa_family ) {
		case AF_UNIX:
			l.sl_name = ch_malloc( strlen(l.sl_sa.sa_un_addr.sun_path) + sizeof("PATH=") );
			sprintf( l.sl_name, "PATH=%s", l.sl_sa.sa_un_addr.sun_path );
			break;
		case AF_INET:
			l.sl_name = ch_malloc( sizeof("IP=255.255.255.255:65336") );
			s = inet_ntoa( l.sl_addr.sin_addr );
			sprintf( l.sl_name, "IP=%s:%d",
				s != NULL ? s : "unknown" , port );
			break;
		default:
			l.sl_name = ch_strdup( "UNKNOWN" );
			break;
	}
#else
	l.sl_name = ch_malloc( sizeof("IP=255.255.255.255:65336") );
	s = inet_ntoa( l.sl_addr.sin_addr );
	sprintf( l.sl_name, "IP=%s:%d",
		s != NULL ? s : "unknown" , port );
#endif /* LDAP_PF_LOCAL */

	li = ch_malloc( sizeof( Listener ) );
	*li = l;

	Debug( LDAP_DEBUG_TRACE, "daemon: initialized %s\n",
		l.sl_url, 0, 0 );

	return li;
}

static int sockinit(void);
static int sockdestroy(void);

int slapd_daemon_init( char *urls )
{
	int i, rc;
	char **u;

	Debug( LDAP_DEBUG_ARGS, "daemon_init: %s\n",
		urls ? urls : "<null>", 0, 0 );

	if( (rc = sockinit()) != 0 ) {
		return rc;
	}

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

	/* open a pipe (or something equivalent connected to itself).
	 * we write a byte on this fd whenever we catch a signal. The main
	 * loop will be select'ing on this socket, and will wake up when
	 * this byte arrives.
	 */
	if( (rc = lutil_pair( wake_sds )) < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: lutil_pair() failed rc=%d\n", rc, 0, 0 );
		return rc;
	}

	FD_ZERO( &slap_daemon.sd_readers );
	FD_ZERO( &slap_daemon.sd_writers );

	if( urls == NULL ) {
		urls = "ldap:///";
	}

	u = str2charray( urls, " " );

	if( u == NULL || u[0] == NULL ) {
		Debug( LDAP_DEBUG_ANY, "daemon_init: no urls (%s) provided.\n",
			urls, 0, 0 );

		return -1;
	}

	for( i=0; u[i] != NULL; i++ ) {
		Debug( LDAP_DEBUG_TRACE, "daemon_init: listen on %s\n",
			u[i], 0, 0 );
	}

	if( i == 0 ) {
		Debug( LDAP_DEBUG_ANY, "daemon_init: no listeners to open (%s)\n",
			urls, 0, 0 );
		charray_free( u );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "daemon_init: %d listeners to open...\n",
		i, 0, 0 );

	slap_listeners = ch_malloc( (i+1)*sizeof(Listener *) );

	for(i = 0; u[i] != NULL; i++ ) {
		slap_listeners[i] = open_listener( u[i] );

		if( slap_listeners[i] == NULL ) {
			charray_free( u );
			return -1;
		}
	}
	slap_listeners[i] = NULL;

	Debug( LDAP_DEBUG_TRACE, "daemon_init: %d listeners opened\n",
		i, 0, 0 );

	charray_free( u );
	ldap_pvt_thread_mutex_init( &slap_daemon.sd_mutex );
	return !i;
}


int
slapd_daemon_destroy(void)
{
	connections_destroy();
	tcp_close( wake_sds[1] );
	tcp_close( wake_sds[0] );
	sockdestroy();
	return 0;
}


static void *
slapd_daemon_task(
	void *ptr
)
{
	int l;
	time_t	last_idle_check = slap_get_time();
	time( &starttime );

	for ( l = 0; slap_listeners[l] != NULL; l++ ) {
		if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
			continue;

		if ( listen( slap_listeners[l]->sl_sd, 5 ) == -1 ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"daemon: listen(%s, 5) failed errno=%d (%s)\n",
					slap_listeners[l]->sl_url, err,
					sock_errstr(err) );
			return( (void*)-1 );
		}

		slapd_add( slap_listeners[l]->sl_sd );
	}

#ifdef HAVE_NT_SERVICE_MANAGER
	if ( started_event != NULL ) {
		ldap_pvt_thread_cond_signal( &started_event );
	}
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
		time_t	now = slap_get_time();


		fd_set			readfds;
		fd_set			writefds;
#ifdef LDAP_PF_LOCAL
		Sockaddr		from;
/* minimize impact, undefine later. */
#define	sin_addr sa_in_addr.sin_addr
#define	sin_port sa_in_addr.sin_port
#else
		struct sockaddr_in	from;
#endif /* LDAP_PF_LOCAL */
#if defined(SLAPD_RLOOKUPS)
        struct hostent		*hp;
#endif
		struct timeval		zero;
		struct timeval		*tvp;

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
			if(FD_ISSET( &slap_sd_readers, s )) {
				FD_SET( s, &readfds );
			}
			if(FD_ISSET( &slap_sd_writers, s )) {
				FD_SET( s, &writefds );
			}
		}
#else
		memcpy( &readfds, &slap_daemon.sd_readers, sizeof(fd_set) );
		memcpy( &writefds, &slap_daemon.sd_writers, sizeof(fd_set) );
#endif
		assert(!FD_ISSET(wake_sds[0], &readfds));
		FD_SET( wake_sds[0], &readfds );

		for ( l = 0; slap_listeners[l] != NULL; l++ ) {
			if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
				continue;
			if (!FD_ISSET(slap_listeners[l]->sl_sd, &readfds))
			    FD_SET( slap_listeners[l]->sl_sd, &readfds );
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

		for ( l = 0; slap_listeners[l] != NULL; l++ ) {
			if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
				continue;

			Debug( LDAP_DEBUG_CONNS,
				"daemon: select: listen=%d active_threads=%d tvp=%s\n",
					slap_listeners[l]->sl_sd, at,
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
				int err = sock_errno();

				if( err == EBADF 
#ifdef HAVE_WINSOCK
					|| err == WSAENOTSOCK	/* you'd think this would be EBADF */
#endif
				) {
					if (++ebadf < SLAPD_EBADF_LIMIT)
						continue;
				}

				if( err != EINTR ) {
					Debug( LDAP_DEBUG_CONNS,
						"daemon: select failed (%d): %s\n",
						err, sock_errstr(err), 0 );

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

		if( FD_ISSET( wake_sds[0], &readfds ) ) {
			char c[BUFSIZ];
			tcp_read( wake_sds[0], c, sizeof(c) );
#ifdef NO_THREADS
			waking = 0;
#endif
			continue;
		}

		for ( l = 0; slap_listeners[l] != NULL; l++ ) {
			ber_int_t s;
			socklen_t len = sizeof(from);
			long id;

			char	*dnsname;
			char	*peeraddr;
#ifdef LDAP_PF_LOCAL
			char	peername[MAXPATHLEN + sizeof("PATH=")];
#else
			char	peername[sizeof("IP=255.255.255.255:65336")];
#endif /* LDAP_PF_LOCAL */
			if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
				continue;

			if ( !FD_ISSET( slap_listeners[l]->sl_sd, &readfds ) )
				continue;

			if ( (s = accept( slap_listeners[l]->sl_sd,
				(struct sockaddr *) &from, &len )) == AC_SOCKET_INVALID )
			{
				int err = sock_errno();
				Debug( LDAP_DEBUG_ANY,
				    "daemon: accept(%ld) failed errno=%d (%s)\n",
				    (long) slap_listeners[l]->sl_sd, err,
				    sock_errstr(err) );
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

			if ( getpeername( s, (struct sockaddr *) &from, &len ) != 0 ) {
				int err = sock_errno();
				Debug( LDAP_DEBUG_ANY,
					"daemon: getpeername( %ld ) failed: errno=%d (%s)\n",
					(long) s, err, sock_errstr(err) );
				slapd_close(s);
				continue;
			}

#ifdef LDAP_PF_LOCAL
			switch ( from.sa_addr.sa_family ) {
			case AF_UNIX:
				sprintf( peername, "PATH=%s", from.sa_un_addr.sun_path );
				break;
			case AF_INET:
#endif /* LDAP_PF_LOCAL */
			peeraddr = inet_ntoa( from.sin_addr );
			sprintf( peername, "IP=%s:%d",
				peeraddr != NULL ? peeraddr : "unknown",
				(unsigned) ntohs( from.sin_port ) );

#if defined(SLAPD_RLOOKUPS)
			hp = gethostbyaddr( (char *)
			    &(from.sin_addr),
			    sizeof(from.sin_addr), AF_INET );

			if(hp) {
				dnsname = ldap_pvt_str2lower( hp->h_name );

			} else {
				dnsname = NULL;
			}
#else
			dnsname = NULL;
#endif

#ifdef HAVE_TCPD
			if( !hosts_ctl("slapd",
				dnsname != NULL ? dnsname : STRING_UNKNOWN,
				peeraddr != NULL ? peeraddr : STRING_UNKNOWN,
				STRING_UNKNOWN ))
			{
				/* DENY ACCESS */
				Statslog( LDAP_DEBUG_ANY,
			   	 "fd=%ld connection from %s (%s) denied.\n",
			   	 	(long) s,
					dnsname != NULL ? dnsname : "unknown",
					peeraddr != NULL ? peeraddr : "unknown",
			   	  0, 0 );

				slapd_close(s);
				continue;
			}
#endif /* HAVE_TCPD */
#ifdef LDAP_PF_LOCAL
				break;
			default:
				slapd_close(s);
				continue;
			}
#undef	sin_addr
#undef	sin_port
#endif /* LDAP_PF_LOCAL */

			if( (id = connection_init(s,
				slap_listeners[l]->sl_url,
				dnsname != NULL ? dnsname : "unknown",
				peername,
				slap_listeners[l]->sl_name,
#ifdef HAVE_TLS
				slap_listeners[l]->sl_is_tls
#else
				0
#endif
				)) < 0 )
			{
				Debug( LDAP_DEBUG_ANY,
					"daemon: connection_init(%ld, %s, %s) failed.\n",
					(long) s,
					peername,
					slap_listeners[l]->sl_name );
				slapd_close(s);
				continue;
			}

			Statslog( LDAP_DEBUG_STATS,
				"daemon: conn=%ld fd=%ld connection from %s (%s) accepted.\n",
				id, (long) s,
				peername,
				slap_listeners[l]->sl_name,
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
			int	r, w;
			int	is_listener = 0;

			for ( l = 0; slap_listeners[l] != NULL; l++ ) {
				if ( i == slap_listeners[l]->sl_sd ) {
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

			for ( l = 0; slap_listeners[l] != NULL; l++ ) {
				if ( i == slap_listeners[l]->sl_sd ) {
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

			for ( l = 0; slap_listeners[l] != NULL; l++ ) {
				if ( rd == slap_listeners[l]->sl_sd ) {
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
#ifdef HAVE_NT_SERVICE_MANAGER
		if (slapd_shutdown == -1)
		    Debug( LDAP_DEBUG_TRACE,
			  "daemon: shutdown initiated by Service Manager.\n",
			  0, 0, 0);
		else
#endif
		Debug( LDAP_DEBUG_TRACE,
			"daemon: abnormal condition, shutdown initiated.\n",
			0, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: no active streams, shutdown initiated.\n",
			0, 0, 0 );
	}

	for ( l = 0; slap_listeners[l] != NULL; l++ ) {
		if ( slap_listeners[l]->sl_sd != AC_SOCKET_INVALID ) {
#ifdef LDAP_PF_LOCAL
			if ( slap_listeners[l]->sl_sa.sa_addr.sa_family == AF_UNIX ) {
				unlink( slap_listeners[l]->sl_sa.sa_un_addr.sun_path );
			}
#endif /* LDAP_PF_LOCAL */
			slapd_close( slap_listeners[l]->sl_sd );
			break;
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


int slapd_daemon( void )
{
	int rc;

	connections_init();

#define SLAPD_LISTENER_THREAD 1
#if defined( SLAPD_LISTENER_THREAD ) || !defined(HAVE_PTHREADS)

	/* listener as a separate THREAD */
	rc = ldap_pvt_thread_create( &listener_tid,
		0, slapd_daemon_task, NULL );

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "listener ldap_pvt_thread_create failed (%d)\n", rc, 0, 0 );
		return rc;
	}

	/* wait for the listener thread to complete */
	ldap_pvt_thread_join( listener_tid, (void *) NULL );
#else
	/* expermimental code */
	listener_tid = pthread_self();
	slapd_daemon_task( NULL );
#endif

	return 0;

}

#ifdef HAVE_WINSOCK2
int sockinit(void)
{
    WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	wVersionRequested = MAKEWORD( 2, 0 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 ) {
		/* Tell the user that we couldn't find a usable */
		/* WinSock DLL.                                  */
		return -1;
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
	    WSACleanup();
	    return -1; 
	}

	/* The WinSock DLL is acceptable. Proceed. */
	return 0;
}

int sockdestroy(void)
{
	WSACleanup();
	return 0;
}

#elif HAVE_WINSOCK
static int sockinit(void)
{
	WSADATA wsaData;
	if ( WSAStartup( 0x0101, &wsaData ) != 0 ) {
	    return -1;
	}
	return 0;
}
static int sockdestroy(void)
{
	WSACleanup();
	return 0;
}

#else
static int sockinit(void)
{
	return 0;
}
static int sockdestroy(void)
{
	return 0;
}
#endif

RETSIGTYPE
slap_sig_shutdown( int sig )
{
	Debug(LDAP_DEBUG_TRACE, "slap_sig_shutdown: signal %d\n", sig, 0, 0);

	/*
	 * If the NT Service Manager is controlling the server, we don't
	 * want SIGBREAK to kill the server. For some strange reason,
	 * SIGBREAK is generated when a user logs out.
	 */

#if HAVE_NT_SERVICE_MANAGER && SIGBREAK
	if (is_NT_Service && sig == SIGBREAK)
	    Debug(LDAP_DEBUG_TRACE, "slap_sig_shutdown: SIGBREAK ignored.\n",
		  0, 0, 0);
	else
#endif
	slapd_shutdown = sig;

	WAKE_LISTENER(1);

	/* reinstall self */
	(void) SIGNAL( sig, slap_sig_shutdown );
}

RETSIGTYPE
slap_sig_wake( int sig )
{
	WAKE_LISTENER(1);

	/* reinstall self */
	(void) SIGNAL( sig, slap_sig_wake );
}
