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

typedef union slap_sockaddr {
	struct sockaddr sa_addr;
	struct sockaddr_in sa_in_addr;
#ifdef LDAP_PF_INET6
	struct sockaddr_in6 sa_in6_addr;
#endif
#ifdef LDAP_PF_LOCAL
	struct sockaddr_un sa_un_addr;
#endif
} Sockaddr;

typedef struct slap_listener {
	char* sl_url;
	char* sl_name;
#ifdef HAVE_TLS
	int		sl_is_tls;
#endif
	ber_socket_t		sl_sd;
	Sockaddr sl_sa;
#define sl_addr	sl_sa.sa_in_addr
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
#ifdef HAVE_GETADDRINFO
	char serv[7];
	struct addrinfo hints, *res, *sai;
	int err;
#endif

	rc = ldap_url_parse( url, &lud );

	if( rc != LDAP_URL_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: listen URL \"%s\" parse error=%d\n",
			url, rc, 0 );
		return NULL;
	}

#ifndef HAVE_TLS
	if( ldap_pvt_url_scheme2tls( lud->lud_scheme ) ) {
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
	l.sl_is_tls = ldap_pvt_url_scheme2tls( lud->lud_scheme );

	if(! lud->lud_port ) {
		lud->lud_port = l.sl_is_tls ? LDAPS_PORT : LDAP_PORT;
	}
#endif

#ifdef HAVE_GETADDRINFO
	memset( &hints, '\0', sizeof(hints) );
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

#  ifdef LDAP_PF_LOCAL
	if ( ldap_pvt_url_scheme2proto(lud->lud_scheme) == LDAP_PROTO_IPC ) {
		if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
			err = getaddrinfo(NULL, LDAPI_SOCK, &hints, &res);
			if (!err)
				unlink( LDAPI_SOCK );
		} else {
			err = getaddrinfo(NULL, lud->lud_host, &hints, &res);
			if (!err)
				unlink( lud->lud_host );
		}
	} else
#  endif /* LDAP_PF_LOCAL */
	{
		snprintf(serv, sizeof serv, "%d", lud->lud_port);
		if( lud->lud_host == NULL || lud->lud_host[0] == '\0'
			|| strcmp(lud->lud_host, "*") == 0 )
		{
			err = getaddrinfo(NULL, serv, &hints, &res);
		} else {
			err = getaddrinfo(lud->lud_host, serv, &hints, &res);
		}
	}

	if ( err ) {
		Debug( LDAP_DEBUG_ANY, "daemon: getaddrinfo failed\n", 0, 0, 0);
		ldap_free_urldesc( lud );
		return NULL;
	}

	ldap_free_urldesc( lud );
	sai = res;
	do {
		if ( (sai->ai_family != AF_INET)
#  ifdef LDAP_PF_INET6
		     && (sai->ai_family != AF_INET6)
#  endif
#  ifdef LDAP_PF_LOCAL
		     && (sai->ai_family != AF_LOCAL)
#  endif
		     )
			continue;
		l.sl_sd = socket( sai->ai_family, sai->ai_socktype, sai->ai_protocol);
		if ( l.sl_sd == AC_SOCKET_INVALID ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"daemon: socket() failed errno=%d (%s)\n", err,
				sock_errstr(err), 0 );
			continue;
		}

		if ( sai->ai_family != AF_LOCAL ) {
#else

	if ( ldap_pvt_url_scheme2proto(lud->lud_scheme) == LDAP_PROTO_IPC ) {
#ifdef LDAP_PF_LOCAL
		port = 0;
		(void) memset( (void *)&l.sl_sa.sa_un_addr, '\0', sizeof(l.sl_sa.sa_un_addr) );

		l.sl_sa.sa_un_addr.sun_family = AF_LOCAL;

		/* hack: overload the host to be the path */
		if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
			strcpy( l.sl_sa.sa_un_addr.sun_path, LDAPI_SOCK );
		} else {
			if ( strlen(lud->lud_host) > (sizeof(l.sl_sa.sa_un_addr.sun_path) - 1) ) {
				Debug( LDAP_DEBUG_ANY,
					"daemon: domain socket path (%s) too long in URL: %s",
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
#else
		Debug( LDAP_DEBUG_ANY, "daemon: URL scheme not supported: %s",
			url, 0, 0);
		ldap_free_urldesc( lud );
		return NULL;
#endif /* LDAP_PF_LOCAL */
	} else {

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
				Debug( LDAP_DEBUG_ANY,
					"daemon: invalid host (%s) in URL: %s",
					lud->lud_host, url, 0);
				ldap_free_urldesc( lud );
				return NULL;
			}

			AC_MEMCPY( &l.sl_addr.sin_addr, he->h_addr,
			       sizeof( l.sl_addr.sin_addr ) );
		}
	}
	}

	ldap_free_urldesc( lud );

	l.sl_sd = socket( l.sl_sa.sa_addr.sa_family, SOCK_STREAM, 0 );
	if ( l.sl_sd == AC_SOCKET_INVALID ) {
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
	/* for IPv4 and IPv6 sockets only */
	if ( l.sl_sa.sa_addr.sa_family != AF_LOCAL ) {
#endif /* LDAP_PF_LOCAL */
#endif /* HAVE_GETADDRINFO */

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

#ifdef HAVE_GETADDRINFO
		} /* sai->ai_family != AF_LOCAL */
		if (!bind(l.sl_sd, sai->ai_addr, sai->ai_addrlen))
			break;
		err = sock_errno();
		Debug( LDAP_DEBUG_ANY, "daemon: bind(%ld) failed errno=%d (%s)\n",
			(long) l.sl_sd, err, sock_errstr(err) );
		tcp_close( l.sl_sd );
	} while ((sai = sai->ai_next) != NULL);

	if (!sai) {
		Debug( LDAP_DEBUG_ANY, "daemon: bind(%ld) failed\n",
			(long) l.sl_sd, 0, 0 );
		return NULL;
	}

	switch ( sai->ai_family ) {
#  ifdef LDAP_PF_LOCAL
	case AF_LOCAL:
		if ( chmod( (char *)sai->ai_addr, S_IRWXU ) < 0 ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY, "daemon: fchmod(%ld) failed errno=%d (%s)",
				(long) l.sl_sd, err, sock_errstr(err) );
			tcp_close( l.sl_sd );
			return NULL;
		}
		l.sl_name = ch_malloc( strlen((char *)sai->ai_addr) + sizeof("PATH=") );
		sprintf( l.sl_name, "PATH=%s", sai->ai_addr );
		break;
#  endif /* LDAP_PF_LOCAL */

	case AF_INET: {
		char addr[INET_ADDRSTRLEN];
		inet_ntop( AF_INET,
			&((struct sockaddr_in *)sai->ai_addr)->sin_addr,
			addr, sizeof(addr) );
		l.sl_name = ch_malloc( strlen(addr) + strlen(serv) + sizeof("IP=:") );
		sprintf( l.sl_name, "IP=%s:%s", addr, serv );
	} break;

#  ifdef LDAP_PF_INET6
	case AF_INET6: {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop( AF_INET6,
			&((struct sockaddr_in6 *)sai->ai_addr)->sin6_addr,
			addr, sizeof addr);
		l.sl_name = ch_malloc( strlen(addr) + strlen(serv) + sizeof("IP= ") );
		sprintf( l.sl_name, "IP=%s %s", addr, serv );
	} break;
#  endif /* LDAP_PF_INET6 */

	default:
		Debug( LDAP_DEBUG_ANY, "daemon: unsupported address family (%d)\n",
			(int) sai->ai_family, 0, 0 );
		break;
	}
#else
#ifdef LDAP_PF_LOCAL
	/* close conditional */
	}
#endif /* LDAP_PF_LOCAL */

	switch ( l.sl_sa.sa_addr.sa_family ) {
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
			rc = bind( l.sl_sd, (struct sockaddr *)&l.sl_sa,
				sizeof(l.sl_sa.sa_un_addr) );
			break;
#endif

		case AF_INET:
			rc = bind( l.sl_sd, (struct sockaddr *)&l.sl_sa,
				sizeof(l.sl_sa.sa_in_addr) );
			break;

		default:
			rc = AC_SOCKET_ERROR;
			errno = EINVAL;
			break;
	}

	if ( rc == AC_SOCKET_ERROR ) {
		int err = sock_errno();
		Debug( LDAP_DEBUG_ANY, "daemon: bind(%ld) failed errno=%d (%s)\n",
	    	(long) l.sl_sd, err, sock_errstr(err) );
		tcp_close( l.sl_sd );
		return NULL;
	}

	switch ( l.sl_sa.sa_addr.sa_family ) {
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
			if ( chmod( l.sl_sa.sa_un_addr.sun_path, S_IRWXU ) < 0 ) {
				int err = sock_errno();
				Debug( LDAP_DEBUG_ANY,
					"daemon: chmod(%ld) failed errno=%d (%s)",
					(long) l.sl_sd, err, sock_errstr(err) );
				tcp_close( l.sl_sd );
				return NULL;
			}

			l.sl_name = ch_malloc( strlen(l.sl_sa.sa_un_addr.sun_path)
				+ sizeof("PATH=") );
			sprintf( l.sl_name, "PATH=%s", l.sl_sa.sa_un_addr.sun_path );
			break;
#endif /* LDAP_PF_LOCAL */

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

#endif /* HAVE_GETADDRINFO */

	l.sl_url = ch_strdup( url );
	li = ch_malloc( sizeof( Listener ) );
	*li = l;

	Debug( LDAP_DEBUG_TRACE, "daemon: initialized %s\n",
		l.sl_url, 0, 0 );

	return li;
}

static int sockinit(void);
static int sockdestroy(void);

int slapd_daemon_init( const char *urls )
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
#define SLAPD_EBADF_LIMIT 16
		int ebadf = 0;

#define SLAPD_IDLE_CHECK_LIMIT 4
		time_t	now = slap_get_time();


		fd_set			readfds;
		fd_set			writefds;
		Sockaddr		from;

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
		AC_MEMCPY( &readfds, &slap_daemon.sd_readers, sizeof(fd_set) );
		AC_MEMCPY( &writefds, &slap_daemon.sd_writers, sizeof(fd_set) );
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

		at = ldap_pvt_thread_pool_backload(&connection_pool);

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
#ifdef WSAENOTSOCK
					/* you'd think this would be EBADF */
					|| err == WSAENOTSOCK
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
			slap_ssf_t ssf = 0;
			char *authid = NULL;

			char	*dnsname;
			char	*peeraddr;
#ifdef LDAP_PF_LOCAL
			char	peername[MAXPATHLEN + sizeof("PATH=")];
#elif defined(LDAP_PF_INET6)
			char	peername[sizeof("IP=ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535")];
#else
			char	peername[sizeof("IP=255.255.255.255:65336")];
#endif /* LDAP_PF_LOCAL */

			peername[0] = '\0';

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

			switch ( from.sa_addr.sa_family ) {
#  ifdef LDAP_PF_LOCAL
			case AF_LOCAL:
				sprintf( peername, "PATH=%s", from.sa_un_addr.sun_path );
				ssf = LDAP_PVT_SASL_LOCAL_SSF;
				break;
#endif /* LDAP_PF_LOCAL */

#  ifdef LDAP_PF_INET6
			case AF_INET6:
			if ( IN6_IS_ADDR_V4MAPPED(&from.sa_in6_addr.sin6_addr) ) {
				peeraddr = inet_ntoa( *((struct in_addr *)
							&from.sa_in6_addr.sin6_addr.s6_addr[12]) );
				sprintf( peername, "IP=%s:%d",
					 peeraddr != NULL ? peeraddr : "unknown",
					 (unsigned) ntohs( from.sa_in6_addr.sin6_port ) );
			} else {
				char addr[INET6_ADDRSTRLEN];
				sprintf( peername, "IP=%s %d",
					 inet_ntop( AF_INET6,
						    &from.sa_in6_addr.sin6_addr,
						    addr, sizeof addr) ? addr : "unknown",
					 (unsigned) ntohs( from.sa_in6_addr.sin6_port ) );
			}
			break;
#  endif /* LDAP_PF_INET6 */

			case AF_INET:
			peeraddr = inet_ntoa( from.sa_in_addr.sin_addr );
			sprintf( peername, "IP=%s:%d",
				peeraddr != NULL ? peeraddr : "unknown",
				(unsigned) ntohs( from.sa_in_addr.sin_port ) );
				break;

			default:
				slapd_close(s);
				continue;
			}
			if ( ( from.sa_addr.sa_family == AF_INET ) 
#ifdef LDAP_PF_INET6
				|| ( from.sa_addr.sa_family == AF_INET6 )
#endif
			) {
#ifdef SLAPD_RLOOKUPS
#  ifdef LDAP_PF_INET6
				if ( from.sa_addr.sa_family == AF_INET6 )
					hp = gethostbyaddr(
						(char *)&(from.sa_in6_addr.sin6_addr),
						sizeof(from.sa_in6_addr.sin6_addr),
						AF_INET6 );
				else
#  endif LDAP_PF_INET6
				hp = gethostbyaddr(
					(char *) &(from.sa_in_addr.sin_addr),
					sizeof(from.sa_in_addr.sin_addr),
					AF_INET );
				dnsname = hp ? ldap_pvt_str2lower( hp->h_name ) : NULL;
#else
				dnsname = NULL;
#endif /* SLAPD_RLOOKUPS */

#ifdef HAVE_TCPD
				if ( !hosts_ctl("slapd",
						dnsname != NULL ? dnsname : STRING_UNKNOWN,
						peeraddr != NULL ? peeraddr : STRING_UNKNOWN,
						STRING_UNKNOWN ))
				{
					/* DENY ACCESS */
					Statslog( LDAP_DEBUG_ANY,
						"fd=%ld host access from %s (%s) denied.\n",
						(long) s,
						dnsname != NULL ? dnsname : "unknown",
						peeraddr != NULL ? peeraddr : "unknown",
						0, 0 );
					slapd_close(s);
					continue;
				}
#endif /* HAVE_TCPD */
			}

			id = connection_init(s,
				slap_listeners[l]->sl_url,
				dnsname != NULL ? dnsname : "unknown",
				peername,
				slap_listeners[l]->sl_name,
#ifdef HAVE_TLS
				slap_listeners[l]->sl_is_tls,
#else
				0,
#endif
				ssf,
				authid );

			if( authid ) ch_free(authid);

			if( id < 0 ) {
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
			if ( slap_listeners[l]->sl_sa.sa_addr.sa_family == AF_LOCAL ) {
				unlink( slap_listeners[l]->sl_sa.sa_un_addr.sun_path );
			}
#endif /* LDAP_PF_LOCAL */
			slapd_close( slap_listeners[l]->sl_sd );
			break;
		}
	}

	Debug( LDAP_DEBUG_ANY,
	    "slapd shutdown: waiting for %d threads to terminate\n",
	    ldap_pvt_thread_pool_backload(&connection_pool), 0, 0 );

	ldap_pvt_thread_pool_destroy(&connection_pool, 1);

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

int sockinit(void)
{
#if defined( HAVE_WINSOCK2 )
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
#elif defined( HAVE_WINSOCK )
	WSADATA wsaData;
	if ( WSAStartup( 0x0101, &wsaData ) != 0 ) {
	    return -1;
	}
#endif
	return 0;
}

int sockdestroy(void)
{
#if defined( HAVE_WINSOCK2 ) || defined( HAVE_WINSOCK )
	WSACleanup();
#endif
	return 0;
}

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
	(void) SIGNAL_REINSTALL( sig, slap_sig_shutdown );
}

RETSIGTYPE
slap_sig_wake( int sig )
{
	WAKE_LISTENER(1);

	/* reinstall self */
	(void) SIGNAL_REINSTALL( sig, slap_sig_wake );
}
