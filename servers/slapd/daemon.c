/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "slap.h"
#include "ldap_pvt_thread.h"
#include "lutil.h"

#include "ldap_rq.h"

#ifdef HAVE_TCPD
#include <tcpd.h>
#define SLAP_STRING_UNKNOWN	STRING_UNKNOWN

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#else /* ! TCP Wrappers */
#define SLAP_STRING_UNKNOWN	"unknown"
#endif /* ! TCP Wrappers */

#ifdef LDAP_PF_LOCAL
#include <sys/stat.h>
/* this should go in <ldap.h> as soon as it is accepted */
#define LDAPI_MOD_URLEXT		"x-mod"
#endif /* LDAP_PF_LOCAL */

#ifdef LDAP_PF_INET6
int slap_inet4or6 = AF_UNSPEC;
#else
int slap_inet4or6 = AF_INET;
#endif

/* globals */
time_t starttime;
ber_socket_t dtblsize;
slap_ssf_t local_ssf = LDAP_PVT_SASL_LOCAL_SSF;

Listener **slap_listeners = NULL;

#define SLAPD_LISTEN 10

static ber_socket_t wake_sds[2];
static int emfile;

static int waking;
#define WAKE_LISTENER(w) \
do { if (w && waking < 5) { tcp_write( wake_sds[1], "0", 1 ); waking++;} } while(0)

volatile sig_atomic_t slapd_shutdown = 0, slapd_gentle_shutdown = 0;
volatile sig_atomic_t slapd_abrupt_shutdown = 0;

static struct slap_daemon {
	ldap_pvt_thread_mutex_t	sd_mutex;

	ber_socket_t sd_nactives;
	int sd_nwriters;

#ifdef HAVE_EPOLL
	struct epoll_event *sd_epolls;
	int	sd_nepolls;
	int	*sd_index;
	int	sd_epfd;
	int	sd_nfds;
#else

#ifndef HAVE_WINSOCK
	/* In winsock, accept() returns values higher than dtblsize
		so don't bother with this optimization */
	int sd_nfds;
#endif

	fd_set sd_actives;
	fd_set sd_readers;
	fd_set sd_writers;
#endif
} slap_daemon;

#ifdef HAVE_EPOLL
#define	SLAP_EVENTS_ARE_INDEXED	0
#define	SLAP_SOCK_IX(fd)	(slap_daemon.sd_index[fd])
#define SLAP_SOCK_EP(fd)	(slap_daemon.sd_epolls[SLAP_SOCK_IX(fd)])
#define SLAP_SOCK_FD(fd)	(SLAP_SOCK_EP(fd).data.fd)
#define SLAP_SOCK_EV(fd)	(SLAP_SOCK_EP(fd).events)
#define SLAP_SOCK_IS_ACTIVE(fd)	(SLAP_SOCK_IX(fd) != -1 && SLAP_SOCK_FD(fd) == fd)
#define SLAP_SOCK_NOT_ACTIVE(fd)	(SLAP_SOCK_IX(fd) == -1)
#define SLAP_SOCK_IS_SET(fd, mode)	(SLAP_SOCK_EV(fd) & mode)

#define SLAP_SOCK_IS_READ(fd)	SLAP_SOCK_IS_SET(fd, EPOLLIN)
#define SLAP_SOCK_IS_WRITE(fd)	SLAP_SOCK_IS_SET(fd, EPOLLOUT)

#define	SLAP_SET_SOCK(fd, events) do { \
	assert(SLAP_SOCK_IS_ACTIVE(fd));	\
	if ((SLAP_SOCK_EV(fd) & events) != events) {	\
		SLAP_SOCK_EV(fd) |= events;	\
		rc = epoll_ctl(slap_daemon.sd_epfd, EPOLL_CTL_MOD, fd,	\
			&SLAP_SOCK_EP(fd));	\
	}	\
} while(0)

#define SLAP_CLR_SOCK(fd, events) do { \
	assert(SLAP_SOCK_IS_ACTIVE(fd));	\
	if ((SLAP_SOCK_EV(fd) & events)) { \
		SLAP_SOCK_EV(fd) &= ~events;	\
		rc = epoll_ctl(slap_daemon.sd_epfd, EPOLL_CTL_MOD, fd,	\
			&SLAP_SOCK_EP(fd));	\
	}	\
} while(0)	\

#define SLAP_SOCK_SET_READ(fd)	SLAP_SET_SOCK(fd, EPOLLIN)
#define SLAP_SOCK_SET_WRITE(fd)	SLAP_SET_SOCK(fd, EPOLLOUT)

#define SLAP_SOCK_CLR_READ(fd)	SLAP_CLR_SOCK(fd, EPOLLIN)
#define SLAP_SOCK_CLR_WRITE(fd)	SLAP_CLR_SOCK(fd, EPOLLOUT)

#define SLAP_CLR_EVENT(i, events)	(revents[i].events &= ~events)

#define SLAP_EVENT_CLR_READ(i)	SLAP_CLR_EVENT(i, EPOLLIN)
#define SLAP_EVENT_CLR_WRITE(i)	SLAP_CLR_EVENT(i, EPOLLOUT)

#define SLAP_CHK_EVENT(i, events)	(revents[i].events & events)

#define SLAP_EVENT_IS_READ(i)	SLAP_CHK_EVENT(i, EPOLLIN)
#define SLAP_EVENT_IS_WRITE(i)	SLAP_CHK_EVENT(i, EPOLLOUT)

#define SLAP_EVENT_FD(i)	(revents[i].data.fd)

#define SLAP_ADD_SOCK(fd) do { \
	SLAP_SOCK_IX(fd) = slap_daemon.sd_nfds;	\
	SLAP_SOCK_FD(fd) = fd;	\
	SLAP_SOCK_EV(fd) = EPOLLIN;	\
	rc = epoll_ctl(slap_daemon.sd_epfd, EPOLL_CTL_ADD, fd,	\
			&SLAP_SOCK_EP(fd));	\
	if ( rc == 0 ) slap_daemon.sd_nfds++;	\
} while(0)

#define SLAP_DEL_SOCK(fd) do { \
	int index = SLAP_SOCK_IX(fd);
	
	rc = epoll_ctl(slap_daemon.sd_epfd, EPOLL_CTL_DEL, fd,	\
			&SLAP_SOCK_EP(fd));	\
	slap_daemon.sd_epolls[index] = slap_daemon.sd_epolls[slap_daemon.sd_nfds-1];	\
	slap_daemon.sd_index[slap_daemon.sd_epools[index].data.fd] = index;	\
	slap_daemon.sd_index[fd] = -1;	\
	slap_daemon.sd_nfds--;	\
} while(0)

#define	SLAP_SOCK_SET_MUTE(fd)	SLAP_SOCK_CLR_READ(fd)
#define	SLAP_SOCK_CLR_MUTE(fd)	SLAP_SOCK_SET_READ(fd)
#define	SLAP_SOCK_IS_MUTE(fd)	!SLAP_SOCK_IS_READ(fd)

#define SLAP_SOCK_SET_INIT	\
	slap_daemon.sd_epolls = ch_malloc(sizeof(struct epoll_event) * dtblsize * 2);	\
	slap_daemon.sd_index = ch_malloc(sizeof(int) * dtblsize);	\
	slap_daemon.sd_epfd = epoll_create( dtblsize )

#define	SLAP_EVENT_DECL	\
	struct epoll_event *revents

#define SLAP_EVENT_INIT	\
	revents = slap_daemon.sd_epolls + dtblsize;	\

#define SLAP_EVENT_WAIT(tvp)	\
	epoll_wait( slap_daemon.sd_epfd, revents, dtblsize, tvp ? tvp->tv_sec * 1000 : -1 )

#else

/* select */
#define	SLAP_EVENTS_ARE_INDEXED	1
#define SLAP_EVENT_DECL	\
	fd_set readfds, writefds

#define SLAP_EVENT_INIT \
	AC_MEMCPY( &readfds, &slap_daemon.sd_readers, sizeof(fd_set) );	\
	if ( nwriters )	\
		AC_MEMCPY( &writefds, &slap_daemon.sd_writers, sizeof(fd_set) );

#ifdef FD_SETSIZE
#define	CHK_SETSIZE	\
	if (dtblsize > FD_SETSIZE) dtblsize = FD_SETSIZE
#else
#define	CHK_SETSIZE
#endif

#define	SLAP_SOCK_SET_INIT	\
	CHK_SETSIZE;	\
	FD_ZERO(&slap_daemon.sd_readers);	\
	FD_ZERO(&slap_daemon.sd_writers)

#define SLAP_SOCK_IS_ACTIVE(fd)	FD_ISSET(fd, &slap_daemon.sd_actives)

#define SLAP_SOCK_IS_READ(fd)	FD_ISSET(fd, &slap_daemon.sd_readers)
#define SLAP_SOCK_IS_WRITE(fd)	FD_ISSET(fd, &slap_daemon.sd_writers)

#define SLAP_SOCK_NOT_ACTIVE(fd)	(!SLAP_SOCK_IS_ACTIVE(fd) && \
	 !SLAP_SOCK_IS_READ(fd) && !SLAP_SOCK_IS_WRITE(fd))

#ifdef HAVE_WINSOCK
#define SLAP_SOCK_SET_READ(fd)	do { \
	if (!SLAP_SOCK_IS_READ(fd)) {FD_SET(fd, &slap_daemon.sd_readers);}	\
} while(0)
#define SLAP_SOCK_SET_WRITE(fd)	do { \
	if (!SLAP_SOCK_IS_WRITE(fd)) {FD_SET(fd, &slap_daemon.sd_writers);}	\
} while(0)

#define SLAP_ADDTEST(s)
#define SLAP_MAXWAIT	dtblsize
#else
#define SLAP_SOCK_SET_READ(fd)	FD_SET(fd, &slap_daemon.sd_readers)
#define SLAP_SOCK_SET_WRITE(fd)	FD_SET(fd, &slap_daemon.sd_writers)

#define SLAP_MAXWAIT	slap_daemon.sd_nfds
#define	SLAP_ADDTEST(s)	if (s >= slap_daemon.sd_nfds) slap_daemon.sd_nfds = s+1
#endif

#define SLAP_SOCK_CLR_READ(fd)	FD_CLR(fd, &slap_daemon.sd_readers)
#define SLAP_SOCK_CLR_WRITE(fd)	FD_CLR(fd, &slap_daemon.sd_writers)

#define	SLAP_ADD_SOCK(s) do {	\
	SLAP_ADDTEST(s);	\
	FD_SET(s, &slap_daemon.sd_actives);	\
	FD_SET(s, &slap_daemon.sd_readers);	\
} while(0)

#define SLAP_DEL_SOCK(s) do {	\
	FD_CLR(s, &slap_daemon.sd_actives);	\
	FD_CLR(s, &slap_daemon.sd_readers);	\
	FD_CLR(s, &slap_daemon.sd_writers);	\
} while(0)

#define SLAP_EVENT_IS_READ(fd)	FD_ISSET(fd, &readfds)
#define SLAP_EVENT_IS_WRITE(fd)	FD_ISSET(fd, &writefds)

#define SLAP_EVENT_CLR_READ(fd)	FD_CLR(fd, &readfds)
#define SLAP_EVENT_CLR_WRITE(fd)	FD_CLR(fd, &writefds)

#define SLAP_EVENT_WAIT(tvp)	\
	select( SLAP_MAXWAIT, &readfds,	\
		nwriters > 0 ? &writefds : NULL, NULL, tvp )

#define	SLAP_SOCK_SET_MUTE(s)	FD_CLR(s, &readfds)
#define SLAP_SOCK_CLR_MUTE(s)	FD_SET(s, &readfds)
#define	SLAP_SOCK_IS_MUTE(s)	FD_ISSET(s, &readfds)

#endif


#ifdef HAVE_SLP
/*
 * SLP related functions
 */
#include <slp.h>

#define LDAP_SRVTYPE_PREFIX "service:ldap://"
#define LDAPS_SRVTYPE_PREFIX "service:ldaps://"
static char** slapd_srvurls = NULL;
static SLPHandle slapd_hslp = 0;
int slapd_register_slp = 0;

void slapd_slp_init( const char* urls ) {
	int i;

	slapd_srvurls = ldap_str2charray( urls, " " );

	if( slapd_srvurls == NULL ) return;

	/* find and expand INADDR_ANY URLs */
	for( i=0; slapd_srvurls[i] != NULL; i++ ) {
		if( strcmp( slapd_srvurls[i], "ldap:///" ) == 0) {
			char *host = ldap_pvt_get_fqdn( NULL );
			if ( host != NULL ) {
				slapd_srvurls[i] = (char *) ch_realloc( slapd_srvurls[i],
					strlen( host ) +
					sizeof( LDAP_SRVTYPE_PREFIX ) );
				strcpy( lutil_strcopy(slapd_srvurls[i],
					LDAP_SRVTYPE_PREFIX ), host );

				ch_free( host );
			}

		} else if ( strcmp( slapd_srvurls[i], "ldaps:///" ) == 0) {
			char *host = ldap_pvt_get_fqdn( NULL );
			if ( host != NULL ) {
				slapd_srvurls[i] = (char *) ch_realloc( slapd_srvurls[i],
					strlen( host ) +
					sizeof( LDAPS_SRVTYPE_PREFIX ) );
				strcpy( lutil_strcopy(slapd_srvurls[i],
					LDAPS_SRVTYPE_PREFIX ), host );

				ch_free( host );
			}
		}
	}

	/* open the SLP handle */
	SLPOpen( "en", 0, &slapd_hslp );
}

void slapd_slp_deinit() {
	if( slapd_srvurls == NULL ) return;

	ldap_charray_free( slapd_srvurls );
	slapd_srvurls = NULL;

	/* close the SLP handle */
	SLPClose( slapd_hslp );
}

void slapd_slp_regreport(
	SLPHandle hslp,
	SLPError errcode,
	void* cookie )
{
	/* empty report */
}

void slapd_slp_reg() {
	int i;

	if( slapd_srvurls == NULL ) return;

	for( i=0; slapd_srvurls[i] != NULL; i++ ) {
		if( strncmp( slapd_srvurls[i], LDAP_SRVTYPE_PREFIX,
				sizeof( LDAP_SRVTYPE_PREFIX ) - 1 ) == 0 ||
		    strncmp( slapd_srvurls[i], LDAPS_SRVTYPE_PREFIX,
				sizeof( LDAPS_SRVTYPE_PREFIX ) - 1 ) == 0 )
		{
			SLPReg( slapd_hslp,
				slapd_srvurls[i],
				SLP_LIFETIME_MAXIMUM,
				"ldap",
				"",
				1,
				slapd_slp_regreport,
				NULL );
		}
	}
}

void slapd_slp_dereg() {
	int i;

	if( slapd_srvurls == NULL ) return;

	for( i=0; slapd_srvurls[i] != NULL; i++ ) {
		SLPDereg( slapd_hslp,
			slapd_srvurls[i],
			slapd_slp_regreport,
			NULL );
	}
}
#endif /* HAVE_SLP */

/*
 * Add a descriptor to daemon control
 *
 * If isactive, the descriptor is a live server session and is subject
 * to idletimeout control. Otherwise, the descriptor is a passive
 * listener or an outbound client session, and not subject to
 * idletimeout.
 */
static void slapd_add(ber_socket_t s, int isactive) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( SLAP_SOCK_NOT_ACTIVE(s) );

	if ( isactive ) {
		slap_daemon.sd_nactives++;
	}

	SLAP_ADD_SOCK(s);

	Debug( LDAP_DEBUG_CONNS, "daemon: added %ldr\n",
		(long) s, 0, 0 );
	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
}

/*
 * Remove the descriptor from daemon control
 */
void slapd_remove(ber_socket_t s, int wasactive, int wake) {
	int waswriter;
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	if ( wasactive ) {
		slap_daemon.sd_nactives--;
	}
	waswriter = SLAP_SOCK_IS_WRITE(s);

	Debug( LDAP_DEBUG_CONNS, "daemon: removing %ld%s%s\n",
		(long) s,
	    SLAP_SOCK_IS_READ(s) ? "r" : "",
		waswriter ? "w" : "" );
	if ( waswriter ) slap_daemon.sd_nwriters--;

	SLAP_DEL_SOCK(s);

	/* If we ran out of file descriptors, we dropped a listener from
	 * the select() loop. Now that we're removing a session from our
	 * control, we can try to resume a dropped listener to use.
	 */
	if ( emfile ) {
		int i;
		for ( i = 0; slap_listeners[i] != NULL; i++ ) {
			if ( slap_listeners[i]->sl_sd != AC_SOCKET_INVALID ) {
				if ( slap_listeners[i]->sl_sd == s ) continue;
				if ( slap_listeners[i]->sl_is_mute ) {
					slap_listeners[i]->sl_is_mute = 0;
					emfile--;
					break;
				}
			}
		}
		/* Walked the entire list without enabling anything; emfile
		 * counter is stale. Reset it.
		 */
		if ( slap_listeners[i] == NULL )
			emfile = 0;
	}
	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake || slapd_gentle_shutdown == 2);
}

void slapd_clr_write(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( SLAP_SOCK_IS_ACTIVE( s ));
	if ( SLAP_SOCK_IS_WRITE( s )) {
		SLAP_SOCK_CLR_WRITE( s );
		slap_daemon.sd_nwriters--;
	}

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_set_write(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( SLAP_SOCK_IS_ACTIVE( s ));
	if ( !SLAP_SOCK_IS_WRITE( s )) {
		SLAP_SOCK_SET_WRITE( s );
		slap_daemon.sd_nwriters++;
	}

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_clr_read(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( SLAP_SOCK_IS_ACTIVE( s ));
	SLAP_SOCK_CLR_READ( s );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

void slapd_set_read(ber_socket_t s, int wake) {
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	assert( SLAP_SOCK_IS_ACTIVE( s ));
	if (!SLAP_SOCK_IS_READ( s ))
		SLAP_SOCK_SET_READ( s );

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
	WAKE_LISTENER(wake);
}

static void slapd_close(ber_socket_t s) {
	Debug( LDAP_DEBUG_CONNS, "daemon: closing %ld\n",
		(long) s, 0, 0 );
	tcp_close(s);
}

static void slap_free_listener_addresses(struct sockaddr **sal)
{
	struct sockaddr **sap;

	if (sal == NULL) {
		return;
	}

	for (sap = sal; *sap != NULL; sap++) {
		ch_free(*sap);
	}

	ch_free(sal);
}

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
static int get_url_perms(
	char 	**exts,
	mode_t	*perms,
	int	*crit )
{
	int	i;

	assert( exts );
	assert( perms );
	assert( crit );

	*crit = 0;
	for ( i = 0; exts[ i ]; i++ ) {
		char	*type = exts[ i ];
		int	c = 0;

		if ( type[ 0 ] == '!' ) {
			c = 1;
			type++;
		}

		if ( strncasecmp( type, LDAPI_MOD_URLEXT "=", sizeof(LDAPI_MOD_URLEXT "=") - 1 ) == 0 ) {
			char 	*value = type
				+ ( sizeof(LDAPI_MOD_URLEXT "=") - 1 );
			mode_t	p = 0;
			int 	j;

			switch (strlen(value)) {
			case 4:
				/* skip leading '0' */
				if ( value[ 0 ] != '0' ) {
					return LDAP_OTHER;
				}
				value++;

			case 3:
				for ( j = 0; j < 3; j++) {
					int	v;

					v = value[ j ] - '0';

					if ( v < 0 || v > 7 ) {
						return LDAP_OTHER;
					}

					p |= v << 3*(2-j);
				}
				break;

			case 10:
				for ( j = 1; j < 10; j++ ) {
					static mode_t	m[] = { 0, 
						S_IRUSR, S_IWUSR, S_IXUSR,
						S_IRGRP, S_IWGRP, S_IXGRP,
						S_IROTH, S_IWOTH, S_IXOTH
					};
					static char	c[] = "-rwxrwxrwx"; 

					if ( value[ j ] == c[ j ] ) {
						p |= m[ j ];
	
					} else if ( value[ j ] != '-' ) {
						return LDAP_OTHER;
					}
				}
				break;

			default:
				return LDAP_OTHER;
			} 

			*crit = c;
			*perms = p;

			return LDAP_SUCCESS;
		}
	}

	return LDAP_OTHER;
}
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

/* port = 0 indicates AF_LOCAL */
static int slap_get_listener_addresses(
	const char *host,
	unsigned short port,
	struct sockaddr ***sal)
{
	struct sockaddr **sap;

#ifdef LDAP_PF_LOCAL
	if ( port == 0 ) {
		*sal = ch_malloc(2 * sizeof(void *));
		if (*sal == NULL) {
			return -1;
		}

		sap = *sal;
		*sap = ch_malloc(sizeof(struct sockaddr_un));
		if (*sap == NULL)
			goto errexit;
		sap[1] = NULL;

		if ( strlen(host) >
		     (sizeof(((struct sockaddr_un *)*sap)->sun_path) - 1) ) {
			Debug( LDAP_DEBUG_ANY,
			       "daemon: domain socket path (%s) too long in URL",
			       host, 0, 0);
			goto errexit;
		}

		(void)memset( (void *)*sap, '\0', sizeof(struct sockaddr_un) );
		(*sap)->sa_family = AF_LOCAL;
		strcpy( ((struct sockaddr_un *)*sap)->sun_path, host );
	} else
#endif
	{
#ifdef HAVE_GETADDRINFO
		struct addrinfo hints, *res, *sai;
		int n, err;
		char serv[7];

		memset( &hints, '\0', sizeof(hints) );
		hints.ai_flags = AI_PASSIVE;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = slap_inet4or6;
		snprintf(serv, sizeof serv, "%d", port);

		if ( (err = getaddrinfo(host, serv, &hints, &res)) ) {
			Debug( LDAP_DEBUG_ANY, "daemon: getaddrinfo failed: %s\n",
				AC_GAI_STRERROR(err), 0, 0);
			return -1;
		}

		sai = res;
		for (n=2; (sai = sai->ai_next) != NULL; n++) {
			/* EMPTY */ ;
		}
		*sal = ch_calloc(n, sizeof(void *));
		if (*sal == NULL) {
			return -1;
		}

		sap = *sal;
		*sap = NULL;

		for ( sai=res; sai; sai=sai->ai_next ) {
			if( sai->ai_addr == NULL ) {
				Debug( LDAP_DEBUG_ANY, "slap_get_listener_addresses: "
					"getaddrinfo ai_addr is NULL?\n", 0, 0, 0 );
				freeaddrinfo(res);
				goto errexit;
			}

			switch (sai->ai_family) {
#  ifdef LDAP_PF_INET6
			case AF_INET6:
				*sap = ch_malloc(sizeof(struct sockaddr_in6));
				if (*sap == NULL) {
					freeaddrinfo(res);
					goto errexit;
				}
				*(struct sockaddr_in6 *)*sap =
					*((struct sockaddr_in6 *)sai->ai_addr);
				break;
#  endif
			case AF_INET:
				*sap = ch_malloc(sizeof(struct sockaddr_in));
				if (*sap == NULL) {
					freeaddrinfo(res);
					goto errexit;
				}
				*(struct sockaddr_in *)*sap =
					*((struct sockaddr_in *)sai->ai_addr);
				break;
			default:
				*sap = NULL;
				break;
			}

			if (*sap != NULL) {
				(*sap)->sa_family = sai->ai_family;
				sap++;
				*sap = NULL;
			}
		}

		freeaddrinfo(res);
#else
		int i, n = 1;
		struct in_addr in;
		struct hostent *he = NULL;

		if ( host == NULL ) {
			in.s_addr = htonl(INADDR_ANY);

		} else if ( !inet_aton( host, &in ) ) {
			he = gethostbyname( host );
			if( he == NULL ) {
				Debug( LDAP_DEBUG_ANY,
				       "daemon: invalid host %s", host, 0, 0);
				return -1;
			}
			for (n = 0; he->h_addr_list[n]; n++) ;
		}

		*sal = ch_malloc((n+1) * sizeof(void *));
		if (*sal == NULL) {
			return -1;
		}

		sap = *sal;
		for ( i = 0; i<n; i++ ) {
			sap[i] = ch_malloc(sizeof(struct sockaddr_in));
			if (*sap == NULL) {
				goto errexit;
			}
			(void)memset( (void *)sap[i], '\0', sizeof(struct sockaddr_in) );
			sap[i]->sa_family = AF_INET;
			((struct sockaddr_in *)sap[i])->sin_port = htons(port);
			if (he) {
				AC_MEMCPY( &((struct sockaddr_in *)sap[i])->sin_addr, he->h_addr_list[i], sizeof(struct in_addr) );
			} else {
				AC_MEMCPY( &((struct sockaddr_in *)sap[i])->sin_addr, &in, sizeof(struct in_addr) );
			}
		}
		sap[i] = NULL;
#endif
	}

	return 0;

errexit:
	slap_free_listener_addresses(*sal);
	return -1;
}

static int slap_open_listener(
	const char* url,
	int *listeners,
	int *cur
	)
{
	int	num, tmp, rc;
	Listener l;
	Listener *li;
	LDAPURLDesc *lud;
	unsigned short port;
	int err, addrlen = 0;
	struct sockaddr **sal, **psal;
	int socktype = SOCK_STREAM;	/* default to COTS */

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
	/*
	 * use safe defaults
	 */
	int	crit = 1;
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

	rc = ldap_url_parse( url, &lud );

	if( rc != LDAP_URL_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: listen URL \"%s\" parse error=%d\n",
			url, rc, 0 );
		return rc;
	}

	l.sl_url.bv_val = NULL;
	l.sl_is_mute = 0;

#ifndef HAVE_TLS
	if( ldap_pvt_url_scheme2tls( lud->lud_scheme ) ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: TLS not supported (%s)\n",
			url, 0, 0 );
		ldap_free_urldesc( lud );
		return -1;
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

	port = (unsigned short) lud->lud_port;

	tmp = ldap_pvt_url_scheme2proto(lud->lud_scheme);
	if ( tmp == LDAP_PROTO_IPC ) {
#ifdef LDAP_PF_LOCAL
		if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
			err = slap_get_listener_addresses(LDAPI_SOCK, 0, &sal);
		} else {
			err = slap_get_listener_addresses(lud->lud_host, 0, &sal);
		}
#else

		Debug( LDAP_DEBUG_ANY, "daemon: URL scheme not supported: %s",
			url, 0, 0);
		ldap_free_urldesc( lud );
		return -1;
#endif
	} else {
		if( lud->lud_host == NULL || lud->lud_host[0] == '\0'
			|| strcmp(lud->lud_host, "*") == 0 )
		{
			err = slap_get_listener_addresses(NULL, port, &sal);
		} else {
			err = slap_get_listener_addresses(lud->lud_host, port, &sal);
		}
	}
#ifdef LDAP_CONNECTIONLESS
	l.sl_is_udp = ( tmp == LDAP_PROTO_UDP );
#endif

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
	if ( lud->lud_exts ) {
		err = get_url_perms( lud->lud_exts, &l.sl_perms, &crit );
	} else {
		l.sl_perms = S_IRWXU | S_IRWXO;
	}
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

	ldap_free_urldesc( lud );
	if ( err ) {
		return -1;
	}

	/* If we got more than one address returned, we need to make space
	 * for it in the slap_listeners array.
	 */
	for ( num=0; sal[num]; num++ );
	if ( num > 1 ) {
		*listeners += num-1;
		slap_listeners = ch_realloc( slap_listeners, (*listeners + 1) * sizeof(Listener *) );
	}

	psal = sal;
	while ( *sal != NULL ) {
		char *af;
		switch( (*sal)->sa_family ) {
		case AF_INET:
			af = "IPv4";
			break;
#ifdef LDAP_PF_INET6
		case AF_INET6:
			af = "IPv6";
			break;
#endif
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
			af = "Local";
			break;
#endif
		default:
			sal++;
			continue;
		}
#ifdef LDAP_CONNECTIONLESS
		if( l.sl_is_udp ) socktype = SOCK_DGRAM;
#endif
		l.sl_sd = socket( (*sal)->sa_family, socktype, 0);
		if ( l.sl_sd == AC_SOCKET_INVALID ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"daemon: %s socket() failed errno=%d (%s)\n",
				af, err, sock_errstr(err) );
			sal++;
			continue;
		}
#ifndef HAVE_WINSOCK
		if ( l.sl_sd >= dtblsize ) {
			Debug( LDAP_DEBUG_ANY,
				"daemon: listener descriptor %ld is too great %ld\n",
				(long) l.sl_sd, (long) dtblsize, 0 );
			tcp_close( l.sl_sd );
			sal++;
			continue;
		}
#endif
#ifdef LDAP_PF_LOCAL
		if ( (*sal)->sa_family == AF_LOCAL ) {
			unlink ( ((struct sockaddr_un *)*sal)->sun_path );
		} else
#endif
		{
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
		}

		switch( (*sal)->sa_family ) {
		case AF_INET:
			addrlen = sizeof(struct sockaddr_in);
			break;
#ifdef LDAP_PF_INET6
		case AF_INET6:
#ifdef IPV6_V6ONLY
			/* Try to use IPv6 sockets for IPv6 only */
			tmp = 1;
			rc = setsockopt( l.sl_sd, IPPROTO_IPV6, IPV6_V6ONLY,
					 (char *) &tmp, sizeof(tmp) );
			if ( rc == AC_SOCKET_ERROR ) {
				int err = sock_errno();
				Debug( LDAP_DEBUG_ANY,
				       "slapd(%ld): setsockopt(IPV6_V6ONLY) failed errno=%d (%s)\n",
				       (long) l.sl_sd, err, sock_errstr(err) );
			}
#endif
			addrlen = sizeof(struct sockaddr_in6);
			break;
#endif
#ifdef LDAP_PF_LOCAL
		case AF_LOCAL:
			addrlen = sizeof(struct sockaddr_un);
			break;
#endif
		}

		if (bind(l.sl_sd, *sal, addrlen)) {
			err = sock_errno();
		Debug( LDAP_DEBUG_ANY, "daemon: bind(%ld) failed errno=%d (%s)\n",
		       (long) l.sl_sd, err, sock_errstr(err) );
			tcp_close( l.sl_sd );
			sal++;
			continue;
		}

	switch ( (*sal)->sa_family ) {
#ifdef LDAP_PF_LOCAL
	case AF_LOCAL: {
		char *addr = ((struct sockaddr_un *)*sal)->sun_path;
#if 0 /* don't muck with socket perms */
		if ( chmod( addr, l.sl_perms ) < 0 && crit ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY, "daemon: fchmod(%ld) failed errno=%d (%s)",
			       (long) l.sl_sd, err, sock_errstr(err) );
			tcp_close( l.sl_sd );
			slap_free_listener_addresses(psal);
			return -1;
		}
#endif
		l.sl_name.bv_len = strlen(addr) + sizeof("PATH=") - 1;
		l.sl_name.bv_val = ber_memalloc( l.sl_name.bv_len + 1 );
		snprintf( l.sl_name.bv_val, l.sl_name.bv_len + 1, 
				"PATH=%s", addr );
	} break;
#endif /* LDAP_PF_LOCAL */

	case AF_INET: {
		char *s;
#if defined( HAVE_GETADDRINFO ) && defined( HAVE_INET_NTOP )
		char addr[INET_ADDRSTRLEN];
		inet_ntop( AF_INET, &((struct sockaddr_in *)*sal)->sin_addr,
			   addr, sizeof(addr) );
		s = addr;
#else
		s = inet_ntoa( ((struct sockaddr_in *) *sal)->sin_addr );
#endif
		port = ntohs( ((struct sockaddr_in *)*sal) ->sin_port );
		l.sl_name.bv_val = ber_memalloc( sizeof("IP=255.255.255.255:65535") );
		snprintf( l.sl_name.bv_val, sizeof("IP=255.255.255.255:65535"),
			"IP=%s:%d",
			 s != NULL ? s : SLAP_STRING_UNKNOWN, port );
		l.sl_name.bv_len = strlen( l.sl_name.bv_val );
	} break;

#ifdef LDAP_PF_INET6
	case AF_INET6: {
		char addr[INET6_ADDRSTRLEN];
		inet_ntop( AF_INET6, &((struct sockaddr_in6 *)*sal)->sin6_addr,
			   addr, sizeof addr);
		port = ntohs( ((struct sockaddr_in6 *)*sal)->sin6_port );
		l.sl_name.bv_len = strlen(addr) + sizeof("IP= 65535");
		l.sl_name.bv_val = ber_memalloc( l.sl_name.bv_len );
		snprintf( l.sl_name.bv_val, l.sl_name.bv_len, "IP=%s %d", 
				addr, port );
		l.sl_name.bv_len = strlen( l.sl_name.bv_val );
	} break;
#endif /* LDAP_PF_INET6 */

	default:
		Debug( LDAP_DEBUG_ANY, "daemon: unsupported address family (%d)\n",
			(int) (*sal)->sa_family, 0, 0 );
		break;
	}

	AC_MEMCPY(&l.sl_sa, *sal, addrlen);
	ber_str2bv( url, 0, 1, &l.sl_url);
	li = ch_malloc( sizeof( Listener ) );
	*li = l;
	slap_listeners[*cur] = li;
	(*cur)++;
	sal++;

	} /* while ( *sal != NULL ) */

	slap_free_listener_addresses(psal);

	if ( l.sl_url.bv_val == NULL )
	{
		Debug( LDAP_DEBUG_TRACE,
			"slap_open_listener: failed on %s\n", url, 0, 0 );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "daemon: initialized %s\n",
		l.sl_url.bv_val, 0, 0 );
	return 0;
}

static int sockinit(void);
static int sockdestroy(void);

int slapd_daemon_init( const char *urls )
{
	int i, j, n, rc;
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

	SLAP_SOCK_SET_INIT;

	if( urls == NULL ) {
		urls = "ldap:///";
	}

	u = ldap_str2charray( urls, " " );

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
		ldap_charray_free( u );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "daemon_init: %d listeners to open...\n",
		i, 0, 0 );
	slap_listeners = ch_malloc( (i+1)*sizeof(Listener *) );

	for(n = 0, j = 0; u[n]; n++ ) {
		if ( slap_open_listener( u[n], &i, &j ) ) {
			ldap_charray_free( u );
			return -1;
		}
	}
	slap_listeners[j] = NULL;

	Debug( LDAP_DEBUG_TRACE, "daemon_init: %d listeners opened\n",
		i, 0, 0 );

#ifdef HAVE_SLP
	if( slapd_register_slp ) {
		slapd_slp_init( urls );
		slapd_slp_reg();
	}
#endif

	ldap_charray_free( u );
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

#ifdef HAVE_SLP
	if( slapd_register_slp ) {
		slapd_slp_dereg();
		slapd_slp_deinit();
	}
#endif

	return 0;
}


static void
close_listeners(
	int remove
)
{
	int l;

	for ( l = 0; slap_listeners[l] != NULL; l++ ) {
		if ( slap_listeners[l]->sl_sd != AC_SOCKET_INVALID ) {
			if ( remove )
				slapd_remove( slap_listeners[l]->sl_sd, 0, 0 );
#ifdef LDAP_PF_LOCAL
			if ( slap_listeners[l]->sl_sa.sa_addr.sa_family == AF_LOCAL ) {
				unlink( slap_listeners[l]->sl_sa.sa_un_addr.sun_path );
			}
#endif /* LDAP_PF_LOCAL */
			slapd_close( slap_listeners[l]->sl_sd );
		}
		if ( slap_listeners[l]->sl_url.bv_val )
			ber_memfree( slap_listeners[l]->sl_url.bv_val );
		if ( slap_listeners[l]->sl_name.bv_val )
			ber_memfree( slap_listeners[l]->sl_name.bv_val );
		free ( slap_listeners[l] );
		slap_listeners[l] = NULL;
	}
}

static int
slapd_handle_listener(
	Listener *sl
)
{
	Sockaddr		from;

	ber_socket_t s;
	socklen_t len = sizeof(from);
	long id;
	slap_ssf_t ssf = 0;
	struct berval authid = BER_BVNULL;
#ifdef SLAPD_RLOOKUPS
	char hbuf[NI_MAXHOST];
#endif

	char	*dnsname = NULL;
	char	*peeraddr = NULL;
#ifdef LDAP_PF_LOCAL
	char peername[MAXPATHLEN + sizeof("PATH=")];
#elif defined(LDAP_PF_INET6)
	char peername[sizeof("IP=ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535")];
#else
	char peername[sizeof("IP=255.255.255.255:65336")];
#endif /* LDAP_PF_LOCAL */

	peername[0] = '\0';

#ifdef LDAP_CONNECTIONLESS
	if ( sl->sl_is_udp ) {
		/* The first time we receive a query, we set this
		 * up as a "connection". It remains open for the life
		 * of the slapd.
		 */
		if ( sl->sl_is_udp < 2 ) {
			id = connection_init( sl->sl_sd, sl, "", "",
				CONN_IS_UDP, ssf, NULL );
		    sl->sl_is_udp++;
		}
		return 1;
	}
#endif

#  ifdef LDAP_PF_LOCAL
	/* FIXME: apparently accept doesn't fill
	 * the sun_path sun_path member */
	from.sa_un_addr.sun_path[0] = '\0';
#  endif /* LDAP_PF_LOCAL */

	s = accept( sl->sl_sd, (struct sockaddr *) &from, &len );
	if ( s == AC_SOCKET_INVALID ) {
		int err = sock_errno();

		if(
#ifdef EMFILE
		    err == EMFILE ||
#endif
#ifdef ENFILE
		    err == ENFILE ||
#endif
		    0 )
		{
			ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
			emfile++;
			/* Stop listening until an existing session closes */
			sl->sl_is_mute = 1;
			ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
		}

		Debug( LDAP_DEBUG_ANY,
			"daemon: accept(%ld) failed errno=%d (%s)\n",
			(long) sl->sl_sd, err,
			sock_errstr(err) );
		ldap_pvt_thread_yield();
		return 0;
	}

#ifndef HAVE_WINSOCK
	/* make sure descriptor number isn't too great */
	if ( s >= dtblsize ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: %ld beyond descriptor table size %ld\n",
			(long) s, (long) dtblsize, 0 );

		slapd_close(s);
		ldap_pvt_thread_yield();
		return 0;
	}
#endif

#ifdef LDAP_DEBUG
	ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

	/* newly accepted stream should not be in any of the FD SETS */
	assert( SLAP_SOCK_NOT_ACTIVE( s ));

	ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
#endif

#if defined( SO_KEEPALIVE ) || defined( TCP_NODELAY )
#ifdef LDAP_PF_LOCAL
	/* for IPv4 and IPv6 sockets only */
	if ( from.sa_addr.sa_family != AF_LOCAL )
#endif /* LDAP_PF_LOCAL */
	{
		int rc;
		int tmp;
#ifdef SO_KEEPALIVE
		/* enable keep alives */
		tmp = 1;
		rc = setsockopt( s, SOL_SOCKET, SO_KEEPALIVE,
			(char *) &tmp, sizeof(tmp) );
		if ( rc == AC_SOCKET_ERROR ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"slapd(%ld): setsockopt(SO_KEEPALIVE) failed "
				"errno=%d (%s)\n", (long) s, err, sock_errstr(err) );
		}
#endif
#ifdef TCP_NODELAY
		/* enable no delay */
		tmp = 1;
		rc = setsockopt( s, IPPROTO_TCP, TCP_NODELAY,
			(char *)&tmp, sizeof(tmp) );
		if ( rc == AC_SOCKET_ERROR ) {
			int err = sock_errno();
			Debug( LDAP_DEBUG_ANY,
				"slapd(%ld): setsockopt(TCP_NODELAY) failed "
				"errno=%d (%s)\n", (long) s, err, sock_errstr(err) );
		}
#endif
	}
#endif

	Debug( LDAP_DEBUG_CONNS, "daemon: new connection on %ld\n",
		(long) s, 0, 0 );
	switch ( from.sa_addr.sa_family ) {
#  ifdef LDAP_PF_LOCAL
	case AF_LOCAL:
		/* FIXME: apparently accept doesn't fill
		 * the sun_path sun_path member */
		if ( from.sa_un_addr.sun_path[0] == '\0' ) {
			AC_MEMCPY( from.sa_un_addr.sun_path,
					sl->sl_sa.sa_un_addr.sun_path,
					sizeof( from.sa_un_addr.sun_path ) );
		}

		sprintf( peername, "PATH=%s", from.sa_un_addr.sun_path );
		ssf = local_ssf;
		{
			uid_t uid;
			gid_t gid;

			if( getpeereid( s, &uid, &gid ) == 0 ) {
				authid.bv_val = ch_malloc(
					sizeof("uidnumber=4294967295+gidnumber=4294967295,"
					"cn=peercred,cn=external,cn=auth"));
				authid.bv_len = sprintf( authid.bv_val,
					"uidnumber=%d+gidnumber=%d,"
					"cn=peercred,cn=external,cn=auth",
					(int) uid, (int) gid);
			}
		}
		dnsname = "local";
		break;
#endif /* LDAP_PF_LOCAL */

#  ifdef LDAP_PF_INET6
	case AF_INET6:
	if ( IN6_IS_ADDR_V4MAPPED(&from.sa_in6_addr.sin6_addr) ) {
		peeraddr = inet_ntoa( *((struct in_addr *)
					&from.sa_in6_addr.sin6_addr.s6_addr[12]) );
		sprintf( peername, "IP=%s:%d",
			 peeraddr != NULL ? peeraddr : SLAP_STRING_UNKNOWN,
			 (unsigned) ntohs( from.sa_in6_addr.sin6_port ) );
	} else {
		char addr[INET6_ADDRSTRLEN];

		peeraddr = (char *) inet_ntop( AF_INET6,
				      &from.sa_in6_addr.sin6_addr,
				      addr, sizeof addr );
		sprintf( peername, "IP=%s %d",
			 peeraddr != NULL ? peeraddr : SLAP_STRING_UNKNOWN,
			 (unsigned) ntohs( from.sa_in6_addr.sin6_port ) );
	}
	break;
#  endif /* LDAP_PF_INET6 */

	case AF_INET:
	peeraddr = inet_ntoa( from.sa_in_addr.sin_addr );
	sprintf( peername, "IP=%s:%d",
		peeraddr != NULL ? peeraddr : SLAP_STRING_UNKNOWN,
		(unsigned) ntohs( from.sa_in_addr.sin_port ) );
		break;

	default:
		slapd_close(s);
		return 0;
	}

	if ( ( from.sa_addr.sa_family == AF_INET )
#ifdef LDAP_PF_INET6
		|| ( from.sa_addr.sa_family == AF_INET6 )
#endif
	) {
#ifdef SLAPD_RLOOKUPS
		if ( use_reverse_lookup ) {
			char *herr;
			if (ldap_pvt_get_hname( (const struct sockaddr *)&from, len, hbuf,
				sizeof(hbuf), &herr ) == 0) {
				ldap_pvt_str2lower( hbuf );
				dnsname = hbuf;
			}
		}
#else
		dnsname = NULL;
#endif /* SLAPD_RLOOKUPS */

#ifdef HAVE_TCPD
		if ( !hosts_ctl("slapd",
				dnsname != NULL ? dnsname : SLAP_STRING_UNKNOWN,
				peeraddr != NULL ? peeraddr : SLAP_STRING_UNKNOWN,
				SLAP_STRING_UNKNOWN ))
		{
			/* DENY ACCESS */
			Statslog( LDAP_DEBUG_STATS,
				"fd=%ld DENIED from %s (%s)\n",
				(long) s,
				dnsname != NULL ? dnsname : SLAP_STRING_UNKNOWN,
				peeraddr != NULL ? peeraddr : SLAP_STRING_UNKNOWN,
				0, 0 );
			slapd_close(s);
			return 0;
		}
#endif /* HAVE_TCPD */
	}

	id = connection_init(s, sl,
		dnsname != NULL ? dnsname : SLAP_STRING_UNKNOWN,
		peername,
#ifdef HAVE_TLS
		sl->sl_is_tls ? CONN_IS_TLS : 0,
#else
		0,
#endif
		ssf,
		authid.bv_val ? &authid : NULL );

	if( authid.bv_val ) ch_free(authid.bv_val);

	if( id < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"daemon: connection_init(%ld, %s, %s) failed.\n",
			(long) s, peername, sl->sl_name.bv_val );
		slapd_close(s);
		return 0;
	}

	Statslog( LDAP_DEBUG_STATS,
		"conn=%ld fd=%ld ACCEPT from %s (%s)\n",
		id, (long) s, peername, sl->sl_name.bv_val,
		0 );

	slapd_add( s, 1 );
	return 0;
}

static void *
slapd_daemon_task(
	void *ptr
)
{
	int l;
	time_t	last_idle_check = 0;
	struct timeval idle;

#define SLAPD_IDLE_CHECK_LIMIT 4

	if ( global_idletimeout > 0 ) {
		last_idle_check = slap_get_time();
		/* Set the select timeout.
		 * Don't just truncate, preserve the fractions of
		 * seconds to prevent sleeping for zero time.
		 */
		idle.tv_sec = global_idletimeout/SLAPD_IDLE_CHECK_LIMIT;
		idle.tv_usec = global_idletimeout - idle.tv_sec * SLAPD_IDLE_CHECK_LIMIT;
		idle.tv_usec *= 1000000 / SLAPD_IDLE_CHECK_LIMIT;
	} else {
		idle.tv_sec = 0;
		idle.tv_usec = 0;
	}

	slapd_add( wake_sds[0], 0 );

	for ( l = 0; slap_listeners[l] != NULL; l++ ) {
		if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
			continue;
#ifdef LDAP_CONNECTIONLESS
		/* Since this is connectionless, the data port is the
		 * listening port. The listen() and accept() calls
		 * are unnecessary.
		 */
		if ( slap_listeners[l]->sl_is_udp ) {
			slapd_add( slap_listeners[l]->sl_sd, 1 );
			continue;
		}
#endif

		if ( listen( slap_listeners[l]->sl_sd, SLAPD_LISTEN ) == -1 ) {
			int err = sock_errno();

#ifdef LDAP_PF_INET6
			/* If error is EADDRINUSE, we are trying to listen to INADDR_ANY and
			 * we are already listening to in6addr_any, then we want to ignore
			 * this and continue.
			 */
			if ( err == EADDRINUSE ) {
				int i;
				struct sockaddr_in sa = slap_listeners[l]->sl_sa.sa_in_addr;
				struct sockaddr_in6 sa6;
				
				if ( sa.sin_family == AF_INET &&
				     sa.sin_addr.s_addr == htonl(INADDR_ANY) ) {
					for ( i = 0 ; i < l; i++ ) {
						sa6 = slap_listeners[i]->sl_sa.sa_in6_addr;
						if ( sa6.sin6_family == AF_INET6 &&
						     !memcmp( &sa6.sin6_addr, &in6addr_any, sizeof(struct in6_addr) ) )
							break;
					}

					if ( i < l ) {
						/* We are already listening to in6addr_any */
						Debug( LDAP_DEBUG_CONNS,
						       "daemon: Attempt to listen to 0.0.0.0 failed, already listening on ::, assuming IPv4 included\n",
						       0, 0, 0 );
						slapd_close( slap_listeners[l]->sl_sd );
						slap_listeners[l]->sl_sd = AC_SOCKET_INVALID;
						continue;
					}
				}
			}
#endif				
			Debug( LDAP_DEBUG_ANY,
				"daemon: listen(%s, 5) failed errno=%d (%s)\n",
					slap_listeners[l]->sl_url.bv_val, err,
					sock_errstr(err) );
			return( (void*)-1 );
		}

		slapd_add( slap_listeners[l]->sl_sd, 0 );
	}

#ifdef HAVE_NT_SERVICE_MANAGER
	if ( started_event != NULL ) {
		ldap_pvt_thread_cond_signal( &started_event );
	}
#endif
	/* initialization complete. Here comes the loop. */

	while ( !slapd_shutdown ) {
		ber_socket_t i;
		int ns, nwriters;
		int at;
		ber_socket_t nfds, nrfds, nwfds;
#define SLAPD_EBADF_LIMIT 16
		int ebadf = 0;

		time_t	now;

		SLAP_EVENT_DECL;

		struct timeval		tv;
		struct timeval		*tvp;

		struct timeval		*cat;
		time_t				tdelta = 1;
		struct re_s*		rtask;
		now = slap_get_time();

		if( ( global_idletimeout > 0 ) &&
			difftime( last_idle_check +
			global_idletimeout/SLAPD_IDLE_CHECK_LIMIT, now ) < 0 ) {
			connections_timeout_idle( now );
			last_idle_check = now;
		}
		tv = idle;

#ifdef SIGHUP
		if( slapd_gentle_shutdown ) {
			ber_socket_t active;

			if( slapd_gentle_shutdown == 1 ) {
				Debug( LDAP_DEBUG_ANY, "slapd gentle shutdown\n", 0, 0, 0 );
				close_listeners( 1 );
				frontendDB->be_restrictops |= SLAP_RESTRICT_OP_WRITES;
				slapd_gentle_shutdown = 2;
			}

			ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );
			active = slap_daemon.sd_nactives;
			ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );
			if( active == 0 ) {
				slapd_shutdown = 2;
				break;
			}
		}
#endif

		at = 0;

		ldap_pvt_thread_mutex_lock( &slap_daemon.sd_mutex );

		nwriters = slap_daemon.sd_nwriters;
		SLAP_EVENT_INIT;

		for ( l = 0; slap_listeners[l] != NULL; l++ ) {
			if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
				continue;
			if ( slap_listeners[l]->sl_is_mute )
				SLAP_SOCK_SET_MUTE( slap_listeners[l]->sl_sd );
			else
			if ( SLAP_SOCK_IS_MUTE( slap_listeners[l]->sl_sd ))
			    SLAP_SOCK_CLR_MUTE( slap_listeners[l]->sl_sd );
		}

		nfds = SLAP_MAXWAIT;

		if ( global_idletimeout && slap_daemon.sd_nactives )
			at = 1;

		ldap_pvt_thread_mutex_unlock( &slap_daemon.sd_mutex );

		if ( at 
#if defined(HAVE_YIELDING_SELECT) || defined(NO_THREADS)
			&&  ( tv.tv_sec || tv.tv_usec )
#endif
			)
			tvp = &tv;
		else
			tvp = NULL;

		ldap_pvt_thread_mutex_lock( &syncrepl_rq.rq_mutex );
		rtask = ldap_pvt_runqueue_next_sched( &syncrepl_rq, &cat );
		while ( cat && cat->tv_sec && cat->tv_sec <= now ) {
			if ( ldap_pvt_runqueue_isrunning( &syncrepl_rq, rtask )) {
				ldap_pvt_runqueue_resched( &syncrepl_rq, rtask, 0 );
			} else {
				ldap_pvt_runqueue_runtask( &syncrepl_rq, rtask );
				ldap_pvt_runqueue_resched( &syncrepl_rq, rtask, 0 );
				ldap_pvt_thread_mutex_unlock( &syncrepl_rq.rq_mutex );
				ldap_pvt_thread_pool_submit( &connection_pool,
											rtask->routine, (void *) rtask );
				ldap_pvt_thread_mutex_lock( &syncrepl_rq.rq_mutex );
			}
			rtask = ldap_pvt_runqueue_next_sched( &syncrepl_rq, &cat );
		}
		ldap_pvt_thread_mutex_unlock( &syncrepl_rq.rq_mutex );

		if ( cat != NULL ) {
			time_t diff = difftime( cat->tv_sec, now );
			if ( diff == 0 )
				diff = tdelta;
			if ( tvp == NULL || diff < tv.tv_sec ) {
				tv.tv_sec = diff;
				tv.tv_usec = 0;
				tvp = &tv;
			}
		}

		for ( l = 0; slap_listeners[l] != NULL; l++ ) {
			if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID ||
			    slap_listeners[l]->sl_is_mute )
				continue;

			Debug( LDAP_DEBUG_CONNS,
				"daemon: select: listen=%d active_threads=%d tvp=%s\n",
					slap_listeners[l]->sl_sd, at,
					tvp == NULL ? "NULL" : "zero" );
		}

		switch(ns = SLAP_EVENT_WAIT(tvp))
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
					slapd_shutdown = 2;
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
			if( slapd_shutdown ) continue;

			ebadf = 0;
			Debug( LDAP_DEBUG_CONNS, "daemon: activity on %d descriptors\n",
				ns, 0, 0 );
			/* FALL THRU */
		}

		/* We don't need to examine the event status for wake_sds;
		 * if waking is set and we woke up, we'll read whatever
		 * we can.
		 */
		if ( waking ) {
			char c[BUFSIZ];
			tcp_read( wake_sds[0], c, sizeof(c) );
			waking = 0;
			ns--;
			continue;
		}

#if SLAP_EVENTS_ARE_INDEXED
		/* The event slot equals the descriptor number - this is
		 * true for Unix select and poll. We treat Windows select
		 * like this too, even though it's a kludge.
		 */
		for ( l = 0; slap_listeners[l] != NULL; l++ ) {
			int rc;

			if ( ns <= 0 ) break;

			if ( slap_listeners[l]->sl_sd == AC_SOCKET_INVALID )
				continue;

			if ( !SLAP_EVENT_IS_READ( slap_listeners[l]->sl_sd ))
				continue;
			
			ns--;

			rc = slapd_handle_listener(slap_listeners[l]);

#ifdef LDAP_CONNECTIONLESS
			if ( rc ) continue;
#endif

			/* Don't need to look at this in the data loops */
			SLAP_EVENT_CLR_READ( slap_listeners[l]->sl_sd );
			SLAP_EVENT_CLR_WRITE( slap_listeners[l]->sl_sd );
		}

		/* bypass the following tests if no descriptors left */
		if ( ns <= 0 ) {
			ldap_pvt_thread_yield();
			continue;
		}

		Debug( LDAP_DEBUG_CONNS, "daemon: activity on:", 0, 0, 0 );
#ifdef HAVE_WINSOCK
		nrfds = readfds.fd_count;
		nwfds = writefds.fd_count;
		for ( i = 0; i < readfds.fd_count; i++ ) {
			Debug( LDAP_DEBUG_CONNS, " %d%s",
				readfds.fd_array[i], "r", 0 );
		}
		for ( i = 0; i < writefds.fd_count; i++ ) {
			Debug( LDAP_DEBUG_CONNS, " %d%s",
				writefds.fd_array[i], "w", 0 );
		}

#else
		nrfds = 0;
		nwfds = 0;
		for ( i = 0; i < nfds; i++ ) {
			int	r, w;

			r = SLAP_EVENT_IS_READ( i );
			w = SLAP_EVENT_IS_WRITE( i );
			if ( r || w ) {
				Debug( LDAP_DEBUG_CONNS, " %d%s%s", i,
				    r ? "r" : "", w ? "w" : "" );
				if ( r ) {
					nrfds++;
					ns--;
				}
				if ( w ) {
					nwfds++;
					ns--;
				}
			}
			if ( ns <= 0 ) break;
		}
#endif
		Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );


		/* loop through the writers */
		for ( i = 0; nwfds > 0; i++ )
		{
			ber_socket_t wd;
#ifdef HAVE_WINSOCK
			wd = writefds.fd_array[i];
#else
			if( ! SLAP_EVENT_IS_WRITE( i ) ) {
				continue;
			}
			wd = i;
#endif
			nwfds--;

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
				if ( SLAP_EVENT_IS_READ( wd )) {
					SLAP_EVENT_CLR_READ( (unsigned) wd );
					nrfds--;
				}
				slapd_close( wd );
			}
		}

		for ( i = 0; nrfds > 0; i++ )
		{
			ber_socket_t rd;
#ifdef HAVE_WINSOCK
			rd = readfds.fd_array[i];
#else
			if( ! SLAP_EVENT_IS_READ( i ) ) {
				continue;
			}
			rd = i;
#endif
			nrfds--;

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
#else	/* !SLAP_EVENTS_ARE_INDEXED */
	/* FIXME */
	/* The events are returned in an arbitrary list. This is true
	 * for /dev/poll, epoll and kqueue. In order to prioritize things
	 * so that we can handle wake_sds first, listeners second, and then
	 * all other connections last (as we do for select), we would need
	 * to use multiple event handles and cascade them.
	 *
	 * That seems like a bit of hassle. So the wake_sds check has moved
	 * above. For epoll and kqueue we can associate arbitrary data with
	 * an event, so we could use pointers to the listener structure
	 * instead of just the file descriptor. For /dev/poll we have to
	 * search the listeners array for a matching descriptor.
	 */
#endif
		ldap_pvt_thread_yield();
	}

	if( slapd_shutdown == 1 ) {
		Debug( LDAP_DEBUG_TRACE,
			"daemon: shutdown requested and initiated.\n",
			0, 0, 0 );

	} else if ( slapd_shutdown == 2 ) {
#ifdef HAVE_NT_SERVICE_MANAGER
			Debug( LDAP_DEBUG_TRACE,
			       "daemon: shutdown initiated by Service Manager.\n",
			       0, 0, 0);
#else /* !HAVE_NT_SERVICE_MANAGER */
			Debug( LDAP_DEBUG_TRACE,
			       "daemon: abnormal condition, shutdown initiated.\n",
			       0, 0, 0 );
#endif /* !HAVE_NT_SERVICE_MANAGER */
	} else {
		Debug( LDAP_DEBUG_TRACE,
		       "daemon: no active streams, shutdown initiated.\n",
		       0, 0, 0 );
	}

	if( slapd_gentle_shutdown != 2 ) {
		close_listeners ( 0 );
	}

	free ( slap_listeners );
	slap_listeners = NULL;

	if( !slapd_gentle_shutdown ) {
		slapd_abrupt_shutdown = 1;
		connections_shutdown();
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
#if defined( SLAPD_LISTENER_THREAD )
	{
		ldap_pvt_thread_t	listener_tid;

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
	}
#else
	/* experimental code */
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
		/* WinSock DLL.					 */
		return -1;
	}

	/* Confirm that the WinSock DLL supports 2.0.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.0 in addition to 2.0, it will still return */
	/* 2.0 in wVersion since that is the version we	     */
	/* requested.					     */

	if ( LOBYTE( wsaData.wVersion ) != 2 ||
		HIBYTE( wsaData.wVersion ) != 0 )
	{
	    /* Tell the user that we couldn't find a usable */
	    /* WinSock DLL.				     */
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
#if 0
	Debug(LDAP_DEBUG_TRACE, "slap_sig_shutdown: signal %d\n", sig, 0, 0);
#endif

	/*
	 * If the NT Service Manager is controlling the server, we don't
	 * want SIGBREAK to kill the server. For some strange reason,
	 * SIGBREAK is generated when a user logs out.
	 */

#if HAVE_NT_SERVICE_MANAGER && SIGBREAK
	if (is_NT_Service && sig == SIGBREAK)
		;
	else
#endif
#ifdef SIGHUP
	if (sig == SIGHUP && global_gentlehup && slapd_gentle_shutdown == 0)
		slapd_gentle_shutdown = 1;
	else
#endif
	slapd_shutdown = 1;
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


void slapd_add_internal(ber_socket_t s, int isactive) {
	slapd_add(s, isactive);
}

Listener ** slapd_get_listeners(void) {
	return slap_listeners;
}

void slap_wake_listener()
{
	WAKE_LISTENER(1);
}
