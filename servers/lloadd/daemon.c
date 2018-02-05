/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2015 The OpenLDAP Foundation.
 * Portions Copyright 2007 by Howard Chu, Symas Corporation.
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

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include "lload.h"
#include "ldap_pvt_thread.h"
#include "lutil.h"

#include "ldap_rq.h"

#ifdef LDAP_PF_LOCAL
#include <sys/stat.h>
/* this should go in <ldap.h> as soon as it is accepted */
#define LDAPI_MOD_URLEXT "x-mod"
#endif /* LDAP_PF_LOCAL */

#ifndef BALANCER_MODULE
#ifdef LDAP_PF_INET6
int slap_inet4or6 = AF_UNSPEC;
#else /* ! INETv6 */
int slap_inet4or6 = AF_INET;
#endif /* ! INETv6 */

/* globals */
time_t starttime;
struct runqueue_s slapd_rq;

#ifdef LDAP_TCP_BUFFER
int slapd_tcp_rmem;
int slapd_tcp_wmem;
#endif /* LDAP_TCP_BUFFER */

volatile sig_atomic_t slapd_shutdown = 0;
volatile sig_atomic_t slapd_gentle_shutdown = 0;
volatile sig_atomic_t slapd_abrupt_shutdown = 0;
#endif /* !BALANCER_MODULE */

static int emfile;

#ifndef SLAPD_MAX_DAEMON_THREADS
#define SLAPD_MAX_DAEMON_THREADS 16
#endif
int lload_daemon_threads = 1;
int lload_daemon_mask;

struct event_base *listener_base = NULL;
LloadListener **lload_listeners = NULL;
static ldap_pvt_thread_t listener_tid, *daemon_tid;

struct evdns_base *dnsbase;

struct event *lload_timeout_event;

/*
 * global lload statistics. Not mutex protected to preserve performance -
 * increment is atomic, at most we risk a bit of inconsistency
 */
lload_global_stats_t lload_stats;

#ifndef SLAPD_LISTEN_BACKLOG
#define SLAPD_LISTEN_BACKLOG 1024
#endif /* ! SLAPD_LISTEN_BACKLOG */

#define DAEMON_ID(fd) ( fd & lload_daemon_mask )

#ifdef HAVE_WINSOCK
ldap_pvt_thread_mutex_t slapd_ws_mutex;
SOCKET *slapd_ws_sockets;
#define SD_READ 1
#define SD_WRITE 2
#define SD_ACTIVE 4
#define SD_LISTENER 8
#endif

#ifdef HAVE_TCPD
static ldap_pvt_thread_mutex_t sd_tcpd_mutex;
#endif /* TCP Wrappers */

typedef struct listener_item {
    struct evconnlistener *listener;
    ber_socket_t fd;
} listener_item;

typedef struct lload_daemon_st {
    ldap_pvt_thread_mutex_t sd_mutex;

    struct event_base *base;
    struct event *wakeup_event;
} lload_daemon_st;

static lload_daemon_st lload_daemon[SLAPD_MAX_DAEMON_THREADS];

static void daemon_wakeup_cb( evutil_socket_t sig, short what, void *arg );

static void
lloadd_close( ber_socket_t s )
{
    Debug( LDAP_DEBUG_CONNS, "lloadd_close: "
            "closing fd=%ld\n",
            (long)s );
    tcp_close( s );
}

static void
lload_free_listener_addresses( struct sockaddr **sal )
{
    struct sockaddr **sap;
    if ( sal == NULL ) return;
    for ( sap = sal; *sap != NULL; sap++ )
        ch_free(*sap);
    ch_free( sal );
}

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
static int
get_url_perms( char **exts, mode_t *perms, int *crit )
{
    int i;

    assert( exts != NULL );
    assert( perms != NULL );
    assert( crit != NULL );

    *crit = 0;
    for ( i = 0; exts[i]; i++ ) {
        char *type = exts[i];
        int c = 0;

        if ( type[0] == '!' ) {
            c = 1;
            type++;
        }

        if ( strncasecmp( type, LDAPI_MOD_URLEXT "=",
                     sizeof(LDAPI_MOD_URLEXT "=") - 1 ) == 0 ) {
            char *value = type + ( sizeof(LDAPI_MOD_URLEXT "=") - 1 );
            mode_t p = 0;
            int j;

            switch ( strlen( value ) ) {
                case 4:
                    /* skip leading '0' */
                    if ( value[0] != '0' ) return LDAP_OTHER;
                    value++;

                case 3:
                    for ( j = 0; j < 3; j++ ) {
                        int v;

                        v = value[j] - '0';

                        if ( v < 0 || v > 7 ) return LDAP_OTHER;

                        p |= v << 3 * ( 2 - j );
                    }
                    break;

                case 10:
                    for ( j = 1; j < 10; j++ ) {
                        static mode_t m[] = { 0, S_IRUSR, S_IWUSR, S_IXUSR,
                                S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH,
                                S_IXOTH };
                        static const char c[] = "-rwxrwxrwx";

                        if ( value[j] == c[j] ) {
                            p |= m[j];

                        } else if ( value[j] != '-' ) {
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
static int
lload_get_listener_addresses(
        const char *host,
        unsigned short port,
        struct sockaddr ***sal )
{
    struct sockaddr **sap;

#ifdef LDAP_PF_LOCAL
    if ( port == 0 ) {
        sap = *sal = ch_malloc( 2 * sizeof(void *) );

        *sap = ch_calloc( 1, sizeof(struct sockaddr_un) );
        sap[1] = NULL;

        if ( strlen( host ) >
                ( sizeof( ((struct sockaddr_un *)*sap)->sun_path ) - 1 ) ) {
            Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                    "domain socket path (%s) too long in URL\n",
                    host );
            goto errexit;
        }

        (*sap)->sa_family = AF_LOCAL;
        strcpy( ((struct sockaddr_un *)*sap)->sun_path, host );
    } else
#endif /* LDAP_PF_LOCAL */
    {
#ifdef HAVE_GETADDRINFO
        struct addrinfo hints, *res, *sai;
        int n, err;
        char serv[7];

        memset( &hints, '\0', sizeof(hints) );
        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family = slap_inet4or6;
        snprintf( serv, sizeof(serv), "%d", port );

        if ( (err = getaddrinfo( host, serv, &hints, &res )) ) {
            Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                    "getaddrinfo() failed: %s\n",
                    AC_GAI_STRERROR(err) );
            return -1;
        }

        sai = res;
        for ( n = 2; ( sai = sai->ai_next ) != NULL; n++ ) {
            /* EMPTY */;
        }
        sap = *sal = ch_calloc( n, sizeof(void *) );

        *sap = NULL;

        for ( sai = res; sai; sai = sai->ai_next ) {
            if ( sai->ai_addr == NULL ) {
                Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                        "getaddrinfo ai_addr is NULL?\n" );
                freeaddrinfo( res );
                goto errexit;
            }

            switch ( sai->ai_family ) {
#ifdef LDAP_PF_INET6
                case AF_INET6:
                    *sap = ch_malloc( sizeof(struct sockaddr_in6) );
                    *(struct sockaddr_in6 *)*sap =
                            *((struct sockaddr_in6 *)sai->ai_addr);
                    break;
#endif /* LDAP_PF_INET6 */
                case AF_INET:
                    *sap = ch_malloc( sizeof(struct sockaddr_in) );
                    *(struct sockaddr_in *)*sap =
                            *((struct sockaddr_in *)sai->ai_addr);
                    break;
                default:
                    *sap = NULL;
                    break;
            }

            if ( *sap != NULL ) {
                (*sap)->sa_family = sai->ai_family;
                sap++;
                *sap = NULL;
            }
        }

        freeaddrinfo( res );

#else /* ! HAVE_GETADDRINFO */
        int i, n = 1;
        struct in_addr in;
        struct hostent *he = NULL;

        if ( host == NULL ) {
            in.s_addr = htonl( INADDR_ANY );

        } else if ( !inet_aton( host, &in ) ) {
            he = gethostbyname( host );
            if ( he == NULL ) {
                Debug( LDAP_DEBUG_ANY, "lload_get_listener_addresses: "
                        "invalid host %s\n",
                        host );
                return -1;
            }
            for ( n = 0; he->h_addr_list[n]; n++ ) /* empty */;
        }

        sap = *sal = ch_malloc( ( n + 1 ) * sizeof(void *) );

        for ( i = 0; i < n; i++ ) {
            sap[i] = ch_calloc( 1, sizeof(struct sockaddr_in) );
            sap[i]->sa_family = AF_INET;
            ((struct sockaddr_in *)sap[i])->sin_port = htons( port );
            AC_MEMCPY( &((struct sockaddr_in *)sap[i])->sin_addr,
                    he ? (struct in_addr *)he->h_addr_list[i] : &in,
                    sizeof(struct in_addr) );
        }
        sap[i] = NULL;
#endif /* ! HAVE_GETADDRINFO */
    }

    return 0;

errexit:
    lload_free_listener_addresses(*sal);
    return -1;
}

static int
lload_open_listener( const char *url, int *listeners, int *cur )
{
    int num, tmp, rc;
    LloadListener l;
    LloadListener *li;
    LDAPURLDesc *lud;
    unsigned short port;
    int err, addrlen = 0;
    struct sockaddr **sal = NULL, **psal;
    int socktype = SOCK_STREAM; /* default to COTS */
    ber_socket_t s;
    char ebuf[128];

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
    /*
     * use safe defaults
     */
    int crit = 1;
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

    rc = ldap_url_parse( url, &lud );

    if ( rc != LDAP_URL_SUCCESS ) {
        Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                "listen URL \"%s\" parse error=%d\n",
                url, rc );
        return rc;
    }

    l.sl_url.bv_val = NULL;
    l.sl_mute = 0;
    l.sl_busy = 0;

#ifndef HAVE_TLS
    if ( ldap_pvt_url_scheme2tls( lud->lud_scheme ) ) {
        Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                "TLS not supported (%s)\n",
                url );
        ldap_free_urldesc( lud );
        return -1;
    }

    if ( !lud->lud_port ) lud->lud_port = LDAP_PORT;

#else /* HAVE_TLS */
    l.sl_is_tls = ldap_pvt_url_scheme2tls( lud->lud_scheme );

    if ( !lud->lud_port ) {
        lud->lud_port = l.sl_is_tls ? LDAPS_PORT : LDAP_PORT;
    }
#endif /* HAVE_TLS */

#ifdef LDAP_TCP_BUFFER
    l.sl_tcp_rmem = 0;
    l.sl_tcp_wmem = 0;
#endif /* LDAP_TCP_BUFFER */

    port = (unsigned short)lud->lud_port;

    tmp = ldap_pvt_url_scheme2proto( lud->lud_scheme );
    if ( tmp == LDAP_PROTO_IPC ) {
#ifdef LDAP_PF_LOCAL
        if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
            err = lload_get_listener_addresses( LDAPI_SOCK, 0, &sal );
        } else {
            err = lload_get_listener_addresses( lud->lud_host, 0, &sal );
        }
#else /* ! LDAP_PF_LOCAL */

        Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                "URL scheme not supported: %s\n",
                url );
        ldap_free_urldesc( lud );
        return -1;
#endif /* ! LDAP_PF_LOCAL */
    } else {
        if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ||
                strcmp( lud->lud_host, "*" ) == 0 ) {
            err = lload_get_listener_addresses( NULL, port, &sal );
        } else {
            err = lload_get_listener_addresses( lud->lud_host, port, &sal );
        }
    }

#if defined(LDAP_PF_LOCAL) || defined(SLAP_X_LISTENER_MOD)
    if ( lud->lud_exts ) {
        err = get_url_perms( lud->lud_exts, &l.sl_perms, &crit );
    } else {
        l.sl_perms = S_IRWXU | S_IRWXO;
    }
#endif /* LDAP_PF_LOCAL || SLAP_X_LISTENER_MOD */

    ldap_free_urldesc( lud );
    if ( err ) {
        lload_free_listener_addresses( sal );
        return -1;
    }

    /* If we got more than one address returned, we need to make space
     * for it in the lload_listeners array.
     */
    for ( num = 0; sal[num]; num++ ) /* empty */;
    if ( num > 1 ) {
        *listeners += num - 1;
        lload_listeners = ch_realloc( lload_listeners,
                ( *listeners + 1 ) * sizeof(LloadListener *) );
    }

    psal = sal;
    while ( *sal != NULL ) {
        char *af;
        switch ( (*sal)->sa_family ) {
            case AF_INET:
                af = "IPv4";
                break;
#ifdef LDAP_PF_INET6
            case AF_INET6:
                af = "IPv6";
                break;
#endif /* LDAP_PF_INET6 */
#ifdef LDAP_PF_LOCAL
            case AF_LOCAL:
                af = "Local";
                break;
#endif /* LDAP_PF_LOCAL */
            default:
                sal++;
                continue;
        }

        s = socket( (*sal)->sa_family, socktype, 0 );
        if ( s == AC_SOCKET_INVALID ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                    "%s socket() failed errno=%d (%s)\n",
                    af, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            sal++;
            continue;
        }
        ber_pvt_socket_set_nonblock( s, 1 );
        l.sl_sd = s;

#ifdef LDAP_PF_LOCAL
        if ( (*sal)->sa_family == AF_LOCAL ) {
            unlink( ((struct sockaddr_un *)*sal)->sun_path );
        } else
#endif /* LDAP_PF_LOCAL */
        {
#ifdef SO_REUSEADDR
            /* enable address reuse */
            tmp = 1;
            rc = setsockopt(
                    s, SOL_SOCKET, SO_REUSEADDR, (char *)&tmp, sizeof(tmp) );
            if ( rc == AC_SOCKET_ERROR ) {
                int err = sock_errno();
                Debug( LDAP_DEBUG_ANY, "lload_open_listener(%ld): "
                        "setsockopt(SO_REUSEADDR) failed errno=%d (%s)\n",
                        (long)l.sl_sd, err,
                        sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }
#endif /* SO_REUSEADDR */
        }

        switch ( (*sal)->sa_family ) {
            case AF_INET:
                addrlen = sizeof(struct sockaddr_in);
                break;
#ifdef LDAP_PF_INET6
            case AF_INET6:
#ifdef IPV6_V6ONLY
                /* Try to use IPv6 sockets for IPv6 only */
                tmp = 1;
                rc = setsockopt( s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&tmp,
                        sizeof(tmp) );
                if ( rc == AC_SOCKET_ERROR ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_open_listener(%ld): "
                            "setsockopt(IPV6_V6ONLY) failed errno=%d (%s)\n",
                            (long)l.sl_sd, err,
                            sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }
#endif /* IPV6_V6ONLY */
                addrlen = sizeof(struct sockaddr_in6);
                break;
#endif /* LDAP_PF_INET6 */

#ifdef LDAP_PF_LOCAL
            case AF_LOCAL:
#ifdef LOCAL_CREDS
            {
                int one = 1;
                setsockopt( s, 0, LOCAL_CREDS, &one, sizeof(one) );
            }
#endif /* LOCAL_CREDS */

                addrlen = sizeof(struct sockaddr_un);
                break;
#endif /* LDAP_PF_LOCAL */
        }

#ifdef LDAP_PF_LOCAL
        /* create socket with all permissions set for those systems
         * that honor permissions on sockets (e.g. Linux); typically,
         * only write is required.  To exploit filesystem permissions,
         * place the socket in a directory and use directory's
         * permissions.  Need write perms to the directory to
         * create/unlink the socket; likely need exec perms to access
         * the socket (ITS#4709) */
        {
            mode_t old_umask = 0;

            if ( (*sal)->sa_family == AF_LOCAL ) {
                old_umask = umask( 0 );
            }
#endif /* LDAP_PF_LOCAL */
            rc = bind( s, *sal, addrlen );
#ifdef LDAP_PF_LOCAL
            if ( old_umask != 0 ) {
                umask( old_umask );
            }
        }
#endif /* LDAP_PF_LOCAL */
        if ( rc ) {
            err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                    "bind(%ld) failed errno=%d (%s)\n",
                    (long)l.sl_sd, err,
                    sock_errstr( err, ebuf, sizeof(ebuf) ) );
            tcp_close( s );
            sal++;
            continue;
        }

        switch ( (*sal)->sa_family ) {
#ifdef LDAP_PF_LOCAL
            case AF_LOCAL: {
                char *path = ((struct sockaddr_un *)*sal)->sun_path;
                l.sl_name.bv_len = strlen( path ) + STRLENOF("PATH=");
                l.sl_name.bv_val = ch_malloc( l.sl_name.bv_len + 1 );
                snprintf( l.sl_name.bv_val, l.sl_name.bv_len + 1, "PATH=%s",
                        path );
            } break;
#endif /* LDAP_PF_LOCAL */

            case AF_INET: {
                char addr[INET_ADDRSTRLEN];
                const char *s;
#if defined(HAVE_GETADDRINFO) && defined(HAVE_INET_NTOP)
                s = inet_ntop( AF_INET,
                        &((struct sockaddr_in *)*sal)->sin_addr, addr,
                        sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                s = inet_ntoa( ((struct sockaddr_in *)*sal)->sin_addr );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                if ( !s ) s = SLAP_STRING_UNKNOWN;
                port = ntohs( ((struct sockaddr_in *)*sal)->sin_port );
                l.sl_name.bv_val =
                        ch_malloc( sizeof("IP=255.255.255.255:65535") );
                snprintf( l.sl_name.bv_val,
                        sizeof("IP=255.255.255.255:65535"), "IP=%s:%d", s,
                        port );
                l.sl_name.bv_len = strlen( l.sl_name.bv_val );
            } break;

#ifdef LDAP_PF_INET6
            case AF_INET6: {
                char addr[INET6_ADDRSTRLEN];
                const char *s;
                s = inet_ntop( AF_INET6,
                        &((struct sockaddr_in6 *)*sal)->sin6_addr, addr,
                        sizeof(addr) );
                if ( !s ) s = SLAP_STRING_UNKNOWN;
                port = ntohs( ((struct sockaddr_in6 *)*sal)->sin6_port );
                l.sl_name.bv_len = strlen( s ) + sizeof("IP=[]:65535");
                l.sl_name.bv_val = ch_malloc( l.sl_name.bv_len );
                snprintf( l.sl_name.bv_val, l.sl_name.bv_len, "IP=[%s]:%d", s,
                        port );
                l.sl_name.bv_len = strlen( l.sl_name.bv_val );
            } break;
#endif /* LDAP_PF_INET6 */

            default:
                Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                        "unsupported address family (%d)\n",
                        (int)(*sal)->sa_family );
                break;
        }

        AC_MEMCPY( &l.sl_sa, *sal, addrlen );
        ber_str2bv( url, 0, 1, &l.sl_url );
        li = ch_malloc( sizeof(LloadListener) );
        *li = l;
        lload_listeners[*cur] = li;
        (*cur)++;
        sal++;
    }

    lload_free_listener_addresses( psal );

    if ( l.sl_url.bv_val == NULL ) {
        Debug( LDAP_DEBUG_ANY, "lload_open_listener: "
                "failed on %s\n",
                url );
        return -1;
    }

    Debug( LDAP_DEBUG_TRACE, "lload_open_listener: "
            "listener initialized %s\n",
            l.sl_url.bv_val );

    return 0;
}

int lloadd_inited = 0;

int
lloadd_daemon_init( const char *urls )
{
    int i, j, n;
    char **u;

    Debug( LDAP_DEBUG_ARGS, "lloadd_daemon_init: %s\n",
            urls ? urls : "<null>" );

#ifdef HAVE_TCPD
    ldap_pvt_thread_mutex_init( &sd_tcpd_mutex );
#endif /* TCP Wrappers */

    if ( urls == NULL ) urls = "ldap:///";

    u = ldap_str2charray( urls, " " );

    if ( u == NULL || u[0] == NULL ) {
        Debug( LDAP_DEBUG_ANY, "lloadd_daemon_init: "
                "no urls (%s) provided\n",
                urls );
        if ( u ) ldap_charray_free( u );
        return -1;
    }

    for ( i = 0; u[i] != NULL; i++ ) {
        Debug( LDAP_DEBUG_TRACE, "lloadd_daemon_init: "
                "listen on %s\n",
                u[i] );
    }

    if ( i == 0 ) {
        Debug( LDAP_DEBUG_ANY, "lloadd_daemon_init: "
                "no listeners to open (%s)\n",
                urls );
        ldap_charray_free( u );
        return -1;
    }

    Debug( LDAP_DEBUG_TRACE, "lloadd_daemon_init: "
            "%d listeners to open...\n",
            i );
    lload_listeners = ch_malloc( ( i + 1 ) * sizeof(LloadListener *) );

    for ( n = 0, j = 0; u[n]; n++ ) {
        if ( lload_open_listener( u[n], &i, &j ) ) {
            ldap_charray_free( u );
            return -1;
        }
    }
    lload_listeners[j] = NULL;

    Debug( LDAP_DEBUG_TRACE, "lloadd_daemon_init: "
            "%d listeners opened\n",
            i );

    ldap_charray_free( u );

    return !i;
}

int
lloadd_daemon_destroy( void )
{
    if ( lloadd_inited ) {
        int i;

        for ( i = 0; i < lload_daemon_threads; i++ ) {
            ldap_pvt_thread_mutex_destroy( &lload_daemon[i].sd_mutex );
            if ( lload_daemon[i].wakeup_event ) {
                event_free( lload_daemon[i].wakeup_event );
            }
            if ( lload_daemon[i].base ) {
                event_base_free( lload_daemon[i].base );
            }
        }
        lloadd_inited = 0;
#ifdef HAVE_TCPD
        ldap_pvt_thread_mutex_destroy( &sd_tcpd_mutex );
#endif /* TCP Wrappers */
    }

    return 0;
}

static void
destroy_listeners( void )
{
    LloadListener *lr, **ll = lload_listeners;

    if ( ll == NULL ) return;

    ldap_pvt_thread_join( listener_tid, (void *)NULL );

    while ( (lr = *ll++) != NULL ) {
        if ( lr->sl_url.bv_val ) {
            ber_memfree( lr->sl_url.bv_val );
        }

        if ( lr->sl_name.bv_val ) {
            ber_memfree( lr->sl_name.bv_val );
        }

#ifdef LDAP_PF_LOCAL
        if ( lr->sl_sa.sa_addr.sa_family == AF_LOCAL ) {
            unlink( lr->sl_sa.sa_un_addr.sun_path );
        }
#endif /* LDAP_PF_LOCAL */

        evconnlistener_free( lr->listener );

        free( lr );
    }

    free( lload_listeners );
    lload_listeners = NULL;

    if ( listener_base ) {
        event_base_free( listener_base );
    }
}

static void
lload_listener(
        struct evconnlistener *listener,
        ber_socket_t s,
        struct sockaddr *a,
        int len,
        void *arg )
{
    LloadListener *sl = arg;
    LloadConnection *c;
    Sockaddr *from = (Sockaddr *)a;
#ifdef SLAPD_RLOOKUPS
    char hbuf[NI_MAXHOST];
#endif /* SLAPD_RLOOKUPS */

    const char *peeraddr = NULL;
    /* we assume INET6_ADDRSTRLEN > INET_ADDRSTRLEN */
    char addr[INET6_ADDRSTRLEN];
#ifdef LDAP_PF_LOCAL
    char peername[MAXPATHLEN + sizeof("PATH=")];
#ifdef LDAP_PF_LOCAL_SENDMSG
    char peerbuf[8];
    struct berval peerbv = BER_BVNULL;
#endif
#elif defined(LDAP_PF_INET6)
    char peername[sizeof("IP=[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")];
#else /* ! LDAP_PF_LOCAL && ! LDAP_PF_INET6 */
    char peername[sizeof("IP=255.255.255.255:65336")];
#endif /* LDAP_PF_LOCAL */
    int cflag;
    int tid;
    char ebuf[128];

    Debug( LDAP_DEBUG_TRACE, ">>> lload_listener(%s)\n", sl->sl_url.bv_val );

    peername[0] = '\0';

    /* Resume the listener FD to allow concurrent-processing of
     * additional incoming connections.
     */
    sl->sl_busy = 0;

    tid = DAEMON_ID(s);

    Debug( LDAP_DEBUG_CONNS, "lload_listener: "
            "listen=%ld, new connection fd=%ld\n",
            (long)sl->sl_sd, (long)s );

#if defined(SO_KEEPALIVE) || defined(TCP_NODELAY)
#ifdef LDAP_PF_LOCAL
    /* for IPv4 and IPv6 sockets only */
    if ( from->sa_addr.sa_family != AF_LOCAL )
#endif /* LDAP_PF_LOCAL */
    {
        int rc;
        int tmp;
#ifdef SO_KEEPALIVE
        /* enable keep alives */
        tmp = 1;
        rc = setsockopt(
                s, SOL_SOCKET, SO_KEEPALIVE, (char *)&tmp, sizeof(tmp) );
        if ( rc == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_listener(%ld): "
                    "setsockopt(SO_KEEPALIVE) failed errno=%d (%s)\n",
                    (long)s, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
        }
#endif /* SO_KEEPALIVE */
#ifdef TCP_NODELAY
        /* enable no delay */
        tmp = 1;
        rc = setsockopt(
                s, IPPROTO_TCP, TCP_NODELAY, (char *)&tmp, sizeof(tmp) );
        if ( rc == AC_SOCKET_ERROR ) {
            int err = sock_errno();
            Debug( LDAP_DEBUG_ANY, "lload_listener(%ld): "
                    "setsockopt(TCP_NODELAY) failed errno=%d (%s)\n",
                    (long)s, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
        }
#endif /* TCP_NODELAY */
    }
#endif /* SO_KEEPALIVE || TCP_NODELAY */

    cflag = 0;
    switch ( from->sa_addr.sa_family ) {
#ifdef LDAP_PF_LOCAL
        case AF_LOCAL:
            cflag |= CONN_IS_IPC;

            /* FIXME: apparently accept doesn't fill the sun_path member */
            sprintf( peername, "PATH=%s", sl->sl_sa.sa_un_addr.sun_path );
            break;
#endif /* LDAP_PF_LOCAL */

#ifdef LDAP_PF_INET6
        case AF_INET6:
            if ( IN6_IS_ADDR_V4MAPPED( &from->sa_in6_addr.sin6_addr ) ) {
#if defined(HAVE_GETADDRINFO) && defined(HAVE_INET_NTOP)
                peeraddr = inet_ntop( AF_INET,
                        ( (struct in_addr *)&from->sa_in6_addr.sin6_addr
                                        .s6_addr[12] ),
                        addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                peeraddr = inet_ntoa( *( (struct in_addr *)&from->sa_in6_addr
                                                 .sin6_addr.s6_addr[12] ) );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
                if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
                sprintf( peername, "IP=%s:%d", peeraddr,
                        (unsigned)ntohs( from->sa_in6_addr.sin6_port ) );
            } else {
                peeraddr = inet_ntop( AF_INET6, &from->sa_in6_addr.sin6_addr,
                        addr, sizeof(addr) );
                if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
                sprintf( peername, "IP=[%s]:%d", peeraddr,
                        (unsigned)ntohs( from->sa_in6_addr.sin6_port ) );
            }
            break;
#endif /* LDAP_PF_INET6 */

        case AF_INET: {
#if defined(HAVE_GETADDRINFO) && defined(HAVE_INET_NTOP)
            peeraddr = inet_ntop(
                    AF_INET, &from->sa_in_addr.sin_addr, addr, sizeof(addr) );
#else /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
            peeraddr = inet_ntoa( from->sa_in_addr.sin_addr );
#endif /* ! HAVE_GETADDRINFO || ! HAVE_INET_NTOP */
            if ( !peeraddr ) peeraddr = SLAP_STRING_UNKNOWN;
            sprintf( peername, "IP=%s:%d", peeraddr,
                    (unsigned)ntohs( from->sa_in_addr.sin_port ) );
        } break;

        default:
            lloadd_close( s );
            return;
    }

#ifdef HAVE_TLS
    if ( sl->sl_is_tls ) cflag |= CONN_IS_TLS;
#endif
    c = client_init( s, sl, peername, lload_daemon[tid].base, cflag );

    if ( !c ) {
        Debug( LDAP_DEBUG_ANY, "lload_listener: "
                "client_init(%ld, %s, %s) failed\n",
                (long)s, peername, sl->sl_name.bv_val );
        lloadd_close( s );
    }

    return;
}

static void *
lload_listener_thread( void *ctx )
{
    int rc = event_base_dispatch( listener_base );
    Debug( LDAP_DEBUG_ANY, "lload_listener_thread: "
            "event loop finished: rc=%d\n",
            rc );

    return (void *)NULL;
}

static void
listener_error_cb( struct evconnlistener *lev, void *arg )
{
    LloadListener *l = arg;
    int err = EVUTIL_SOCKET_ERROR();

    assert( l->listener == lev );
    if (
#ifdef EMFILE
            err == EMFILE ||
#endif /* EMFILE */
#ifdef ENFILE
            err == ENFILE ||
#endif /* ENFILE */
            0 ) {
        ldap_pvt_thread_mutex_lock( &lload_daemon[0].sd_mutex );
        emfile++;
        /* Stop listening until an existing session closes */
        l->sl_mute = 1;
        evconnlistener_disable( lev );
        ldap_pvt_thread_mutex_unlock( &lload_daemon[0].sd_mutex );
        Debug( LDAP_DEBUG_ANY, "listener_error_cb: "
                "too many open files, cannot accept new connections on "
                "url=%s\n",
                l->sl_url.bv_val );
    } else {
        char ebuf[128];
        Debug( LDAP_DEBUG_ANY, "listener_error_cb: "
                "received an error on a listener, shutting down: '%s'\n",
                sock_errstr( err, ebuf, sizeof(ebuf) ) );
        event_base_loopexit( l->base, NULL );
    }
}

void
listeners_reactivate( void )
{
    int i;

    ldap_pvt_thread_mutex_lock( &lload_daemon[0].sd_mutex );
    for ( i = 0; emfile && lload_listeners[i] != NULL; i++ ) {
        LloadListener *lr = lload_listeners[i];

        if ( lr->sl_sd == AC_SOCKET_INVALID ) continue;
        if ( lr->sl_mute ) {
            emfile--;
            evconnlistener_enable( lr->listener );
            lr->sl_mute = 0;
            Debug( LDAP_DEBUG_CONNS, "listeners_reactivate: "
                    "reactivated listener url=%s\n",
                    lr->sl_url.bv_val );
        }
    }
    if ( emfile && lload_listeners[i] == NULL ) {
        /* Walked the entire list without enabling anything; emfile
         * counter is stale. Reset it. */
        emfile = 0;
    }
    ldap_pvt_thread_mutex_unlock( &lload_daemon[0].sd_mutex );
}

static int
lload_listener_activate( void )
{
    struct evconnlistener *listener;
    int l, rc;
    char ebuf[128];

    listener_base = event_base_new();
    if ( !listener_base ) return -1;

    for ( l = 0; lload_listeners[l] != NULL; l++ ) {
        if ( lload_listeners[l]->sl_sd == AC_SOCKET_INVALID ) continue;

            /* FIXME: TCP-only! */
#ifdef LDAP_TCP_BUFFER
        if ( 1 ) {
            int origsize, size, realsize, rc;
            socklen_t optlen;

            size = 0;
            if ( lload_listeners[l]->sl_tcp_rmem > 0 ) {
                size = lload_listeners[l]->sl_tcp_rmem;
            } else if ( slapd_tcp_rmem > 0 ) {
                size = slapd_tcp_rmem;
            }

            if ( size > 0 ) {
                optlen = sizeof(origsize);
                rc = getsockopt( lload_listeners[l]->sl_sd, SOL_SOCKET,
                        SO_RCVBUF, (void *)&origsize, &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                            "getsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                            err, AC_STRERROR_R( err, ebuf, sizeof(ebuf) ) );
                }

                optlen = sizeof(size);
                rc = setsockopt( lload_listeners[l]->sl_sd, SOL_SOCKET,
                        SO_RCVBUF, (const void *)&size, optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                            "setsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                            err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }

                optlen = sizeof(realsize);
                rc = getsockopt( lload_listeners[l]->sl_sd, SOL_SOCKET,
                        SO_RCVBUF, (void *)&realsize, &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                            "getsockopt(SO_RCVBUF) failed errno=%d (%s)\n",
                            err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }

                Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                        "url=%s (#%d) RCVBUF original size=%d requested "
                        "size=%d real size=%d\n",
                        lload_listeners[l]->sl_url.bv_val, l, origsize, size,
                        realsize );
            }

            size = 0;
            if ( lload_listeners[l]->sl_tcp_wmem > 0 ) {
                size = lload_listeners[l]->sl_tcp_wmem;
            } else if ( slapd_tcp_wmem > 0 ) {
                size = slapd_tcp_wmem;
            }

            if ( size > 0 ) {
                optlen = sizeof(origsize);
                rc = getsockopt( lload_listeners[l]->sl_sd, SOL_SOCKET,
                        SO_SNDBUF, (void *)&origsize, &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                            "getsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                            err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }

                optlen = sizeof(size);
                rc = setsockopt( lload_listeners[l]->sl_sd, SOL_SOCKET,
                        SO_SNDBUF, (const void *)&size, optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                            "setsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                            err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }

                optlen = sizeof(realsize);
                rc = getsockopt( lload_listeners[l]->sl_sd, SOL_SOCKET,
                        SO_SNDBUF, (void *)&realsize, &optlen );

                if ( rc ) {
                    int err = sock_errno();
                    Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                            "getsockopt(SO_SNDBUF) failed errno=%d (%s)\n",
                            err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
                }

                Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                        "url=%s (#%d) SNDBUF original size=%d requested "
                        "size=%d real size=%d\n",
                        lload_listeners[l]->sl_url.bv_val, l, origsize, size,
                        realsize );
            }
        }
#endif /* LDAP_TCP_BUFFER */

        lload_listeners[l]->sl_busy = 1;
        listener = evconnlistener_new( listener_base, lload_listener,
                lload_listeners[l], LEV_OPT_THREADSAFE, SLAPD_LISTEN_BACKLOG,
                lload_listeners[l]->sl_sd );
        if ( !listener ) {
            int err = sock_errno();

#ifdef LDAP_PF_INET6
            /* If error is EADDRINUSE, we are trying to listen to INADDR_ANY and
             * we are already listening to in6addr_any, then we want to ignore
             * this and continue.
             */
            if ( err == EADDRINUSE ) {
                int i;
                struct sockaddr_in sa = lload_listeners[l]->sl_sa.sa_in_addr;
                struct sockaddr_in6 sa6;

                if ( sa.sin_family == AF_INET &&
                        sa.sin_addr.s_addr == htonl( INADDR_ANY ) ) {
                    for ( i = 0; i < l; i++ ) {
                        sa6 = lload_listeners[i]->sl_sa.sa_in6_addr;
                        if ( sa6.sin6_family == AF_INET6 &&
                                !memcmp( &sa6.sin6_addr, &in6addr_any,
                                        sizeof(struct in6_addr) ) ) {
                            break;
                        }
                    }

                    if ( i < l ) {
                        /* We are already listening to in6addr_any */
                        Debug( LDAP_DEBUG_CONNS, "lload_listener_activate: "
                                "Attempt to listen to 0.0.0.0 failed, "
                                "already listening on ::, assuming IPv4 "
                                "included\n" );
                        lloadd_close( lload_listeners[l]->sl_sd );
                        lload_listeners[l]->sl_sd = AC_SOCKET_INVALID;
                        continue;
                    }
                }
            }
#endif /* LDAP_PF_INET6 */
            Debug( LDAP_DEBUG_ANY, "lload_listener_activate: "
                    "listen(%s, 5) failed errno=%d (%s)\n",
                    lload_listeners[l]->sl_url.bv_val, err,
                    sock_errstr( err, ebuf, sizeof(ebuf) ) );
            return -1;
        }

        lload_listeners[l]->base = listener_base;
        lload_listeners[l]->listener = listener;
        evconnlistener_set_error_cb( listener, listener_error_cb );
    }

    rc = ldap_pvt_thread_create(
            &listener_tid, 0, lload_listener_thread, lload_listeners[l] );

    if ( rc != 0 ) {
        Debug( LDAP_DEBUG_ANY, "lload_listener_activate(%d): "
                "submit failed (%d)\n",
                lload_listeners[l]->sl_sd, rc );
    }
    return rc;
}

static void *
lloadd_io_task( void *ptr )
{
    int rc;
    int tid = (ldap_pvt_thread_t *)ptr - daemon_tid;
    struct event_base *base = lload_daemon[tid].base;
    struct event *event;

    event = event_new( base, -1, EV_WRITE, daemon_wakeup_cb, ptr );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "lloadd_io_task: "
                "failed to set up the wakeup event\n" );
        return (void *)-1;
    }
    event_add( event, NULL );
    lload_daemon[tid].wakeup_event = event;

    /* run */
    rc = event_base_dispatch( base );
    Debug( LDAP_DEBUG_ANY, "lloadd_io_task: "
            "Daemon %d, event loop finished: rc=%d\n",
            tid, rc );

    if ( !slapd_gentle_shutdown ) {
        slapd_abrupt_shutdown = 1;
    }

    return NULL;
}

int
lloadd_daemon( struct event_base *daemon_base )
{
    int i, rc;
    LloadBackend *b;
    struct event_base *base;
    struct event *event;

    assert( daemon_base != NULL );

    dnsbase = evdns_base_new( daemon_base,
            EVDNS_BASE_INITIALIZE_NAMESERVERS |
                    EVDNS_BASE_DISABLE_WHEN_INACTIVE );
    if ( !dnsbase ) {
        Debug( LDAP_DEBUG_ANY, "lloadd startup: "
                "failed to set up for async name resolution\n" );
        return -1;
    }

    if ( lload_daemon_threads > SLAPD_MAX_DAEMON_THREADS )
        lload_daemon_threads = SLAPD_MAX_DAEMON_THREADS;

    daemon_tid =
            ch_malloc( lload_daemon_threads * sizeof(ldap_pvt_thread_t) );

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        base = event_base_new();
        if ( !base ) {
            Debug( LDAP_DEBUG_ANY, "lloadd startup: "
                    "failed to acquire event base for an I/O thread\n" );
            return -1;
        }
        lload_daemon[i].base = base;

        ldap_pvt_thread_mutex_init( &lload_daemon[i].sd_mutex );
        /* threads that handle client and upstream sockets */
        rc = ldap_pvt_thread_create(
                &daemon_tid[i], 0, lloadd_io_task, &daemon_tid[i] );

        if ( rc != 0 ) {
            Debug( LDAP_DEBUG_ANY, "lloadd startup: "
                    "listener ldap_pvt_thread_create failed (%d)\n",
                    rc );
            return rc;
        }
    }

    if ( (rc = lload_listener_activate()) != 0 ) {
        return rc;
    }

    current_backend = LDAP_CIRCLEQ_FIRST( &backend );
    LDAP_CIRCLEQ_FOREACH ( b, &backend, b_next ) {
        event = evtimer_new( daemon_base, backend_connect, b );
        if ( !event ) {
            Debug( LDAP_DEBUG_ANY, "lloadd: "
                    "failed to allocate retry event\n" );
            return -1;
        }
        b->b_retry_event = event;

        backend_retry( b );
    }

    event = evtimer_new( daemon_base, operations_timeout, event_self_cbarg() );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "lloadd: "
                "failed to allocate timeout event\n" );
        return -1;
    }
    lload_timeout_event = event;

    /* TODO: should we just add it with any timeout and re-add when the timeout
     * changes? */
    if ( lload_timeout_api ) {
        event_add( event, lload_timeout_api );
    }

    lloadd_inited = 1;
    rc = event_base_dispatch( daemon_base );
    Debug( LDAP_DEBUG_ANY, "lloadd shutdown: "
            "Main event loop finished: rc=%d\n",
            rc );

    /* shutdown */
    event_base_loopexit( listener_base, 0 );

    /* wait for the listener threads to complete */
    destroy_listeners();

    for ( i = 0; i < lload_daemon_threads; i++ )
        ldap_pvt_thread_join( daemon_tid[i], (void *)NULL );

    if ( LogTest( LDAP_DEBUG_ANY ) ) {
        int t = ldap_pvt_thread_pool_backload( &connection_pool );
        Debug( LDAP_DEBUG_ANY, "lloadd shutdown: "
                "waiting for %d operations/tasks to finish\n",
                t );
    }
    ldap_pvt_thread_pool_close( &connection_pool, 1 );
    backends_destroy();
    clients_destroy();
    lload_bindconf_free( &bindconf );
    evdns_base_free( dnsbase, 0 );

    ch_free( daemon_tid );
    daemon_tid = NULL;

    lloadd_daemon_destroy();

    return 0;
}

static void
daemon_wakeup_cb( evutil_socket_t sig, short what, void *arg )
{
    int tid = (ldap_pvt_thread_t *)arg - daemon_tid;

    Debug( LDAP_DEBUG_TRACE, "daemon_wakeup_cb: "
            "Daemon thread %d woken up\n",
            tid );
    if ( slapd_shutdown ) {
        event_base_loopexit( lload_daemon[tid].base, NULL );
    }
}

void
lload_sig_shutdown( evutil_socket_t sig, short what, void *arg )
{
    struct event_base *daemon_base = arg;
    int save_errno = errno;
    int i;

    /*
     * If the NT Service Manager is controlling the server, we don't
     * want SIGBREAK to kill the server. For some strange reason,
     * SIGBREAK is generated when a user logs out.
     */

#if defined(HAVE_NT_SERVICE_MANAGER) && defined(SIGBREAK)
    if ( is_NT_Service && sig == SIGBREAK ) {
        /* empty */;
    } else
#endif /* HAVE_NT_SERVICE_MANAGER && SIGBREAK */
#ifdef SIGHUP
    if ( sig == SIGHUP && global_gentlehup && slapd_gentle_shutdown == 0 ) {
        slapd_gentle_shutdown = 1;
    } else
#endif /* SIGHUP */
    {
        slapd_shutdown = 1;
    }

    for ( i = 0; i < lload_daemon_threads; i++ ) {
        event_base_loopexit( lload_daemon[i].base, NULL );
    }
    event_base_loopexit( daemon_base, NULL );

    errno = save_errno;
}

struct event_base *
lload_get_base( ber_socket_t s )
{
    int tid = DAEMON_ID(s);
    return lload_daemon[tid].base;
}

LloadListener **
lloadd_get_listeners( void )
{
    /* Could return array with no listeners if !listening, but current
     * callers mostly look at the URLs.  E.g. syncrepl uses this to
     * identify the server, which means it wants the startup arguments.
     */
    return lload_listeners;
}

/* Reject all incoming requests */
void
lload_suspend_listeners( void )
{
    int i;
    for ( i = 0; lload_listeners[i]; i++ ) {
        lload_listeners[i]->sl_mute = 1;
        evconnlistener_disable( lload_listeners[i]->listener );
        listen( lload_listeners[i]->sl_sd, 0 );
    }
}

/* Resume after a suspend */
void
lload_resume_listeners( void )
{
    int i;
    for ( i = 0; lload_listeners[i]; i++ ) {
        lload_listeners[i]->sl_mute = 0;
        listen( lload_listeners[i]->sl_sd, SLAPD_LISTEN_BACKLOG );
        evconnlistener_enable( lload_listeners[i]->listener );
    }
}

/* we need this in a file that compiles for both module and server */
void
lload_counters_init()
{
    memset( &lload_stats, 0, sizeof(lload_global_stats_t) );
}
