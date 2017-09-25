/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2020 The OpenLDAP Foundation.
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

#include "portable.h"

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <event2/event.h>
#include <event2/dns.h>

#include "lutil.h"
#include "slap.h"

static void
upstream_connect_cb( evutil_socket_t s, short what, void *arg )
{
    PendingConnection *conn = arg;
    Backend *b = conn->backend;
    int error = 0, rc = -1;

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    Debug( LDAP_DEBUG_CONNS, "upstream_connect_cb: "
            "fd=%d connection callback for backend uri='%s'\n",
            s, b->b_uri.bv_val );
    if ( what == EV_WRITE ) {
        socklen_t optlen = sizeof(error);

        if ( getsockopt( conn->fd, SOL_SOCKET, SO_ERROR, (void *)&error,
                     &optlen ) < 0 ) {
            goto done;
        }
        if ( error == EINTR || error == EINPROGRESS || error == EWOULDBLOCK ) {
            ldap_pvt_thread_mutex_unlock( &b->b_mutex );
            return;
        } else if ( error ) {
            goto done;
        } else if ( !upstream_init( s, conn->backend ) ) {
            goto done;
        }
        rc = LDAP_SUCCESS;
    }

done:
    if ( rc ) {
        char ebuf[128];
        evutil_closesocket( conn->fd );
        b->b_opening--;
        b->b_failed++;
        Debug( LDAP_DEBUG_ANY, "upstream_connect_cb: "
                "fd=%d connection set up failed%s%s\n",
                s, error ? ": " : "",
                error ? sock_errstr( error, ebuf, sizeof(ebuf) ) : "" );
    } else {
        b->b_failed = 0;
    }
    LDAP_LIST_REMOVE( conn, next );
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    event_free( conn->event );
    ch_free( conn );

    if ( rc ) {
        backend_retry( b );
    }
}

static void
upstream_name_cb( int result, struct evutil_addrinfo *res, void *arg )
{
    Backend *b = arg;
    ber_socket_t s = AC_SOCKET_INVALID;
    int rc;

    ldap_pvt_thread_mutex_lock( &b->b_mutex );

    if ( result || !res ) {
        Debug( LDAP_DEBUG_ANY, "upstream_name_cb: "
                "name resolution failed for backend '%s': %s\n",
                b->b_uri.bv_val, evutil_gai_strerror( result ) );
        goto fail;
    }

    /* TODO: if we get failures, try the other addrinfos */
    if ( (s = socket( res->ai_family, SOCK_STREAM, 0 )) ==
            AC_SOCKET_INVALID ) {
        goto fail;
    }

    if ( ber_pvt_socket_set_nonblock( s, 1 ) ) {
        goto fail;
    }

    if ( res->ai_family == PF_INET ) {
        struct sockaddr_in *ai = (struct sockaddr_in *)res->ai_addr;
        ai->sin_port = htons( b->b_port );
        rc = connect( s, (struct sockaddr *)ai, res->ai_addrlen );
    } else {
        struct sockaddr_in6 *ai = (struct sockaddr_in6 *)res->ai_addr;
        ai->sin6_port = htons( b->b_port );
        rc = connect( s, (struct sockaddr *)ai, res->ai_addrlen );
    }
    /* Asynchronous connect */
    if ( rc ) {
        struct timeval tv = { slap_write_timeout / 1000,
                1000 * ( slap_write_timeout % 1000 ) };
        PendingConnection *conn;

        if ( errno != EINPROGRESS && errno != EWOULDBLOCK ) {
            Debug( LDAP_DEBUG_ANY, "upstream_name_cb: "
                    "failed to connect to server '%s'\n",
                    b->b_uri.bv_val );
            evutil_closesocket( s );
            goto fail;
        }

        conn = ch_calloc( 1, sizeof(PendingConnection) );
        LDAP_LIST_ENTRY_INIT( conn, next );
        conn->backend = b;
        conn->fd = s;

        conn->event = event_new( slap_get_base( s ), s, EV_WRITE|EV_PERSIST,
                upstream_connect_cb, conn );
        if ( !conn->event ) {
            Debug( LDAP_DEBUG_ANY, "upstream_name_cb: "
                    "failed to acquire an event to finish upstream "
                    "connection setup.\n" );
            ch_free( conn );
            evutil_closesocket( s );
            goto fail;
        }

        event_add( conn->event, &tv );
        LDAP_LIST_INSERT_HEAD( &b->b_connecting, conn, next );
        Debug( LDAP_DEBUG_CONNS, "upstream_name_cb: "
                "connection to backend uri=%s in progress\n",
                b->b_uri.bv_val );
    } else if ( !upstream_init( s, b ) ) {
        goto fail;
    }

    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    evutil_freeaddrinfo( res );
    return;

fail:
    if ( s != AC_SOCKET_INVALID ) {
        evutil_closesocket( s );
    }
    b->b_opening--;
    b->b_failed++;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    backend_retry( b );
    if ( res ) {
        evutil_freeaddrinfo( res );
    }
}

Connection *
backend_select( Operation *op )
{
    Backend *b, *first, *next;

    ldap_pvt_thread_mutex_lock( &backend_mutex );
    first = b = current_backend;
    ldap_pvt_thread_mutex_unlock( &backend_mutex );

    if ( !first ) {
        return NULL;
    }

    /* TODO: Two runs, one with trylock, then one actually locked if we don't
     * find anything? */
    do {
        struct ConnSt *head;
        Connection *c;

        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        next = LDAP_CIRCLEQ_LOOP_NEXT( &backend, b, b_next );

        if ( b->b_max_pending && b->b_n_ops_executing >= b->b_max_pending ) {
            Debug( LDAP_DEBUG_CONNS, "backend_select: "
                    "backend %s too busy\n",
                    b->b_uri.bv_val );
            ldap_pvt_thread_mutex_unlock( &b->b_mutex );
            b = next;
            continue;
        }

        if ( op->o_tag == LDAP_REQ_BIND
#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
                && !(lload_features & LLOAD_FEATURE_VC)
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
        ) {
            head = &b->b_bindconns;
        } else {
            head = &b->b_conns;
        }

        LDAP_CIRCLEQ_FOREACH ( c, head, c_next ) {
            ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
            CONNECTION_LOCK(c);
            if ( c->c_state == SLAP_C_READY && !c->c_pendingber &&
                    ( b->b_max_conn_pending == 0 ||
                            c->c_n_ops_executing < b->b_max_conn_pending ) ) {
                Debug( LDAP_DEBUG_CONNS, "backend_select: "
                        "selected connection connid=%lu for client "
                        "connid=%lu msgid=%d\n",
                        c->c_connid, op->o_client_connid, op->o_client_msgid );

                /*
                 * Round-robin step:
                 * Rotate the queue to put this connection at the end, same for
                 * the backend.
                 */
                LDAP_CIRCLEQ_MAKE_TAIL( head, c, c_next );

                ldap_pvt_thread_mutex_lock( &backend_mutex );
                current_backend = next;
                ldap_pvt_thread_mutex_unlock( &backend_mutex );

                b->b_n_ops_executing++;
                c->c_n_ops_executing++;
                CONNECTION_UNLOCK_INCREF(c);

                ldap_pvt_thread_mutex_unlock( &b->b_mutex );
                return c;
            }
            CONNECTION_UNLOCK(c);
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        }
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );

        b = next;
    } while ( b != first );

    return NULL;
}

void
backend_retry( Backend *b )
{
    int rc, requested;

    if ( slapd_shutdown ) {
        Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                "shutting down\n" );
        return;
    }

    ldap_pvt_thread_mutex_lock( &b->b_mutex );

    requested = b->b_numconns;
#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
    if ( !(lload_features & LLOAD_FEATURE_VC) )
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
    {
        requested += b->b_numbindconns;
    }
    if ( b->b_active + b->b_bindavail + b->b_opening < requested ) {
        if ( b->b_opening > 0 || b->b_failed > 0 ) {
            if ( b->b_failed > 0 &&
                    !event_pending( b->b_retry_event, EV_TIMEOUT, NULL ) ) {
                Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                        "scheduling a retry in %d ms\n",
                        b->b_retry_timeout );
                b->b_opening++;
                event_add( b->b_retry_event, &b->b_retry_tv );
                ldap_pvt_thread_mutex_unlock( &b->b_mutex );
                return;
            } else {
                Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                        "retry in progress already\n" );
            }
        } else {
            Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                    "scheduling re-connection straight away\n" );
            b->b_opening++;
            rc = ldap_pvt_thread_pool_submit(
                    &connection_pool, backend_connect_task, b );
            if ( rc ) {
                ldap_pvt_thread_mutex_unlock( &b->b_mutex );
                backend_connect( -1, 0, b );
                return;
            }
        }
    } else {
        Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                "no more connections needed for this backend\n" );
    }
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
}

void
backend_connect( evutil_socket_t s, short what, void *arg )
{
    struct evutil_addrinfo hints = {};
    Backend *b = arg;
    char *hostname;

    if ( slapd_shutdown ) {
        Debug( LDAP_DEBUG_CONNS, "backend_connect: "
                "doing nothing, shutdown in progress\n" );
        return;
    }

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    Debug( LDAP_DEBUG_CONNS, "backend_connect: "
            "%sattempting connection to %s\n",
            (what & EV_TIMEOUT) ? "retry timeout finished, " : "",
            b->b_host );

#ifdef LDAP_PF_LOCAL
    if ( b->b_proto == LDAP_PROTO_IPC ) {
        struct sockaddr_un addr;
        ber_socket_t s = socket( PF_LOCAL, SOCK_STREAM, 0 );
        int rc;

        if ( s == AC_SOCKET_INVALID ) {
            goto fail;
        }

        rc = ber_pvt_socket_set_nonblock( s, 1 );
        if ( rc ) {
            evutil_closesocket( s );
            goto fail;
        }

        if ( strlen( b->b_host ) > ( sizeof(addr.sun_path) - 1 ) ) {
            evutil_closesocket( s );
            goto fail;
        }
        memset( &addr, '\0', sizeof(addr) );
        addr.sun_family = AF_LOCAL;
        strcpy( addr.sun_path, b->b_host );

        rc = connect(
                s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un) );
        /* Asynchronous connect */
        if ( rc ) {
            struct timeval tv = { slap_write_timeout / 1000,
                    1000 * ( slap_write_timeout % 1000 ) };
            PendingConnection *conn;

            if ( errno != EINPROGRESS && errno != EWOULDBLOCK ) {
                evutil_closesocket( s );
                goto fail;
            }

            conn = ch_calloc( 1, sizeof(PendingConnection) );
            LDAP_LIST_ENTRY_INIT( conn, next );
            conn->backend = b;
            conn->fd = s;

            conn->event = event_new( slap_get_base( s ), s,
                    EV_WRITE|EV_PERSIST, upstream_connect_cb, conn );
            if ( !conn->event ) {
                Debug( LDAP_DEBUG_ANY, "backend_connect: "
                        "failed to acquire an event to finish upstream "
                        "connection setup.\n" );
                ch_free( conn );
                evutil_closesocket( s );
                goto fail;
            }

            event_add( conn->event, &tv );
            LDAP_LIST_INSERT_HEAD( &b->b_connecting, conn, next );
            Debug( LDAP_DEBUG_CONNS, "backend_connect: "
                    "connection to backend uri=%s in progress\n",
                    b->b_uri.bv_val );
        } else if ( !upstream_init( s, b ) ) {
            goto fail;
        }

        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        return;
    }
#endif /* LDAP_PF_LOCAL */

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    hostname = b->b_host;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    evdns_getaddrinfo( dnsbase, hostname, NULL, &hints, upstream_name_cb, b );
    return;

fail:
    b->b_opening--;
    b->b_failed++;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    backend_retry( b );
}

void *
backend_connect_task( void *ctx, void *arg )
{
    backend_connect( -1, 0, arg );
    return NULL;
}

void
backends_destroy( void )
{
    while ( !LDAP_CIRCLEQ_EMPTY( &backend ) ) {
        Backend *b = LDAP_CIRCLEQ_FIRST( &backend );

        Debug( LDAP_DEBUG_CONNS, "backends_destroy: "
                "destroying backend uri='%s', numconns=%d, numbindconns=%d\n",
                b->b_uri.bv_val, b->b_numconns, b->b_numbindconns );

        while ( !LDAP_LIST_EMPTY( &b->b_connecting ) ) {
            PendingConnection *pending = LDAP_LIST_FIRST( &b->b_connecting );

            Debug( LDAP_DEBUG_CONNS, "backends_destroy: "
                    "destroying socket pending connect() fd=%d\n",
                    pending->fd );

            event_free( pending->event );
            evutil_closesocket( pending->fd );
            LDAP_LIST_REMOVE( pending, next );
            ch_free( pending );
        }
        while ( !LDAP_CIRCLEQ_EMPTY( &b->b_preparing ) ) {
            Connection *c = LDAP_CIRCLEQ_FIRST( &b->b_preparing );

            CONNECTION_LOCK(c);
            Debug( LDAP_DEBUG_CONNS, "backends_destroy: "
                    "destroying connection being set up connid=%lu\n",
                    c->c_connid );

            assert( c->c_live );
            CONNECTION_DESTROY(c);
        }
        while ( !LDAP_CIRCLEQ_EMPTY( &b->b_bindconns ) ) {
            Connection *c = LDAP_CIRCLEQ_FIRST( &b->b_bindconns );

            CONNECTION_LOCK(c);
            Debug( LDAP_DEBUG_CONNS, "backends_destroy: "
                    "destroying bind connection connid=%lu, pending ops=%ld\n",
                    c->c_connid, c->c_n_ops_executing );

            assert( c->c_live );
            CONNECTION_DESTROY(c);
        }
        while ( !LDAP_CIRCLEQ_EMPTY( &b->b_conns ) ) {
            Connection *c = LDAP_CIRCLEQ_FIRST( &b->b_conns );

            CONNECTION_LOCK(c);
            Debug( LDAP_DEBUG_CONNS, "backends_destroy: "
                    "destroying regular connection connid=%lu, pending "
                    "ops=%ld\n",
                    c->c_connid, c->c_n_ops_executing );

            assert( c->c_live );
            CONNECTION_DESTROY(c);
        }

        LDAP_CIRCLEQ_REMOVE( &backend, b, b_next );
        ldap_pvt_thread_mutex_destroy( &b->b_mutex );

        event_del( b->b_retry_event );
        event_free( b->b_retry_event );

        ch_free( b->b_host );
        ch_free( b->b_uri.bv_val );
        ch_free( b );
    }
}
