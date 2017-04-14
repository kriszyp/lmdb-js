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
upstream_name_cb( int result, struct evutil_addrinfo *res, void *arg )
{
    Backend *b = arg;
    ber_socket_t s = AC_SOCKET_INVALID;
    int rc;

    ldap_pvt_thread_mutex_lock( &b->b_mutex );

    if ( result || !res ) {
        Debug( LDAP_DEBUG_ANY, "upstream_name_cb: "
                "name resolution failed for backend '%s': %s\n",
                b->b_bindconf.sb_uri.bv_val, evutil_gai_strerror( result ) );
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
    if ( rc && errno != EINPROGRESS && errno != EWOULDBLOCK ) {
        Debug( LDAP_DEBUG_ANY, "upstream_name_cb: "
                "failed to connect to server '%s'\n",
                b->b_bindconf.sb_uri.bv_val );
        goto fail;
    }

    if ( !upstream_init( s, b ) ) {
        goto fail;
    }
    b->b_opening--;
    b->b_failed = 0;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    backend_retry( b );
    return;

fail:
    if ( s != AC_SOCKET_INVALID ) {
        evutil_closesocket( s );
    }
    b->b_opening--;
    b->b_failed++;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    backend_retry( b );
}

Connection *
backend_select( Operation *op )
{
    Backend *b;

    /* TODO: Two runs, one with trylock, then one actually locked if we don't
     * find anything? */
    LDAP_STAILQ_FOREACH ( b, &backend, b_next ) {
        struct ConnSt *head;
        Connection *c;

        ldap_pvt_thread_mutex_lock( &b->b_mutex );

        if ( b->b_max_pending && b->b_n_ops_executing >= b->b_max_pending ) {
            Debug( LDAP_DEBUG_CONNS, "backend_select: "
                    "backend %s too busy\n",
                    b->b_bindconf.sb_uri.bv_val );
            ldap_pvt_thread_mutex_unlock( &b->b_mutex );
            continue;
        }

        if ( op->o_tag == LDAP_REQ_BIND &&
                !(lload_features & LLOAD_FEATURE_VC) ) {
            head = &b->b_bindconns;
        } else {
            head = &b->b_conns;
        }

        /* TODO: Use CIRCLEQ so that we can do a natural round robin over the
         * backend's connections? */
        LDAP_LIST_FOREACH( c, head, c_next )
        {
            ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
            if ( c->c_state == SLAP_C_READY && !c->c_pendingber &&
                    ( b->b_max_conn_pending == 0 ||
                            c->c_n_ops_executing < b->b_max_conn_pending ) ) {
                Debug( LDAP_DEBUG_CONNS, "backend_select: "
                        "selected connection %lu for client %lu msgid=%d\n",
                        c->c_connid, op->o_client_connid, op->o_client_msgid );

                b->b_n_ops_executing++;
                c->c_n_ops_executing++;
                ldap_pvt_thread_mutex_unlock( &b->b_mutex );
                return c;
            }
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        }
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    }

    return NULL;
}

void
backend_retry( Backend *b )
{
    int rc, requested;

    ldap_pvt_thread_mutex_lock( &b->b_mutex );

    requested = b->b_numconns;
    if ( !(lload_features & LLOAD_FEATURE_VC) ) {
        requested += b->b_numbindconns;
    }
    if ( b->b_active + b->b_bindavail + b->b_opening < requested ) {
        if ( b->b_opening > 0 || b->b_failed > 0 ) {
            if ( !event_pending( b->b_retry_event, EV_TIMEOUT, NULL ) ) {
                Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                        "scheduling a retry in %d ms\n",
                        b->b_retry_timeout );
                b->b_opening++;
                event_add( b->b_retry_event, &b->b_retry_tv );
                ldap_pvt_thread_mutex_unlock( &b->b_mutex );
                return;
            } else {
                Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                        "retry already scheduled\n" );
            }
        } else {
            Debug( LDAP_DEBUG_CONNS, "backend_retry: "
                    "scheduling re-connection straight away\n" );
            b->b_opening++;
            rc = ldap_pvt_thread_pool_submit(
                    &connection_pool, backend_connect_task, b );
            /* TODO check we're not shutting down */
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

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    Debug( LDAP_DEBUG_CONNS, "backend_connect: "
            "attempting connection to %s\n",
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
        if ( rc && errno != EINPROGRESS && errno != EWOULDBLOCK ) {
            evutil_closesocket( s );
            goto fail;
        }

        if ( !upstream_init( s, b ) ) {
            goto fail;
        }
        b->b_opening--;
        b->b_failed = 0;
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        backend_retry( b );
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
