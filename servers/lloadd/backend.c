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
    Connection *c;
    ber_socket_t s;
    int rc;

    if ( result || !res ) {
        Debug( LDAP_DEBUG_ANY, "upstream_name_cb: "
                "name resolution failed for backend '%s': %s\n",
                b->b_bindconf.sb_uri.bv_val, evutil_gai_strerror( result ) );
        return;
    }

    s = socket( res->ai_family, SOCK_STREAM, 0 );
    if ( s == AC_SOCKET_INVALID ) {
        return;
    }

    rc = ber_pvt_socket_set_nonblock( s, 1 );
    if ( rc ) {
        evutil_closesocket( s );
        return;
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
        evutil_closesocket( s );
        return;
    }

    c = upstream_init( s, b );
    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    b->b_conns = c;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
}

Connection *
backend_select( Operation *op )
{
    Backend *b;

    LDAP_STAILQ_FOREACH ( b, &backend, b_next ) {
        Connection *c;

        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        c = b->b_conns;
        ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
        if ( c->c_state == SLAP_C_READY && !c->c_pendingber ) {
            ldap_pvt_thread_mutex_unlock( &b->b_mutex );
            return b->b_conns;
        }
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    }

    return NULL;
}

void *
backend_connect( void *ctx, void *arg )
{
    struct evutil_addrinfo hints = {};
    Backend *b = arg;

#ifdef LDAP_PF_LOCAL
    if ( b->b_proto == LDAP_PROTO_IPC ) {
        struct sockaddr_un addr;
        ber_socket_t s = socket( PF_LOCAL, SOCK_STREAM, 0 );
        int rc;

        if ( s == AC_SOCKET_INVALID ) {
            return (void *)-1;
        }

        rc = ber_pvt_socket_set_nonblock( s, 1 );
        if ( rc ) {
            evutil_closesocket( s );
            return (void *)-1;
        }

        if ( strlen( b->b_host ) > ( sizeof(addr.sun_path) - 1 ) ) {
            evutil_closesocket( s );
            return (void *)-1;
        }
        memset( &addr, '\0', sizeof(addr) );
        addr.sun_family = AF_LOCAL;
        strcpy( addr.sun_path, b->b_host );

        rc = connect(
                s, (struct sockaddr *)&addr, sizeof(struct sockaddr_un) );
        if ( rc && errno != EINPROGRESS && errno != EWOULDBLOCK ) {
            evutil_closesocket( s );
            return (void *)-1;
        }

        b->b_conns = upstream_init( s, b );
        return NULL;
    }
#endif /* LDAP_PF_LOCAL */

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    evdns_getaddrinfo( dnsbase, b->b_host, NULL, &hints, upstream_name_cb, b );
    return NULL;
}
