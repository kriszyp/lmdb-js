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

#include "lutil.h"
#include "slap.h"

slap_c_head clients = LDAP_CIRCLEQ_HEAD_INITIALIZER( clients );

ldap_pvt_thread_mutex_t clients_mutex;

typedef int (*RequestHandler)( Connection *c, Operation *op );

static void
client_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    ber_tag_t tag;
    ber_len_t len;

    CONNECTION_LOCK(c);
    if ( !c->c_live ) {
        event_del( c->c_read_event );
        Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
                "suspended read event on a dead connid=%lu\n",
                c->c_connid );
        CONNECTION_UNLOCK(c);
        return;
    }

    Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
            "connection connid=%lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "client_read_cb: "
                "connid=%lu, ber_alloc failed\n",
                c->c_connid );
        CLIENT_DESTROY(c);
        return;
    }
    c->c_currentber = ber;

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            if ( err || tag == LBER_ERROR ) {
                char ebuf[128];
                Debug( LDAP_DEBUG_STATS, "client_read_cb: "
                        "ber_get_next on fd=%d failed errno=%d (%s)\n",
                        c->c_fd, err,
                        sock_errstr( err, ebuf, sizeof(ebuf) ) );
            } else {
                Debug( LDAP_DEBUG_STATS, "client_read_cb: "
                        "ber_get_next on fd=%d connid=%lu received "
                        "a strange PDU tag=%lx\n",
                        c->c_fd, c->c_connid, tag );
            }

            c->c_currentber = NULL;
            ber_free( ber, 1 );

            event_del( c->c_read_event );
            Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
                    "suspended read event on dying connid=%lu\n",
                    c->c_connid );
            CLIENT_DESTROY(c);
            return;
        }
        event_add( c->c_read_event, NULL );
        Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
                "re-enabled read event on connid=%lu\n",
                c->c_connid );
        CONNECTION_UNLOCK(c);
        return;
    }

    if ( !slap_conn_max_pdus_per_cycle ||
            ldap_pvt_thread_pool_submit(
                    &connection_pool, handle_requests, c ) ) {
        /* If we're overloaded or configured as such, process one and resume in
         * the next cycle.
         *
         * handle_one_request re-locks the mutex in the
         * process, need to test it's still alive */
        if ( handle_one_request( c ) == LDAP_SUCCESS ) {
            CLIENT_UNLOCK_OR_DESTROY(c);
        }
        return;
    }

    event_del( c->c_read_event );
    Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
            "suspended read event on connid=%lu\n",
            c->c_connid );

    /* We have scheduled a call to handle_requests which takes care of
     * handling further requests, just make sure the connection sticks around
     * for that */
    CONNECTION_UNLOCK_INCREF(c);
    return;
}

void *
handle_requests( void *ctx, void *arg )
{
    Connection *c = arg;
    int requests_handled = 0;

    CONNECTION_LOCK_DECREF(c);
    for ( ;; ) {
        BerElement *ber;
        ber_tag_t tag;
        ber_len_t len;

        /* handle_one_response may unlock the connection in the process, we
         * need to expect that might be our responsibility to destroy it */
        if ( handle_one_request( c ) ) {
            /* Error, connection is unlocked and might already have been
             * destroyed */
            return NULL;
        }
        /* Otherwise, handle_one_request leaves the connection locked */

        if ( ++requests_handled >= slap_conn_max_pdus_per_cycle ) {
            /* Do not read now, re-enable read event instead */
            break;
        }

        if ( (ber = ber_alloc()) == NULL ) {
            Debug( LDAP_DEBUG_ANY, "client_read_cb: "
                    "connid=%lu, ber_alloc failed\n",
                    c->c_connid );
            CLIENT_DESTROY(c);
            return NULL;
        }
        c->c_currentber = ber;

        tag = ber_get_next( c->c_sb, &len, ber );
        if ( tag != LDAP_TAG_MESSAGE ) {
            int err = sock_errno();

            if ( err != EWOULDBLOCK && err != EAGAIN ) {
                if ( err || tag == LBER_ERROR ) {
                    char ebuf[128];
                    Debug( LDAP_DEBUG_ANY, "handle_requests: "
                            "ber_get_next on fd=%d failed errno=%d (%s)\n",
                            c->c_fd, err,
                            sock_errstr( err, ebuf, sizeof(ebuf) ) );
                } else {
                    Debug( LDAP_DEBUG_STATS, "handle_requests: "
                            "ber_get_next on fd=%d connid=%lu received "
                            "a strange PDU tag=%lx\n",
                            c->c_fd, c->c_connid, tag );
                }

                c->c_currentber = NULL;
                ber_free( ber, 1 );
                CLIENT_DESTROY(c);
                return NULL;
            }
            break;
        }
    }

    event_add( c->c_read_event, NULL );
    Debug( LDAP_DEBUG_CONNS, "handle_requests: "
            "re-enabled read event on connid=%lu\n",
            c->c_connid );
    CLIENT_UNLOCK_OR_DESTROY(c);
    return NULL;
}

int
handle_one_request( Connection *c )
{
    BerElement *ber;
    Operation *op = NULL;
    RequestHandler handler = NULL;

    ber = c->c_currentber;
    c->c_currentber = NULL;

    op = operation_init( c, ber );
    if ( !op ) {
        Debug( LDAP_DEBUG_ANY, "handle_one_request: "
                "connid=%lu, operation_init failed\n",
                c->c_connid );
        CLIENT_DESTROY(c);
        ber_free( ber, 1 );
        return -1;
    }

    switch ( op->o_tag ) {
        case LDAP_REQ_UNBIND:
            /* There is never a response for this operation */
            operation_destroy_from_client( op );
            Debug( LDAP_DEBUG_STATS, "handle_one_request: "
                    "received unbind, closing client connid=%lu\n",
                    c->c_connid );
            CLIENT_DESTROY(c);
            return -1;
        case LDAP_REQ_BIND:
            handler = client_bind;
            break;
        case LDAP_REQ_ABANDON:
            /* FIXME: We need to be able to abandon a Bind request, handling
             * ExOps (esp. Cancel) will be different */
            handler = request_abandon;
            break;
        default:
            if ( c->c_state == SLAP_C_BINDING ) {
                op->o_client_refcnt++;
                CONNECTION_UNLOCK_INCREF(c);
                operation_send_reject(
                        op, LDAP_PROTOCOL_ERROR, "bind in progress", 0 );
                CONNECTION_LOCK_DECREF(c);
                op->o_client_refcnt--;
                operation_destroy_from_client( op );
                return LDAP_SUCCESS;
            }
            handler = request_process;
            break;
    }

    return handler( c, op );
}

void
client_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;

    CONNECTION_LOCK(c);
    if ( !c->c_live ) {
        CONNECTION_UNLOCK(c);
        return;
    }
    CONNECTION_UNLOCK_INCREF(c);

    /* Before we acquire any locks */
    event_del( c->c_write_event );

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    Debug( LDAP_DEBUG_CONNS, "client_write_cb: "
            "have something to write to client connid=%lu\n",
            c->c_connid );

    /* We might have been beaten to flushing the data by another thread */
    if ( c->c_pendingber && ber_flush( c->c_sb, c->c_pendingber, 1 ) ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            Debug( LDAP_DEBUG_ANY, "client_write_cb: "
                    "ber_flush on fd=%d failed errno=%d (%s)\n",
                    c->c_fd, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            CLIENT_LOCK_DESTROY(c);
            return;
        }
        event_add( c->c_write_event, NULL );
    } else {
        c->c_pendingber = NULL;
    }
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    CONNECTION_LOCK_DECREF(c);
    CLIENT_UNLOCK_OR_DESTROY(c);
}

Connection *
client_init(
        ber_socket_t s,
        Listener *listener,
        const char *peername,
        struct event_base *base,
        int flags )
{
    Connection *c;
    struct event *event;

    assert( listener != NULL );

    c = connection_init( s, peername, flags );

    {
        ber_len_t max = sockbuf_max_incoming_client;
        ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
    }

    c->c_state = SLAP_C_READY;

    event = event_new( base, s, EV_READ|EV_PERSIST, client_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "client_init: "
                "Read event could not be allocated\n" );
        goto fail;
    }
    event_add( event, NULL );
    c->c_read_event = event;

    event = event_new( base, s, EV_WRITE, client_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "client_init: "
                "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    c->c_private = listener;

    /* There should be no lock inversion yet since no other thread could
     * approach it from clients side */
    ldap_pvt_thread_mutex_lock( &clients_mutex );
    LDAP_CIRCLEQ_INSERT_TAIL( &clients, c, c_next );
    ldap_pvt_thread_mutex_unlock( &clients_mutex );

    CONNECTION_UNLOCK(c);

    return c;
fail:
    if ( c->c_write_event ) {
        event_free( c->c_write_event );
        c->c_write_event = NULL;
    }
    if ( c->c_read_event ) {
        event_free( c->c_read_event );
        c->c_read_event = NULL;
    }
    c->c_state = SLAP_C_INVALID;
    connection_destroy( c );
    return NULL;
}

void
client_destroy( Connection *c )
{
    enum sc_state state;
    struct event *read_event, *write_event;

    Debug( LDAP_DEBUG_CONNS, "client_destroy: "
            "destroying client connid=%lu\n",
            c->c_connid );

    assert( c->c_state != SLAP_C_INVALID );
    state = c->c_state;
    c->c_state = SLAP_C_INVALID;

    read_event = c->c_read_event;
    write_event = c->c_write_event;

    /*
     * FIXME: operation_destroy_from_upstream might copy op->o_client and bump
     * c_refcnt, it is then responsible to call destroy_client again, does that
     * mean that we can be triggered for recursion over all connections?
     */
    CONNECTION_UNLOCK_INCREF(c);

    /*
     * Avoid a deadlock:
     * event_del will block if the event is currently executing its callback,
     * that callback might be waiting to lock c->c_mutex
     */
    if ( read_event ) {
        event_del( read_event );
    }

    if ( write_event ) {
        event_del( write_event );
    }

    if ( state != SLAP_C_CLOSING ) {
        ldap_pvt_thread_mutex_lock( &clients_mutex );
        LDAP_CIRCLEQ_REMOVE( &clients, c, c_next );
        ldap_pvt_thread_mutex_unlock( &clients_mutex );
    }

    CONNECTION_LOCK_DECREF(c);

    if ( c->c_read_event ) {
        event_free( c->c_read_event );
        c->c_read_event = NULL;
    }

    if ( c->c_write_event ) {
        event_free( c->c_write_event );
        c->c_write_event = NULL;
    }

    client_reset( c );

    /*
     * If we attempted to destroy any operations, we might have lent a new
     * refcnt token for a thread that raced us to that, let them call us again
     * later
     */
    assert( c->c_refcnt >= 0 );
    if ( c->c_refcnt ) {
        c->c_state = SLAP_C_CLOSING;
        Debug( LDAP_DEBUG_CONNS, "client_destroy: "
                "connid=%lu aborting with refcnt=%d\n",
                c->c_connid, c->c_refcnt );
        CONNECTION_UNLOCK(c);
        return;
    }

    connection_destroy( c );
}

void
clients_destroy( void )
{
    ldap_pvt_thread_mutex_lock( &clients_mutex );
    while ( !LDAP_CIRCLEQ_EMPTY( &clients ) ) {
        Connection *c = LDAP_CIRCLEQ_FIRST( &clients );

        ldap_pvt_thread_mutex_unlock( &clients_mutex );
        CONNECTION_LOCK(c);
        /* We have shut down all processing, a dying connection connection
         * should have been reclaimed by now! */
        assert( c->c_live );
        /* Upstream connections have already been destroyed, there should be no
         * ops left */
        assert( !c->c_ops );
        CLIENT_DESTROY(c);
        ldap_pvt_thread_mutex_lock( &clients_mutex );
    }
    ldap_pvt_thread_mutex_unlock( &clients_mutex );
}
