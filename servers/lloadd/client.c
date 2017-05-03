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

typedef int (*RequestHandler)( Connection *c, Operation *op );

static void
client_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    ber_tag_t tag;
    ber_len_t len;

    CONNECTION_LOCK(c);

    Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
            "connection %lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "client_read_cb: "
                "ber_alloc failed\n" );
        CLIENT_DESTROY(c);
        return;
    }
    c->c_currentber = ber;

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            Debug( LDAP_DEBUG_ANY, "client_read_cb: "
                    "ber_get_next on fd %d failed errno=%d (%s)\n",
                    c->c_fd, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );

            c->c_currentber = NULL;
            ber_free( ber, 1 );
            CLIENT_DESTROY(c);
            return;
        }
        event_add( c->c_read_event, NULL );
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

    CONNECTION_UNLOCK(c);
    return;
}

void *
handle_requests( void *ctx, void *arg )
{
    Connection *c = arg;
    int requests_handled = 0;

    CONNECTION_LOCK(c);
    for ( ; requests_handled < slap_conn_max_pdus_per_cycle;
            requests_handled++ ) {
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

        if ( (ber = ber_alloc()) == NULL ) {
            Debug( LDAP_DEBUG_ANY, "client_read_cb: "
                    "ber_alloc failed\n" );
            CLIENT_DESTROY(c);
            return NULL;
        }
        c->c_currentber = ber;

        tag = ber_get_next( c->c_sb, &len, ber );
        if ( tag != LDAP_TAG_MESSAGE ) {
            int err = sock_errno();

            if ( err != EWOULDBLOCK && err != EAGAIN ) {
                char ebuf[128];
                Debug( LDAP_DEBUG_ANY, "handle_requests: "
                        "ber_get_next on fd %d failed errno=%d (%s)\n",
                        c->c_fd, err,
                        sock_errstr( err, ebuf, sizeof(ebuf) ) );

                c->c_currentber = NULL;
                ber_free( ber, 1 );
                CLIENT_DESTROY(c);
                return NULL;
            }
            break;
        }
    }

    event_add( c->c_read_event, NULL );
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
                "operation_init failed\n" );
        CLIENT_DESTROY(c);
        ber_free( ber, 1 );
        return -1;
    }

    switch ( op->o_tag ) {
        case LDAP_REQ_UNBIND:
            c->c_state = SLAP_C_CLOSING;
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
                CONNECTION_UNLOCK_INCREF(c);
                operation_send_reject(
                        op, LDAP_PROTOCOL_ERROR, "bind in progress", 0 );
                CONNECTION_LOCK_DECREF(c);
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

    /* What if the shutdown is already in progress and we get to lock the
     * connection? */
    CONNECTION_LOCK(c);
    CONNECTION_UNLOCK_INCREF(c);

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    Debug( LDAP_DEBUG_CONNS, "client_write_cb: "
            "have something to write to client %lu\n",
            c->c_connid );

    if ( ber_flush( c->c_sb, c->c_pendingber, 1 ) ) {
        int err = sock_errno();
        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
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
    CONNECTION_UNLOCK(c);

    return c;
fail:
    if ( c->c_write_event ) {
        event_del( c->c_write_event );
        event_free( c->c_write_event );
    }
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    c->c_state = SLAP_C_INVALID;
    connection_destroy( c );
    return NULL;
}

void
client_destroy( Connection *c )
{
    TAvlnode *root, *node;

    Debug( LDAP_DEBUG_CONNS, "client_destroy: "
            "destroying client %lu\n",
            c->c_connid );

    assert( c->c_read_event != NULL );
    event_del( c->c_read_event );
    event_free( c->c_read_event );

    assert( c->c_write_event != NULL );
    event_del( c->c_write_event );
    event_free( c->c_write_event );

    root = c->c_ops;
    c->c_ops = NULL;

    if ( !BER_BVISNULL( &c->c_auth ) ) {
        ch_free( c->c_auth.bv_val );
    }

    c->c_state = SLAP_C_INVALID;
    connection_destroy( c );

    if ( !root ) return;

    /* We don't hold c_mutex anymore */
    node = tavl_end( root, TAVL_DIR_LEFT );
    do {
        Operation *op = node->avl_data;

        op->o_client = NULL;
        operation_abandon( op );
    } while ( (node = tavl_next( node, TAVL_DIR_RIGHT )) );
    tavl_free( root, NULL );
}
