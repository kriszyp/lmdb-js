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
        CONNECTION_DESTROY(c);
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
            CONNECTION_DESTROY(c);
            return -1;
        case LDAP_REQ_BIND:
            handler = request_bind;
            break;
        case LDAP_REQ_ABANDON:
            /* FIXME: We need to be able to abandon a Bind request, handling
             * ExOps (esp. Cancel) will be different */
            handler = request_abandon;
            break;
        case LDAP_REQ_EXTENDED:
            handler = request_extended;
            break;
        default:
            if ( c->c_state == LLOAD_C_BINDING ) {
                return operation_send_reject_locked(
                        op, LDAP_PROTOCOL_ERROR, "bind in progress", 0 );
            }
            handler = request_process;
            break;
    }

    return handler( c, op );
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
    event_callback_fn read_cb = connection_read_cb,
                      write_cb = connection_write_cb;

    assert( listener != NULL );

    if ( (c = connection_init( s, peername, flags )) == NULL ) {
        return NULL;
    }

    {
        ber_len_t max = sockbuf_max_incoming_client;
        ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
    }

    c->c_state = LLOAD_C_READY;

    event = event_new( base, s, EV_READ|EV_PERSIST, read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "client_init: "
                "Read event could not be allocated\n" );
        goto fail;
    }
    c->c_read_event = event;
    event_add( c->c_read_event, NULL );

    event = event_new( base, s, EV_WRITE, write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "client_init: "
                "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    c->c_private = listener;
    c->c_destroy = client_destroy;
    c->c_pdu_cb = handle_one_request;

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

    c->c_state = LLOAD_C_INVALID;
    CONNECTION_DESTROY(c);
    assert( c == NULL );
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

    assert( c->c_state != LLOAD_C_INVALID );
    state = c->c_state;
    c->c_state = LLOAD_C_INVALID;

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

    if ( state != LLOAD_C_CLOSING ) {
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
        c->c_state = LLOAD_C_CLOSING;
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
        CONNECTION_DESTROY(c);
        ldap_pvt_thread_mutex_lock( &clients_mutex );
    }
    ldap_pvt_thread_mutex_unlock( &clients_mutex );
}
