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
#include "lload.h"

lload_c_head clients = LDAP_CIRCLEQ_HEAD_INITIALIZER( clients );

ldap_pvt_thread_mutex_t clients_mutex;

int
request_abandon( LloadConnection *c, LloadOperation *op )
{
    LloadOperation *request, needle = { .o_client_connid = c->c_connid };
    int rc = LDAP_SUCCESS;

    if ( ber_decode_int( &op->o_request, &needle.o_client_msgid ) ) {
        Debug( LDAP_DEBUG_STATS, "request_abandon: "
                "connid=%lu msgid=%d invalid integer sent in abandon request\n",
                c->c_connid, op->o_client_msgid );

        operation_destroy_from_client( op );
        CONNECTION_DESTROY(c);
        return -1;
    }

    request = tavl_find( c->c_ops, &needle, operation_client_cmp );
    if ( !request ) {
        Debug( LDAP_DEBUG_STATS, "request_abandon: "
                "connid=%lu msgid=%d requests abandon of an operation "
                "msgid=%d not being processed anymore\n",
                c->c_connid, op->o_client_msgid, needle.o_client_msgid );
        goto done;
    } else if ( request->o_tag == LDAP_REQ_BIND ) {
        /* RFC 4511 states we must not allow Abandon on Binds */
        Debug( LDAP_DEBUG_STATS, "request_abandon: "
                "connid=%lu msgid=%d requests abandon of a bind operation "
                "msgid=%d\n",
                c->c_connid, op->o_client_msgid, needle.o_client_msgid );
        goto done;
    }
    Debug( LDAP_DEBUG_STATS, "request_abandon: "
            "connid=%lu msgid=%d abandoning %s msgid=%d\n",
            c->c_connid, op->o_client_msgid,
            lload_msgtype2str( request->o_tag ), needle.o_client_msgid );

    if ( c->c_state == LLOAD_C_BINDING ) {
        /* We have found the request and we are binding, it must be a bind
         * request */
        assert( request->o_tag == LDAP_REQ_BIND );
        c->c_state = LLOAD_C_READY;
    }

    CONNECTION_UNLOCK_INCREF(c);
    operation_abandon( request );
    CONNECTION_LOCK_DECREF(c);

done:
    operation_destroy_from_client( op );
    return rc;
}

int
request_process( LloadConnection *client, LloadOperation *op )
{
    BerElement *output;
    LloadConnection *upstream;
    ber_int_t msgid;
    int rc = LDAP_SUCCESS;

    op->o_client_refcnt++;
    CONNECTION_UNLOCK_INCREF(client);

    upstream = backend_select( op );
    if ( !upstream ) {
        Debug( LDAP_DEBUG_STATS, "request_process: "
                "connid=%lu, msgid=%d no available connection found\n",
                op->o_client_connid, op->o_client_msgid );

        operation_send_reject(
                op, LDAP_UNAVAILABLE, "no connections available", 1 );
        goto fail;
    }
    op->o_upstream = upstream;
    op->o_upstream_connid = upstream->c_connid;

    output = upstream->c_pendingber;
    if ( output == NULL && (output = ber_alloc()) == NULL ) {
        rc = -1;
        goto fail;
    }
    upstream->c_pendingber = output;

    CONNECTION_LOCK_DECREF(upstream);
    op->o_upstream_msgid = msgid = upstream->c_next_msgid++;
    rc = tavl_insert(
            &upstream->c_ops, op, operation_upstream_cmp, avl_dup_error );
    CONNECTION_UNLOCK_INCREF(upstream);

    Debug( LDAP_DEBUG_TRACE, "request_process: "
            "client connid=%lu added %s msgid=%d to upstream connid=%lu as "
            "msgid=%d\n",
            op->o_client_connid, lload_msgtype2str( op->o_tag ),
            op->o_client_msgid, op->o_upstream_connid, op->o_upstream_msgid );
    assert( rc == LDAP_SUCCESS );

    if ( (lload_features & LLOAD_FEATURE_PROXYAUTHZ) &&
            client->c_type != LLOAD_C_PRIVILEGED ) {
        CONNECTION_LOCK_DECREF(client);
        Debug( LDAP_DEBUG_TRACE, "request_process: "
                "proxying identity %s to upstream\n",
                client->c_auth.bv_val );
        ber_printf( output, "t{titOt{{sbO}" /* "}}" */, LDAP_TAG_MESSAGE,
                LDAP_TAG_MSGID, msgid,
                op->o_tag, &op->o_request,
                LDAP_TAG_CONTROLS,
                LDAP_CONTROL_PROXY_AUTHZ, 1, &client->c_auth );
        CONNECTION_UNLOCK_INCREF(client);

        if ( !BER_BVISNULL( &op->o_ctrls ) ) {
            ber_write( output, op->o_ctrls.bv_val, op->o_ctrls.bv_len, 0 );
        }

        ber_printf( output, /* "{{" */ "}}" );
    } else {
        ber_printf( output, "t{titOtO}", LDAP_TAG_MESSAGE,
                LDAP_TAG_MSGID, msgid,
                op->o_tag, &op->o_request,
                LDAP_TAG_CONTROLS, BER_BV_OPTIONAL( &op->o_ctrls ) );
    }
    ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );

    connection_write_cb( -1, 0, upstream );

    CONNECTION_LOCK_DECREF(upstream);
    CONNECTION_UNLOCK_OR_DESTROY(upstream);

    CONNECTION_LOCK_DECREF(client);
    if ( !--op->o_client_refcnt ) {
        operation_destroy_from_client( op );
    }
    return rc;

fail:
    if ( upstream ) {
        LloadBackend *b;

        ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );
        CONNECTION_LOCK_DECREF(upstream);
        upstream->c_n_ops_executing--;
        b = (LloadBackend *)upstream->c_private;
        CONNECTION_UNLOCK_OR_DESTROY(upstream);

        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        b->b_n_ops_executing--;
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );

        operation_send_reject( op, LDAP_OTHER, "internal error", 0 );
    }
    CONNECTION_LOCK_DECREF(client);
    op->o_client_refcnt--;
    operation_destroy_from_client( op );
    if ( rc ) {
        CONNECTION_DESTROY(client);
    }
    return rc;
}

int
handle_one_request( LloadConnection *c )
{
    BerElement *ber;
    LloadOperation *op = NULL;
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
            /* We can't send a response to abandon requests even if a bind is
             * currently in progress */
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

/*
 * The connection has a token assigned to it when the callback is set up.
 */
void
client_tls_handshake_cb( evutil_socket_t s, short what, void *arg )
{
    LloadConnection *c = arg;
    int rc = 0;

    CONNECTION_LOCK_DECREF(c);
    if ( what & EV_TIMEOUT ) {
        Debug( LDAP_DEBUG_CONNS, "client_tls_handshake_cb: "
                "connid=%lu, timeout reached, destroying\n",
                c->c_connid );
        goto fail;
    }

    /*
     * In case of StartTLS, make sure we flush the response first.
     * Also before we try to read anything from the connection, it isn't
     * permitted to Abandon a StartTLS exop per RFC4511 anyway.
     */
    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    if ( c->c_pendingber ) {
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        CONNECTION_UNLOCK_INCREF(c);
        connection_write_cb( s, what, arg );
        ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
        CONNECTION_LOCK_DECREF(c);

        if ( !c->c_live ) {
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            goto fail;
        }

        /* Do we still have data pending? If so, connection_write_cb would
         * already have arranged the write callback to trigger again */
        if ( c->c_pendingber ) {
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            CONNECTION_UNLOCK_INCREF(c);
            return;
        }
    }
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    rc = ldap_pvt_tls_accept( c->c_sb, lload_tls_ctx );
    if ( rc < 0 ) {
        goto fail;
    }

    if ( rc == 0 ) {
        struct event_base *base = event_get_base( c->c_read_event );

        /*
         * We're finished, replace the callbacks
         *
         * This is deadlock-safe, since both share the same base - the one
         * that's just running us.
         */
        event_del( c->c_read_event );
        event_del( c->c_write_event );

        c->c_read_timeout = NULL;
        event_assign( c->c_read_event, base, c->c_fd, EV_READ|EV_PERSIST,
                connection_read_cb, c );
        event_add( c->c_read_event, c->c_read_timeout );

        event_assign( c->c_write_event, base, c->c_fd, EV_WRITE,
                connection_write_cb, c );
        Debug( LDAP_DEBUG_CONNS, "client_tls_handshake_cb: "
                "connid=%lu finished\n",
                c->c_connid );

        c->c_is_tls = LLOAD_TLS_ESTABLISHED;

        /* The temporary reference established for us is no longer needed */
        CONNECTION_UNLOCK_OR_DESTROY(c);
        return;
    } else if ( ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_NEEDS_WRITE, NULL ) ) {
        event_add( c->c_write_event, lload_write_timeout );
        Debug( LDAP_DEBUG_CONNS, "client_tls_handshake_cb: "
                "connid=%lu need write rc=%d\n",
                c->c_connid, rc );
    }
    CONNECTION_UNLOCK_INCREF(c);
    return;

fail:
    Debug( LDAP_DEBUG_CONNS, "client_tls_handshake_cb: "
            "connid=%lu failed rc=%d\n",
            c->c_connid, rc );
    CONNECTION_DESTROY(c);
}

LloadConnection *
client_init(
        ber_socket_t s,
        LloadListener *listener,
        const char *peername,
        struct event_base *base,
        int flags )
{
    LloadConnection *c;
    struct event *event;
    event_callback_fn read_cb = connection_read_cb,
                      write_cb = connection_write_cb;

    assert( listener != NULL );

    if ( (c = lload_connection_init( s, peername, flags) ) == NULL ) {
        return NULL;
    }

    {
        ber_len_t max = sockbuf_max_incoming_client;
        ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
    }

    c->c_state = LLOAD_C_READY;

    if ( flags & CONN_IS_TLS ) {
        int rc;

        c->c_is_tls = LLOAD_LDAPS;

        rc = ldap_pvt_tls_accept( c->c_sb, lload_tls_ctx );
        if ( rc < 0 ) {
            Debug( LDAP_DEBUG_CONNS, "client_init: "
                    "connid=%lu failed initial TLS accept rc=%d\n",
                    c->c_connid, rc );
            goto fail;
        }

        if ( rc ) {
            c->c_refcnt++;
            c->c_read_timeout = lload_timeout_net;
            read_cb = write_cb = client_tls_handshake_cb;
        }
    }

    event = event_new( base, s, EV_READ|EV_PERSIST, read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "client_init: "
                "Read event could not be allocated\n" );
        goto fail;
    }
    c->c_read_event = event;
    event_add( c->c_read_event, c->c_read_timeout );

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
client_reset( LloadConnection *c )
{
    TAvlnode *root;

    root = c->c_ops;
    c->c_ops = NULL;

    /* unless op->o_client_refcnt > op->o_client_live, there is noone using the
     * operation from the client side and noone new will now that we've removed
     * it from client's c_ops */
    if ( root ) {
        TAvlnode *node = tavl_end( root, TAVL_DIR_LEFT );
        do {
            LloadOperation *op = node->avl_data;

            /* make sure it's useable after we've unlocked the connection */
            op->o_client_refcnt++;
        } while ( (node = tavl_next( node, TAVL_DIR_RIGHT )) );
    }

    if ( !BER_BVISNULL( &c->c_auth ) ) {
        ch_free( c->c_auth.bv_val );
        BER_BVZERO( &c->c_auth );
    }
    if ( !BER_BVISNULL( &c->c_sasl_bind_mech ) ) {
        ch_free( c->c_sasl_bind_mech.bv_val );
        BER_BVZERO( &c->c_sasl_bind_mech );
    }
    CONNECTION_UNLOCK_INCREF(c);

    if ( root ) {
        int freed;
        freed = tavl_free( root, (AVL_FREE)operation_abandon );
        Debug( LDAP_DEBUG_TRACE, "client_reset: "
                "dropped %d operations\n",
                freed );
    }

    CONNECTION_LOCK_DECREF(c);
}

void
client_destroy( LloadConnection *c )
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
        LloadConnection *c = LDAP_CIRCLEQ_FIRST( &clients );

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
