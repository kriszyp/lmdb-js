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

static void upstream_destroy( Connection *c );

void
upstream_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    ber_tag_t tag;
    Operation *op, needle = { .o_upstream = c };
    ber_len_t len;
    int finished = 0;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    Debug( LDAP_DEBUG_CONNS, "upstream_read_cb: "
            "connection %lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n" );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        return;
    }

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            Debug( LDAP_DEBUG_ANY, "ber_get_next on fd %d failed errno=%d (%s)\n", c->c_fd,
                    err, sock_errstr( err, ebuf, sizeof(ebuf) ) );

            c->c_currentber = NULL;
            goto fail;
        }
        c->c_currentber = ber;
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        return;
    }

    c->c_currentber = NULL;

    tag = ber_get_int( ber, &needle.o_upstream_msgid );
    if ( tag != LDAP_TAG_MSGID || needle.o_upstream_msgid == 0 ) {
        goto fail;
    }

    op = tavl_find( c->c_ops, &needle, operation_upstream_cmp );
    if ( !op ) {
        ber_free( ber, 1 );
    } else {
        Connection *client = op->o_client;
        BerElement *output;
        BerValue response, controls;
        ber_tag_t type;

        type = ber_skip_element( ber, &response );
        switch ( type ) {
            case LDAP_RES_SEARCH_ENTRY:
            case LDAP_RES_SEARCH_REFERENCE:
            case LDAP_RES_INTERMEDIATE:
                break;
            default:
                finished = 1;
                tavl_delete( &c->c_ops, op, operation_upstream_cmp );
                break;
        }
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );

        tag = ber_peek_tag( ber, &len );
        if ( tag == LDAP_TAG_CONTROLS ) {
            tag = ber_skip_element( ber, &controls );
        }

        output = ber_alloc();
        if ( !output ) {
            goto fail;
        }

        ber_start_seq( output, LDAP_TAG_MESSAGE );
        ber_put_int( output, op->o_client_msgid, LDAP_TAG_MSGID );
        ber_put_berval( output, &response, type );
        if ( tag == LDAP_TAG_CONTROLS ) {
            ber_put_berval( output, &controls, LDAP_TAG_CONTROLS );
        }
        ber_put_seq( output );

        if ( finished ) {
            ldap_pvt_thread_mutex_lock( &client->c_mutex );
            tavl_delete( &client->c_ops, op, operation_client_cmp );
            ldap_pvt_thread_mutex_unlock( &client->c_mutex );
            operation_destroy( op );
        }

        ldap_pvt_thread_mutex_lock( &client->c_io_mutex );
        client->c_pendingber = output;
        ldap_pvt_thread_mutex_unlock( &client->c_io_mutex );

        client_write_cb( -1, 0, client );
        return;
    }

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    return;
fail:
    Debug( LDAP_DEBUG_ANY, "upstream_read_cb: "
            "error on processing a response on upstream connection %ld\n",
            c->c_connid );
    ber_free( ber, 1 );
    upstream_destroy( c );
}

void
upstream_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    Debug( LDAP_DEBUG_CONNS, "upstream_write_cb: "
            "have something to write to upstream %lu\n",
            c->c_connid );

    if ( ber_flush( c->c_sb, c->c_pendingber, 1 ) ) {
        int err = sock_errno();
        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            ldap_pvt_thread_mutex_lock( &c->c_mutex );
            Debug( LDAP_DEBUG_ANY, "upstream_write_cb: "
                    "error writing to connection %ld\n",
                    c->c_connid );
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            upstream_destroy( c );
            return;
        }
        event_add( c->c_write_event, 0 );
    }
    c->c_pendingber = NULL;
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
}

Connection *
upstream_init( ber_socket_t s, Backend *backend )
{
    Connection *c;
    struct event_base *base = slap_get_base( s );
    struct event *event;
    int flags = (backend->b_tls == LLOAD_LDAPS) ? CONN_IS_TLS : 0;

    assert( backend != NULL );

    c = connection_init( s, backend->b_host, flags );

    event = event_new( base, s, EV_READ|EV_PERSIST, upstream_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Read event could not be allocated\n" );
        goto fail;
    }
    event_add( event, NULL );
    c->c_read_event = event;

    event = event_new( base, s, EV_WRITE, upstream_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    c->c_private = backend;

    c->c_state = SLAP_C_READY;
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

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
    connection_destroy( c );
    return NULL;
}

static void
upstream_destroy( Connection *c )
{
    Backend *b = c->c_private;

    c->c_state = SLAP_C_INVALID;
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    ldap_pvt_thread_mutex_lock( &b->b_lock );
    if ( !(b->b_conns == c) ) {
        ldap_pvt_thread_mutex_unlock( &b->b_lock );
        return;
    }
    b->b_conns = NULL;
    ldap_pvt_thread_mutex_unlock( &b->b_lock );

    ldap_pvt_thread_pool_submit( &connection_pool, backend_connect, b );

    ldap_pvt_thread_mutex_lock( &c->c_mutex );

    event_del( c->c_read_event );
    event_free( c->c_read_event );

    event_del( c->c_write_event );
    event_free( c->c_write_event );

    connection_destroy( c );
}
