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
upstream_finish( Connection *c )
{
    struct event_base *base;
    struct event *event;
    evutil_socket_t s = c->c_fd;

    Debug( LDAP_DEBUG_CONNS, "upstream_finish: "
            "connection %lu is ready for use\n", c->c_connid );

    base = slap_get_base( s );

    event = event_new( base, s, EV_READ|EV_PERSIST, upstream_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Read event could not be allocated\n" );
        goto fail;
    }
    event_add( event, NULL );
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    c->c_read_event = event;

    c->c_state = SLAP_C_READY;

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    return;
fail:
    if ( c->c_write_event ) {
        event_del( c->c_write_event );
        event_free( c->c_write_event );
    }
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    upstream_destroy( c );
    return;
}

void
upstream_bind_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    char *matcheddn = NULL, *message = NULL;
    ber_tag_t tag;
    ber_len_t len;
    ber_int_t msgid, result;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    Debug( LDAP_DEBUG_CONNS, "upstream_bind_cb: "
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

    if ( ber_scanf( ber, "it", &msgid, &tag ) == LBER_ERROR ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb:"
                " protocol violation from server\n" );
        goto fail;
    }

    if ( msgid != ( c->c_next_msgid - 1 ) || tag != LDAP_RES_BIND ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb:"
                " unexpected %s from server, msgid=%d\n",
                slap_msgtype2str( tag ), msgid );
        goto fail;
    }

    if ( ber_scanf( ber, "{eAA" /* "}" */, &result, &matcheddn, &message ) ==
                 LBER_ERROR ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb:"
                " response does not conform with a bind response\n" );
        goto fail;
    }

    switch ( result ) {
        case LDAP_SUCCESS:
            upstream_finish( c );
            break;
#ifdef HAVE_CYRUS_SASL
        case LDAP_SASL_BIND_IN_PROGRESS:
            /* TODO: fallthrough until we implement SASL */
#endif /* HAVE_CYRUS_SASL */
        default:
            Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                    "upstream bind failed, rc=%d, message='%s'\n",
                    result, message );
            goto fail;
    }

    if ( matcheddn ) ber_memfree( matcheddn );
    if ( message ) ber_memfree( message );

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    return;
fail:
    if ( matcheddn ) ber_memfree( matcheddn );
    if ( message ) ber_memfree( message );

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
        event_add( c->c_write_event, NULL );
    }
    c->c_pendingber = NULL;
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
}

void *
upstream_bind( void *ctx, void *arg )
{
    Connection *c = arg;
    Backend *b;
    BerElement *ber = ber_alloc();
    struct event_base *base;
    struct event *event;
    ber_int_t msgid;
    evutil_socket_t s;

    assert( ber );

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    b = c->c_private;
    s = c->c_fd;
    base = slap_get_base( s );

    event = event_new( base, s, EV_READ|EV_PERSIST, upstream_bind_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Read event could not be allocated\n" );
        upstream_destroy( c );
        return NULL;
    }
    event_add( event, NULL );
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    c->c_read_event = event;

    msgid = c->c_next_msgid++;

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    if ( b->b_bindconf.sb_method == LDAP_AUTH_SIMPLE ) {
        /* simple bind */
        ber_printf( ber, "{it{iOtON}}",
                msgid, LDAP_REQ_BIND, LDAP_VERSION3,
                &b->b_bindconf.sb_binddn, LDAP_AUTH_SIMPLE,
                &b->b_bindconf.sb_cred );

#ifdef HAVE_CYRUS_SASL
    } else {
        BerValue cred = BER_BVNULL;
        ber_printf( ber, "{it{iOt{OON}N}}",
                msgid, LDAP_REQ_BIND, LDAP_VERSION3,
                &b->b_bindconf.sb_binddn, LDAP_AUTH_SASL,
                &b->b_bindconf.sb_saslmech, BER_BV_OPTIONAL( &cred ) );
#endif /* HAVE_CYRUS_SASL */
    }
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    c->c_pendingber = ber;
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    upstream_write_cb( -1, 0, c );

    return NULL;
}

Connection *
upstream_init( ber_socket_t s, Backend *b )
{
    Connection *c;
    struct event_base *base = slap_get_base( s );
    struct event *event;
    int flags = (b->b_tls == LLOAD_LDAPS) ? CONN_IS_TLS : 0;

    assert( b != NULL );

    c = connection_init( s, b->b_host, flags );
    c->c_private = b;

    event = event_new( base, s, EV_WRITE, upstream_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    if ( b->b_bindconf.sb_method == LDAP_AUTH_NONE ) {
        upstream_finish( c );
    } else {
        ldap_pvt_thread_pool_submit( &connection_pool, upstream_bind, c );
    }

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

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    if ( !(b->b_conns == c) ) {
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        return;
    }
    b->b_conns = NULL;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    ldap_pvt_thread_pool_submit( &connection_pool, backend_connect, b );

    ldap_pvt_thread_mutex_lock( &c->c_mutex );

    event_del( c->c_read_event );
    event_free( c->c_read_event );

    event_del( c->c_write_event );
    event_free( c->c_write_event );

    connection_destroy( c );
}
