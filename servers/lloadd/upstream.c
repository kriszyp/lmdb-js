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

static int
forward_response( Operation *op, BerElement *ber )
{
    Connection *c = op->o_client;
    BerElement *output;
    BerValue response, controls = BER_BVNULL;
    ber_tag_t tag, response_tag;
    ber_len_t len;

    response_tag = ber_skip_element( ber, &response );

    tag = ber_peek_tag( ber, &len );
    if ( tag == LDAP_TAG_CONTROLS ) {
        ber_skip_element( ber, &controls );
    }

    Debug( LDAP_DEBUG_CONNS, "forward_response: "
            "%s to client %lu request #%d\n",
            slap_msgtype2str( response_tag ), c->c_connid, op->o_client_msgid );

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    output = c->c_pendingber;
    if ( output == NULL && (output = ber_alloc()) == NULL ) {
        ber_free( ber, 1 );
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        return -1;
    }
    c->c_pendingber = output;

    ber_printf( output, "t{titOtO}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_client_msgid,
            response_tag, &response,
            LDAP_TAG_CONTROLS, BER_BV_OPTIONAL( &controls ) );

    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    ber_free( ber, 1 );
    client_write_cb( -1, 0, c );
    return 0;
}

static int
forward_final_response( Operation *op, BerElement *ber )
{
    int rc;

    Debug( LDAP_DEBUG_CONNS, "forward_final_response: "
            "finishing up with request #%d for client %lu\n",
            op->o_client_msgid, op->o_client->c_connid );
    rc = forward_response( op, ber );
    operation_destroy( op );

    return rc;
}

static int
handle_bind_response( Operation *op, BerElement *ber )
{
    Connection *c = op->o_client;
    BerElement *copy;
    ber_int_t msgid, result;
    ber_tag_t tag;
    int rc = 0;

    copy = ber_dup( ber );
    if ( !copy ) {
        rc = -1;
        goto done;
    }

    tag = ber_scanf( copy, "{i{e" /* "}}" */, &msgid, &result );
    ber_free( copy, 0 );

    if ( tag == LBER_ERROR ) {
        rc = -1;
        goto done;
    }

    Debug( LDAP_DEBUG_CONNS, "handle_bind_response: "
            "received response for bind request by client %lu, result=%d\n",
            c->c_connid, result );

    switch ( result ) {
        case LDAP_SASL_BIND_IN_PROGRESS:
            break;
        case LDAP_SUCCESS:
        default: {
            ldap_pvt_thread_mutex_lock( &c->c_mutex );
            c->c_state = SLAP_C_READY;
            if ( result != LDAP_SUCCESS ) {
                ber_memfree( c->c_auth.bv_val );
                BER_BVZERO( &c->c_auth );
            }
            if ( !BER_BVISNULL( &c->c_sasl_bind_mech ) ) {
                ber_memfree( c->c_sasl_bind_mech.bv_val );
                BER_BVZERO( &c->c_sasl_bind_mech );
            }
            ldap_pvt_thread_mutex_unlock( &c->c_mutex );
            break;
        }
    }

done:
    if ( rc ) {
        operation_destroy( op );
        ber_free( ber, 1 );
        return rc;
    }
    return forward_final_response( op, ber );
}

static int
handle_vc_bind_response( Operation *op, BerElement *ber )
{
    Connection *c = op->o_client;
    BerElement *output;
    BerValue matched, diagmsg, creds = BER_BVNULL, controls = BER_BVNULL;
    ber_int_t result;
    ber_tag_t tag;
    ber_len_t len;
    int rc = 0;

    tag = ber_scanf( ber, "{emm" /* "}" */,
            &result, &matched, &diagmsg );
    if ( tag == LBER_ERROR ) {
        rc = -1;
        goto done;
    }

    tag = ber_peek_tag( ber, &len );
    if ( result == LDAP_PROTOCOL_ERROR ) {
        Backend *b = op->o_upstream->c_private;
        ldap_pvt_thread_mutex_lock( &op->o_upstream->c_mutex );
        Debug( LDAP_DEBUG_ANY, "VC extended operation not supported on backend %s\n",
                b->b_bindconf.sb_uri.bv_val );
        ldap_pvt_thread_mutex_unlock( &op->o_upstream->c_mutex );
    }

    ldap_pvt_thread_mutex_lock( &c->c_mutex );

    Debug( LDAP_DEBUG_CONNS, "handle_vc_bind_response: "
            "received response for bind request by client %lu, result=%d\n",
            c->c_connid, result );

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE ) {
        if ( !BER_BVISNULL( &c->c_vc_cookie ) ) {
            ber_memfree( c->c_vc_cookie.bv_val );
        }
        tag = ber_scanf( ber, "o", &c->c_vc_cookie );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            ldap_pvt_thread_mutex_unlock( &c->c_mutex );
            goto done;
        }
        tag = ber_peek_tag( ber, &len );
    }

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_SCREDS ) {
        tag = ber_scanf( ber, "m", &creds );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            ldap_pvt_thread_mutex_unlock( &c->c_mutex );
            goto done;
        }
        tag = ber_peek_tag( ber, &len );
    }

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_CONTROLS ) {
        tag = ber_scanf( ber, "m", &controls );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            ldap_pvt_thread_mutex_unlock( &c->c_mutex );
            goto done;
        }
    }

    switch ( result ) {
        case LDAP_SASL_BIND_IN_PROGRESS:
            break;
        case LDAP_SUCCESS:
        default: {
            c->c_state = SLAP_C_READY;
            if ( result != LDAP_SUCCESS ) {
                ber_memfree( c->c_auth.bv_val );
                BER_BVZERO( &c->c_auth );
            }
            if ( !BER_BVISNULL( &c->c_vc_cookie ) ) {
                ber_memfree( c->c_vc_cookie.bv_val );
                BER_BVZERO( &c->c_vc_cookie );
            }
            if ( !BER_BVISNULL( &c->c_sasl_bind_mech ) ) {
                ber_memfree( c->c_sasl_bind_mech.bv_val );
                BER_BVZERO( &c->c_sasl_bind_mech );
            }
            break;
        }
    }
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    output = c->c_pendingber;
    if ( output == NULL && (output = ber_alloc()) == NULL ) {
        rc = -1;
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        goto done;
    }
    c->c_pendingber = output;

    rc = ber_printf( output, "t{tit{eOOtO}tO}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_client_msgid, LDAP_RES_BIND,
            result, &matched, &diagmsg,
            LDAP_TAG_SASL_RES_CREDS, BER_BV_OPTIONAL( &creds ),
            LDAP_TAG_CONTROLS, BER_BV_OPTIONAL( &controls ) );

    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
    if ( rc >= 0 ) {
        client_write_cb( -1, 0, c );
        rc = 0;
    }

done:
    operation_destroy( op );
    ber_free( ber, 1 );
    return rc;
}

static int
handle_unsolicited( Connection *c, BerElement *ber )
{
    TAvlnode *root;
    int freed;

    Debug( LDAP_DEBUG_CONNS, "handle_unsolicited: "
            "teardown for upstream connection %lu\n",
            c->c_connid );

    root = c->c_ops;
    c->c_ops = NULL;
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    freed = tavl_free( root, (AVL_FREE)operation_lost_upstream );
    Debug( LDAP_DEBUG_TRACE, "handle_unsolicited: "
            "dropped %d operations\n",
            freed );

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    upstream_destroy( c );
    ber_free( ber, 1 );

    return -1;
}

/*
 * Pull c->c_currentber from the connection and try to look up the operation on
 * the upstream.
 *
 * If it's a notice of disconnection, we won't find it and need to tear down
 * the connection and tell the clients, if we can't find the operation, ignore
 * the message (either client already disconnected/abandoned it or the upstream
 * is pulling our leg).
 *
 * Some responses need special handling:
 * - Bind response
 * - VC response where the client requested a Bind (both need to update the
 *   client's bind status)
 * - search entries/referrals and intermediate responses (will not trigger
 *   operation to be removed)
 *
 * If the worker pool is overloaded, we might be called directly from
 * upstream_read_cb, at that point, the connection hasn't been muted.
 *
 * TODO: when the client already has data pending on write, we should mute the
 * upstream.
 * - should record the BerElement on the Op and the Op on the client
 */
static int
handle_one_response( Connection *c )
{
    BerElement *ber;
    Operation *op = NULL, needle = { .o_upstream = c };
    OperationHandler handler = NULL;
    ber_tag_t tag;
    ber_len_t len;
    int rc = 0;

    ber = c->c_currentber;
    c->c_currentber = NULL;

    tag = ber_get_int( ber, &needle.o_upstream_msgid );
    if ( tag != LDAP_TAG_MSGID ) {
        rc = -1;
        ber_free( ber, 1 );
        goto fail;
    }

    if ( needle.o_upstream_msgid == 0 ) {
        return handle_unsolicited( c, ber );
    } else if ( !( op = tavl_find(
                           c->c_ops, &needle, operation_upstream_cmp ) ) ) {
        /* Already abandoned, do nothing */
        /*
    } else if ( op->o_response_pending ) {
        c->c_pendingop = op;
        event_del( c->c_read_event );
    */
    } else {
        /*
        op->o_response_pending = ber;
        */

        tag = ber_peek_tag( ber, &len );
        switch ( tag ) {
            case LDAP_RES_SEARCH_ENTRY:
            case LDAP_RES_SEARCH_REFERENCE:
            case LDAP_RES_INTERMEDIATE:
                handler = forward_response;
                break;
            case LDAP_RES_BIND:
                handler = handle_bind_response;
                break;
            case LDAP_RES_EXTENDED:
                if ( op->o_tag == LDAP_REQ_BIND ) {
                    handler = handle_vc_bind_response;
                }
                break;
        }
        if ( !handler ) {
            handler = forward_final_response;
        }
    }
    if ( op ) {
        Debug( LDAP_DEBUG_TRACE, "handle_one_response: "
                "upstream=%lu, processing response for client %lu, msgid=%d\n",
                c->c_connid, op->o_client->c_connid, op->o_client_msgid );
    } else {
        tag = ber_peek_tag( ber, &len );
        Debug( LDAP_DEBUG_TRACE, "handle_one_response: "
                "upstream=%lu, %s, msgid=%d not for a pending operation\n",
                c->c_connid, slap_msgtype2str( tag ), needle.o_upstream_msgid );
    }

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    if ( handler ) {
        rc = handler( op, ber );
    }
    ldap_pvt_thread_mutex_lock( &c->c_mutex );

fail:
    if ( rc ) {
        Debug( LDAP_DEBUG_ANY, "handle_one_response: "
                "error on processing a response on upstream connection %ld\n",
                c->c_connid );
        upstream_destroy( c );
    }
    return rc;
}

/*
 * We start off with the upstream muted and c_currentber holding the response
 * we received.
 *
 * We run handle_one_response on each response, stopping once we hit an error,
 * have to wait on reading or process slap_conn_max_pdus_per_cycle responses so
 * as to maintain fairness and not hog the worker thread forever.
 *
 * If we've run out of responses from the upstream or hit the budget, we unmute
 * the connection and run handle_one_response, it might return an 'error' when
 * the client is blocked on writing, it's that client's job to wake us again.
 */
static void *
handle_responses( void *ctx, void *arg )
{
    Connection *c = arg;
    int responses_handled = 0;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    for ( ; responses_handled < slap_conn_max_pdus_per_cycle;
            responses_handled++ ) {
        BerElement *ber;
        ber_tag_t tag;
        ber_len_t len;

        if ( handle_one_response( c ) ) {
            /* Error, connection might already have been destroyed */
            return NULL;
        }
        /* Otherwise, handle_one_response leaves the connection locked */

        if ( (ber = ber_alloc()) == NULL ) {
            Debug( LDAP_DEBUG_ANY, "handle_responses: "
                    "ber_alloc failed\n" );
            upstream_destroy( c );
            return NULL;
        }
        c->c_currentber = ber;

        tag = ber_get_next( c->c_sb, &len, ber );
        if ( tag != LDAP_TAG_MESSAGE ) {
            int err = sock_errno();

            if ( err != EWOULDBLOCK && err != EAGAIN ) {
                char ebuf[128];
                Debug( LDAP_DEBUG_ANY, "handle_responses: "
                        "ber_get_next on fd %d failed errno=%d (%s)\n",
                        c->c_fd, err,
                        sock_errstr( err, ebuf, sizeof(ebuf) ) );

                c->c_currentber = NULL;
                ber_free( ber, 1 );
                upstream_destroy( c );
                return NULL;
            }
            break;
        }
    }

    event_add( c->c_read_event, NULL );
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    return NULL;
}

/*
 * Initial read on the upstream connection, if we get an LDAP PDU, submit the
 * processing of this and successive ones to the work queue.
 *
 * If we can't submit it to the queue (overload), process this one and return
 * to the event loop immediately after.
 */
void
upstream_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    ber_tag_t tag;
    ber_len_t len;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    Debug( LDAP_DEBUG_CONNS, "upstream_read_cb: "
            "connection %lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "upstream_read_cb: "
                "ber_alloc failed\n" );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        return;
    }
    c->c_currentber = ber;

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            Debug( LDAP_DEBUG_ANY, "upstream_read_cb: "
                    "ber_get_next on fd %d failed errno=%d (%s)\n",
                    c->c_fd, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );

            c->c_currentber = NULL;
            ber_free( ber, 1 );
            upstream_destroy( c );
            return;
        }
        event_add( c->c_read_event, NULL );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        return;
    }

    if ( !slap_conn_max_pdus_per_cycle ||
            ldap_pvt_thread_pool_submit(
                    &connection_pool, handle_responses, c ) ) {
        /* If we're overloaded or configured as such, process one and resume in
         * the next cycle */
        if ( handle_one_response( c ) == LDAP_SUCCESS ) {
            ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        }
        return;
    }
    event_del( c->c_read_event );

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    return;
}

void
upstream_finish( Connection *c )
{
    struct event_base *base;
    struct event *event;
    evutil_socket_t s = c->c_fd;

    Debug( LDAP_DEBUG_CONNS, "upstream_finish: "
            "connection %lu is ready for use\n",
            c->c_connid );

    base = slap_get_base( s );

    event = event_new( base, s, EV_READ|EV_PERSIST, upstream_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "upstream_finish: "
                "Read event could not be allocated\n" );
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
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                "ber_alloc failed\n" );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        return;
    }
    c->c_currentber = ber;

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                    "ber_get_next on fd %d failed errno=%d (%s)\n",
                    c->c_fd, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );

            c->c_currentber = NULL;
            goto fail;
        }
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
        return;
    }
    c->c_currentber = NULL;

    if ( ber_scanf( ber, "it", &msgid, &tag ) == LBER_ERROR ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                "protocol violation from server\n" );
        goto fail;
    }

    if ( msgid != ( c->c_next_msgid - 1 ) || tag != LDAP_RES_BIND ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                "unexpected %s from server, msgid=%d\n",
                slap_msgtype2str( tag ), msgid );
        goto fail;
    }

    if ( ber_scanf( ber, "{eAA" /* "}" */, &result, &matcheddn, &message ) ==
                 LBER_ERROR ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                "response does not conform with a bind response\n" );
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
        Debug( LDAP_DEBUG_ANY, "upstream_bind: "
                "Read event could not be allocated\n" );
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

/*
 * We must already hold b->b_mutex when called.
 */
Connection *
upstream_init( ber_socket_t s, Backend *b )
{
    Connection *c;
    struct event_base *base = slap_get_base( s );
    struct event *event;
    int flags, is_bindconn = 0;

    assert( b != NULL );

    flags = (b->b_tls == LLOAD_LDAPS) ? CONN_IS_TLS : 0;
    c = connection_init( s, b->b_host, flags );
    c->c_private = b;

    event = event_new( base, s, EV_WRITE, upstream_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "upstream_init: "
                "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    /* Unless we are configured to use the VC exop, consider allocating the
     * connection into the bind conn pool. Start off by allocating one for
     * general use, then one for binds, then we start filling up the general
     * connection pool, finally the bind pool */
    if ( !(lload_features & LLOAD_FEATURE_VC) && b->b_active &&
            b->b_numbindconns ) {
        if ( !b->b_bindavail ) {
            is_bindconn = 1;
        } else if ( b->b_active >= b->b_numconns &&
                b->b_bindavail < b->b_numbindconns ) {
            is_bindconn = 1;
        }
    }

    if ( is_bindconn || b->b_bindconf.sb_method == LDAP_AUTH_NONE ) {
        upstream_finish( c );
    } else {
        ldap_pvt_thread_pool_submit( &connection_pool, upstream_bind, c );
    }

    if ( is_bindconn ) {
        LDAP_LIST_INSERT_HEAD( &b->b_bindconns, c, c_next );
        c->c_type = SLAP_C_BIND;
        b->b_bindavail++;
    } else {
        LDAP_LIST_INSERT_HEAD( &b->b_conns, c, c_next );
        b->b_active++;
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

void
upstream_destroy( Connection *c )
{
    Backend *b = c->c_private;

    Debug( LDAP_DEBUG_CONNS, "upstream_destroy: "
            "freeing connection %lu\n",
            c->c_connid );

    assert( c->c_state != SLAP_C_INVALID );
    c->c_state = SLAP_C_INVALID;
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    LDAP_LIST_REMOVE( c, c_next );
    if ( c->c_type == SLAP_C_BIND ) {
        b->b_bindavail--;
    } else {
        b->b_active--;
    }
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    backend_retry( b );

    ldap_pvt_thread_mutex_lock( &c->c_mutex );

    event_del( c->c_read_event );
    event_free( c->c_read_event );

    event_del( c->c_write_event );
    event_free( c->c_write_event );

    connection_destroy( c );
}
