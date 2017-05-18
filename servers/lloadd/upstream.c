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
            slap_msgtype2str( response_tag ), op->o_client_connid,
            op->o_client_msgid );

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
            op->o_client_msgid, op->o_client_connid );
    rc = forward_response( op, ber );
    CONNECTION_LOCK_DECREF(op->o_upstream);
    operation_destroy_from_upstream( op );
    CONNECTION_UNLOCK_INCREF(op->o_upstream);

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
            op->o_client_connid, result );

    CONNECTION_LOCK(c);
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
            if ( !BER_BVISNULL( &c->c_sasl_bind_mech ) ) {
                ber_memfree( c->c_sasl_bind_mech.bv_val );
                BER_BVZERO( &c->c_sasl_bind_mech );
            }
            break;
        }
    }

done:
    if ( rc ) {
        operation_destroy_from_client( op );
        CONNECTION_UNLOCK(c);

        ber_free( ber, 1 );
        return rc;
    }
    CONNECTION_UNLOCK(c);
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
        Connection *upstream = op->o_upstream;
        Backend *b;

        CONNECTION_LOCK(upstream);
        b = (Backend *)upstream->c_private;
        Debug( LDAP_DEBUG_ANY, "VC extended operation not supported on backend %s\n",
                b->b_bindconf.sb_uri.bv_val );
        CONNECTION_UNLOCK(upstream);
    }

    CONNECTION_LOCK(c);

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
            CONNECTION_UNLOCK_INCREF(c);
            goto done;
        }
        tag = ber_peek_tag( ber, &len );
    }

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_SCREDS ) {
        tag = ber_scanf( ber, "m", &creds );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            CONNECTION_UNLOCK_INCREF(c);
            goto done;
        }
        tag = ber_peek_tag( ber, &len );
    }

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_CONTROLS ) {
        tag = ber_scanf( ber, "m", &controls );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            CONNECTION_UNLOCK_INCREF(c);
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
    CONNECTION_UNLOCK_INCREF(c);

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
    CONNECTION_LOCK_DECREF(c);
    operation_destroy_from_client( op );
    CLIENT_UNLOCK_OR_DESTROY(c);
    ber_free( ber, 1 );
    return rc;
}

static int
handle_unsolicited( Connection *c, BerElement *ber )
{
    TAvlnode *root;
    long freed, executing;

    Debug( LDAP_DEBUG_CONNS, "handle_unsolicited: "
            "teardown for upstream connection %lu\n",
            c->c_connid );

    root = c->c_ops;
    c->c_ops = NULL;
    executing = c->c_n_ops_executing;
    CONNECTION_UNLOCK_INCREF(c);

    freed = tavl_free( root, (AVL_FREE)operation_lost_upstream );
    assert( freed == executing );
    Debug( LDAP_DEBUG_TRACE, "handle_unsolicited: "
            "dropped %ld operations\n",
            freed );

    UPSTREAM_LOCK_DESTROY(c);
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
    Operation *op = NULL, needle = { .o_upstream_connid = c->c_connid };
    OperationHandler handler = NULL;
    ber_tag_t tag;
    ber_len_t len;
    int rc = LDAP_SUCCESS;

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
        ber_free( ber, 1 );
        return rc;
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
                "upstream=%lu, processing response for client connid=%lu, "
                "msgid=%d\n",
                c->c_connid, op->o_client_connid, op->o_client_msgid );
    } else {
        tag = ber_peek_tag( ber, &len );
        Debug( LDAP_DEBUG_TRACE, "handle_one_response: "
                "upstream=%lu, %s, msgid=%d not for a pending operation\n",
                c->c_connid, slap_msgtype2str( tag ), needle.o_upstream_msgid );
    }

    if ( handler ) {
        Connection *client;

        op->o_upstream_refcnt++;
        CONNECTION_UNLOCK_INCREF(c);

        ldap_pvt_thread_mutex_lock( &operation_mutex );
        client = op->o_client;
        if ( client ) {
            CONNECTION_LOCK(client);
            CONNECTION_UNLOCK_INCREF(client);
        }
        ldap_pvt_thread_mutex_unlock( &operation_mutex );

        if ( client ) {
            rc = handler( op, ber );
            CONNECTION_LOCK_DECREF(client);
            CLIENT_UNLOCK_OR_DESTROY(client);
        } else {
            ber_free( ber, 1 );
        }

        CONNECTION_LOCK_DECREF(c);
        op->o_upstream_refcnt--;
        if ( !client || !op->o_upstream_live ) {
            operation_destroy_from_upstream( op );
        }
    } else {
        ber_free( ber, 1 );
    }

fail:
    if ( rc ) {
        Debug( LDAP_DEBUG_ANY, "handle_one_response: "
                "error on processing a response on upstream connection %ld\n",
                c->c_connid );
        UPSTREAM_DESTROY(c);
    }
    /* We leave the connection locked */
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

    CONNECTION_LOCK_DECREF(c);
    for ( ; responses_handled < slap_conn_max_pdus_per_cycle;
            responses_handled++ ) {
        BerElement *ber;
        ber_tag_t tag;
        ber_len_t len;

        /* handle_one_response may unlock the connection in the process, we
         * need to expect that might be our responsibility to destroy it */
        if ( handle_one_response( c ) ) {
            /* Error, connection is unlocked and might already have been
             * destroyed */
            return NULL;
        }
        /* Otherwise, handle_one_response leaves the connection locked */

        if ( (ber = ber_alloc()) == NULL ) {
            Debug( LDAP_DEBUG_ANY, "handle_responses: "
                    "ber_alloc failed\n" );
            UPSTREAM_DESTROY(c);
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
                UPSTREAM_DESTROY(c);
                return NULL;
            }
            break;
        }
    }

    event_add( c->c_read_event, NULL );
    UPSTREAM_UNLOCK_OR_DESTROY(c);
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

    CONNECTION_LOCK(c);
    if ( !c->c_live ) {
        event_del( c->c_read_event );
        CONNECTION_UNLOCK(c);
        return;
    }
    Debug( LDAP_DEBUG_CONNS, "upstream_read_cb: "
            "connection %lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "upstream_read_cb: "
                "ber_alloc failed\n" );
        UPSTREAM_DESTROY(c);
        return;
    }
    c->c_currentber = ber;

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            if ( err ) {
                char ebuf[128];
                Debug( LDAP_DEBUG_ANY, "upstream_read_cb: "
                        "ber_get_next on fd %d failed errno=%d (%s)\n",
                        c->c_fd, err,
                        sock_errstr( err, ebuf, sizeof(ebuf) ) );
            }

            c->c_currentber = NULL;
            ber_free( ber, 1 );

            event_del( c->c_read_event );
            UPSTREAM_DESTROY(c);
            return;
        }
        event_add( c->c_read_event, NULL );
        CONNECTION_UNLOCK(c);
        return;
    }

    if ( !slap_conn_max_pdus_per_cycle ||
            ldap_pvt_thread_pool_submit(
                    &connection_pool, handle_responses, c ) ) {
        /* If we're overloaded or configured as such, process one and resume in
         * the next cycle.
         *
         * handle_one_response re-locks the mutex in the
         * process, need to test it's still alive */
        if ( handle_one_response( c ) == LDAP_SUCCESS ) {
            UPSTREAM_UNLOCK_OR_DESTROY(c);
        }
        return;
    }

    /* We have scheduled a call to handle_responses which takes care of
     * handling further requests, just make sure the connection sticks around
     * for that */
    event_del( c->c_read_event );
    CONNECTION_UNLOCK_INCREF(c);
    return;
}

int
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
        return -1;
    }
    event_add( event, NULL );
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    c->c_read_event = event;

    c->c_state = SLAP_C_READY;

    return 0;
}

void
upstream_bind_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    BerValue matcheddn, message;
    ber_tag_t tag;
    ber_len_t len;
    ber_int_t msgid, result;

    CONNECTION_LOCK(c);
    Debug( LDAP_DEBUG_CONNS, "upstream_bind_cb: "
            "connection %lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                "ber_alloc failed\n" );
        CONNECTION_UNLOCK(c);
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
        CONNECTION_UNLOCK(c);
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

    if ( ber_scanf( ber, "{emm" /* "}" */, &result, &matcheddn, &message ) ==
                 LBER_ERROR ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                "response does not conform with a bind response\n" );
        goto fail;
    }

    switch ( result ) {
        case LDAP_SUCCESS:
            if ( upstream_finish( c ) ) {
                goto fail;
            }
            break;
#ifdef HAVE_CYRUS_SASL
        case LDAP_SASL_BIND_IN_PROGRESS:
            /* TODO: fallthrough until we implement SASL */
#endif /* HAVE_CYRUS_SASL */
        default:
            Debug( LDAP_DEBUG_ANY, "upstream_bind_cb: "
                    "upstream bind failed, rc=%d, message='%s'\n",
                    result, message.bv_val );
            goto fail;
    }

    CONNECTION_UNLOCK(c);

    ber_free( ber, 1 );
    return;

fail:
    event_del( c->c_read_event );
    ber_free( ber, 1 );
    UPSTREAM_DESTROY(c);
}

void
upstream_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;

    CONNECTION_LOCK(c);
    if ( !c->c_live ) {
        CONNECTION_UNLOCK(c);
        return;
    }
    CONNECTION_UNLOCK_INCREF(c);

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    Debug( LDAP_DEBUG_CONNS, "upstream_write_cb: "
            "have something to write to upstream %lu\n",
            c->c_connid );

    /* We might have been beaten to flushing the data by another thread */
    if ( c->c_pendingber && ber_flush( c->c_sb, c->c_pendingber, 1 ) ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            Debug( LDAP_DEBUG_ANY, "upstream_write_cb: "
                    "ber_flush on fd %d failed errno=%d (%s)\n",
                    c->c_fd, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            UPSTREAM_LOCK_DESTROY(c);
            return;
        }
        event_add( c->c_write_event, NULL );
    } else {
        c->c_pendingber = NULL;
    }
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    CONNECTION_LOCK_DECREF(c);
    UPSTREAM_UNLOCK_OR_DESTROY(c);
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

    CONNECTION_LOCK(c);
    b = c->c_private;
    s = c->c_fd;
    base = slap_get_base( s );

    event = event_new( base, s, EV_READ|EV_PERSIST, upstream_bind_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "upstream_bind: "
                "Read event could not be allocated\n" );
        UPSTREAM_DESTROY(c);
        return NULL;
    }
    event_add( event, NULL );
    if ( c->c_read_event ) {
        event_del( c->c_read_event );
        event_free( c->c_read_event );
    }
    c->c_read_event = event;

    msgid = c->c_next_msgid++;

    CONNECTION_UNLOCK_INCREF(c);

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

    CONNECTION_LOCK_DECREF(c);
    UPSTREAM_UNLOCK_OR_DESTROY(c);

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
        if ( upstream_finish( c ) ) {
            goto fail;
        }
    } else {
        ldap_pvt_thread_pool_submit( &connection_pool, upstream_bind, c );
    }

    if ( is_bindconn ) {
        LDAP_CIRCLEQ_INSERT_HEAD( &b->b_bindconns, c, c_next );
        c->c_type = SLAP_C_BIND;
        b->b_bindavail++;
    } else {
        LDAP_CIRCLEQ_INSERT_HEAD( &b->b_conns, c, c_next );
        b->b_active++;
    }

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
    UPSTREAM_DESTROY(c);
    return NULL;
}

void
upstream_destroy( Connection *c )
{
    Backend *b = c->c_private;
    struct event *read_event, *write_event;

    Debug( LDAP_DEBUG_CONNS, "upstream_destroy: "
            "freeing connection %lu\n",
            c->c_connid );

    c->c_state = SLAP_C_INVALID;

    read_event = c->c_read_event;
    write_event = c->c_write_event;
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

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    if ( c->c_type == SLAP_C_BIND ) {
        LDAP_CIRCLEQ_REMOVE( &b->b_bindconns, c, c_next );
        b->b_bindavail--;
    } else {
        LDAP_CIRCLEQ_REMOVE( &b->b_conns, c, c_next );
        b->b_active--;
    }
    b->b_n_ops_executing -= c->c_n_ops_executing;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    backend_retry( b );

    CONNECTION_LOCK_DECREF(c);

    if ( c->c_read_event ) {
        event_free( c->c_read_event );
        c->c_read_event = NULL;
    }

    if ( c->c_write_event ) {
        event_free( c->c_write_event );
        c->c_write_event = NULL;
    }

    /*
     * If we attempted to destroy any operations, we might have lent a new
     * refcnt token for a thread that raced us to that, let them call us again
     * later
     */
    assert( c->c_refcnt >= 0 );
    if ( c->c_refcnt ) {
        c->c_state = SLAP_C_CLOSING;
        Debug( LDAP_DEBUG_CONNS, "upstream_destroy: "
                "connid=%lu aborting with refcnt=%d\n",
                c->c_connid, c->c_refcnt );
        CONNECTION_UNLOCK(c);
        return;
    }
    connection_destroy( c );
}
