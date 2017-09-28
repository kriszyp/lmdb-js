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

    Debug( LDAP_DEBUG_TRACE, "forward_response: "
            "%s to client connid=%lu request msgid=%d\n",
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
    connection_write_cb( -1, 0, c );
    return 0;
}

static int
forward_final_response( Operation *op, BerElement *ber )
{
    int rc;

    Debug( LDAP_DEBUG_STATS, "forward_final_response: "
            "connid=%lu msgid=%d finishing up with a request for "
            "client connid=%lu\n",
            op->o_upstream_connid, op->o_upstream_msgid, op->o_client_connid );
    rc = forward_response( op, ber );
    CONNECTION_LOCK_DECREF(op->o_upstream);
    operation_destroy_from_upstream( op );
    CONNECTION_UNLOCK_INCREF(op->o_upstream);

    return rc;
}

static int
handle_bind_response( Operation *op, BerElement *ber )
{
    Connection *client = op->o_client, *upstream = op->o_upstream;
    BerValue response;
    BerElement *copy;
    ber_int_t result;
    ber_tag_t tag;
    int rc = LDAP_SUCCESS;

    if ( (copy = ber_alloc()) == NULL ) {
        rc = -1;
        goto done;
    }

    tag = ber_peek_element( ber, &response );
    assert( tag == LDAP_RES_BIND );

    ber_init2( copy, &response, 0 );

    tag = ber_get_enum( copy, &result );
    ber_free( copy, 0 );

    if ( tag == LBER_ERROR ) {
        rc = -1;
        goto done;
    }

    Debug( LDAP_DEBUG_STATS, "handle_bind_response: "
            "received response for bind request msgid=%d by client "
            "connid=%lu, result=%d\n",
            op->o_client_msgid, op->o_client_connid, result );

    CONNECTION_LOCK(upstream);
    if ( result != LDAP_SASL_BIND_IN_PROGRESS ) {
        upstream->c_state = LLOAD_C_READY;
    }
    CONNECTION_UNLOCK(upstream);

    CONNECTION_LOCK(client);
    if ( client->c_state == LLOAD_C_BINDING ) {
        switch ( result ) {
            case LDAP_SASL_BIND_IN_PROGRESS:
                break;
            case LDAP_SUCCESS:
            default: {
                client->c_state = LLOAD_C_READY;
                client->c_type = LLOAD_C_OPEN;
                if ( result != LDAP_SUCCESS ) {
                    ber_memfree( client->c_auth.bv_val );
                    BER_BVZERO( &client->c_auth );
                } else if ( !ber_bvstrcasecmp(
                                    &client->c_auth, &lloadd_identity ) ) {
                    client->c_type = LLOAD_C_PRIVILEGED;
                }
                if ( !BER_BVISNULL( &client->c_sasl_bind_mech ) ) {
                    ber_memfree( client->c_sasl_bind_mech.bv_val );
                    BER_BVZERO( &client->c_sasl_bind_mech );
                }
                break;
            }
        }
    } else {
        assert( client->c_state == LLOAD_C_INVALID ||
                client->c_state == LLOAD_C_CLOSING );
    }
    CONNECTION_UNLOCK(client);

done:
    if ( rc ) {
        operation_send_reject( op, LDAP_OTHER, "internal error", 0 );

        ber_free( ber, 1 );
        return LDAP_SUCCESS;
    }
    return forward_final_response( op, ber );
}

#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
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
        Debug( LDAP_DEBUG_ANY, "handle_vc_bind_response: "
                "VC extended operation not supported on backend %s\n",
                b->b_uri.bv_val );
        CONNECTION_UNLOCK(upstream);
    }

    Debug( LDAP_DEBUG_STATS, "handle_vc_bind_response: "
            "received response for bind request msgid=%d by client "
            "connid=%lu, result=%d\n",
            op->o_client_msgid, op->o_client_connid, result );

    CONNECTION_LOCK(c);

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

    if ( c->c_state == LLOAD_C_BINDING ) {
        switch ( result ) {
            case LDAP_SASL_BIND_IN_PROGRESS:
                break;
            case LDAP_SUCCESS:
            default: {
                c->c_state = LLOAD_C_READY;
                c->c_type = LLOAD_C_OPEN;
                if ( result != LDAP_SUCCESS ) {
                    ber_memfree( c->c_auth.bv_val );
                    BER_BVZERO( &c->c_auth );
                } else if ( !ber_bvstrcasecmp(
                                    &c->c_auth, &lloadd_identity ) ) {
                    c->c_type = LLOAD_C_PRIVILEGED;
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
    } else {
        assert( c->c_state == LLOAD_C_INVALID ||
                c->c_state == LLOAD_C_CLOSING );
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
        connection_write_cb( -1, 0, c );
        rc = 0;
    }

done:
    CONNECTION_LOCK_DECREF(c);
    operation_destroy_from_client( op );
    CONNECTION_UNLOCK_OR_DESTROY(c);
    ber_free( ber, 1 );
    return rc;
}
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */

static int
handle_unsolicited( Connection *c, BerElement *ber )
{
    if ( c->c_state == LLOAD_C_READY ) {
        c->c_state = LLOAD_C_CLOSING;
    }

    Debug( LDAP_DEBUG_CONNS, "handle_unsolicited: "
            "teardown for upstream connection connid=%lu\n",
            c->c_connid );

    CONNECTION_DESTROY(c);
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
 * the read callback, at that point, the connection hasn't been muted.
 *
 * TODO: when the client already has data pending on write, we should mute the
 * upstream.
 * - should record the BerElement on the Op and the Op on the client
 *
 * The following hold on entering any of the handlers:
 * - op->o_upstream_refcnt > 0
 * - op->o_upstream->c_refcnt > 0
 * - op->o_client->c_refcnt > 0
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
#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
                if ( op->o_tag == LDAP_REQ_BIND ) {
                    handler = handle_vc_bind_response;
                }
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
                break;
        }
        if ( !handler ) {
            handler = forward_final_response;
        }
    }
    if ( op ) {
        Debug( LDAP_DEBUG_STATS2, "handle_one_response: "
                "upstream connid=%lu, processing response for "
                "client connid=%lu, msgid=%d\n",
                c->c_connid, op->o_client_connid, op->o_client_msgid );
    } else {
        tag = ber_peek_tag( ber, &len );
        Debug( LDAP_DEBUG_STATS2, "handle_one_response: "
                "upstream connid=%lu, %s, msgid=%d not for a pending "
                "operation\n",
                c->c_connid, slap_msgtype2str( tag ), needle.o_upstream_msgid );
    }

    if ( handler ) {
        Connection *client;

        op->o_upstream_refcnt++;
        CONNECTION_UNLOCK_INCREF(c);

        ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
        client = op->o_client;
        if ( client ) {
            CONNECTION_LOCK(client);
            if ( client->c_live ) {
                op->o_client_refcnt++;
                CONNECTION_UNLOCK_INCREF(client);
            } else {
                CONNECTION_UNLOCK(client);
                client = NULL;
            }
        }
        ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );

        if ( client ) {
            rc = handler( op, ber );
            CONNECTION_LOCK_DECREF(client);
            op->o_client_refcnt--;
            if ( !op->o_client_refcnt ) {
                operation_destroy_from_client( op );
            }
            CONNECTION_UNLOCK_OR_DESTROY(client);
        } else {
            ber_free( ber, 1 );
        }

        CONNECTION_LOCK_DECREF(c);
        op->o_upstream_refcnt--;
        if ( !client || !op->o_upstream_refcnt ) {
            if ( c->c_state == LLOAD_C_BINDING ) {
                c->c_state = LLOAD_C_READY;
            }
            operation_destroy_from_upstream( op );
        }
    } else {
        ber_free( ber, 1 );
    }

fail:
    if ( rc ) {
        Debug( LDAP_DEBUG_STATS, "handle_one_response: "
                "error on processing a response (%s) on upstream connection "
                "connid=%ld, tag=%lx\n",
                slap_msgtype2str( tag ), c->c_connid, tag );
        CONNECTION_DESTROY(c);
    }
    /* We leave the connection locked */
    return rc;
}

int
upstream_bind_cb( Connection *c )
{
    BerElement *ber = c->c_currentber;
    Backend *b = c->c_private;
    BerValue matcheddn, message;
    ber_tag_t tag;
    ber_int_t msgid, result;

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
        case LDAP_SUCCESS: {
            c->c_pdu_cb = handle_one_response;
            c->c_state = LLOAD_C_READY;
            c->c_type = LLOAD_C_OPEN;
            CONNECTION_UNLOCK_INCREF(c);
            ldap_pvt_thread_mutex_lock( &b->b_mutex );
            LDAP_CIRCLEQ_REMOVE( &b->b_preparing, c, c_next );
            LDAP_CIRCLEQ_INSERT_HEAD( &b->b_conns, c, c_next );
            b->b_active++;
            b->b_opening--;
            b->b_failed = 0;
            ldap_pvt_thread_mutex_unlock( &b->b_mutex );
            backend_retry( b );
            CONNECTION_LOCK_DECREF(c);
        } break;
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

    ber_free( ber, 1 );
    return LDAP_SUCCESS;

fail:
    ber_free( ber, 1 );
    CONNECTION_DESTROY(c);
    return -1;
}

void *
upstream_bind( void *ctx, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    ber_int_t msgid;

    CONNECTION_LOCK(c);
    c->c_pdu_cb = upstream_bind_cb;
    CONNECTION_UNLOCK_INCREF(c);

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    ber = c->c_pendingber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        CONNECTION_LOCK_DESTROY(c);
        return NULL;
    }
    c->c_pendingber = ber;
    msgid = c->c_next_msgid++;

    if ( bindconf.sb_method == LDAP_AUTH_SIMPLE ) {
        /* simple bind */
        ber_printf( ber, "{it{iOtON}}",
                msgid, LDAP_REQ_BIND, LDAP_VERSION3,
                &bindconf.sb_binddn, LDAP_AUTH_SIMPLE,
                &bindconf.sb_cred );

#ifdef HAVE_CYRUS_SASL
    } else {
        BerValue cred = BER_BVNULL;
        ber_printf( ber, "{it{iOt{OON}N}}",
                msgid, LDAP_REQ_BIND, LDAP_VERSION3,
                &bindconf.sb_binddn, LDAP_AUTH_SASL,
                &bindconf.sb_saslmech, BER_BV_OPTIONAL( &cred ) );
#endif /* HAVE_CYRUS_SASL */
    }
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    connection_write_cb( -1, 0, c );

    CONNECTION_LOCK_DECREF(c);
    CONNECTION_UNLOCK_OR_DESTROY(c);

    return NULL;
}

/*
 * The backend is already locked when entering the function.
 */
static int
upstream_finish( Connection *c )
{
    Backend *b = c->c_private;
    int is_bindconn = 0, rc = 0;

    c->c_pdu_cb = handle_one_response;

    /* Unless we are configured to use the VC exop, consider allocating the
     * connection into the bind conn pool. Start off by allocating one for
     * general use, then one for binds, then we start filling up the general
     * connection pool, finally the bind pool */
    if (
#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
            !(lload_features & LLOAD_FEATURE_VC) &&
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
            b->b_active && b->b_numbindconns ) {
        if ( !b->b_bindavail ) {
            is_bindconn = 1;
        } else if ( b->b_active >= b->b_numconns &&
                b->b_bindavail < b->b_numbindconns ) {
            is_bindconn = 1;
        }
    }

    if ( is_bindconn ) {
        LDAP_CIRCLEQ_REMOVE( &b->b_preparing, c, c_next );
        LDAP_CIRCLEQ_INSERT_HEAD( &b->b_bindconns, c, c_next );
        c->c_state = LLOAD_C_READY;
        c->c_type = LLOAD_C_BIND;
        b->b_bindavail++;
        b->b_opening--;
        b->b_failed = 0;
    } else if ( bindconf.sb_method == LDAP_AUTH_NONE ) {
        LDAP_CIRCLEQ_REMOVE( &b->b_preparing, c, c_next );
        LDAP_CIRCLEQ_INSERT_HEAD( &b->b_conns, c, c_next );
        c->c_state = LLOAD_C_READY;
        c->c_type = LLOAD_C_OPEN;
        b->b_active++;
        b->b_opening--;
        b->b_failed = 0;
    } else {
        rc = 1;
        ldap_pvt_thread_pool_submit( &connection_pool, upstream_bind, c );
    }

    Debug( LDAP_DEBUG_CONNS, "upstream_finish: "
            "%sconnection connid=%lu is%s ready for use\n",
            is_bindconn ? "bind " : "", c->c_connid, rc ? " almost" : "" );

    return rc;
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
    int flags, rc = -1;

    assert( b != NULL );

    flags = (b->b_tls == LLOAD_LDAPS) ? CONN_IS_TLS : 0;
    if ( (c = connection_init( s, b->b_host, flags )) == NULL ) {
        return NULL;
    }

    c->c_private = b;
    c->c_is_tls = b->b_tls;
    c->c_pdu_cb = handle_one_response;

    LDAP_CIRCLEQ_INSERT_HEAD( &b->b_preparing, c, c_next );
    c->c_type = LLOAD_C_PREPARING;

    {
        ber_len_t max = sockbuf_max_incoming_upstream;
        ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
    }

    event = event_new( base, s, EV_READ|EV_PERSIST, connection_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "upstream_init: "
                "Read event could not be allocated\n" );
        goto fail;
    }
    c->c_read_event = event;

    event = event_new( base, s, EV_WRITE, connection_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "upstream_init: "
                "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only add the write event when we have data pending */
    c->c_write_event = event;

    rc = upstream_finish( c );
    if ( rc < 0 ) {
        goto fail;
    }

    event_add( c->c_read_event, NULL );

    c->c_destroy = upstream_destroy;
    CONNECTION_UNLOCK_OR_DESTROY(c);

    /* has upstream_finish() finished? */
    if ( rc == LDAP_SUCCESS ) {
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        backend_retry( b );
        ldap_pvt_thread_mutex_lock( &b->b_mutex );
    }

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

    c->c_state = LLOAD_C_INVALID;
    CONNECTION_DESTROY(c);
    assert( c == NULL );

    return NULL;
}

void
upstream_destroy( Connection *c )
{
    Backend *b = c->c_private;
    struct event *read_event, *write_event;
    TAvlnode *root;
    long freed, executing;
    enum sc_state state;

    Debug( LDAP_DEBUG_CONNS, "upstream_destroy: "
            "freeing connection connid=%lu\n",
            c->c_connid );

    assert( c->c_state != LLOAD_C_INVALID );
    state = c->c_state;
    c->c_state = LLOAD_C_INVALID;

    root = c->c_ops;
    c->c_ops = NULL;
    executing = c->c_n_ops_executing;
    c->c_n_ops_executing = 0;

    read_event = c->c_read_event;
    write_event = c->c_write_event;

    CONNECTION_UNLOCK_INCREF(c);

    freed = tavl_free( root, (AVL_FREE)operation_lost_upstream );
    assert( freed == executing );

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

    /* Remove from the backend on first pass */
    if ( state != LLOAD_C_CLOSING ) {
        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        if ( c->c_type == LLOAD_C_PREPARING ) {
            LDAP_CIRCLEQ_REMOVE( &b->b_preparing, c, c_next );
            b->b_opening--;
            b->b_failed++;
        } else if ( c->c_type == LLOAD_C_BIND ) {
            LDAP_CIRCLEQ_REMOVE( &b->b_bindconns, c, c_next );
            b->b_bindavail--;
        } else {
            LDAP_CIRCLEQ_REMOVE( &b->b_conns, c, c_next );
            b->b_active--;
        }
        b->b_n_ops_executing -= executing;
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        backend_retry( b );
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

    /*
     * If we attempted to destroy any operations, we might have lent a new
     * refcnt token for a thread that raced us to that, let them call us again
     * later
     */
    assert( c->c_refcnt >= 0 );
    if ( c->c_refcnt ) {
        c->c_state = LLOAD_C_CLOSING;
        Debug( LDAP_DEBUG_CONNS, "upstream_destroy: "
                "connid=%lu aborting with refcnt=%d\n",
                c->c_connid, c->c_refcnt );
        CONNECTION_UNLOCK(c);
        return;
    }
    connection_destroy( c );
}
