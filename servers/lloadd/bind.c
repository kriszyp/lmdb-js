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

struct berval mech_external = BER_BVC("EXTERNAL");

int
bind_mech_external(
        LloadConnection *client,
        LloadOperation *op,
        struct berval *credentials )
{
    BerValue binddn;
    void *ssl;
    char *ptr;

    client->c_state = LLOAD_C_READY;
    client->c_type = LLOAD_C_OPEN;

    op->o_res = LLOAD_OP_COMPLETED;

    /*
     * We only support implicit assertion.
     *
     * Although RFC 4513 says the credentials field must be missing, RFC 4422
     * doesn't and libsasl2 will pass a zero-length string to send. We have to
     * allow that.
     */
    if ( !BER_BVISEMPTY( credentials ) ) {
        return operation_send_reject_locked( op, LDAP_UNWILLING_TO_PERFORM,
                "proxy authorization is not supported", 1 );
    }

    ssl = ldap_pvt_tls_sb_ctx( client->c_sb );
    if ( !ssl || ldap_pvt_tls_get_peer_dn( ssl, &binddn, NULL, 0 ) ) {
        return operation_send_reject_locked( op, LDAP_INVALID_CREDENTIALS,
                "no externally negotiated identity", 1 );
    }
    client->c_auth.bv_len = binddn.bv_len + STRLENOF("dn:");
    client->c_auth.bv_val = ch_malloc( client->c_auth.bv_len + 1 );

    ptr = lutil_strcopy( client->c_auth.bv_val, "dn:" );
    ptr = lutil_strncopy( ptr, binddn.bv_val, binddn.bv_len );
    *ptr = '\0';

    ber_memfree( binddn.bv_val );

    if ( !ber_bvstrcasecmp( &client->c_auth, &lloadd_identity ) ) {
        client->c_type = LLOAD_C_PRIVILEGED;
    }

    return operation_send_reject_locked( op, LDAP_SUCCESS, "", 1 );
}

/*
 * On entering the function, we've put a reference on both connections and hold
 * upstream's c_io_mutex.
 */
static int
client_bind(
        LloadOperation *op,
        struct berval *binddn,
        ber_tag_t tag,
        struct berval *auth )
{
    LloadConnection *upstream = op->o_upstream;

    ber_printf( upstream->c_pendingber, "t{titOtO}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_upstream_msgid,
            LDAP_REQ_BIND, &op->o_request,
            LDAP_TAG_CONTROLS, BER_BV_OPTIONAL( &op->o_ctrls ) );

    return 0;
}

#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
/*
 * On entering the function, we've put a reference on both connections and hold
 * upstream's c_io_mutex.
 */
static int
client_bind_as_vc(
        LloadOperation *op,
        struct berval *binddn,
        ber_tag_t tag,
        struct berval *auth )
{
    LloadConnection *upstream = op->o_upstream;

    CONNECTION_LOCK(upstream);
    ber_printf( upstream->c_pendingber, "t{tit{tst{{tOOtOtO}}}}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_upstream_msgid,
            LDAP_REQ_EXTENDED,
            LDAP_TAG_EXOP_REQ_OID, LDAP_EXOP_VERIFY_CREDENTIALS,
            LDAP_TAG_EXOP_REQ_VALUE,
            LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE, BER_BV_OPTIONAL( &upstream->c_vc_cookie ),
            &binddn, tag, &auth,
            LDAP_TAG_EXOP_VERIFY_CREDENTIALS_CONTROLS, BER_BV_OPTIONAL( &op->o_ctrls ) );
    CONNECTION_UNLOCK(upstream);
    return 0;
}
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */

/*
 * The client connection can be in the following states:
 * 1) there are betwee zero and many non-bind operations pending
 *    client->c_state == LLOAD_C_READY && client->c_pin_id == 0
 * 2) there is one bind operation pending (waiting on an upstream response)
 *    a) It is a simple bind
 *    b) It is a SASL bind
 * 3) there is one SASL bind in progress (received a LDAP_SASL_BIND_IN_PROGRESS
 *    response)
 *
 * In cases 2 and 3, client->c_state == LLOAD_C_BINDING, a SASL bind is in
 * progress/pending if c_sasl_bind_mech is set.
 *
 * In the first case, client_reset abandons all operations on the respective
 * upstreams, case 2a has client_reset send an anonymous bind to upstream to
 * terminate the bind. In cases 2b and 3, c_pin_id is set and we retrieve the
 * op. The rest is the same for both.
 *
 * If c_pin_id is unset, we request an upstream connection assigned, otherwise,
 * we try to reuse the pinned upstream. In the case of no upstream, we reject
 * the request. A SASL bind request means we acquire a new pin_id if we don't
 * have one already.
 *
 * We have to reset c_auth (which holds the current or pending identity) and
 * make sure we set it up eventually:
 * - In the case of a simple bind, we already know the final identity being
 *   requested so we set it up immediately
 * - In SASL binds, for mechanisms we implement ourselves (EXTERNAL), we set it
 *   up at some point
 * - Otherwise, we have to ask the upstream what it thinks as the bind
 *   succeeds, we send an LDAP "Who Am I?" exop, this is one of the few
 *   requests we send on our own. If we implement the mechanism, we provide the
 *   identity (EXTERNAL uses the client certificate DN)
 *
 * At the end of the request processing, if nothing goes wrong, we're in state
 * 2b (with c_pin_id set to the op's o_pin_id), or state 2a (we could reset
 * c_pin_id/o_pin_id if we wanted but we don't always do that at the moment).
 * If something does go wrong, we're either tearing down the client or we
 * reject the request and switch to state 1 (clearing c_pin_id).
 *
 * As usual, we have to make any changes to the target connection before we've
 * sent the PDU over it - while we are in charge of the read side and nothing
 * happens there without our ceding control, the other read side could wake up
 * at any time and pre-empt us.
 *
 * On a response (in handle_bind_response):
 * - to a simple bind, clear c_auth on a failure otherwise keep it while we
 *   just reset the client to state 1
 * - failure response to a SASL bind - reset client to state 1
 * - LDAP_SASL_BIND_IN_PROGRESS - clear o_*_msgid from the op (have to
 *   remove+reinsert it from the respective c_ops!), we need it since it is the
 *   vessel maintaining the pin between client and upstream
 * - all of the above forward the response immediately
 * - LDAP_SUCCESS for a SASL bind - we send a "Who Am I?" request to retrieve
 *   the client's DN, only on receiving the response do we finalise the
 *   exchange by forwarding the successful bind response
 *
 * We can't do the same for VC Exop since the exchange is finished at the end
 * and we need a change to the VC Exop spec to have the server (optionally?)
 * respond with the final authzid (saving us a roundtrip as well).
 */
int
request_bind( LloadConnection *client, LloadOperation *op )
{
    LloadConnection *upstream = NULL;
    BerElement *ber, *copy;
    struct berval binddn, auth, mech = BER_BVNULL;
    ber_int_t version;
    ber_tag_t tag;
    unsigned long pin = client->c_pin_id;
    int res, rc = LDAP_SUCCESS;

    if ( pin ) {
        LloadOperation *pinned_op, needle = {
            .o_client_connid = client->c_connid,
            .o_client_msgid = 0,
            .o_pin_id = client->c_pin_id,
        };

        Debug( LDAP_DEBUG_CONNS, "request_bind: "
                "client connid=%lu is pinned pin=%lu\n",
                client->c_connid, pin );

        pinned_op =
                tavl_delete( &client->c_ops, &needle, operation_client_cmp );
        if ( pinned_op ) {
            assert( op->o_tag == pinned_op->o_tag );

            pinned_op->o_client_msgid = op->o_client_msgid;

            /* Preserve the new BerElement and its pointers, reclaim the old
             * one in operation_destroy_from_client if it's still there */
            needle.o_ber = pinned_op->o_ber;
            pinned_op->o_ber = op->o_ber;
            op->o_ber = needle.o_ber;

            pinned_op->o_request = op->o_request;
            pinned_op->o_ctrls = op->o_ctrls;

            /*
             * pinned_op is accessible from the upstream, protect it since we
             * lose the client lock in operation_destroy_from_client temporarily
             */
            pinned_op->o_client_refcnt++;
            op->o_res = LLOAD_OP_COMPLETED;

            /* We didn't start a new operation, just continuing an existing one */
            lload_stats.counters[LLOAD_STATS_OPS_BIND].lc_ops_received--;

            operation_destroy_from_client( op );
            pinned_op->o_client_refcnt--;

            op = pinned_op;
        }
    }

    /* protect the Bind operation */
    op->o_client_refcnt++;
    tavl_delete( &client->c_ops, op, operation_client_cmp );

    client_reset( client );

    client->c_state = LLOAD_C_BINDING;
    client->c_type = LLOAD_C_OPEN;

    if ( (copy = ber_alloc()) == NULL ) {
        goto fail;
    }
    ber_init2( copy, &op->o_request, 0 );

    tag = ber_get_int( copy, &version );
    if ( tag == LBER_ERROR ) {
        Debug( LDAP_DEBUG_PACKETS, "request_bind: "
                "failed to parse version field\n" );
        goto fail;
    } else if ( version != LDAP_VERSION3 ) {
        operation_send_reject_locked(
                op, LDAP_PROTOCOL_ERROR, "LDAP version unsupported", 1 );
        ber_free( copy, 0 );
        return LDAP_SUCCESS;
    }

    tag = ber_get_stringbv( copy, &binddn, LBER_BV_NOTERM );
    if ( tag == LBER_ERROR ) {
        Debug( LDAP_DEBUG_PACKETS, "request_bind: "
                "failed to parse bind name field\n" );
        goto fail;
    }

    if ( !BER_BVISNULL( &client->c_auth ) ) {
        ch_free( client->c_auth.bv_val );
        BER_BVZERO( &client->c_auth );
    }

    tag = ber_skip_element( copy, &auth );
    if ( tag == LDAP_AUTH_SIMPLE ) {
        if ( !BER_BVISEMPTY( &binddn ) ) {
            char *ptr;
            client->c_auth.bv_len = STRLENOF("dn:") + binddn.bv_len;
            client->c_auth.bv_val = ch_malloc( client->c_auth.bv_len + 1 );

            ptr = lutil_strcopy( client->c_auth.bv_val, "dn:" );
            ptr = lutil_strncopy( ptr, binddn.bv_val, binddn.bv_len );
            *ptr = '\0';
        }

        if ( !BER_BVISNULL( &client->c_sasl_bind_mech ) ) {
            ber_memfree( client->c_sasl_bind_mech.bv_val );
            BER_BVZERO( &client->c_sasl_bind_mech );
        }
    } else if ( tag == LDAP_AUTH_SASL ) {
        ber_init2( copy, &auth, 0 );

        if ( ber_get_stringbv( copy, &mech, LBER_BV_NOTERM ) == LBER_ERROR ) {
            goto fail;
        }
        if ( !ber_bvcmp( &mech, &mech_external ) ) {
            struct berval credentials = BER_BVNULL;

            ber_get_stringbv( copy, &credentials, LBER_BV_NOTERM );
            rc = bind_mech_external( client, op, &credentials );

            /* terminate the upstream side if client switched mechanisms */
            if ( pin ) {
                op->o_client_refcnt++;
                CONNECTION_UNLOCK_INCREF(client);
                operation_abandon( op );
                CONNECTION_LOCK_DECREF(client);
            }

            ber_free( copy, 0 );
            return rc;
        } else if ( BER_BVISNULL( &client->c_sasl_bind_mech ) ) {
            ber_dupbv( &client->c_sasl_bind_mech, &mech );
        } else if ( ber_bvcmp( &mech, &client->c_sasl_bind_mech ) ) {
            ber_bvreplace( &client->c_sasl_bind_mech, &mech );
        }
    } else {
        goto fail;
    }

    rc = tavl_insert( &client->c_ops, op, operation_client_cmp, avl_dup_error );
    assert( rc == LDAP_SUCCESS );
    CONNECTION_UNLOCK_INCREF(client);

    if ( pin ) {
        ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
        upstream = op->o_upstream;
        if ( upstream ) {
            CONNECTION_LOCK(upstream);
            if ( !upstream->c_live ) {
                CONNECTION_UNLOCK(upstream);
                upstream = NULL;
            }
        }
        ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );
    }

    /* If we were pinned but lost the link, don't look for a new upstream, we
     * have to reject the op and clear pin */
    if ( upstream ) {
        CONNECTION_UNLOCK_INCREF(upstream);
        ldap_pvt_thread_mutex_lock( &upstream->c_io_mutex );
    } else if ( !pin ) {
        upstream = backend_select( op, &res );
    } else {
        Debug( LDAP_DEBUG_STATS, "request_bind: "
                "connid=%lu, msgid=%d pinned upstream lost\n",
                op->o_client_connid, op->o_client_msgid );
        operation_send_reject( op, LDAP_UNAVAILABLE,
                "connection to the remote server has been severed", 1 );
        pin = 0;
        goto done;
    }

    if ( !upstream ) {
        Debug( LDAP_DEBUG_STATS, "request_bind: "
                "connid=%lu, msgid=%d no available connection found\n",
                op->o_client_connid, op->o_client_msgid );
        operation_send_reject( op, res, "no connections available", 1 );
        assert( client->c_pin_id == 0 );
        goto done;
    }
    /*
     * At this point, either:
     * - upstream is READY and pin == 0
     * - upstream is BINDING, pin != 0 and op->o_upstream_msgid == 0
     *
     * A pinned upstream we marked for closing at some point ago should have
     * closed by now.
     */

    ber = upstream->c_pendingber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "request_bind: "
                "ber_alloc failed\n" );
        CONNECTION_LOCK_DECREF(upstream);
        ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );
        upstream->c_state = LLOAD_C_READY;
        if ( !BER_BVISNULL( &upstream->c_sasl_bind_mech ) ) {
            ber_memfree( upstream->c_sasl_bind_mech.bv_val );
            BER_BVZERO( &upstream->c_sasl_bind_mech );
        }
        CONNECTION_UNLOCK_OR_DESTROY(upstream);

        CONNECTION_LOCK_DECREF(client);
        goto fail;
    }
    upstream->c_pendingber = ber;

    if ( !pin ) {
        lload_stats.counters[LLOAD_STATS_OPS_BIND].lc_ops_forwarded++;
    }

    CONNECTION_LOCK(upstream);
    if ( pin ) {
        tavl_delete( &upstream->c_ops, op, operation_upstream_cmp );
        if ( tag == LDAP_AUTH_SIMPLE ) {
            pin = op->o_pin_id = 0;
        }
    } else if ( tag == LDAP_AUTH_SASL && !op->o_pin_id ) {
        ldap_pvt_thread_mutex_lock( &lload_pin_mutex );
        pin = op->o_pin_id = lload_next_pin++;
        Debug( LDAP_DEBUG_CONNS, "request_bind: "
                "client connid=%lu allocated pin=%lu linking it to upstream "
                "connid=%lu\n",
                op->o_client_connid, pin, upstream->c_connid );
        ldap_pvt_thread_mutex_unlock( &lload_pin_mutex );
    }

    op->o_upstream = upstream;
    op->o_upstream_connid = upstream->c_connid;
    op->o_upstream_msgid = upstream->c_next_msgid++;
    op->o_res = LLOAD_OP_FAILED;

    if ( BER_BVISNULL( &mech ) ) {
        if ( !BER_BVISNULL( &upstream->c_sasl_bind_mech ) ) {
            ber_memfree( upstream->c_sasl_bind_mech.bv_val );
            BER_BVZERO( &upstream->c_sasl_bind_mech );
        }
    } else if ( ber_bvcmp( &upstream->c_sasl_bind_mech, &mech ) ) {
        ber_bvreplace( &upstream->c_sasl_bind_mech, &mech );
    }

    Debug( LDAP_DEBUG_TRACE, "request_bind: "
            "added bind from client connid=%lu to upstream connid=%lu "
            "as msgid=%d\n",
            op->o_client_connid, op->o_upstream_connid, op->o_upstream_msgid );
    if ( tavl_insert( &upstream->c_ops, op, operation_upstream_cmp,
                 avl_dup_error ) ) {
        assert(0);
    }
    upstream->c_state = LLOAD_C_BINDING;
    CONNECTION_UNLOCK(upstream);

#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
    if ( lload_features & LLOAD_FEATURE_VC ) {
        rc = client_bind_as_vc( op, &binddn, tag, &auth );
    } else
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
    {
        rc = client_bind( op, &binddn, tag, &auth );
    }

done:
    if ( rc == LDAP_SUCCESS ) {
        CONNECTION_LOCK(client);
        if ( upstream ) {
            ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );
        }

        client->c_pin_id = pin;
        if ( !--op->o_client_refcnt || !upstream ) {
            operation_destroy_from_client( op );
            if ( client->c_state == LLOAD_C_BINDING ) {
                client->c_state = LLOAD_C_READY;
                client->c_type = LLOAD_C_OPEN;
                client->c_pin_id = 0;
                if ( !BER_BVISNULL( &client->c_auth ) ) {
                    ch_free( client->c_auth.bv_val );
                    BER_BVZERO( &client->c_auth );
                }
                if ( !BER_BVISNULL( &client->c_sasl_bind_mech ) ) {
                    ber_memfree( client->c_sasl_bind_mech.bv_val );
                    BER_BVZERO( &client->c_sasl_bind_mech );
                }
            }
        }
        CONNECTION_UNLOCK(client);

        if ( upstream ) {
            connection_write_cb( -1, 0, upstream );
            CONNECTION_LOCK_DECREF(upstream);
            CONNECTION_UNLOCK_OR_DESTROY(upstream);
        }
        CONNECTION_LOCK_DECREF(client);
    } else {
fail:
        rc = -1;

        CONNECTION_LOCK_DECREF(client);
        op->o_client_refcnt--;
        operation_destroy_from_client( op );
        client->c_pin_id = 0;
        CONNECTION_DESTROY(client);
    }

    ber_free( copy, 0 );
    return rc;
}

/*
 * Remember the response, but first ask the server what
 * authorization identity has been negotiated.
 *
 * Also, this request will fail if the server thinks a SASL
 * confidentiality/integrity layer has been negotiated so we catch
 * it early and no other clients are affected.
 */
int
finish_sasl_bind(
        LloadConnection *upstream,
        LloadOperation *op,
        BerElement *ber )
{
    LloadConnection *client = op->o_client;
    BerElement *output;
    LloadOperation *removed;
    ber_int_t msgid;
    int rc;

    if ( !(lload_features & LLOAD_FEATURE_PROXYAUTHZ) ) {
        Debug( LDAP_DEBUG_TRACE, "finish_sasl_bind: "
                "connid=%lu not configured to do proxyauthz, making no "
                "attempt to resolve final authzid name\n",
                op->o_client_connid );
        CONNECTION_UNLOCK(upstream);
        return forward_final_response( client, op, ber );
    }

    removed = tavl_delete( &upstream->c_ops, op, operation_upstream_cmp );
    if ( !removed ) {
        assert( upstream->c_state != LLOAD_C_BINDING );
        /* FIXME: has client replaced this bind since? */
        assert(0);

        operation_destroy_from_upstream( op );
    }
    assert( removed == op && upstream->c_state == LLOAD_C_BINDING );

    CONNECTION_UNLOCK(upstream);

    Debug( LDAP_DEBUG_TRACE, "finish_sasl_bind: "
            "SASL exchange in lieu of client connid=%lu to upstream "
            "connid=%lu finished, resolving final authzid name\n",
            op->o_client_connid, op->o_upstream_connid );

    ldap_pvt_thread_mutex_lock( &upstream->c_io_mutex );
    output = upstream->c_pendingber;
    if ( output == NULL && (output = ber_alloc()) == NULL ) {
        ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );
        return -1;
    }
    upstream->c_pendingber = output;

    msgid = upstream->c_next_msgid++;
    ber_printf( output, "t{tit{ts}}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, msgid,
            LDAP_REQ_EXTENDED,
            LDAP_TAG_EXOP_REQ_OID, LDAP_EXOP_WHO_AM_I );

    /* Make sure noone flushes the buffer before we re-insert the operation */
    CONNECTION_LOCK(upstream);
    ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );

    op->o_upstream_msgid = msgid;

    /* remember the response for later */
    ber_free( op->o_ber, 1 );
    op->o_ber = ber;

    rc = tavl_insert(
            &upstream->c_ops, op, operation_upstream_cmp, avl_dup_error );
    assert( rc == LDAP_SUCCESS );

    CONNECTION_UNLOCK(upstream);

    connection_write_cb( -1, 0, upstream );
    return LDAP_SUCCESS;
}

int
handle_bind_response(
        LloadConnection *client,
        LloadOperation *op,
        BerElement *ber )
{
    LloadConnection *upstream = op->o_upstream;
    BerValue response;
    BerElement *copy;
    LloadOperation *removed;
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
    if ( !tavl_find( upstream->c_ops, op, operation_upstream_cmp ) ) {
        /*
         * operation might not be found because:
         * - it has timed out (only happens when debugging/hung/...)
         *   a response has been sent for us, we must not send another
         * - it has been abandoned (new bind, unbind)
         *   no response is expected
         * - ???
         */
        operation_destroy_from_upstream( op );
        CONNECTION_UNLOCK(upstream);
        return LDAP_SUCCESS;
    }

    /*
     * We might be marked for closing, forward the response if we can, but do
     * no more if it's a SASL bind - just finish the operation and send failure
     * in that case (since we can't resolve the bind identity correctly).
     */
    if ( upstream->c_state == LLOAD_C_CLOSING ) {
        /* FIXME: this is too ad-hoc */
        if ( ( result == LDAP_SUCCESS ||
                     result == LDAP_SASL_BIND_IN_PROGRESS ) &&
                !BER_BVISNULL( &upstream->c_sasl_bind_mech ) ) {
            CONNECTION_UNLOCK(upstream);
            operation_send_reject(
                    op, LDAP_UNAVAILABLE, "upstream connection is closing", 0 );

            ber_free( ber, 1 );
            return LDAP_SUCCESS;
        }

        assert( op->o_client_msgid && op->o_upstream_msgid );
        op->o_pin_id = 0;

    } else if ( result == LDAP_SASL_BIND_IN_PROGRESS ) {
        tavl_delete( &upstream->c_ops, op, operation_upstream_cmp );
        op->o_upstream_msgid = 0;
        op->o_upstream_refcnt++;
        rc = tavl_insert(
                &upstream->c_ops, op, operation_upstream_cmp, avl_dup_error );
        assert( rc == LDAP_SUCCESS );
    } else {
        int sasl_finished = 0;
        if ( !BER_BVISNULL( &upstream->c_sasl_bind_mech ) ) {
            sasl_finished = 1;
            ber_memfree( upstream->c_sasl_bind_mech.bv_val );
            BER_BVZERO( &upstream->c_sasl_bind_mech );
        }

        assert( op->o_client_msgid && op->o_upstream_msgid );
        op->o_pin_id = 0;

        if ( sasl_finished && result == LDAP_SUCCESS ) {
            return finish_sasl_bind( upstream, op, ber );
        }
        upstream->c_state = LLOAD_C_READY;
    }
    CONNECTION_UNLOCK(upstream);

    CONNECTION_LOCK(client);
    removed = tavl_delete( &client->c_ops, op, operation_client_cmp );
    assert( !removed || op == removed );

    if ( client->c_state == LLOAD_C_BINDING ) {
        switch ( result ) {
            case LDAP_SASL_BIND_IN_PROGRESS:
                op->o_saved_msgid = op->o_client_msgid;
                op->o_client_msgid = 0;
                rc = tavl_insert( &client->c_ops, op, operation_client_cmp,
                        avl_dup_error );
                assert( rc == LDAP_SUCCESS );
                break;
            case LDAP_SUCCESS:
            default: {
                op->o_client = NULL;
                client->c_state = LLOAD_C_READY;
                client->c_type = LLOAD_C_OPEN;
                client->c_pin_id = 0;
                if ( !BER_BVISNULL( &client->c_auth ) ) {
                    if ( result != LDAP_SUCCESS ) {
                        ber_memfree( client->c_auth.bv_val );
                        BER_BVZERO( &client->c_auth );
                    } else if ( !ber_bvstrcasecmp(
                                        &client->c_auth, &lloadd_identity ) ) {
                        client->c_type = LLOAD_C_PRIVILEGED;
                    }
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
        operation_send_reject( op, LDAP_OTHER, "internal error", 1 );

        ber_free( ber, 1 );
        return LDAP_SUCCESS;
    }
    return forward_final_response( client, op, ber );
}

int
handle_whoami_response(
        LloadConnection *client,
        LloadOperation *op,
        BerElement *ber )
{
    LloadConnection *upstream = op->o_upstream;
    BerValue matched, diagmsg;
    BerElement *saved_response = op->o_ber;
    LloadOperation *removed;
    ber_int_t result;
    ber_tag_t tag;
    ber_len_t len;

    Debug( LDAP_DEBUG_TRACE, "handle_whoami_response: "
            "connid=%ld received whoami response in lieu of connid=%ld\n",
            upstream->c_connid, client->c_connid );

    tag = ber_scanf( ber, "{emm" /* "}" */,
            &result, &matched, &diagmsg );
    if ( tag == LBER_ERROR ) {
        operation_send_reject( op, LDAP_OTHER, "upstream protocol error", 0 );
        return -1;
    }

    CONNECTION_LOCK_DECREF(upstream);
    if ( result == LDAP_PROTOCOL_ERROR ) {
        LloadBackend *b;

        b = (LloadBackend *)upstream->c_private;
        Debug( LDAP_DEBUG_ANY, "handle_whoami_response: "
                "Who Am I? extended operation not supported on backend %s, "
                "proxyauthz with clients that do SASL binds will not work "
                "msg=%s!\n",
                b->b_uri.bv_val, diagmsg.bv_val );
        CONNECTION_UNLOCK_INCREF(upstream);
        operation_send_reject( op, LDAP_OTHER, "upstream protocol error", 0 );
        return -1;
    }

    if ( upstream->c_state != LLOAD_C_CLOSING ) {
        assert( upstream->c_state == LLOAD_C_BINDING );
        upstream->c_state = LLOAD_C_READY;
    }
    if ( !BER_BVISNULL( &upstream->c_sasl_bind_mech ) ) {
        ber_memfree( upstream->c_sasl_bind_mech.bv_val );
        BER_BVZERO( &upstream->c_sasl_bind_mech );
    }

    CONNECTION_UNLOCK_INCREF(upstream);

    tag = ber_peek_tag( ber, &len );

    CONNECTION_LOCK_DECREF(client);

    assert( client->c_state == LLOAD_C_BINDING &&
            BER_BVISNULL( &client->c_auth ) );
    if ( !BER_BVISNULL( &client->c_auth ) ) {
        ber_memfree( client->c_auth.bv_val );
        BER_BVZERO( &client->c_auth );
    }

    if ( tag == LDAP_TAG_EXOP_RES_VALUE ) {
        tag = ber_scanf( ber, "o", &client->c_auth );
        if ( tag == LBER_ERROR ) {
            operation_send_reject_locked(
                    op, LDAP_OTHER, "upstream protocol error", 0 );
            CONNECTION_DESTROY(client);
            return -1;
        }
    }

    removed = tavl_delete( &client->c_ops, op, operation_client_cmp );
    assert( !removed || op == removed );

    Debug( LDAP_DEBUG_TRACE, "handle_whoami_response: "
            "connid=%ld new authid=%s\n",
            client->c_connid, client->c_auth.bv_val );

    if ( client->c_state == LLOAD_C_BINDING ) {
        op->o_client = NULL;
        client->c_state = LLOAD_C_READY;
        client->c_type = LLOAD_C_OPEN;
        client->c_pin_id = 0;
        if ( !BER_BVISNULL( &client->c_auth ) &&
                !ber_bvstrcasecmp( &client->c_auth, &lloadd_identity ) ) {
            client->c_type = LLOAD_C_PRIVILEGED;
        }
        if ( !BER_BVISNULL( &client->c_sasl_bind_mech ) ) {
            ber_memfree( client->c_sasl_bind_mech.bv_val );
            BER_BVZERO( &client->c_sasl_bind_mech );
        }
    }

    CONNECTION_UNLOCK_INCREF(client);

    /* defer the disposal of ber to operation_destroy_* */
    op->o_ber = ber;
    return forward_final_response( client, op, saved_response );
}

#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
int
handle_vc_bind_response(
        LloadConnection *client,
        LloadOperation *op,
        BerElement *ber )
{
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
        LloadConnection *upstream = op->o_upstream;
        LloadBackend *b;

        CONNECTION_LOCK(upstream);
        b = (LloadBackend *)upstream->c_private;
        Debug( LDAP_DEBUG_ANY, "handle_vc_bind_response: "
                "VC extended operation not supported on backend %s\n",
                b->b_uri.bv_val );
        CONNECTION_UNLOCK(upstream);
    }

    Debug( LDAP_DEBUG_STATS, "handle_vc_bind_response: "
            "received response for bind request msgid=%d by client "
            "connid=%lu, result=%d\n",
            op->o_client_msgid, op->o_client_connid, result );

    CONNECTION_LOCK(client);

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE ) {
        if ( !BER_BVISNULL( &client->c_vc_cookie ) ) {
            ber_memfree( client->c_vc_cookie.bv_val );
        }
        tag = ber_scanf( ber, "o", &client->c_vc_cookie );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            CONNECTION_UNLOCK_INCREF(client);
            goto done;
        }
        tag = ber_peek_tag( ber, &len );
    }

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_SCREDS ) {
        tag = ber_scanf( ber, "m", &creds );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            CONNECTION_UNLOCK_INCREF(client);
            goto done;
        }
        tag = ber_peek_tag( ber, &len );
    }

    if ( tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_CONTROLS ) {
        tag = ber_scanf( ber, "m", &controls );
        if ( tag == LBER_ERROR ) {
            rc = -1;
            CONNECTION_UNLOCK_INCREF(client);
            goto done;
        }
    }

    if ( client->c_state == LLOAD_C_BINDING ) {
        switch ( result ) {
            case LDAP_SASL_BIND_IN_PROGRESS:
                break;
            case LDAP_SUCCESS:
            default: {
                client->c_state = LLOAD_C_READY;
                client->c_type = LLOAD_C_OPEN;
                client->c_pin_id = 0;
                if ( result != LDAP_SUCCESS ) {
                    ber_memfree( client->c_auth.bv_val );
                    BER_BVZERO( &client->c_auth );
                } else if ( !ber_bvstrcasecmp(
                                    &client->c_auth, &lloadd_identity ) ) {
                    client->c_type = LLOAD_C_PRIVILEGED;
                }
                if ( !BER_BVISNULL( &client->c_vc_cookie ) ) {
                    ber_memfree( client->c_vc_cookie.bv_val );
                    BER_BVZERO( &client->c_vc_cookie );
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
    CONNECTION_UNLOCK_INCREF(client);

    ldap_pvt_thread_mutex_lock( &client->c_io_mutex );
    output = client->c_pendingber;
    if ( output == NULL && (output = ber_alloc()) == NULL ) {
        rc = -1;
        ldap_pvt_thread_mutex_unlock( &client->c_io_mutex );
        goto done;
    }
    client->c_pendingber = output;

    rc = ber_printf( output, "t{tit{eOOtO}tO}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_client_msgid, LDAP_RES_BIND,
            result, &matched, &diagmsg,
            LDAP_TAG_SASL_RES_CREDS, BER_BV_OPTIONAL( &creds ),
            LDAP_TAG_CONTROLS, BER_BV_OPTIONAL( &controls ) );

    ldap_pvt_thread_mutex_unlock( &client->c_io_mutex );
    if ( rc >= 0 ) {
        connection_write_cb( -1, 0, client );
        rc = 0;
    }

done:
    CONNECTION_LOCK_DECREF(client);
    operation_destroy_from_client( op );
    CONNECTION_UNLOCK_OR_DESTROY(client);
    ber_free( ber, 1 );
    return rc;
}
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
