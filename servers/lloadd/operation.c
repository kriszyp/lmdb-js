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

#include "lutil.h"
#include "slap.h"

ber_tag_t
slap_req2res( ber_tag_t tag )
{
    switch ( tag ) {
        case LDAP_REQ_ADD:
        case LDAP_REQ_BIND:
        case LDAP_REQ_COMPARE:
        case LDAP_REQ_EXTENDED:
        case LDAP_REQ_MODIFY:
        case LDAP_REQ_MODRDN:
            tag++;
            break;

        case LDAP_REQ_DELETE:
            tag = LDAP_RES_DELETE;
            break;

        case LDAP_REQ_ABANDON:
        case LDAP_REQ_UNBIND:
            tag = LBER_SEQUENCE;
            break;

        case LDAP_REQ_SEARCH:
            tag = LDAP_RES_SEARCH_RESULT;
            break;

        default:
            tag = LBER_SEQUENCE;
    }

    return tag;
}

const char *
slap_msgtype2str( ber_tag_t tag )
{
    switch ( tag ) {
        case LDAP_REQ_ABANDON: return "abandon request";
        case LDAP_REQ_ADD: return "add request";
        case LDAP_REQ_BIND: return "bind request";
        case LDAP_REQ_COMPARE: return "compare request";
        case LDAP_REQ_DELETE: return "delete request";
        case LDAP_REQ_EXTENDED: return "extended request";
        case LDAP_REQ_MODIFY: return "modify request";
        case LDAP_REQ_RENAME: return "rename request";
        case LDAP_REQ_SEARCH: return "search request";
        case LDAP_REQ_UNBIND: return "unbind request";

        case LDAP_RES_ADD: return "add result";
        case LDAP_RES_BIND: return "bind result";
        case LDAP_RES_COMPARE: return "compare result";
        case LDAP_RES_DELETE: return "delete result";
        case LDAP_RES_EXTENDED: return "extended result";
        case LDAP_RES_INTERMEDIATE: return "intermediate response";
        case LDAP_RES_MODIFY: return "modify result";
        case LDAP_RES_RENAME: return "rename result";
        case LDAP_RES_SEARCH_ENTRY: return "search-entry response";
        case LDAP_RES_SEARCH_REFERENCE: return "search-reference response";
        case LDAP_RES_SEARCH_RESULT: return "search result";
    }
    return "unknown message";
}

int
operation_client_cmp( const void *left, const void *right )
{
    const Operation *l = left, *r = right;

    assert( l->o_client_connid == r->o_client_connid );
    return ( l->o_client_msgid < r->o_client_msgid ) ?
            -1 :
            ( l->o_client_msgid > r->o_client_msgid );
}

int
operation_upstream_cmp( const void *left, const void *right )
{
    const Operation *l = left, *r = right;

    assert( l->o_upstream_connid == r->o_upstream_connid );
    return ( l->o_upstream_msgid < r->o_upstream_msgid ) ?
            -1 :
            ( l->o_upstream_msgid > r->o_upstream_msgid );
}

/*
 * Free the operation, subject to there being noone else holding a reference
 * to it.
 *
 * Both operation_destroy_from_* functions are the same, two implementations
 * exist to cater for the fact that either side (client or upstream) might
 * decide to destroy it and each holds a different mutex.
 *
 * Due to the fact that we rely on mutexes on both connections which have a
 * different timespan from the operation, we have to take the following race
 * into account:
 *
 * Trigger
 * - both operation_destroy_from_client and operation_destroy_from_upstream
 *   are called at the same time (each holding its mutex), several times
 *   before one of them finishes
 * - either or both connections might have started the process of being
 *   destroyed
 *
 * We need to detect that the race has happened and only allow one of them to
 * free the operation (we use o_freeing != 0 to announce+detect that).
 *
 * In case the caller was in the process of destroying the connection and the
 * race had been won by the mirror caller, it will increment c_refcnt on its
 * connection and make sure to postpone the final step in
 * client/upstream_destroy(). Testing o_freeing for the mirror side's token
 * allows the winner to detect that it has been a party to the race and a token
 * in c_refcnt has been deposited on its behalf.
 *
 * Beware! This widget really touches all the mutexes we have and showcases the
 * issues with maintaining so many mutex ordering restrictions.
 */
void
operation_destroy_from_client( Operation *op )
{
    Connection *upstream, *client = op->o_client;
    Backend *b = NULL;
    int race_state, detach_client = !client->c_live;

    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
            "op=%p attempting to release operation\n",
            op );

    /* 1. liveness/refcnt adjustment and test */
    op->o_client_refcnt -= op->o_client_live;
    op->o_client_live = 0;

    assert( op->o_client_refcnt <= client->c_refcnt );
    if ( op->o_client_refcnt ) {
        Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                "op=%p not dead yet\n",
                op );
        return;
    }

    /* 2. Remove from the operation map and TODO adjust the pending op count */
    tavl_delete( &client->c_ops, op, operation_client_cmp );

    /* 3. Detect whether we entered a race to free op and indicate that to any
     * others */
    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    race_state = op->o_freeing;
    op->o_freeing |= SLAP_OP_FREEING_CLIENT;
    ldap_pvt_thread_mutex_unlock( &op->o_mutex );

    CONNECTION_UNLOCK_INCREF(client);

    if ( detach_client ) {
        ldap_pvt_thread_mutex_lock( &operation_mutex );
        op->o_client = NULL;
        ldap_pvt_thread_mutex_unlock( &operation_mutex );
    }

    /* 4. If we lost the race, deal with it */
    if ( race_state ) {
        /*
         * We have raced to destroy op and the first one to lose on this side,
         * leave a refcnt token on client so we don't destroy it before the
         * other side has finished (it knows we did that when it examines
         * o_freeing again).
         */
        if ( !detach_client && race_state == SLAP_OP_FREEING_UPSTREAM ) {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                    "op=%p lost race, increased client refcnt connid=%lu "
                    "to refcnt=%d\n",
                    op, client->c_connid, client->c_refcnt );
            CONNECTION_LOCK(client);
        } else {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                    "op=%p lost race with another "
                    "operation_destroy_from_client\n",
                    op );
            CONNECTION_LOCK_DECREF(client);
        }
        return;
    }

    /* 5. If we raced the upstream side and won, reclaim the token */
    ldap_pvt_thread_mutex_lock( &operation_mutex );
    upstream = op->o_upstream;
    if ( upstream ) {
        CONNECTION_LOCK(upstream);
    }
    ldap_pvt_thread_mutex_unlock( &operation_mutex );

    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    if ( upstream && ( op->o_freeing & SLAP_OP_FREEING_UPSTREAM ) ) {
        /*
         * We have raced to destroy op and won. To avoid freeing the connection
         * under us, a refcnt token has been left over for us on the upstream,
         * decref and see whether we are in charge of freeing it
         */
        upstream->c_refcnt--;
        Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                "op=%p other side lost race with us, upstream connid=%lu\n",
                op, upstream->c_connid );
    }
    ldap_pvt_thread_mutex_unlock( &op->o_mutex );

    /* 6. liveness/refcnt adjustment and test */
    op->o_upstream_refcnt -= op->o_upstream_live;
    op->o_upstream_live = 0;
    if ( op->o_upstream_refcnt ) {
        Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                "op=%p other side still alive, refcnt=%d\n",
                op, op->o_upstream_refcnt );

        /* There must have been no race if op is still alive */
        ldap_pvt_thread_mutex_lock( &op->o_mutex );
        op->o_freeing &= ~SLAP_OP_FREEING_CLIENT;
        assert( op->o_freeing == 0 );
        ldap_pvt_thread_mutex_unlock( &op->o_mutex );

        assert( upstream != NULL );
        UPSTREAM_UNLOCK_OR_DESTROY(upstream);
        CONNECTION_LOCK_DECREF(client);
        return;
    }

    /* 7. Remove from the operation map and adjust the pending op count */
    if ( upstream ) {
        if ( tavl_delete( &upstream->c_ops, op, operation_upstream_cmp ) ) {
            upstream->c_n_ops_executing--;
            b = (Backend *)upstream->c_private;
        }
        UPSTREAM_UNLOCK_OR_DESTROY(upstream);

        if ( b ) {
            ldap_pvt_thread_mutex_lock( &b->b_mutex );
            b->b_n_ops_executing--;
            ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        }
    }

    /* 8. Release the operation */
    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
            "op=%p destroyed operation from client connid=%lu, "
            "client msgid=%d\n",
            op, op->o_client_connid, op->o_client_msgid );
    ber_free( op->o_ber, 1 );
    ldap_pvt_thread_mutex_destroy( &op->o_mutex );
    ch_free( op );

    CONNECTION_LOCK_DECREF(client);
}

/*
 * See operation_destroy_from_client.
 */
void
operation_destroy_from_upstream( Operation *op )
{
    Connection *client, *upstream = op->o_upstream;
    Backend *b = NULL;
    int race_state, detach_upstream = !upstream->c_live;

    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
            "op=%p attempting to release operation\n",
            op );

    /* 1. liveness/refcnt adjustment and test */
    op->o_upstream_refcnt -= op->o_upstream_live;
    op->o_upstream_live = 0;

    assert( op->o_upstream_refcnt <= upstream->c_refcnt );
    if ( op->o_upstream_refcnt ) {
        Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                "op=%p not dead yet\n",
                op );
        return;
    }

    /* 2. Remove from the operation map and adjust the pending op count */
    if ( tavl_delete( &upstream->c_ops, op, operation_upstream_cmp ) ) {
        upstream->c_n_ops_executing--;
        b = (Backend *)upstream->c_private;
    }

    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    race_state = op->o_freeing;
    op->o_freeing |= SLAP_OP_FREEING_UPSTREAM;
    ldap_pvt_thread_mutex_unlock( &op->o_mutex );

    CONNECTION_UNLOCK_INCREF(upstream);

    /* 3. Detect whether we entered a race to free op */
    ldap_pvt_thread_mutex_lock( &operation_mutex );
    if ( detach_upstream ) {
        op->o_upstream = NULL;
    }
    ldap_pvt_thread_mutex_unlock( &operation_mutex );

    if ( b ) {
        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        b->b_n_ops_executing--;
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    }

    /* 4. If we lost the race, deal with it */
    if ( race_state ) {
        /*
         * We have raced to destroy op and the first one to lose on this side,
         * leave a refcnt token on upstream so we don't destroy it before the
         * other side has finished (it knows we did that when it examines
         * o_freeing again).
         */
        if ( !detach_upstream && race_state == SLAP_OP_FREEING_CLIENT ) {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                    "op=%p lost race, increased upstream refcnt connid=%lu "
                    "to refcnt=%d\n",
                    op, upstream->c_connid, upstream->c_refcnt );
            CONNECTION_LOCK(upstream);
        } else {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                    "op=%p lost race with another "
                    "operation_destroy_from_upstream\n",
                    op );
            CONNECTION_LOCK_DECREF(upstream);
        }
        return;
    }

    /* 5. If we raced the client side and won, reclaim the token */
    ldap_pvt_thread_mutex_lock( &operation_mutex );
    client = op->o_client;
    if ( client ) {
        CONNECTION_LOCK(client);
    }
    ldap_pvt_thread_mutex_unlock( &operation_mutex );

    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    if ( client && ( op->o_freeing & SLAP_OP_FREEING_CLIENT ) ) {
        /*
         * We have raced to destroy op and won. To avoid freeing the connection
         * under us, a refcnt token has been left over for us on the client,
         * decref and see whether we are in charge of freeing it
         */
        client->c_refcnt--;
        Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                "op=%p other side lost race with us, client connid=%lu\n",
                op, client->c_connid );
    }
    ldap_pvt_thread_mutex_unlock( &op->o_mutex );

    /* 6. liveness/refcnt adjustment and test */
    op->o_client_refcnt -= op->o_client_live;
    op->o_client_live = 0;
    if ( op->o_client_refcnt ) {
        Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                "op=%p other side still alive, refcnt=%d\n",
                op, op->o_client_refcnt );
        /* There must have been no race if op is still alive */
        ldap_pvt_thread_mutex_lock( &op->o_mutex );
        op->o_freeing &= ~SLAP_OP_FREEING_UPSTREAM;
        assert( op->o_freeing == 0 );
        ldap_pvt_thread_mutex_unlock( &op->o_mutex );

        assert( client != NULL );
        CLIENT_UNLOCK_OR_DESTROY(client);
        CONNECTION_LOCK_DECREF(upstream);
        return;
    }

    /* 7. Remove from the operation map and TODO adjust the pending op count */
    if ( client ) {
        tavl_delete( &client->c_ops, op, operation_client_cmp );
        CLIENT_UNLOCK_OR_DESTROY(client);
    }

    /* 8. Release the operation */
    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
            "op=%p destroyed operation from client connid=%lu, "
            "client msgid=%d\n",
            op, op->o_client_connid, op->o_client_msgid );
    ber_free( op->o_ber, 1 );
    ldap_pvt_thread_mutex_destroy( &op->o_mutex );
    ch_free( op );

    CONNECTION_LOCK_DECREF(upstream);
}

/*
 * Entered holding c_mutex for now.
 */
Operation *
operation_init( Connection *c, BerElement *ber )
{
    Operation *op;
    ber_tag_t tag;
    ber_len_t len;
    int rc;

    op = ch_calloc( 1, sizeof(Operation) );
    op->o_client = c;
    op->o_client_connid = c->c_connid;
    op->o_ber = ber;

    ldap_pvt_thread_mutex_init( &op->o_mutex );

    op->o_client_live = op->o_client_refcnt = 1;
    op->o_upstream_live = op->o_upstream_refcnt = 1;

    tag = ber_get_int( ber, &op->o_client_msgid );
    if ( tag != LDAP_TAG_MSGID ) {
        goto fail;
    }

    rc = tavl_insert( &c->c_ops, op, operation_client_cmp, avl_dup_error );
    if ( rc ) {
        Debug( LDAP_DEBUG_PACKETS, "operation_init: "
                "several operations with same msgid=%d in-flight "
                "from client connid=%lu\n",
                op->o_client_msgid, op->o_client_connid );
        goto fail;
    }

    tag = op->o_tag = ber_skip_element( ber, &op->o_request );
    switch ( tag ) {
        case LBER_ERROR:
            rc = -1;
            break;
    }
    if ( rc ) {
        tavl_delete( &c->c_ops, op, operation_client_cmp );
        goto fail;
    }

    tag = ber_peek_tag( ber, &len );
    if ( tag == LDAP_TAG_CONTROLS ) {
        ber_skip_element( ber, &op->o_ctrls );
    }

    Debug( LDAP_DEBUG_TRACE, "operation_init: "
            "set up a new operation, %s with msgid=%d for client connid=%lu\n",
            slap_msgtype2str( op->o_tag ), op->o_client_msgid,
            op->o_client_connid );

    c->c_n_ops_executing++;
    return op;

fail:
    ch_free( op );
    return NULL;
}

void
operation_abandon( Operation *op )
{
    Connection *c;
    BerElement *ber;
    Backend *b;
    int rc;

    ldap_pvt_thread_mutex_lock( &operation_mutex );
    c = op->o_upstream;
    if ( !c ) {
        c = op->o_client;
        assert( c );

        /* Caller should hold a reference on client */
        CONNECTION_LOCK(c);
        ldap_pvt_thread_mutex_unlock( &operation_mutex );
        operation_destroy_from_client( op );
        CLIENT_UNLOCK_OR_DESTROY(c);
        return;
    }

    CONNECTION_LOCK(c);
    ldap_pvt_thread_mutex_unlock( &operation_mutex );
    if ( tavl_delete( &c->c_ops, op, operation_upstream_cmp ) == NULL ) {
        /* The operation has already been abandoned or finished */
        goto done;
    }
    c->c_n_ops_executing--;
    b = (Backend *)c->c_private;
    CONNECTION_UNLOCK_INCREF(c);

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    b->b_n_ops_executing--;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );

    ber = c->c_pendingber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "operation_abandon: "
                "ber_alloc failed\n" );
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        CONNECTION_LOCK_DECREF(c);
        goto done;
    }
    c->c_pendingber = ber;

    rc = ber_printf( ber, "t{titi}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, c->c_next_msgid++,
            LDAP_REQ_ABANDON, op->o_upstream_msgid );

    if ( rc == -1 ) {
        ber_free( ber, 1 );
        c->c_pendingber = NULL;
    }

    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    if ( rc != -1 ) {
        upstream_write_cb( -1, 0, c );
    }

    CONNECTION_LOCK_DECREF(c);
done:
    operation_destroy_from_upstream( op );
    UPSTREAM_UNLOCK_OR_DESTROY(c);
}

int
request_abandon( Connection *c, Operation *op )
{
    Operation *request, needle = { .o_client_connid = c->c_connid };
    int rc = LDAP_SUCCESS;

    /* parse two's complement integer */
    if ( !BER_BVISEMPTY( &op->o_request ) ) {
        unsigned char *buf = (unsigned char *)op->o_request.bv_val;
        ber_len_t i;
        ber_int_t netnum = buf[0] & 0xff;

        /* sign extend */
        netnum = ( netnum ^ 0x80 ) - 0x80;

        /* shift in the bytes */
        for ( i = 1; i < op->o_request.bv_len; i++ ) {
            netnum = ( netnum << 8 ) | buf[i];
        }

        needle.o_client_msgid = netnum;
    }

    request = tavl_find( c->c_ops, &needle, operation_client_cmp );
    if ( !request ) {
        Debug( LDAP_DEBUG_TRACE, "request_abandon: "
                "connid=%lu msgid=%d requests abandon of an operation "
                "msgid=%d not being processed anymore\n",
                c->c_connid, op->o_client_msgid, needle.o_client_msgid );
        goto done;
    }
    Debug( LDAP_DEBUG_TRACE, "request_abandon: "
            "connid=%lu msgid=%d abandoning %s msgid=%d\n",
            c->c_connid, op->o_client_msgid, slap_msgtype2str( request->o_tag ),
            needle.o_client_msgid );

    CONNECTION_UNLOCK_INCREF(c);
    operation_abandon( request );
    CONNECTION_LOCK_DECREF(c);

done:
    operation_destroy_from_client( op );
    return rc;
}

void
operation_send_reject(
        Operation *op,
        int result,
        const char *msg,
        int send_anyway )
{
    Connection *c;
    BerElement *ber;
    int found;

    Debug( LDAP_DEBUG_TRACE, "operation_send_reject: "
            "rejecting %s from client connid=%lu with message: \"%s\"\n",
            slap_msgtype2str( op->o_tag ), op->o_client_connid, msg );

    ldap_pvt_thread_mutex_lock( &operation_mutex );
    c = op->o_client;
    if ( !c ) {
        c = op->o_upstream;
        /* One of the connections has initiated this and keeps a reference, if
         * client is dead, it must have been the upstream */
        assert( c );
        CONNECTION_LOCK(c);
        Debug( LDAP_DEBUG_TRACE, "operation_send_reject: "
                "not sending msgid=%d, client connid=%lu is dead\n",
                op->o_client_msgid, op->o_client_connid );
        ldap_pvt_thread_mutex_unlock( &operation_mutex );
        operation_destroy_from_upstream( op );
        UPSTREAM_UNLOCK_OR_DESTROY(c);
        return;
    }
    CONNECTION_LOCK(c);
    ldap_pvt_thread_mutex_unlock( &operation_mutex );

    found = ( tavl_delete( &c->c_ops, op, operation_client_cmp ) == op );
    if ( !found && !send_anyway ) {
        Debug( LDAP_DEBUG_TRACE, "operation_send_reject: "
                "msgid=%d not scheduled for client connid=%lu anymore, "
                "not sending\n",
                op->o_client_msgid, c->c_connid );
        goto done;
    }

    CONNECTION_UNLOCK_INCREF(c);
    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );

    ber = c->c_pendingber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        CONNECTION_LOCK_DECREF(c);
        operation_destroy_from_client( op );
        CLIENT_DESTROY(c);
        return;
    }
    c->c_pendingber = ber;

    ber_printf( ber, "t{tit{ess}}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_client_msgid,
            slap_req2res( op->o_tag ), result, "", msg );

    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    client_write_cb( -1, 0, c );

    CONNECTION_LOCK_DECREF(c);
done:
    operation_destroy_from_client( op );
    CLIENT_UNLOCK_OR_DESTROY(c);
}

void
operation_lost_upstream( Operation *op )
{
    operation_send_reject( op, LDAP_UNAVAILABLE,
            "connection to the remote server has been severed", 0 );
}

int
request_process( Connection *client, Operation *op )
{
    BerElement *output;
    Connection *upstream;
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
            op->o_client_connid, slap_msgtype2str( op->o_tag ),
            op->o_client_msgid, op->o_upstream_connid, op->o_upstream_msgid );
    assert( rc == LDAP_SUCCESS );

    if ( (lload_features & LLOAD_FEATURE_PROXYAUTHZ) &&
            client->c_type != SLAP_C_PRIVILEGED ) {
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

    upstream_write_cb( -1, 0, upstream );

    CONNECTION_LOCK_DECREF(upstream);
    UPSTREAM_UNLOCK_OR_DESTROY(upstream);

    CONNECTION_LOCK_DECREF(client);
    if ( !--op->o_client_refcnt ) {
        operation_destroy_from_client( op );
    }
    return rc;

fail:
    if ( upstream ) {
        ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );
        CONNECTION_LOCK_DECREF(upstream);
        upstream->c_n_ops_executing--;
        UPSTREAM_UNLOCK_OR_DESTROY(upstream);
        operation_send_reject( op, LDAP_OTHER, "internal error", 0 );
    }
    CONNECTION_LOCK_DECREF(client);
    op->o_client_refcnt--;
    operation_destroy_from_client( op );
    CLIENT_UNLOCK_OR_DESTROY(client);
    return -1;
}
