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
#include "lload.h"

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
lload_msgtype2str( ber_tag_t tag )
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
    const LloadOperation *l = left, *r = right;

    assert( l->o_client_connid == r->o_client_connid );
    return ( l->o_client_msgid < r->o_client_msgid ) ?
            -1 :
            ( l->o_client_msgid > r->o_client_msgid );
}

int
operation_upstream_cmp( const void *left, const void *right )
{
    const LloadOperation *l = left, *r = right;

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
operation_destroy_from_client( LloadOperation *op )
{
    LloadConnection *upstream = NULL, *client = op->o_client;
    LloadBackend *b = NULL;
    int race_state, detach_client = !client->c_live;

    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
            "op=%p attempting to release operation%s\n",
            op, detach_client ? " and detach client" : "" );

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
    op->o_freeing |= LLOAD_OP_FREEING_CLIENT;
    if ( detach_client ) {
        op->o_freeing |= LLOAD_OP_DETACHING_CLIENT;
    }
    ldap_pvt_thread_mutex_unlock( &op->o_mutex );

    CONNECTION_UNLOCK_INCREF(client);

    if ( detach_client ) {
        ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
        op->o_client = NULL;
        ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );
    }

    /* 4. If we lost the race, deal with it straight away */
    if ( race_state ) {
        /*
         * We have raced to destroy op and the first one to lose on this side,
         * leave a refcnt token on client so we don't destroy it before the
         * other side has finished (it knows we did that when it examines
         * o_freeing again).
         */
        if ( detach_client ) {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                    "op=%p lost race but client connid=%lu is going down\n",
                    op, client->c_connid );
            CONNECTION_LOCK_DECREF(client);
        } else if ( (race_state & LLOAD_OP_FREEING_MASK) ==
                LLOAD_OP_FREEING_UPSTREAM ) {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                    "op=%p lost race, increased client refcnt connid=%lu "
                    "to refcnt=%d\n",
                    op, client->c_connid, client->c_refcnt );
            CONNECTION_LOCK(client);
        } else {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_client: "
                    "op=%p lost race with another "
                    "operation_destroy_from_client, "
                    "client connid=%lu\n",
                    op, client->c_connid );
            CONNECTION_LOCK_DECREF(client);
        }
        return;
    }

    /* 5. If we raced the upstream side and won, reclaim the token */
    ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
    if ( !(race_state & LLOAD_OP_DETACHING_UPSTREAM) ) {
        upstream = op->o_upstream;
        if ( upstream ) {
            CONNECTION_LOCK(upstream);
        }
    }
    ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );

    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    /* We don't actually resolve the race in full until we grab the other's
     * c_mutex+op->o_mutex here */
    if ( upstream && ( op->o_freeing & LLOAD_OP_FREEING_UPSTREAM ) ) {
        if ( op->o_freeing & LLOAD_OP_DETACHING_UPSTREAM ) {
            CONNECTION_UNLOCK(upstream);
            upstream = NULL;
        } else {
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
        op->o_freeing &= ~LLOAD_OP_FREEING_CLIENT;
        if ( detach_client ) {
            op->o_freeing &= ~LLOAD_OP_DETACHING_CLIENT;
        }
        assert( op->o_freeing == 0 );
        ldap_pvt_thread_mutex_unlock( &op->o_mutex );

        assert( upstream != NULL );
        CONNECTION_UNLOCK_OR_DESTROY(upstream);
        CONNECTION_LOCK_DECREF(client);
        return;
    }

    /* 7. Remove from the operation map and adjust the pending op count */
    if ( upstream ) {
        if ( tavl_delete( &upstream->c_ops, op, operation_upstream_cmp ) ) {
            upstream->c_n_ops_executing--;
            b = (LloadBackend *)upstream->c_private;
        }
        CONNECTION_UNLOCK_OR_DESTROY(upstream);

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
    ldap_pvt_thread_mutex_destroy( &op->o_link_mutex );
    ch_free( op );

    CONNECTION_LOCK_DECREF(client);
}

/*
 * See operation_destroy_from_client.
 */
void
operation_destroy_from_upstream( LloadOperation *op )
{
    LloadConnection *client = NULL, *upstream = op->o_upstream;
    LloadBackend *b = NULL;
    int race_state, detach_upstream = !upstream->c_live;

    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
            "op=%p attempting to release operation%s\n",
            op, detach_upstream ? " and detach upstream" : "" );

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
        b = (LloadBackend *)upstream->c_private;
    }

    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    race_state = op->o_freeing;
    op->o_freeing |= LLOAD_OP_FREEING_UPSTREAM;
    if ( detach_upstream ) {
        op->o_freeing |= LLOAD_OP_DETACHING_UPSTREAM;
    }
    ldap_pvt_thread_mutex_unlock( &op->o_mutex );

    CONNECTION_UNLOCK_INCREF(upstream);

    /* 3. Detect whether we entered a race to free op */
    ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
    if ( detach_upstream ) {
        op->o_upstream = NULL;
    }
    ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );

    if ( b ) {
        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        b->b_n_ops_executing--;
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
    }

    /* 4. If we lost the race, deal with it straight away */
    if ( race_state ) {
        /*
         * We have raced to destroy op and the first one to lose on this side,
         * leave a refcnt token on upstream so we don't destroy it before the
         * other side has finished (it knows we did that when it examines
         * o_freeing again).
         */
        if ( detach_upstream ) {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                    "op=%p lost race but upstream connid=%lu is going down\n",
                    op, upstream->c_connid );
            CONNECTION_LOCK_DECREF(upstream);
        } else if ( (race_state & LLOAD_OP_FREEING_MASK) ==
                LLOAD_OP_FREEING_CLIENT ) {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                    "op=%p lost race, increased upstream refcnt connid=%lu "
                    "to refcnt=%d\n",
                    op, upstream->c_connid, upstream->c_refcnt );
            CONNECTION_LOCK(upstream);
        } else {
            Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
                    "op=%p lost race with another "
                    "operation_destroy_from_upstream, "
                    "upstream connid=%lu\n",
                    op, upstream->c_connid );
            CONNECTION_LOCK_DECREF(upstream);
        }
        return;
    }

    /* 5. If we raced the client side and won, reclaim the token */
    ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
    if ( !(race_state & LLOAD_OP_DETACHING_CLIENT) ) {
        client = op->o_client;
        if ( client ) {
            CONNECTION_LOCK(client);
        }
    }
    ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );

    /* We don't actually resolve the race in full until we grab the other's
     * c_mutex+op->o_mutex here */
    ldap_pvt_thread_mutex_lock( &op->o_mutex );
    if ( client && ( op->o_freeing & LLOAD_OP_FREEING_CLIENT ) ) {
        if ( op->o_freeing & LLOAD_OP_DETACHING_CLIENT ) {
            CONNECTION_UNLOCK(client);
            client = NULL;
        } else {
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
        op->o_freeing &= ~LLOAD_OP_FREEING_UPSTREAM;
        if ( detach_upstream ) {
            op->o_freeing &= ~LLOAD_OP_DETACHING_UPSTREAM;
        }
        assert( op->o_freeing == 0 );
        ldap_pvt_thread_mutex_unlock( &op->o_mutex );

        assert( client != NULL );
        CONNECTION_UNLOCK_OR_DESTROY(client);
        CONNECTION_LOCK_DECREF(upstream);
        return;
    }

    /* 7. Remove from the operation map and TODO adjust the pending op count */
    if ( client ) {
        tavl_delete( &client->c_ops, op, operation_client_cmp );
        CONNECTION_UNLOCK_OR_DESTROY(client);
    }

    /* 8. Release the operation */
    Debug( LDAP_DEBUG_TRACE, "operation_destroy_from_upstream: "
            "op=%p destroyed operation from client connid=%lu, "
            "client msgid=%d\n",
            op, op->o_client_connid, op->o_client_msgid );
    ber_free( op->o_ber, 1 );
    ldap_pvt_thread_mutex_destroy( &op->o_mutex );
    ldap_pvt_thread_mutex_destroy( &op->o_link_mutex );
    ch_free( op );

    CONNECTION_LOCK_DECREF(upstream);
}

/*
 * Entered holding c_mutex for now.
 */
LloadOperation *
operation_init( LloadConnection *c, BerElement *ber )
{
    LloadOperation *op;
    ber_tag_t tag;
    ber_len_t len;
    int rc;

    op = ch_calloc( 1, sizeof(LloadOperation) );
    op->o_client = c;
    op->o_client_connid = c->c_connid;
    op->o_ber = ber;
    op->o_start = slap_get_time();

    ldap_pvt_thread_mutex_init( &op->o_mutex );
    ldap_pvt_thread_mutex_init( &op->o_link_mutex );

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

    Debug( LDAP_DEBUG_STATS, "operation_init: "
            "received a new operation, %s with msgid=%d for client "
            "connid=%lu\n",
            lload_msgtype2str( op->o_tag ), op->o_client_msgid,
            op->o_client_connid );

    c->c_n_ops_executing++;
    return op;

fail:
    ch_free( op );
    return NULL;
}

int
operation_send_abandon( LloadOperation *op )
{
    LloadConnection *upstream = op->o_upstream;
    BerElement *ber;
    int rc = -1;

    ldap_pvt_thread_mutex_lock( &upstream->c_io_mutex );
    ber = upstream->c_pendingber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "operation_send_abandon: "
                "ber_alloc failed\n" );
        goto done;
    }
    upstream->c_pendingber = ber;

    rc = ber_printf( ber, "t{titi}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, upstream->c_next_msgid++,
            LDAP_REQ_ABANDON, op->o_upstream_msgid );

    if ( rc < 0 ) {
        ber_free( ber, 1 );
        upstream->c_pendingber = NULL;
        goto done;
    }
    rc = LDAP_SUCCESS;

done:
    ldap_pvt_thread_mutex_unlock( &upstream->c_io_mutex );
    return rc;
}

/*
 * Will remove the operation from its upstream and if it was still there,
 * sends an abandon request.
 *
 * Being called from client_reset or request_abandon, the following hold:
 * - op->o_client_refcnt > 0 (and it follows that op->o_client != NULL)
 */
void
operation_abandon( LloadOperation *op )
{
    LloadConnection *c;
    LloadBackend *b;
    int rc = LDAP_SUCCESS;

    ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
    c = op->o_upstream;
    if ( !c ) {
        ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );
        goto done;
    }

    CONNECTION_LOCK(c);
    ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );
    if ( tavl_delete( &c->c_ops, op, operation_upstream_cmp ) == NULL ) {
        /* The operation has already been abandoned or finished */
        goto unlock;
    }
    if ( c->c_state == LLOAD_C_BINDING ) {
        c->c_state = LLOAD_C_READY;
    }
    c->c_n_ops_executing--;
    b = (LloadBackend *)c->c_private;
    CONNECTION_UNLOCK_INCREF(c);

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    b->b_n_ops_executing--;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    if ( operation_send_abandon( op ) == LDAP_SUCCESS ) {
        connection_write_cb( -1, 0, c );
    }

    CONNECTION_LOCK_DECREF(c);
unlock:
    /*
     * FIXME: the dance in operation_destroy_from_upstream might be slower than
     * optimal as we've done some of the things above already. However, we want
     * to clear o_upstream from the op if it's dying, but witnessing and
     * navigating the race to do that safely is too complex to copy here.
     */
    if ( !c->c_live ) {
        operation_destroy_from_upstream( op );
    }
    if ( rc ) {
        CONNECTION_DESTROY(c);
    } else {
        CONNECTION_UNLOCK_OR_DESTROY(c);
    }

done:
    c = op->o_client;
    assert( c );

    /* Caller should hold a reference on client */
    CONNECTION_LOCK(c);
    if ( c->c_state == LLOAD_C_BINDING ) {
        c->c_state = LLOAD_C_READY;
    }
    op->o_client_refcnt--;
    operation_destroy_from_client( op );
    CONNECTION_UNLOCK(c);
}

/*
 * Called with op->o_client non-NULL and already locked.
 */
int
operation_send_reject_locked(
        LloadOperation *op,
        int result,
        const char *msg,
        int send_anyway )
{
    LloadConnection *c = op->o_client;
    BerElement *ber;
    int found;

    Debug( LDAP_DEBUG_TRACE, "operation_send_reject_locked: "
            "rejecting %s from client connid=%lu with message: \"%s\"\n",
            lload_msgtype2str( op->o_tag ), c->c_connid, msg );

    found = ( tavl_delete( &c->c_ops, op, operation_client_cmp ) == op );
    if ( !found && !send_anyway ) {
        Debug( LDAP_DEBUG_TRACE, "operation_send_reject_locked: "
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
        Debug( LDAP_DEBUG_ANY, "operation_send_reject_locked: "
                "ber_alloc failed, closing connid=%lu\n",
                c->c_connid );
        CONNECTION_LOCK_DECREF(c);
        operation_destroy_from_client( op );
        CONNECTION_DESTROY(c);
        return -1;
    }
    c->c_pendingber = ber;

    ber_printf( ber, "t{tit{ess}}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_client_msgid,
            slap_req2res( op->o_tag ), result, "", msg );

    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    connection_write_cb( -1, 0, c );

    CONNECTION_LOCK_DECREF(c);
done:
    operation_destroy_from_client( op );
    return LDAP_SUCCESS;
}

void
operation_send_reject(
        LloadOperation *op,
        int result,
        const char *msg,
        int send_anyway )
{
    LloadConnection *c;

    ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
    c = op->o_client;
    if ( !c ) {
        c = op->o_upstream;
        /* One of the connections has initiated this and keeps a reference, if
         * client is dead, it must have been the upstream */
        assert( c );
        CONNECTION_LOCK(c);
        ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );
        Debug( LDAP_DEBUG_TRACE, "operation_send_reject: "
                "not sending msgid=%d, client connid=%lu is dead\n",
                op->o_client_msgid, op->o_client_connid );
        operation_destroy_from_upstream( op );
        CONNECTION_UNLOCK_OR_DESTROY(c);
        return;
    }
    CONNECTION_LOCK(c);
    ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );

    /* Non-zero return means connection has been unlocked and might be
     * destroyed */
    if ( operation_send_reject_locked( op, result, msg, send_anyway ) ==
            LDAP_SUCCESS ) {
        CONNECTION_UNLOCK_OR_DESTROY(c);
    }
}

/*
 * Upstream is shutting down, signal the client if necessary, but we have to
 * call operation_destroy_from_upstream ourselves to detach upstream from the
 * op.
 *
 * Only called from upstream_destroy.
 */
void
operation_lost_upstream( LloadOperation *op )
{
    LloadConnection *c = op->o_upstream;
    CONNECTION_LOCK(c);
    op->o_upstream_refcnt++;
    /* Matching the op reference on the connection as well */
    CONNECTION_UNLOCK_INCREF(c);

    operation_send_reject( op, LDAP_UNAVAILABLE,
            "connection to the remote server has been severed", 0 );

    CONNECTION_LOCK_DECREF(c);
    op->o_upstream_refcnt--;
    operation_destroy_from_upstream( op );
    CONNECTION_UNLOCK(c);
}

void
connection_timeout( LloadConnection *upstream, time_t threshold )
{
    LloadOperation *op;
    TAvlnode *ops = NULL, *node;
    LloadBackend *b = upstream->c_private;
    int rc, nops = 0;

    for ( node = tavl_end( upstream->c_ops, TAVL_DIR_LEFT ); node &&
            ((LloadOperation *)node->avl_data)->o_start <
                    threshold; /* shortcut */
            node = tavl_next( node, TAVL_DIR_RIGHT ) ) {
        LloadOperation *found_op;

        op = node->avl_data;

        /* Have we received another response since? */
        if ( op->o_last_response && op->o_last_response >= threshold ) {
            continue;
        }

        op->o_upstream_refcnt++;
        found_op = tavl_delete( &upstream->c_ops, op, operation_upstream_cmp );
        assert( op == found_op );

        rc = tavl_insert( &ops, op, operation_upstream_cmp, avl_dup_error );
        assert( rc == LDAP_SUCCESS );

        Debug( LDAP_DEBUG_STATS2, "connection_timeout: "
                "timing out %s from connid=%lu msgid=%d sent to connid=%lu as "
                "msgid=%d\n",
                lload_msgtype2str( op->o_tag ), op->o_client_connid,
                op->o_client_msgid, op->o_upstream_connid,
                op->o_upstream_msgid );
        nops++;
    }

    if ( nops == 0 ) {
        return;
    }
    upstream->c_n_ops_executing -= nops;
    Debug( LDAP_DEBUG_STATS, "connection_timeout: "
            "timing out %d operations for connid=%lu\n",
            nops, upstream->c_connid );
    CONNECTION_UNLOCK_INCREF(upstream);

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    b->b_n_ops_executing -= nops;
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    for ( node = tavl_end( ops, TAVL_DIR_LEFT ); node;
            node = tavl_next( node, TAVL_DIR_RIGHT ) ) {
        LloadConnection *client;

        op = node->avl_data;

        ldap_pvt_thread_mutex_lock( &op->o_link_mutex );
        client = op->o_client;
        if ( !client ) {
            ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );
            continue;
        }
        CONNECTION_LOCK(client);
        ldap_pvt_thread_mutex_unlock( &op->o_link_mutex );

        /* operation_send_reject_locked unlocks and destroys client on
         * failure */
        if ( operation_send_reject_locked( op,
                     op->o_tag == LDAP_REQ_SEARCH ? LDAP_TIMELIMIT_EXCEEDED :
                                                    LDAP_ADMINLIMIT_EXCEEDED,
                     "upstream did not respond in time", 0 ) == LDAP_SUCCESS ) {
            CONNECTION_UNLOCK_OR_DESTROY(client);
        }

        if ( rc == LDAP_SUCCESS ) {
            rc = operation_send_abandon( op );
        }

        CONNECTION_LOCK(upstream);
        op->o_upstream_refcnt--;
        operation_destroy_from_upstream( op );
        CONNECTION_UNLOCK(upstream);
    }

    /* TODO: if operation_send_abandon failed, we need to kill the upstream */
    if ( rc == LDAP_SUCCESS ) {
        connection_write_cb( -1, 0, upstream );
    }

    CONNECTION_LOCK_DECREF(upstream);
    /* just dispose of the AVL, most operations should already be gone */
    tavl_free( ops, NULL );
}

static void
backend_timeout(
        LloadBackend *b,
        lload_c_head *cq,
        LloadConnection **lastp,
        time_t threshold )
{
    LloadConnection *c, *old;
    unsigned long last_connid;

    ldap_pvt_thread_mutex_lock( &b->b_mutex );
    if ( !*lastp ) {
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );
        return;
    }
    last_connid = (*lastp)->c_connid;
    c = LDAP_CIRCLEQ_LOOP_NEXT( cq, *lastp, c_next );
    CONNECTION_LOCK(c);
    ldap_pvt_thread_mutex_unlock( &b->b_mutex );

    /*
     * Ugh... concurrency is annoying:
     * - we maintain the connections in the cq CIRCLEQ_ in ascending c_connid
     *   order
     * - the connection with the highest c_connid is maintained at *lastp
     * - we can only use cq when we hold b->b_mutex
     * - connections might be added to or removed from cq while we're busy
     *   processing connections
     * - connection_destroy touches cq
     * - we can't even hold locks of two different connections
     * - we need a way to detect we've finished looping around cq for some
     *   definition of looping around
     *
     * So as a result, 90% of the code below is spent navigating that...
     */
    while ( c->c_connid <= last_connid ) {
        Debug( LDAP_DEBUG_TRACE, "backend_timeout: "
                "timing out operations for connid=%lu which has %ld "
                "pending ops\n",
                c->c_connid, c->c_n_ops_executing );
        connection_timeout( c, threshold );
        if ( c->c_connid == last_connid ) {
            break;
        }

        CONNECTION_UNLOCK_INCREF(c);

        ldap_pvt_thread_mutex_lock( &b->b_mutex );
        old = c;
        c = LDAP_CIRCLEQ_LOOP_NEXT( cq, c, c_next );
        CONNECTION_LOCK(c);
        CONNECTION_UNLOCK_INCREF(c);
        ldap_pvt_thread_mutex_unlock( &b->b_mutex );

        CONNECTION_LOCK_DECREF(old);
        CONNECTION_UNLOCK_OR_DESTROY(old);

        CONNECTION_LOCK_DECREF(c);
    }
    CONNECTION_UNLOCK_OR_DESTROY(c);
}

void
operations_timeout( evutil_socket_t s, short what, void *arg )
{
    struct event *self = arg;
    LloadBackend *b;
    time_t threshold;

    Debug( LDAP_DEBUG_TRACE, "operations_timeout: "
            "running timeout task\n" );
    if ( !lload_timeout_api ) goto done;

    threshold = slap_get_time() - lload_timeout_api->tv_sec;

    LDAP_CIRCLEQ_FOREACH ( b, &backend, b_next ) {
        if ( b->b_n_ops_executing == 0 ) continue;

        Debug( LDAP_DEBUG_TRACE, "operations_timeout: "
                "timing out binds for backend uri=%s\n",
                b->b_uri.bv_val );
        backend_timeout( b, &b->b_bindconns, &b->b_last_bindconn, threshold );

        Debug( LDAP_DEBUG_TRACE, "operations_timeout: "
                "timing out other operations for backend uri=%s\n",
                b->b_uri.bv_val );
        backend_timeout( b, &b->b_conns, &b->b_last_conn, threshold );
    }
done:
    Debug( LDAP_DEBUG_TRACE, "operations_timeout: "
            "timeout task finished\n" );
    evtimer_add( self, lload_timeout_api );
}
