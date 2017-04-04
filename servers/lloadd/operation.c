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

    assert( l->o_client == r->o_client );
    return ( l->o_client_msgid < r->o_client_msgid ) ?
            -1 :
            ( l->o_client_msgid > r->o_client_msgid );
}

int
operation_upstream_cmp( const void *left, const void *right )
{
    const Operation *l = left, *r = right;

    assert( l->o_upstream == r->o_upstream );
    return ( l->o_upstream_msgid < r->o_upstream_msgid ) ?
            -1 :
            ( l->o_upstream_msgid > r->o_upstream_msgid );
}

void
operation_destroy( Operation *op )
{
    Connection *c;

    ber_free( op->o_ber, 1 );

    /* TODO: this is a stopgap and there are many races here, just get
     * something in to test with until we implement the freelist */
    if ( op->o_client ) {
        c = op->o_client;
        ldap_pvt_thread_mutex_lock( &c->c_mutex );
        tavl_delete( &c->c_ops, op, operation_client_cmp );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    }

    if ( op->o_upstream ) {
        c = op->o_upstream;
        ldap_pvt_thread_mutex_lock( &c->c_mutex );
        tavl_delete( &c->c_ops, op, operation_upstream_cmp );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    }

    ch_free( op );
}

Operation *
operation_init( Connection *c, BerElement *ber )
{
    Operation *op;
    ber_tag_t tag;
    ber_len_t len;
    int rc;

    op = ch_calloc( 1, sizeof(Operation) );
    op->o_client = c;
    op->o_ber = ber;

    tag = ber_get_int( ber, &op->o_client_msgid );
    if ( tag != LDAP_TAG_MSGID ) {
        goto fail;
    }

    rc = tavl_insert( &c->c_ops, op, operation_client_cmp, avl_dup_error );
    if ( rc ) {
        Debug( LDAP_DEBUG_PACKETS, "operation_init: "
                "several operations with same msgid=%d in-flight "
                "from the client\n",
                op->o_client_msgid );
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
            "set up a new operation, %s with msgid=%d for client %lu\n",
            slap_msgtype2str( op->o_tag ), op->o_client_msgid, c->c_connid );

    return op;

fail:
    ch_free( op );
    return NULL;
}

void
operation_abandon( Operation *op )
{
    int rc;

    if ( op->o_upstream ) {
        Connection *c = op->o_upstream;
        BerElement *ber;

        ldap_pvt_thread_mutex_lock( &c->c_mutex );
        rc = ( tavl_delete( &c->c_ops, op, operation_upstream_cmp ) == NULL );
        ldap_pvt_thread_mutex_unlock( &c->c_mutex );

        if ( rc ) {
            /* The operation has already been abandoned or finished */
            goto done;
        }

        ldap_pvt_thread_mutex_lock( &c->c_io_mutex );

        ber = c->c_pendingber;
        if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
            Debug( LDAP_DEBUG_ANY, "operation_abandon: "
                    "ber_alloc failed\n" );
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            return;
        }
        c->c_pendingber = ber;

        rc = ber_printf( ber, "t{titi}", LDAP_TAG_MESSAGE,
                LDAP_TAG_MSGID, c->c_next_msgid++,
                LDAP_REQ_ABANDON, op->o_upstream_msgid );

        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

        if ( rc == -1 ) {
            ber_free( ber, 1 );
            return;
        }
        upstream_write_cb( -1, 0, c );
    }

done:
    operation_destroy( op );
}

void
operation_send_reject( Operation *op, int result, const char *msg )
{
    Connection *c = op->o_client;
    BerElement *ber;
    int found;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    found = ( tavl_delete( &c->c_ops, op, operation_client_cmp ) == op );
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    if ( !found ) {
        return;
    }

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );

    ber = c->c_pendingber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
        client_destroy( c );
        return;
    }
    c->c_pendingber = ber;

    ber_printf( ber, "t{tit{ess}}", LDAP_TAG_MESSAGE,
            LDAP_TAG_MSGID, op->o_client_msgid,
            slap_req2res( op->o_tag ), result, "", msg );

    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    client_write_cb( -1, 0, c );

    operation_destroy( op );
}

void
operation_lost_upstream( Operation *op )
{
    operation_send_reject( op, LDAP_UNAVAILABLE,
            "connection to the remote server has been severed" );
}

void *
request_process( void *ctx, void *arg )
{
    Operation *op = arg;
    BerElement *output;
    Connection *c;
    ber_int_t msgid;
    int rc;

    c = backend_select( op );
    if ( !c ) {
        Debug( LDAP_DEBUG_STATS, "request_process: "
                "no available connection found\n" );
        goto fail;
    }
    op->o_upstream = c;

    output = c->c_pendingber;
    if ( output == NULL && (output = ber_alloc()) == NULL ) {
        goto fail;
    }
    c->c_pendingber = output;

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    op->o_upstream_msgid = msgid = c->c_next_msgid++;
    rc = tavl_insert( &c->c_ops, op, operation_upstream_cmp, avl_dup_error );
    assert( rc == LDAP_SUCCESS );

    if ( lload_features & LLOAD_FEATURE_PROXYAUTHZ ) {
        Debug( LDAP_DEBUG_TRACE, "request_process: "
                "proxying identity %s to upstream\n",
                c->c_auth.bv_val );
        ber_printf( output, "t{titOt{{sbO}" /* "}}" */, LDAP_TAG_MESSAGE,
                LDAP_TAG_MSGID, msgid,
                op->o_tag, &op->o_request,
                LDAP_TAG_CONTROLS,
                LDAP_CONTROL_PROXY_AUTHZ, 1, &c->c_auth );

        if ( !BER_BVISNULL( &op->o_ctrls ) ) {
            BerElement *control_ber = ber_alloc();
            BerValue controls;

            if ( !control_ber ) {
                goto fail;
            }
            ber_init2( control_ber, &op->o_ctrls, 0 );
            ber_peek_element( control_ber, &controls );

            ber_write( output, controls.bv_val, controls.bv_len, 0 );
            ber_free( control_ber, 0 );
        }
        ber_printf( output, /* "{{" */ "}}" );
    } else {
        ber_printf( output, "t{titOtO}", LDAP_TAG_MESSAGE,
                LDAP_TAG_MSGID, msgid,
                op->o_tag, &op->o_request,
                LDAP_TAG_CONTROLS, BER_BV_OPTIONAL( &op->o_ctrls ) );
    }
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    upstream_write_cb( -1, 0, c );

    return NULL;
fail:
    operation_send_reject( op, LDAP_OTHER, "internal error" );
    return NULL;
}
