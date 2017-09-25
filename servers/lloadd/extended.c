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

#include <ac/string.h>

#include "lutil.h"
#include "slap.h"

Avlnode *lload_exop_handlers = NULL;

int
request_extended( Connection *c, Operation *op )
{
    ExopHandler *handler, needle = {};
    BerElement *copy;
    struct berval bv;
    ber_tag_t tag;

    if ( (copy = ber_alloc()) == NULL ) {
        if ( operation_send_reject_locked(
                     op, LDAP_OTHER, "internal error", 0 ) == LDAP_SUCCESS ) {
            CONNECTION_DESTROY(c);
        }
        return -1;
    }

    ber_init2( copy, &op->o_request, 0 );

    tag = ber_skip_element( copy, &bv );
    if ( tag != LDAP_TAG_EXOP_REQ_OID ) {
        Debug( LDAP_DEBUG_STATS, "request_extended: "
                "no OID present in extended request\n" );
        return operation_send_reject_locked(
                op, LDAP_PROTOCOL_ERROR, "decoding error", 0 );
    }

    needle.oid = bv;

    handler = avl_find( lload_exop_handlers, &needle, exop_handler_cmp );
    if ( handler ) {
        Debug( LDAP_DEBUG_TRACE, "request_extended: "
                "handling exop OID %.*s internally\n",
                (int)bv.bv_len, bv.bv_val );
        ber_free( copy, 0 );
        return handler->func( c, op );
    }
    ber_free( copy, 0 );

    if ( c->c_state == SLAP_C_BINDING ) {
        return operation_send_reject_locked(
                op, LDAP_PROTOCOL_ERROR, "bind in progress", 0 );
    }
    return request_process( c, op );
}

ExopHandler lload_exops[] = { { BER_BVNULL }
};

int
exop_handler_cmp( const void *left, const void *right )
{
    const struct lload_exop_handlers_t *l = left, *r = right;
    return ber_bvcmp( &l->oid, &r->oid );
}

int
lload_register_exop_handlers( struct lload_exop_handlers_t *handler )
{
    for ( ; !BER_BVISNULL( &handler->oid ); handler++ ) {
        Debug( LDAP_DEBUG_TRACE, "lload_register_exop_handlers: "
                "registering handler for exop oid=%s\n",
                handler->oid.bv_val );
        if ( avl_insert( &lload_exop_handlers, handler, exop_handler_cmp,
                     avl_dup_error ) ) {
            Debug( LDAP_DEBUG_ANY, "lload_register_exop_handlers: "
                    "failed to register handler for exop oid=%s\n",
                    handler->oid.bv_val );
            return -1;
        }
    }

    return LDAP_SUCCESS;
}

int
lload_exop_init( void )
{
    if ( lload_register_exop_handlers( lload_exops ) ) {
        return -1;
    }

    return LDAP_SUCCESS;
}
