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

    ldap_pvt_thread_mutex_lock( &c->c_mutex );
    upstream_destroy( c );
}

void
upstream_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
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

    c->c_struct_state = SLAP_C_UNINITIALIZED;
    ldap_pvt_thread_mutex_unlock( &c->c_mutex );

    ldap_pvt_thread_mutex_lock( &b->b_lock );
    if ( !(b->b_conns == c) ) {
        ldap_pvt_thread_mutex_unlock( &b->b_lock );
        return;
    }
    b->b_conns = NULL;
    ldap_pvt_thread_mutex_unlock( &b->b_lock );

    ldap_pvt_thread_mutex_lock( &c->c_mutex );

    event_del( c->c_read_event );
    event_free( c->c_read_event );

    event_del( c->c_write_event );
    event_free( c->c_write_event );

    connection_destroy( c );
}
