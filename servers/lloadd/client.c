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

static void client_destroy( Connection *c );

static void
client_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    Debug( LDAP_DEBUG_CONNS, "client_read_cb: "
            "connection %lu ready to read\n",
            c->c_connid );
    evutil_closesocket( s );
    client_destroy( c );
}

static void
client_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
}

Connection *
client_init(
        ber_socket_t s,
        Listener *listener,
        const char *peername,
        struct event_base *base,
        int flags )
{
    Connection *c;
    struct event *event;

    assert( listener != NULL );

    c = connection_init( s, peername, flags );

    event = event_new( base, s, EV_READ|EV_PERSIST, client_read_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Read event could not be allocated\n" );
        goto fail;
    }
    event_add( event, NULL );
    c->c_read_event = event;

    event = event_new( base, s, EV_WRITE, client_write_cb, c );
    if ( !event ) {
        Debug( LDAP_DEBUG_ANY, "Write event could not be allocated\n" );
        goto fail;
    }
    /* We only register the write event when we have data pending */
    c->c_write_event = event;

    c->c_private = listener;

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
client_destroy( Connection *c )
{
    event_del( c->c_read_event );
    event_free( c->c_read_event );

    event_del( c->c_write_event );
    event_free( c->c_write_event );

    connection_destroy( c );
}
