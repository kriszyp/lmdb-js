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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "lutil.h"
#include "slap.h"

static ldap_pvt_thread_mutex_t conn_nextid_mutex;
static unsigned long conn_nextid = 0;

static void
connection_assign_nextid( Connection *conn )
{
    ldap_pvt_thread_mutex_lock( &conn_nextid_mutex );
    conn->c_connid = conn_nextid++;
    ldap_pvt_thread_mutex_unlock( &conn_nextid_mutex );
}

void
connection_destroy( Connection *c )
{
    assert( c );
    Debug( LDAP_DEBUG_CONNS, "connection_destroy: "
            "destroying connection %lu.\n",
            c->c_connid );

    assert( c->c_live == 0 );
    assert( c->c_refcnt == 0 );
    assert( c->c_state == SLAP_C_INVALID );

    ber_sockbuf_free( c->c_sb );

    if ( c->c_currentber ) {
        ber_free( c->c_currentber, 1 );
        c->c_currentber = NULL;
    }
    if ( c->c_pendingber ) {
        ber_free( c->c_pendingber, 1 );
        c->c_pendingber = NULL;
    }

    CONNECTION_UNLOCK(c);

    ldap_pvt_thread_mutex_destroy( &c->c_io_mutex );
    ldap_pvt_thread_mutex_destroy( &c->c_mutex );

    ch_free( c );
}

Connection *
connection_init( ber_socket_t s, const char *peername, int flags )
{
    Connection *c;

    assert( peername != NULL );

#ifndef HAVE_TLS
    assert( !(flags & CONN_IS_TLS) );
#endif

    if ( s == AC_SOCKET_INVALID ) {
        Debug( LDAP_DEBUG_ANY, "connection_init: "
                "init of socket fd=%ld invalid.\n",
                (long)s );
        return NULL;
    }

    assert( s >= 0 );

    c = ch_calloc( 1, sizeof(Connection) );

    c->c_fd = s;
    c->c_sb = ber_sockbuf_alloc();
    ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_FD, &s );

    {
        ber_len_t max = sockbuf_max_incoming;
        ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
    }

#ifdef LDAP_PF_LOCAL
    if ( flags & CONN_IS_IPC ) {
#ifdef LDAP_DEBUG
        ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_debug,
                LBER_SBIOD_LEVEL_PROVIDER, (void *)"ipc_" );
#endif
        ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_fd,
                LBER_SBIOD_LEVEL_PROVIDER, (void *)&s );
#ifdef LDAP_PF_LOCAL_SENDMSG
        if ( !BER_BVISEMPTY( peerbv ) )
            ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_UNGET_BUF, peerbv );
#endif
    } else
#endif /* LDAP_PF_LOCAL */
    {
#ifdef LDAP_DEBUG
        ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_debug,
                LBER_SBIOD_LEVEL_PROVIDER, (void *)"tcp_" );
#endif
        ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_tcp,
                LBER_SBIOD_LEVEL_PROVIDER, (void *)&s );
    }

#ifdef LDAP_DEBUG
    ber_sockbuf_add_io(
            c->c_sb, &ber_sockbuf_io_debug, INT_MAX, (void *)"lload_" );
#endif

#ifdef HAVE_TLS
    if ( flags & CONN_IS_TLS ) {
        /* TODO: will need an asynchronous TLS implementation in libldap */
        assert(0);
        c->c_is_tls = 1;
        c->c_needs_tls_accept = 1;
    } else {
        c->c_is_tls = 0;
        c->c_needs_tls_accept = 0;
    }
#endif

    c->c_next_msgid = 1;
    c->c_refcnt = c->c_live = 1;

    LDAP_LIST_ENTRY_INIT( c, c_next );

    ldap_pvt_thread_mutex_init( &c->c_mutex );
    ldap_pvt_thread_mutex_init( &c->c_io_mutex );

    connection_assign_nextid( c );

    Debug( LDAP_DEBUG_CONNS, "connection_init: "
            "connection connid=%lu allocated for socket fd=%d\n",
            c->c_connid, s );

    CONNECTION_LOCK(c);
    c->c_state = SLAP_C_ACTIVE;

    return c;
}
