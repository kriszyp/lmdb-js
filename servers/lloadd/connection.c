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

/*
 * We start off with the connection muted and c_currentber holding the pdu we
 * received.
 *
 * We run c->c_pdu_cb for each pdu, stopping once we hit an error, have to wait
 * on reading or after we process slap_conn_max_pdus_per_cycle pdus so as to
 * maintain fairness and not hog the worker thread forever.
 *
 * If we've run out of pdus immediately available from the stream or hit the
 * budget, we unmute the connection.
 *
 * c->c_pdu_cb might return an 'error' and not free the connection. That can
 * happen when changing the state or when client is blocked on writing and
 * already has a pdu pending on the same operation, it's their job to make sure
 * we're woken up again.
 */
static void *
handle_pdus( void *ctx, void *arg )
{
    Connection *c = arg;
    int pdus_handled = 0;

    CONNECTION_LOCK_DECREF(c);
    for ( ;; ) {
        BerElement *ber;
        ber_tag_t tag;
        ber_len_t len;

        /* handle_one_response may unlock the connection in the process, we
         * need to expect that might be our responsibility to destroy it */
        if ( c->c_pdu_cb( c ) ) {
            /* Error, connection is unlocked and might already have been
             * destroyed */
            return NULL;
        }
        /* Otherwise, handle_one_request leaves the connection locked */

        if ( ++pdus_handled >= slap_conn_max_pdus_per_cycle ) {
            /* Do not read now, re-enable read event instead */
            break;
        }

        if ( (ber = ber_alloc()) == NULL ) {
            Debug( LDAP_DEBUG_ANY, "handle_pdus: "
                    "connid=%lu, ber_alloc failed\n",
                    c->c_connid );
            CONNECTION_DESTROY(c);
            return NULL;
        }
        c->c_currentber = ber;

        tag = ber_get_next( c->c_sb, &len, ber );
        if ( tag != LDAP_TAG_MESSAGE ) {
            int err = sock_errno();

            if ( err != EWOULDBLOCK && err != EAGAIN ) {
                if ( err || tag == LBER_ERROR ) {
                    char ebuf[128];
                    Debug( LDAP_DEBUG_ANY, "handle_pdus: "
                            "ber_get_next on fd=%d failed errno=%d (%s)\n",
                            c->c_fd, err,
                            sock_errstr( err, ebuf, sizeof(ebuf) ) );
                } else {
                    Debug( LDAP_DEBUG_STATS, "handle_pdus: "
                            "ber_get_next on fd=%d connid=%lu received "
                            "a strange PDU tag=%lx\n",
                            c->c_fd, c->c_connid, tag );
                }

                c->c_currentber = NULL;
                ber_free( ber, 1 );
                CONNECTION_DESTROY(c);
                return NULL;
            }
            break;
        }
    }

    event_add( c->c_read_event, c->c_read_timeout );
    Debug( LDAP_DEBUG_CONNS, "handle_pdus: "
            "re-enabled read event on connid=%lu\n",
            c->c_connid );
    CONNECTION_UNLOCK_OR_DESTROY(c);
    return NULL;
}

/*
 * Initial read on the connection, if we get an LDAP PDU, submit the
 * processing of this and successive ones to the work queue.
 *
 * If we can't submit it to the queue (overload), process this one and return
 * to the event loop immediately after.
 */
void
connection_read_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;
    BerElement *ber;
    ber_tag_t tag;
    ber_len_t len;

    CONNECTION_LOCK(c);
    if ( !c->c_live ) {
        event_del( c->c_read_event );
        Debug( LDAP_DEBUG_CONNS, "connection_read_cb: "
                "suspended read event on a dead connid=%lu\n",
                c->c_connid );
        CONNECTION_UNLOCK(c);
        return;
    }

    if ( what & EV_TIMEOUT ) {
        Debug( LDAP_DEBUG_CONNS, "connection_read_cb: "
                "connid=%lu, timeout reached, destroying\n",
                c->c_connid );
        CONNECTION_DESTROY(c);
        return;
    }

    Debug( LDAP_DEBUG_CONNS, "connection_read_cb: "
            "connection connid=%lu ready to read\n",
            c->c_connid );

    ber = c->c_currentber;
    if ( ber == NULL && (ber = ber_alloc()) == NULL ) {
        Debug( LDAP_DEBUG_ANY, "connection_read_cb: "
                "connid=%lu, ber_alloc failed\n",
                c->c_connid );
        CONNECTION_DESTROY(c);
        return;
    }
    c->c_currentber = ber;

    tag = ber_get_next( c->c_sb, &len, ber );
    if ( tag != LDAP_TAG_MESSAGE ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            if ( err || tag == LBER_ERROR ) {
                char ebuf[128];
                Debug( LDAP_DEBUG_STATS, "connection_read_cb: "
                        "ber_get_next on fd=%d failed errno=%d (%s)\n",
                        c->c_fd, err,
                        sock_errstr( err, ebuf, sizeof(ebuf) ) );
            } else {
                Debug( LDAP_DEBUG_STATS, "connection_read_cb: "
                        "ber_get_next on fd=%d connid=%lu received "
                        "a strange PDU tag=%lx\n",
                        c->c_fd, c->c_connid, tag );
            }

            c->c_currentber = NULL;
            ber_free( ber, 1 );

            event_del( c->c_read_event );
            Debug( LDAP_DEBUG_CONNS, "connection_read_cb: "
                    "suspended read event on dying connid=%lu\n",
                    c->c_connid );
            CONNECTION_DESTROY(c);
            return;
        }
        event_add( c->c_read_event, c->c_read_timeout );
        Debug( LDAP_DEBUG_CONNS, "connection_read_cb: "
                "re-enabled read event on connid=%lu\n",
                c->c_connid );
        CONNECTION_UNLOCK(c);
        return;
    }

    if ( !slap_conn_max_pdus_per_cycle ||
            ldap_pvt_thread_pool_submit( &connection_pool, handle_pdus, c ) ) {
        /* If we're overloaded or configured as such, process one and resume in
         * the next cycle.
         *
         * handle_one_request re-locks the mutex in the
         * process, need to test it's still alive */
        if ( c->c_pdu_cb( c ) == LDAP_SUCCESS ) {
            CONNECTION_UNLOCK_OR_DESTROY(c);
        }
        return;
    }

    event_del( c->c_read_event );
    Debug( LDAP_DEBUG_CONNS, "connection_read_cb: "
            "suspended read event on connid=%lu\n",
            c->c_connid );

    /* We have scheduled a call to handle_requests which takes care of
     * handling further requests, just make sure the connection sticks around
     * for that */
    CONNECTION_UNLOCK_INCREF(c);
    return;
}

void
connection_write_cb( evutil_socket_t s, short what, void *arg )
{
    Connection *c = arg;

    CONNECTION_LOCK(c);
    if ( !c->c_live ) {
        CONNECTION_UNLOCK(c);
        return;
    }

    if ( what & EV_TIMEOUT ) {
        Debug( LDAP_DEBUG_CONNS, "connection_write_cb: "
                "connid=%lu, timeout reached, destroying\n",
                c->c_connid );
        CONNECTION_DESTROY(c);
        return;
    }
    CONNECTION_UNLOCK_INCREF(c);

    /* Before we acquire any locks */
    event_del( c->c_write_event );

    ldap_pvt_thread_mutex_lock( &c->c_io_mutex );
    Debug( LDAP_DEBUG_CONNS, "connection_write_cb: "
            "have something to write to connection connid=%lu\n",
            c->c_connid );

    /* We might have been beaten to flushing the data by another thread */
    if ( c->c_pendingber && ber_flush( c->c_sb, c->c_pendingber, 1 ) ) {
        int err = sock_errno();

        if ( err != EWOULDBLOCK && err != EAGAIN ) {
            char ebuf[128];
            ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );
            Debug( LDAP_DEBUG_ANY, "connection_write_cb: "
                    "ber_flush on fd=%d failed errno=%d (%s)\n",
                    c->c_fd, err, sock_errstr( err, ebuf, sizeof(ebuf) ) );
            CONNECTION_LOCK_DESTROY(c);
            return;
        }
        event_add( c->c_write_event, lload_write_timeout );
    } else {
        c->c_pendingber = NULL;
    }
    ldap_pvt_thread_mutex_unlock( &c->c_io_mutex );

    CONNECTION_LOCK_DECREF(c);
    CONNECTION_UNLOCK_OR_DESTROY(c);
}

void
connection_destroy( Connection *c )
{
    assert( c );
    Debug( LDAP_DEBUG_CONNS, "connection_destroy: "
            "destroying connection connid=%lu\n",
            c->c_connid );

    assert( c->c_live == 0 );
    assert( c->c_refcnt == 0 );
    assert( c->c_state == LLOAD_C_INVALID );

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

    listeners_reactivate();
}

Connection *
connection_init( ber_socket_t s, const char *peername, int flags )
{
    Connection *c;

    assert( peername != NULL );

    if ( s == AC_SOCKET_INVALID ) {
        Debug( LDAP_DEBUG_ANY, "connection_init: "
                "init of socket fd=%ld invalid\n",
                (long)s );
        return NULL;
    }

    assert( s >= 0 );

    c = ch_calloc( 1, sizeof(Connection) );

    c->c_fd = s;
    c->c_sb = ber_sockbuf_alloc();
    ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_FD, &s );

#ifdef LDAP_PF_LOCAL
    if ( flags & CONN_IS_IPC ) {
#ifdef LDAP_DEBUG
        ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_debug,
                LBER_SBIOD_LEVEL_PROVIDER, (void *)"ipc_" );
#endif
        ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_fd,
                LBER_SBIOD_LEVEL_PROVIDER, (void *)&s );
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

    c->c_next_msgid = 1;
    c->c_refcnt = c->c_live = 1;
    c->c_destroy = connection_destroy;

    LDAP_CIRCLEQ_ENTRY_INIT( c, c_next );

    ldap_pvt_thread_mutex_init( &c->c_mutex );
    ldap_pvt_thread_mutex_init( &c->c_io_mutex );

    connection_assign_nextid( c );

    Debug( LDAP_DEBUG_CONNS, "connection_init: "
            "connection connid=%lu allocated for socket fd=%d peername=%s\n",
            c->c_connid, s, peername );

    CONNECTION_LOCK(c);
    c->c_state = LLOAD_C_ACTIVE;

    return c;
}
