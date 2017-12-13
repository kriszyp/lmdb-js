/* lload.h - load balancer include file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2015 The OpenLDAP Foundation.
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

#ifndef _LLOAD_H_
#define _LLOAD_H_

#include "ldap_defaults.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <sys/types.h>
#include <ac/syslog.h>
#include <ac/regex.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/time.h>
#include <ac/param.h>

#include "avl.h"

#include "../servers/slapd/slap.h"

#ifndef ldap_debug
#define ldap_debug slap_debug
#endif

#include "ldap_log.h"

#include <ldap.h>
#include <ldap_schema.h>

#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "ldap_pvt_thread.h"
#include "ldap_queue.h"

#include <event2/event.h>

LDAP_BEGIN_DECL

#ifdef SERVICE_NAME
#undef SERVICE_NAME
#endif

#define SERVICE_NAME OPENLDAP_PACKAGE "-lloadd"

#define LLOAD_SB_MAX_INCOMING_CLIENT ( ( 1 << 24 ) - 1 )
#define LLOAD_SB_MAX_INCOMING_UPSTREAM ( ( 1 << 24 ) - 1 )

#define LLOAD_CONN_MAX_PDUS_PER_CYCLE_DEFAULT 10

#define BER_BV_OPTIONAL( bv ) ( BER_BVISNULL( bv ) ? NULL : ( bv ) )

typedef struct LloadBackend LloadBackend;
typedef struct LloadPendingConnection LloadPendingConnection;
typedef struct LloadConnection LloadConnection;
typedef struct LloadOperation LloadOperation;
/* end of forward declarations */

typedef LDAP_CIRCLEQ_HEAD(BeSt, LloadBackend) lload_b_head;
typedef LDAP_CIRCLEQ_HEAD(ConnSt, LloadConnection) lload_c_head;

LDAP_SLAPD_V (lload_b_head) backend;
LDAP_SLAPD_V (lload_c_head) clients;
LDAP_SLAPD_V (ldap_pvt_thread_mutex_t) backend_mutex;
LDAP_SLAPD_V (LloadBackend *) current_backend;
LDAP_SLAPD_V (struct slap_bindconf) bindconf;
LDAP_SLAPD_V (struct berval) lloadd_identity;

typedef int lload_cf_aux_table_parse_x( struct berval *val,
        void *bc,
        slap_cf_aux_table *tab0,
        const char *tabmsg,
        int unparse );

typedef struct LloadListener LloadListener;

typedef enum {
#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
    LLOAD_FEATURE_VC = 1 << 0,
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */
    LLOAD_FEATURE_PROXYAUTHZ = 1 << 1,
} lload_features_t;

enum lload_tls_type {
    LLOAD_CLEARTEXT = 0,
    LLOAD_LDAPS,
    LLOAD_STARTTLS_OPTIONAL,
    LLOAD_STARTTLS,
    LLOAD_TLS_ESTABLISHED,
};

struct LloadPendingConnection {
    LloadBackend *backend;

    struct event *event;
    ber_socket_t fd;

    LDAP_LIST_ENTRY(LloadPendingConnection) next;
};

/* Can hold mutex when locking a linked connection */
struct LloadBackend {
    ldap_pvt_thread_mutex_t b_mutex;

    struct berval b_uri;
    int b_proto, b_port;
    enum lload_tls_type b_tls;
    char *b_host;

    int b_retry_timeout, b_failed;
    struct event *b_retry_event;
    struct timeval b_retry_tv;

    int b_numconns, b_numbindconns;
    int b_bindavail, b_active, b_opening;
    lload_c_head b_conns, b_bindconns, b_preparing;
    LDAP_LIST_HEAD(ConnectingSt, LloadPendingConnection) b_connecting;
    LloadConnection *b_last_conn, *b_last_bindconn;

    long b_max_pending, b_max_conn_pending;
    long b_n_ops_executing;

    LDAP_CIRCLEQ_ENTRY(LloadBackend) b_next;
};

typedef int (*LloadOperationHandler)( LloadConnection *client,
        LloadOperation *op,
        BerElement *ber );
typedef int (*RequestHandler)( LloadConnection *c, LloadOperation *op );
typedef struct lload_exop_handlers_t {
    struct berval oid;
    RequestHandler func;
} ExopHandler;

typedef int (*CONNECTION_PDU_CB)( LloadConnection *c );
typedef void (*CONNECTION_DESTROY_CB)( LloadConnection *c );

/* connection state (protected by c_mutex) */
enum sc_state {
    LLOAD_C_INVALID = 0, /* MUST BE ZERO (0) */
    LLOAD_C_READY,       /* ready */
    LLOAD_C_CLOSING,     /* closing */
    LLOAD_C_ACTIVE,      /* exclusive operation (tls setup, ...) in progress */
    LLOAD_C_BINDING,     /* binding */
};
enum sc_type {
    LLOAD_C_OPEN = 0,  /* regular connection */
    LLOAD_C_PREPARING, /* upstream connection not assigned yet */
    LLOAD_C_BIND, /* connection used to handle bind client requests if VC not enabled */
    LLOAD_C_PRIVILEGED, /* connection can override proxyauthz control */
};
/*
 * represents a connection from an ldap client/to ldap server
 */
struct LloadConnection {
    enum sc_state c_state; /* connection state */
    enum sc_type c_type;
    ber_socket_t c_fd;

/*
 * LloadConnection reference counting:
 * - connection has a reference counter in c_refcnt
 * - also a liveness/validity token is added to c_refcnt during
 *   lload_connection_init, its existence is tracked in c_live and is usually the
 *   only one that prevents it from being destroyed
 * - anyone who needs to be able to lock the connection after unlocking it has
 *   to use CONNECTION_UNLOCK_INCREF, they are then responsible that
 *   CONNECTION_LOCK_DECREF+CONNECTION_UNLOCK_OR_DESTROY is used when they are
 *   done with it
 * - when a connection is considered dead, use CONNECTION_DESTROY on a locked
 *   connection, it might get disposed of or if anyone still holds a token, it
 *   just gets unlocked and it's the last token holder's responsibility to run
 *   CONNECTION_UNLOCK_OR_DESTROY
 * - CONNECTION_LOCK_DESTROY is a shorthand for locking, decreasing refcount
 *   and CONNECTION_DESTROY
 */
    ldap_pvt_thread_mutex_t c_mutex; /* protect the connection */
    int c_refcnt, c_live;
    CONNECTION_DESTROY_CB c_destroy;
    CONNECTION_PDU_CB c_pdu_cb;
#define CONNECTION_LOCK(c) ldap_pvt_thread_mutex_lock( &(c)->c_mutex )
#define CONNECTION_UNLOCK(c) ldap_pvt_thread_mutex_unlock( &(c)->c_mutex )
#define CONNECTION_LOCK_DECREF(c) \
    do { \
        CONNECTION_LOCK(c); \
        (c)->c_refcnt--; \
    } while (0)
#define CONNECTION_UNLOCK_INCREF(c) \
    do { \
        (c)->c_refcnt++; \
        CONNECTION_UNLOCK(c); \
    } while (0)
#define CONNECTION_UNLOCK_OR_DESTROY(c) \
    do { \
        assert( (c)->c_refcnt >= 0 ); \
        if ( !( c )->c_refcnt ) { \
            Debug( LDAP_DEBUG_TRACE, "%s: destroying connection connid=%lu\n", \
                    __func__, (c)->c_connid ); \
            (c)->c_destroy( (c) ); \
            (c) = NULL; \
        } else { \
            CONNECTION_UNLOCK(c); \
        } \
    } while (0)
#define CONNECTION_DESTROY(c) \
    do { \
        (c)->c_refcnt -= (c)->c_live; \
        (c)->c_live = 0; \
        CONNECTION_UNLOCK_OR_DESTROY(c); \
    } while (0)
#define CONNECTION_LOCK_DESTROY(c) \
    do { \
        CONNECTION_LOCK_DECREF(c); \
        CONNECTION_DESTROY(c); \
    } while (0);

    Sockbuf *c_sb; /* ber connection stuff */

    /* set by connection_init */
    unsigned long c_connid;    /* unique id of this connection */
    struct berval c_peer_name; /* peer name (trans=addr:port) */
    time_t c_starttime;        /* when the connection was opened */

    time_t c_activitytime;  /* when the connection was last used */
    ber_int_t c_next_msgid; /* msgid of the next message */

    /* must not be used while holding either mutex */
    struct event *c_read_event, *c_write_event;
    struct timeval *c_read_timeout;

    /* can only be changed by binding thread */
    struct berval c_sasl_bind_mech; /* mech in progress */
    struct berval c_auth;           /* authcDN (possibly in progress) */

    unsigned long c_pin_id;

#ifdef LDAP_API_FEATURE_VERIFY_CREDENTIALS
    struct berval c_vc_cookie;
#endif /* LDAP_API_FEATURE_VERIFY_CREDENTIALS */

    /* Can be held while acquiring c_mutex to inject things into c_ops or
     * destroy the connection */
    ldap_pvt_thread_mutex_t c_io_mutex; /* only one pdu written at a time */

    BerElement *c_currentber; /* ber we're attempting to read */
    BerElement *c_pendingber; /* ber we're attempting to write */

    TAvlnode *c_ops; /* Operations pending on the connection */

#ifdef HAVE_TLS
    enum lload_tls_type c_is_tls; /* true if this LDAP over raw TLS */
#endif

    long c_n_ops_executing; /* num of ops currently executing */
    long c_n_ops_completed; /* num of ops completed */

    /*
     * Protected by the CIRCLEQ mutex:
     * - Client: clients_mutex
     * - Upstream: b->b_mutex
     */
    LDAP_CIRCLEQ_ENTRY(LloadConnection) c_next;

    void *c_private;
};

enum op_state {
    LLOAD_OP_NOT_FREEING = 0,
    LLOAD_OP_FREEING_UPSTREAM = 1 << 0,
    LLOAD_OP_FREEING_CLIENT = 1 << 1,
    LLOAD_OP_DETACHING_UPSTREAM = 1 << 2,
    LLOAD_OP_DETACHING_CLIENT = 1 << 3,
};
#define LLOAD_OP_FREEING_MASK \
    ( LLOAD_OP_FREEING_UPSTREAM | LLOAD_OP_FREEING_CLIENT )
#define LLOAD_OP_DETACHING_MASK \
    ( LLOAD_OP_DETACHING_UPSTREAM | LLOAD_OP_DETACHING_CLIENT )

struct LloadOperation {
    LloadConnection *o_client;
    unsigned long o_client_connid;
    int o_client_live, o_client_refcnt;
    ber_int_t o_client_msgid;

    LloadConnection *o_upstream;
    unsigned long o_upstream_connid;
    int o_upstream_live, o_upstream_refcnt;
    ber_int_t o_upstream_msgid;
    time_t o_last_response;

    /* Protects o_client, o_upstream pointers before we lock their c_mutex if
     * we don't know they are still alive */
    ldap_pvt_thread_mutex_t o_link_mutex;
    /* Protects o_freeing, can be locked while holding c_mutex */
    ldap_pvt_thread_mutex_t o_mutex;
    /* Consistent w.r.t. o_mutex, only written to while holding
     * op->o_{client,upstream}->c_mutex */
    enum op_state o_freeing;
    ber_tag_t o_tag;
    time_t o_start;
    unsigned long o_pin_id;

    BerElement *o_ber;
    BerValue o_request, o_ctrls;
};

/*
 * listener; need to access it from monitor backend
 */
struct LloadListener {
    struct berval sl_url;
    struct berval sl_name;
    mode_t sl_perms;
#ifdef HAVE_TLS
    int sl_is_tls;
#endif
    struct event_base *base;
    struct evconnlistener *listener;
    int sl_mute; /* Listener is temporarily disabled due to emfile */
    int sl_busy; /* Listener is busy (accept thread activated) */
    ber_socket_t sl_sd;
    Sockaddr sl_sa;
#define sl_addr sl_sa.sa_in_addr
#define LDAP_TCP_BUFFER
#ifdef LDAP_TCP_BUFFER
    int sl_tcp_rmem; /* custom TCP read buffer size */
    int sl_tcp_wmem; /* custom TCP write buffer size */
#endif
};

LDAP_END_DECL

#include "proto-lload.h"
#endif /* _LLOAD_H_ */
