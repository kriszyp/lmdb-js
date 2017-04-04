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

#ifndef PROTO_SLAP_H
#define PROTO_SLAP_H

#include <ldap_cdefs.h>
#include "ldap_pvt.h"

#include <event2/event.h>

LDAP_BEGIN_DECL

struct config_args_s;  /* config.h */
struct config_reply_s; /* config.h */

/*
 * backend.c
 */

LDAP_SLAPD_F (void *) backend_connect( void *ctx, void *arg );
LDAP_SLAPD_F (Connection *) backend_select( Operation *op );

/*
 * ch_malloc.c
 */
LDAP_SLAPD_V (BerMemoryFunctions) ch_mfuncs;
LDAP_SLAPD_F (void *) ch_malloc( ber_len_t size );
LDAP_SLAPD_F (void *) ch_realloc( void *block, ber_len_t size );
LDAP_SLAPD_F (void *) ch_calloc( ber_len_t nelem, ber_len_t size );
LDAP_SLAPD_F (char *) ch_strdup( const char *string );
LDAP_SLAPD_F (void) ch_free( void * );

#ifndef CH_FREE
#undef free
#define free ch_free
#endif

/*
 * bind.c
 */
LDAP_SLAPD_F (void *) client_reset( void *ctx, void *arg );
LDAP_SLAPD_F (void *) client_bind( void *ctx, void *arg );

/*
 * client.c
 */
LDAP_SLAPD_F (Connection *) client_init( ber_socket_t s, Listener *url, const char *peername, struct event_base *base, int use_tls );
LDAP_SLAPD_F (void) client_write_cb( evutil_socket_t s, short what, void *arg );
LDAP_SLAPD_F (void) client_destroy( Connection *c );

/*
 * config.c
 */
LDAP_SLAPD_F (int) read_config( const char *fname, const char *dir );
LDAP_SLAPD_F (void) config_destroy( void );
LDAP_SLAPD_F (int) verb_to_mask( const char *word, slap_verbmasks *v );
LDAP_SLAPD_F (int) str2loglevel( const char *s, int *l );
LDAP_SLAPD_F (void) bindconf_tls_defaults( slap_bindconf *bc );
LDAP_SLAPD_F (void) bindconf_free( slap_bindconf *bc );

/*
 * connection.c
 */
LDAP_SLAPD_F (Connection *) connection_init( ber_socket_t s, const char *peername, int use_tls );
LDAP_SLAPD_F (void) connection_destroy( Connection *c );

/*
 * daemon.c
 */
LDAP_SLAPD_F (int) slapd_daemon_init( const char *urls );
LDAP_SLAPD_F (int) slapd_daemon_destroy( void );
LDAP_SLAPD_F (int) slapd_daemon( struct event_base *daemon_base );
LDAP_SLAPD_F (Listener **) slapd_get_listeners( void );
LDAP_SLAPD_F (struct event_base *) slap_get_base( ber_socket_t s );

LDAP_SLAPD_F (void) slap_sig_shutdown( evutil_socket_t sig, short what, void *arg );

LDAP_SLAPD_V (struct evdns_base *) dnsbase;
LDAP_SLAPD_V (volatile sig_atomic_t) slapd_shutdown;
LDAP_SLAPD_V (int) lloadd_inited;
LDAP_SLAPD_V (struct runqueue_s) slapd_rq;
LDAP_SLAPD_V (int) slapd_daemon_threads;
LDAP_SLAPD_V (int) slapd_daemon_mask;
#ifdef LDAP_TCP_BUFFER
LDAP_SLAPD_V (int) slapd_tcp_rmem;
LDAP_SLAPD_V (int) slapd_tcp_wmem;
#endif /* LDAP_TCP_BUFFER */

#define bvmatch( bv1, bv2 ) \
    ( ( (bv1)->bv_len == (bv2)->bv_len ) && \
            ( memcmp( (bv1)->bv_val, (bv2)->bv_val, (bv1)->bv_len ) == 0 ) )

/*
 * globals.c
 */
LDAP_SLAPD_V (const struct berval) slap_empty_bv;
LDAP_SLAPD_V (const struct berval) slap_unknown_bv;
LDAP_SLAPD_V (const struct berval) slap_true_bv;
LDAP_SLAPD_V (const struct berval) slap_false_bv;
LDAP_SLAPD_V (struct slap_sync_cookie_s) slap_sync_cookie;
LDAP_SLAPD_V (void *) slap_tls_ctx;
LDAP_SLAPD_V (LDAP *) slap_tls_ld;

/*
 * init.c
 */
LDAP_SLAPD_F (int) slap_init( int mode, const char *name );
LDAP_SLAPD_F (int) slap_destroy( void );

/*
 * libevent_support.c
 */
LDAP_SLAPD_F (int) lload_libevent_init( void );

/*
 * main.c
 */
LDAP_SLAPD_V (int) slapd_register_slp;
LDAP_SLAPD_V (const char *) slapd_slp_attrs;

/*
 * operation.c
 */
LDAP_SLAPD_F (const char *) slap_msgtype2str( ber_tag_t tag );
LDAP_SLAPD_F (int) operation_upstream_cmp( const void *l, const void *r );
LDAP_SLAPD_F (int) operation_client_cmp( const void *l, const void *r );
LDAP_SLAPD_F (Operation *) operation_init( Connection *c, BerElement *ber );
LDAP_SLAPD_F (void) operation_abandon( Operation *op );
LDAP_SLAPD_F (void) operation_send_reject( Operation *op, int result, const char *msg );
LDAP_SLAPD_F (void) operation_lost_upstream( Operation *op );
LDAP_SLAPD_F (void) operation_destroy( Operation *op );
LDAP_SLAPD_F (void *) request_process( void *ctx, void *arg );

/*
 * sl_malloc.c
 */
LDAP_SLAPD_F (void *) slap_sl_malloc( ber_len_t size, void *ctx );
LDAP_SLAPD_F (void *) slap_sl_realloc( void *block, ber_len_t size, void *ctx );
LDAP_SLAPD_F (void *) slap_sl_calloc( ber_len_t nelem, ber_len_t size, void *ctx );
LDAP_SLAPD_F (void) slap_sl_free( void *, void *ctx );

LDAP_SLAPD_V (BerMemoryFunctions) slap_sl_mfuncs;

LDAP_SLAPD_F (void) slap_sl_mem_init( void );
LDAP_SLAPD_F (void *) slap_sl_mem_create( ber_len_t size, int stack, void *ctx, int flag );
LDAP_SLAPD_F (void) slap_sl_mem_setctx( void *ctx, void *memctx );
LDAP_SLAPD_F (void) slap_sl_mem_destroy( void *key, void *data );
LDAP_SLAPD_F (void *) slap_sl_context( void *ptr );

/* assumes (x) > (y) returns 1 if true, 0 otherwise */
#define SLAP_PTRCMP(x, y) ( (x) < (y) ? -1 : (x) > (y) )

/*
 * upstream.c
 */
LDAP_SLAPD_F (void) upstream_write_cb( evutil_socket_t s, short what, void *arg );
LDAP_SLAPD_F (void) upstream_read_cb( evutil_socket_t s, short what, void *arg );
LDAP_SLAPD_F (Connection *) upstream_init( ber_socket_t s, Backend *b );
LDAP_SLAPD_F (void) upstream_destroy( Connection *c );

/*
 * user.c
 */
#if defined(HAVE_PWD_H) && defined(HAVE_GRP_H)
LDAP_SLAPD_F (void) slap_init_user( char *username, char *groupname );
#endif

/*
 * value.c
 */
LDAP_SLAPD_F (int) value_add_one( BerVarray *vals, struct berval *addval );

#ifdef SLAP_ZONE_ALLOC
/*
 * zn_malloc.c
 */
LDAP_SLAPD_F (void *) slap_zn_malloc( ber_len_t, void * );
LDAP_SLAPD_F (void *) slap_zn_realloc( void *, ber_len_t, void * );
LDAP_SLAPD_F (void *) slap_zn_calloc( ber_len_t, ber_len_t, void * );
LDAP_SLAPD_F (void) slap_zn_free( void *, void * );

LDAP_SLAPD_F (void *) slap_zn_mem_create( ber_len_t, ber_len_t, ber_len_t, ber_len_t );
LDAP_SLAPD_F (void) slap_zn_mem_destroy( void * );
LDAP_SLAPD_F (int) slap_zn_validate( void *, void *, int );
LDAP_SLAPD_F (int) slap_zn_invalidate( void *, void * );
LDAP_SLAPD_F (int) slap_zh_rlock( void * );
LDAP_SLAPD_F (int) slap_zh_runlock( void * );
LDAP_SLAPD_F (int) slap_zh_wlock( void * );
LDAP_SLAPD_F (int) slap_zh_wunlock( void * );
LDAP_SLAPD_F (int) slap_zn_rlock( void *, void * );
LDAP_SLAPD_F (int) slap_zn_runlock( void *, void * );
LDAP_SLAPD_F (int) slap_zn_wlock( void *, void * );
LDAP_SLAPD_F (int) slap_zn_wunlock( void *, void * );
#endif

LDAP_SLAPD_V (ber_len_t) sockbuf_max_incoming;
LDAP_SLAPD_V (ber_len_t) sockbuf_max_incoming_auth;
LDAP_SLAPD_V (int) slap_conn_max_pdus_per_cycle;

LDAP_SLAPD_V (lload_features_t) lload_features;

LDAP_SLAPD_V (slap_mask_t) global_allows;
LDAP_SLAPD_V (slap_mask_t) global_disallows;

LDAP_SLAPD_V (const char) Versionstr[];

LDAP_SLAPD_V (int) global_gentlehup;
LDAP_SLAPD_V (int) global_idletimeout;
LDAP_SLAPD_V (char *) global_host;
LDAP_SLAPD_V (int) lber_debug;
LDAP_SLAPD_V (int) ldap_syslog;

LDAP_SLAPD_V (char *) slapd_pid_file;
LDAP_SLAPD_V (char *) slapd_args_file;
LDAP_SLAPD_V (time_t) starttime;

/* use time(3) -- no mutex */
#define slap_get_time() time( NULL )

LDAP_SLAPD_V (ldap_pvt_thread_pool_t) connection_pool;
LDAP_SLAPD_V (int) connection_pool_max;
LDAP_SLAPD_V (int) connection_pool_queues;
LDAP_SLAPD_V (int) slap_tool_thread_max;

#ifdef USE_MP_BIGNUM
#define UI2BVX( bv, ui, ctx ) \
    do { \
        char *val; \
        ber_len_t len; \
        val = BN_bn2dec( ui ); \
        if (val) { \
            len = strlen( val ); \
            if ( len > (bv)->bv_len ) { \
                (bv)->bv_val = ber_memrealloc_x( (bv)->bv_val, len + 1, (ctx) ); \
            } \
            AC_MEMCPY( (bv)->bv_val, val, len + 1 ); \
            (bv)->bv_len = len; \
            OPENSSL_free( val ); \
        } else { \
            ber_memfree_x( (bv)->bv_val, (ctx) ); \
            BER_BVZERO( (bv) ); \
        } \
    } while (0)

#elif defined(USE_MP_GMP)
/* NOTE: according to the documentation, the result
 * of mpz_sizeinbase() can exceed the length of the
 * string representation of the number by 1
 */
#define UI2BVX( bv, ui, ctx ) \
    do { \
        ber_len_t len = mpz_sizeinbase( (ui), 10 ); \
        if ( len > (bv)->bv_len ) { \
            (bv)->bv_val = ber_memrealloc_x( (bv)->bv_val, len + 1, (ctx) ); \
        } \
        (void)mpz_get_str( (bv)->bv_val, 10, (ui) ); \
        if ( (bv)->bv_val[len - 1] == '\0' ) { \
            len--; \
        } \
        (bv)->bv_len = len; \
    } while (0)

#else
#ifdef USE_MP_LONG_LONG
#define UI2BV_FORMAT "%llu"
#elif defined USE_MP_LONG
#define UI2BV_FORMAT "%lu"
#elif defined HAVE_LONG_LONG
#define UI2BV_FORMAT "%llu"
#else
#define UI2BV_FORMAT "%lu"
#endif

#define UI2BVX( bv, ui, ctx ) \
    do { \
        char buf[LDAP_PVT_INTTYPE_CHARS(long)]; \
        ber_len_t len; \
        len = snprintf( buf, sizeof( buf ), UI2BV_FORMAT, (ui) ); \
        if ( len > (bv)->bv_len ) { \
            (bv)->bv_val = ber_memrealloc_x( (bv)->bv_val, len + 1, (ctx) ); \
        } \
        (bv)->bv_len = len; \
        AC_MEMCPY( (bv)->bv_val, buf, len + 1 ); \
    } while (0)
#endif

#define UI2BV( bv, ui ) UI2BVX( bv, ui, NULL )

LDAP_END_DECL

#endif /* PROTO_SLAP_H */
