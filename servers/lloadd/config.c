/* config.c - configuration file handling routines */
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

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifndef S_ISREG
#define S_ISREG(m) ( ((m) & _S_IFMT ) == _S_IFREG )
#endif

#include "slap.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "config.h"

#ifdef _WIN32
#define LUTIL_ATOULX lutil_atoullx
#define Z "I"
#else
#define LUTIL_ATOULX lutil_atoulx
#define Z "z"
#endif

#define ARGS_STEP 512

/*
 * defaults for various global variables
 */
slap_mask_t global_allows = 0;
slap_mask_t global_disallows = 0;
int global_gentlehup = 0;
int global_idletimeout = 0;
char *global_host = NULL;

static FILE *logfile;
static char *logfileName;

lload_features_t lload_features;

ber_len_t sockbuf_max_incoming = SLAP_SB_MAX_INCOMING_DEFAULT;
ber_len_t sockbuf_max_incoming_auth = SLAP_SB_MAX_INCOMING_AUTH;

int slap_conn_max_pdus_per_cycle = SLAP_CONN_MAX_PDUS_PER_CYCLE_DEFAULT;

char *slapd_pid_file = NULL;
char *slapd_args_file = NULL;

static int fp_getline( FILE *fp, ConfigArgs *c );
static void fp_getline_init( ConfigArgs *c );

static char *strtok_quote(
        char *line,
        char *sep,
        char **quote_ptr,
        int *inquote );

typedef struct ConfigFile {
    struct ConfigFile *c_sibs;
    struct ConfigFile *c_kids;
    struct berval c_file;
    BerVarray c_dseFiles;
} ConfigFile;

static ConfigFile *cfn;

static ConfigDriver config_fname;
static ConfigDriver config_generic;
static ConfigDriver config_backend;
#ifdef LDAP_TCP_BUFFER
static ConfigDriver config_tcp_buffer;
#endif /* LDAP_TCP_BUFFER */
static ConfigDriver config_restrict;
static ConfigDriver config_loglevel;
static ConfigDriver config_include;
static ConfigDriver config_feature;
#ifdef HAVE_TLS
static ConfigDriver config_tls_option;
static ConfigDriver config_tls_config;
#endif

slap_b_head backend = LDAP_STAILQ_HEAD_INITIALIZER(backend);

enum {
    CFG_ACL = 1,
    CFG_BACKEND,
    CFG_DATABASE,
    CFG_TLS_RAND,
    CFG_TLS_CIPHER,
    CFG_TLS_PROTOCOL_MIN,
    CFG_TLS_CERT_FILE,
    CFG_TLS_CERT_KEY,
    CFG_TLS_CA_PATH,
    CFG_TLS_CA_FILE,
    CFG_TLS_DH_FILE,
    CFG_TLS_VERIFY,
    CFG_TLS_CRLCHECK,
    CFG_TLS_CRL_FILE,
    CFG_CONCUR,
    CFG_THREADS,
    CFG_LOGFILE,
    CFG_MIRRORMODE,
    CFG_LTHREADS,
    CFG_THREADQS,
    CFG_TLS_ECNAME,
    CFG_TLS_CACERT,
    CFG_TLS_CERT,
    CFG_TLS_KEY,
    CFG_RESCOUNT,

    CFG_LAST
};

/* alphabetical ordering */

static ConfigTable config_back_cf_table[] = {
    /* This attr is read-only */
    { "", "", 0, 0, 0,
        ARG_MAGIC,
        &config_fname,
    },
    { "argsfile", "file", 2, 2, 0,
        ARG_STRING,
        &slapd_args_file,
    },
    { "concurrency", "level", 2, 2, 0,
        ARG_INT|ARG_MAGIC|CFG_CONCUR,
        &config_generic,
    },
    { "backend", "type", 2, 0, 0,
        ARG_MAGIC|CFG_DATABASE,
        &config_backend,
    },
    { "gentlehup", "on|off", 2, 2, 0,
#ifdef SIGHUP
        ARG_ON_OFF,
        &global_gentlehup,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "idletimeout", "timeout", 2, 2, 0,
        ARG_INT,
        &global_idletimeout,
    },
    { "include", "file", 2, 2, 0,
        ARG_MAGIC,
        &config_include,
    },
    { "listener-threads", "count", 2, 0, 0,
        ARG_UINT|ARG_MAGIC|CFG_LTHREADS,
        &config_generic,
    },
    { "logfile", "file", 2, 2, 0,
        ARG_STRING|ARG_MAGIC|CFG_LOGFILE,
        &config_generic,
    },
    { "loglevel", "level", 2, 0, 0,
        ARG_MAGIC,
        &config_loglevel,
    },
    { "pidfile", "file", 2, 2, 0,
        ARG_STRING,
        &slapd_pid_file,
    },
    { "restrict", "op_list", 2, 0, 0,
        ARG_MAGIC,
        &config_restrict,
    },
    { "sockbuf_max_incoming", "max", 2, 2, 0,
        ARG_BER_LEN_T,
        &sockbuf_max_incoming,
    },
    { "sockbuf_max_incoming_auth", "max", 2, 2, 0,
        ARG_BER_LEN_T,
        &sockbuf_max_incoming_auth,
    },
    { "tcp-buffer", "[listener=<listener>] [{read|write}=]size", 0, 0, 0,
#ifdef LDAP_TCP_BUFFER
        ARG_MAGIC,
        &config_tcp_buffer,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "threads", "count", 2, 2, 0,
        ARG_INT|ARG_MAGIC|CFG_THREADS,
        &config_generic,
    },
    { "threadqueues", "count", 2, 2, 0,
        ARG_INT|ARG_MAGIC|CFG_THREADQS,
        &config_generic,
    },
    { "max_pdus_per_cycle", "count", 2, 2, 0,
        ARG_INT|ARG_MAGIC|CFG_RESCOUNT,
        &config_generic,
    },
    { "feature", "name", 2, 0, 0,
        ARG_MAGIC,
        &config_feature,
    },
    { "TLSCACertificate", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CACERT|ARG_BINARY|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCACertificateFile", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CA_FILE|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCACertificatePath", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CA_PATH|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCertificate", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CERT|ARG_BINARY|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCertificateFile", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CERT_FILE|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCertificateKey", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_KEY|ARG_BINARY|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCertificateKeyFile", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CERT_KEY|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCipherSuite", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_CIPHER|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCRLCheck", NULL, 2, 2, 0,
#if defined(HAVE_TLS) && defined(HAVE_OPENSSL)
        CFG_TLS_CRLCHECK|ARG_STRING|ARG_MAGIC,
        &config_tls_config,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSCRLFile", NULL, 2, 2, 0,
#if defined(HAVE_GNUTLS)
        CFG_TLS_CRL_FILE|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSRandFile", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_RAND|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSVerifyClient", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_VERIFY|ARG_STRING|ARG_MAGIC,
        &config_tls_config,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSDHParamFile", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_DH_FILE|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSECName", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_ECNAME|ARG_STRING|ARG_MAGIC,
        &config_tls_option,
#else
        ARG_IGNORED,
        NULL,
#endif
    },
    { "TLSProtocolMin", NULL, 2, 2, 0,
#ifdef HAVE_TLS
        CFG_TLS_PROTOCOL_MIN|ARG_STRING|ARG_MAGIC,
        &config_tls_config,
#else
        ARG_IGNORED,
        NULL,
#endif
    },

    { NULL, NULL, 0, 0, 0, ARG_IGNORED, NULL }
};

static int
config_generic( ConfigArgs *c )
{
    switch ( c->type ) {
        case CFG_CONCUR:
            ldap_pvt_thread_set_concurrency( c->value_int );
            break;

        case CFG_THREADS:
            if ( c->value_int < 2 ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg),
                        "threads=%d smaller than minimum value 2",
                        c->value_int );
                Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
                return 1;

            } else if ( c->value_int > 2 * SLAP_MAX_WORKER_THREADS ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg),
                        "warning, threads=%d larger than twice the default "
                        "(2*%d=%d); YMMV",
                        c->value_int, SLAP_MAX_WORKER_THREADS,
                        2 * SLAP_MAX_WORKER_THREADS );
                Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
            }
            if ( slapMode & SLAP_SERVER_MODE )
                ldap_pvt_thread_pool_maxthreads(
                        &connection_pool, c->value_int );
            connection_pool_max = c->value_int; /* save for reference */
            break;

        case CFG_THREADQS:
            if ( c->value_int < 1 ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg),
                        "threadqueues=%d smaller than minimum value 1",
                        c->value_int );
                Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
                return 1;
            }
            if ( slapMode & SLAP_SERVER_MODE )
                ldap_pvt_thread_pool_queues( &connection_pool, c->value_int );
            connection_pool_queues = c->value_int; /* save for reference */
            break;

        case CFG_LTHREADS: {
            int mask = 0;
            /* use a power of two */
            while ( c->value_uint > 1 ) {
                c->value_uint >>= 1;
                mask <<= 1;
                mask |= 1;
            }
            slapd_daemon_mask = mask;
            slapd_daemon_threads = mask + 1;
        } break;

        case CFG_LOGFILE: {
            if ( logfileName ) ch_free( logfileName );
            logfileName = c->value_string;
            logfile = fopen( logfileName, "w" );
            if ( logfile ) lutil_debug_file( logfile );
        } break;

        case CFG_RESCOUNT:
            if ( c->value_int < 0 ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg),
                        "max_pdus_per_cycle=%d invalid", c->value_int );
                Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
                return 1;
            }
            slap_conn_max_pdus_per_cycle = c->value_int;
            break;

        default:
            Debug( LDAP_DEBUG_ANY, "%s: unknown CFG_TYPE %d.\n",
                    c->log, c->type );
            return 1;
    }
    return 0;
}

static int
config_backend( ConfigArgs *c )
{
    int i, tmp, rc = -1;
    LDAPURLDesc *lud = NULL;
    Backend *b;

    b = ch_calloc( 1, sizeof(Backend) );

    LDAP_LIST_INIT( &b->b_conns );
    LDAP_LIST_INIT( &b->b_bindconns );

    b->b_numconns = 1;
    b->b_numbindconns = 1;

    for ( i = 1; i < c->argc; i++ ) {
        if ( bindconf_parse( c->argv[i], b ) ) {
            Debug( LDAP_DEBUG_ANY, "config_backend: "
                    "error parsing backend configuration item '%s'\n",
                    c->argv[i] );
            rc = -1;
            goto done;
        }
    }

    bindconf_tls_defaults( &b->b_bindconf );

    if ( b->b_bindconf.sb_method == LDAP_AUTH_SASL ) {
#ifndef HAVE_CYRUS_SASL
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "no sasl support available\n" );
        rc = -1;
        goto done;
#else /* HAVE_CYRUS_SASL */
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "no sasl support yet\n" );
        rc = -1;
        goto done;
#endif
    }

    if ( b->b_numconns <= 0 ) {
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "invalid connection pool configuration\n" );
        rc = -1;
        goto done;
    }

    if ( b->b_numbindconns <= 0 ) {
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "invalid bind connection pool configuration\n" );
        rc = -1;
        goto done;
    }

    if ( b->b_retry_timeout < 0 ) {
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "invalid retry timeout configuration\n" );
        rc = -1;
        goto done;
    }
    b->b_retry_tv.tv_sec = b->b_retry_timeout / 1000;
    b->b_retry_tv.tv_usec = ( b->b_retry_timeout % 1000 ) * 1000;

    if ( BER_BVISNULL( &b->b_bindconf.sb_uri ) ) {
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "backend address not specified\n" );
        rc = -1;
        goto done;
    }

    rc = ldap_url_parse( b->b_bindconf.sb_uri.bv_val, &lud );
    if ( rc != LDAP_URL_SUCCESS ) {
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "listen URL \"%s\" parse error=%d\n",
                b->b_bindconf.sb_uri.bv_val, rc );
        rc = -1;
        goto done;
    }

#ifndef HAVE_TLS
    if ( ldap_pvt_url_scheme2tls( lud->lud_scheme ) ) {
        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "TLS not supported (%s)\n",
                b->b_bindconf.sb_uri.bv_val );
        rc = -1;
        goto done;
    }

    if ( !lud->lud_port ) {
        b->b_port = LDAP_PORT;
    } else {
        b->b_port = lud->lud_port;
    }

#else /* HAVE_TLS */
    tmp = ldap_pvt_url_scheme2tls( lud->lud_scheme );
    if ( tmp ) {
        b->b_tls = LLOAD_LDAPS;
    }

    if ( !lud->lud_port ) {
        b->b_port = b->b_tls ? LDAPS_PORT : LDAP_PORT;
    } else {
        b->b_port = lud->lud_port;
    }
#endif /* HAVE_TLS */

    b->b_proto = tmp = ldap_pvt_url_scheme2proto( lud->lud_scheme );
    if ( tmp == LDAP_PROTO_IPC ) {
#ifdef LDAP_PF_LOCAL
        if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
            b->b_host = ch_strdup( LDAPI_SOCK );
        }
#else /* ! LDAP_PF_LOCAL */

        Debug( LDAP_DEBUG_ANY, "config_backend: "
                "URL scheme not supported: %s",
                url );
        rc = -1;
        goto done;
#endif /* ! LDAP_PF_LOCAL */
    } else {
        if ( lud->lud_host == NULL || lud->lud_host[0] == '\0' ) {
            Debug( LDAP_DEBUG_ANY, "config_backend: "
                    "backend url missing hostname: '%s'\n",
                    b->b_bindconf.sb_uri.bv_val );
            rc = -1;
            goto done;
        }
    }
    if ( !b->b_host ) {
        b->b_host = ch_strdup( lud->lud_host );
    }

    ldap_pvt_thread_mutex_init( &b->b_mutex );

done:
    ldap_free_urldesc( lud );
    if ( rc ) {
        ch_free( b );
    } else {
        LDAP_STAILQ_INSERT_TAIL( &backend, b, b_next );
    }

    return rc;
}

static int
config_fname( ConfigArgs *c )
{
    return 0;
}

/*
 * [listener=<listener>] [{read|write}=]<size>
 */

#ifdef LDAP_TCP_BUFFER
static BerVarray tcp_buffer;
int tcp_buffer_num;

#define SLAP_TCP_RMEM ( 0x1U )
#define SLAP_TCP_WMEM ( 0x2U )

static int
tcp_buffer_parse(
        struct berval *val,
        int argc,
        char **argv,
        int *size,
        int *rw,
        Listener **l )
{
    int i, rc = LDAP_SUCCESS;
    LDAPURLDesc *lud = NULL;
    char *ptr;

    if ( val != NULL && argv == NULL ) {
        char *s = val->bv_val;

        argv = ldap_str2charray( s, " \t" );
        if ( argv == NULL ) {
            return LDAP_OTHER;
        }
    }

    i = 0;
    if ( strncasecmp( argv[i], "listener=", STRLENOF("listener=") ) == 0 ) {
        char *url = argv[i] + STRLENOF("listener=");

        if ( ldap_url_parse( url, &lud ) ) {
            rc = LDAP_INVALID_SYNTAX;
            goto done;
        }

        *l = config_check_my_url( url, lud );
        if ( *l == NULL ) {
            rc = LDAP_NO_SUCH_ATTRIBUTE;
            goto done;
        }

        i++;
    }

    ptr = argv[i];
    if ( strncasecmp( ptr, "read=", STRLENOF("read=") ) == 0 ) {
        *rw |= SLAP_TCP_RMEM;
        ptr += STRLENOF("read=");

    } else if ( strncasecmp( ptr, "write=", STRLENOF("write=") ) == 0 ) {
        *rw |= SLAP_TCP_WMEM;
        ptr += STRLENOF("write=");

    } else {
        *rw |= ( SLAP_TCP_RMEM | SLAP_TCP_WMEM );
    }

    /* accept any base */
    if ( lutil_atoix( size, ptr, 0 ) ) {
        rc = LDAP_INVALID_SYNTAX;
        goto done;
    }

done:;
    if ( val != NULL && argv != NULL ) {
        ldap_charray_free( argv );
    }

    if ( lud != NULL ) {
        ldap_free_urldesc( lud );
    }

    return rc;
}

static int
tcp_buffer_unparse( int size, int rw, Listener *l, struct berval *val )
{
    char buf[sizeof("2147483648")], *ptr;

    /* unparse for later use */
    val->bv_len = snprintf( buf, sizeof(buf), "%d", size );
    if ( l != NULL ) {
        val->bv_len += STRLENOF( "listener="
                                 " " ) +
                l->sl_url.bv_len;
    }

    if ( rw != ( SLAP_TCP_RMEM | SLAP_TCP_WMEM ) ) {
        if ( rw & SLAP_TCP_RMEM ) {
            val->bv_len += STRLENOF("read=");
        } else if ( rw & SLAP_TCP_WMEM ) {
            val->bv_len += STRLENOF("write=");
        }
    }

    val->bv_val = SLAP_MALLOC( val->bv_len + 1 );

    ptr = val->bv_val;

    if ( l != NULL ) {
        ptr = lutil_strcopy( ptr, "listener=" );
        ptr = lutil_strncopy( ptr, l->sl_url.bv_val, l->sl_url.bv_len );
        *ptr++ = ' ';
    }

    if ( rw != ( SLAP_TCP_RMEM | SLAP_TCP_WMEM ) ) {
        if ( rw & SLAP_TCP_RMEM ) {
            ptr = lutil_strcopy( ptr, "read=" );
        } else if ( rw & SLAP_TCP_WMEM ) {
            ptr = lutil_strcopy( ptr, "write=" );
        }
    }

    ptr = lutil_strcopy( ptr, buf );
    *ptr = '\0';

    assert( val->bv_val + val->bv_len == ptr );

    return LDAP_SUCCESS;
}

static int
tcp_buffer_add_one( int argc, char **argv )
{
    int rc = 0;
    int size = -1, rw = 0;
    Listener *l = NULL;

    struct berval val;

    /* parse */
    rc = tcp_buffer_parse( NULL, argc, argv, &size, &rw, &l );
    if ( rc != 0 ) {
        return rc;
    }

    /* unparse for later use */
    rc = tcp_buffer_unparse( size, rw, l, &val );
    if ( rc != LDAP_SUCCESS ) {
        return rc;
    }

    /* use parsed values */
    if ( l != NULL ) {
        int i;
        Listener **ll = slapd_get_listeners();

        for ( i = 0; ll[i] != NULL; i++ ) {
            if ( ll[i] == l ) break;
        }

        if ( ll[i] == NULL ) {
            return LDAP_NO_SUCH_ATTRIBUTE;
        }

        /* buffer only applies to TCP listeners;
         * we do not do any check here, and delegate them
         * to setsockopt(2) */
        if ( rw & SLAP_TCP_RMEM ) l->sl_tcp_rmem = size;
        if ( rw & SLAP_TCP_WMEM ) l->sl_tcp_wmem = size;

        for ( i++; ll[i] != NULL && bvmatch( &l->sl_url, &ll[i]->sl_url );
                i++ ) {
            if ( rw & SLAP_TCP_RMEM ) ll[i]->sl_tcp_rmem = size;
            if ( rw & SLAP_TCP_WMEM ) ll[i]->sl_tcp_wmem = size;
        }

    } else {
        /* NOTE: this affects listeners without a specific setting,
         * does not set all listeners */
        if ( rw & SLAP_TCP_RMEM ) slapd_tcp_rmem = size;
        if ( rw & SLAP_TCP_WMEM ) slapd_tcp_wmem = size;
    }

    tcp_buffer = SLAP_REALLOC(
            tcp_buffer, sizeof(struct berval) * ( tcp_buffer_num + 2 ) );
    /* append */
    tcp_buffer[tcp_buffer_num] = val;

    tcp_buffer_num++;
    BER_BVZERO( &tcp_buffer[tcp_buffer_num] );

    return rc;
}

static int
config_tcp_buffer( ConfigArgs *c )
{
    int rc;

    rc = tcp_buffer_add_one( c->argc - 1, &c->argv[1] );
    if ( rc ) {
        snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> unable to add value #%d",
                c->argv[0], tcp_buffer_num );
        Debug( LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->cr_msg );
        return 1;
    }

    return 0;
}
#endif /* LDAP_TCP_BUFFER */

static int
config_restrict( ConfigArgs *c )
{
    slap_mask_t restrictops = 0;
    int i;
    slap_verbmasks restrictable_ops[] = {
        { BER_BVC("bind"), SLAP_RESTRICT_OP_BIND },
        { BER_BVC("add"), SLAP_RESTRICT_OP_ADD },
        { BER_BVC("modify"), SLAP_RESTRICT_OP_MODIFY },
        { BER_BVC("rename"), SLAP_RESTRICT_OP_RENAME },
        { BER_BVC("modrdn"), 0 },
        { BER_BVC("delete"), SLAP_RESTRICT_OP_DELETE },
        { BER_BVC("search"), SLAP_RESTRICT_OP_SEARCH },
        { BER_BVC("compare"), SLAP_RESTRICT_OP_COMPARE },
        { BER_BVC("read"), SLAP_RESTRICT_OP_READS },
        { BER_BVC("write"), SLAP_RESTRICT_OP_WRITES },
        { BER_BVC("extended"), SLAP_RESTRICT_OP_EXTENDED },
        { BER_BVC("extended=" LDAP_EXOP_START_TLS), SLAP_RESTRICT_EXOP_START_TLS },
        { BER_BVC("extended=" LDAP_EXOP_MODIFY_PASSWD), SLAP_RESTRICT_EXOP_MODIFY_PASSWD },
        { BER_BVC("extended=" LDAP_EXOP_X_WHO_AM_I), SLAP_RESTRICT_EXOP_WHOAMI },
        { BER_BVC("extended=" LDAP_EXOP_X_CANCEL), SLAP_RESTRICT_EXOP_CANCEL },
        { BER_BVC("all"), SLAP_RESTRICT_OP_ALL },
        { BER_BVNULL, 0 }
    };

    i = verbs_to_mask( c->argc, c->argv, restrictable_ops, &restrictops );
    if ( i ) {
        snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> unknown operation",
                c->argv[0] );
        Debug( LDAP_DEBUG_ANY, "%s: %s %s\n",
                c->log, c->cr_msg, c->argv[i] );
        return 1;
    }
    if ( restrictops & SLAP_RESTRICT_OP_EXTENDED )
        restrictops &= ~SLAP_RESTRICT_EXOP_MASK;
    return 0;
}

static slap_verbmasks *loglevel_ops;

static int
loglevel_init( void )
{
    slap_verbmasks lo[] = {
        { BER_BVC("Any"), (slap_mask_t)LDAP_DEBUG_ANY },
        { BER_BVC("Trace"), LDAP_DEBUG_TRACE },
        { BER_BVC("Packets"), LDAP_DEBUG_PACKETS },
        { BER_BVC("Args"), LDAP_DEBUG_ARGS },
        { BER_BVC("Conns"), LDAP_DEBUG_CONNS },
        { BER_BVC("BER"), LDAP_DEBUG_BER },
        { BER_BVC("Filter"), LDAP_DEBUG_FILTER },
        { BER_BVC("Config"), LDAP_DEBUG_CONFIG },
        { BER_BVC("ACL"), LDAP_DEBUG_ACL },
        { BER_BVC("Stats"), LDAP_DEBUG_STATS },
        { BER_BVC("Stats2"), LDAP_DEBUG_STATS2 },
        { BER_BVC("Shell"), LDAP_DEBUG_SHELL },
        { BER_BVC("Parse"), LDAP_DEBUG_PARSE },
        { BER_BVC("Sync"), LDAP_DEBUG_SYNC },
        { BER_BVC("None"), LDAP_DEBUG_NONE },
        { BER_BVNULL, 0 }
    };

    return slap_verbmasks_init( &loglevel_ops, lo );
}

static void
loglevel_destroy( void )
{
    if ( loglevel_ops ) {
        (void)slap_verbmasks_destroy( loglevel_ops );
    }
    loglevel_ops = NULL;
}

int
str2loglevel( const char *s, int *l )
{
    int i;

    if ( loglevel_ops == NULL ) {
        loglevel_init();
    }

    i = verb_to_mask( s, loglevel_ops );

    if ( BER_BVISNULL( &loglevel_ops[i].word ) ) {
        return -1;
    }

    *l = loglevel_ops[i].mask;

    return 0;
}

int
loglevel2bvarray( int l, BerVarray *bva )
{
    if ( loglevel_ops == NULL ) {
        loglevel_init();
    }

    if ( l == 0 ) {
        struct berval bv = BER_BVC("0");
        return value_add_one( bva, &bv );
    }

    return mask_to_verbs( loglevel_ops, l, bva );
}

int
loglevel_print( FILE *out )
{
    int i;

    if ( loglevel_ops == NULL ) {
        loglevel_init();
    }

    fprintf( out, "Installed log subsystems:\n\n" );
    for ( i = 0; !BER_BVISNULL( &loglevel_ops[i].word ); i++ ) {
        unsigned mask = loglevel_ops[i].mask & 0xffffffffUL;
        fprintf( out,
                ( mask == ( (slap_mask_t)-1 & 0xffffffffUL ) ?
                                "\t%-30s (-1, 0xffffffff)\n" :
                                "\t%-30s (%u, 0x%x)\n" ),
                loglevel_ops[i].word.bv_val, mask, mask );
    }

    fprintf( out,
            "\nNOTE: custom log subsystems may be later installed "
            "by specific code\n\n" );

    return 0;
}

static int config_syslog;

static int
config_loglevel( ConfigArgs *c )
{
    int i;

    if ( loglevel_ops == NULL ) {
        loglevel_init();
    }

    if ( c->op == SLAP_CONFIG_EMIT ) {
        /* Get default or commandline slapd setting */
        if ( ldap_syslog && !config_syslog ) config_syslog = ldap_syslog;
        return loglevel2bvarray( config_syslog, &c->rvalue_vals );

    } else if ( c->op == LDAP_MOD_DELETE ) {
        if ( !c->line ) {
            config_syslog = 0;
        } else {
            i = verb_to_mask( c->line, loglevel_ops );
            config_syslog &= ~loglevel_ops[i].mask;
        }
        if ( slapMode & SLAP_SERVER_MODE ) {
            ldap_syslog = config_syslog;
        }
        return 0;
    }

    for ( i = 1; i < c->argc; i++ ) {
        int level;

        if ( isdigit( (unsigned char)c->argv[i][0] ) || c->argv[i][0] == '-' ) {
            if ( lutil_atoix( &level, c->argv[i], 0 ) != 0 ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg),
                        "<%s> unable to parse level",
                        c->argv[0] );
                Debug( LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
                        c->log, c->cr_msg, c->argv[i] );
                return 1;
            }
        } else {
            if ( str2loglevel( c->argv[i], &level ) ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> unknown level",
                        c->argv[0] );
                Debug( LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
                        c->log, c->cr_msg, c->argv[i] );
                return 1;
            }
        }
        /* Explicitly setting a zero clears all the levels */
        if ( level )
            config_syslog |= level;
        else
            config_syslog = 0;
    }
    if ( slapMode & SLAP_SERVER_MODE ) {
        ldap_syslog = config_syslog;
    }
    return 0;
}

static int
config_include( ConfigArgs *c )
{
    int savelineno = c->lineno;
    int rc;
    ConfigFile *cf;
    ConfigFile *cfsave = cfn;
    ConfigFile *cf2 = NULL;

    /* Leftover from RE23. No dynamic config for include files */
    if ( c->op == SLAP_CONFIG_EMIT || c->op == LDAP_MOD_DELETE ) return 1;

    cf = ch_calloc( 1, sizeof(ConfigFile) );
    if ( cfn->c_kids ) {
        for ( cf2 = cfn->c_kids; cf2 && cf2->c_sibs; cf2 = cf2->c_sibs )
            /* empty */;
        cf2->c_sibs = cf;
    } else {
        cfn->c_kids = cf;
    }
    cfn = cf;
    ber_str2bv( c->argv[1], 0, 1, &cf->c_file );
    rc = read_config_file( c->argv[1], c->depth + 1, c, config_back_cf_table );
    c->lineno = savelineno - 1;
    cfn = cfsave;
    if ( rc ) {
        if ( cf2 )
            cf2->c_sibs = NULL;
        else
            cfn->c_kids = NULL;
        ch_free( cf->c_file.bv_val );
        ch_free( cf );
    } else {
        c->ca_private = cf;
    }
    return rc;
}

static int
config_feature( ConfigArgs *c )
{
    slap_verbmasks features[] = {
        { BER_BVC("vc"), LLOAD_FEATURE_VC },
        { BER_BVC("proxyauthz"), LLOAD_FEATURE_PROXYAUTHZ },
        { BER_BVNULL, 0 }
    };
    slap_mask_t mask = 0;
    int i;

    i = verbs_to_mask( c->argc, c->argv, features, &mask );
    if ( i ) {
        Debug( LDAP_DEBUG_ANY, "%s: <%s> unknown feature %s\n", c->log,
                c->argv[0], c->argv[i] );
        return 1;
    }
    lload_features |= mask;
    return 0;
}

#ifdef HAVE_TLS
static int
config_tls_cleanup( ConfigArgs *c )
{
    int rc = 0;

    if ( slap_tls_ld ) {
        int opt = 1;

        ldap_pvt_tls_ctx_free( slap_tls_ctx );
        slap_tls_ctx = NULL;

        /* Force new ctx to be created */
        rc = ldap_pvt_tls_set_option(
                slap_tls_ld, LDAP_OPT_X_TLS_NEWCTX, &opt );
        if ( rc == 0 ) {
            /* The ctx's refcount is bumped up here */
            ldap_pvt_tls_get_option(
                    slap_tls_ld, LDAP_OPT_X_TLS_CTX, &slap_tls_ctx );
        } else {
            if ( rc == LDAP_NOT_SUPPORTED )
                rc = LDAP_UNWILLING_TO_PERFORM;
            else
                rc = LDAP_OTHER;
        }
    }
    return rc;
}

static int
config_tls_option( ConfigArgs *c )
{
    int flag, rc;
    int berval = 0;
    LDAP *ld = slap_tls_ld;
    switch ( c->type ) {
        case CFG_TLS_RAND:
            flag = LDAP_OPT_X_TLS_RANDOM_FILE;
            ld = NULL;
            break;
        case CFG_TLS_CIPHER:
            flag = LDAP_OPT_X_TLS_CIPHER_SUITE;
            break;
        case CFG_TLS_CERT_FILE:
            flag = LDAP_OPT_X_TLS_CERTFILE;
            break;
        case CFG_TLS_CERT_KEY:
            flag = LDAP_OPT_X_TLS_KEYFILE;
            break;
        case CFG_TLS_CA_PATH:
            flag = LDAP_OPT_X_TLS_CACERTDIR;
            break;
        case CFG_TLS_CA_FILE:
            flag = LDAP_OPT_X_TLS_CACERTFILE;
            break;
        case CFG_TLS_DH_FILE:
            flag = LDAP_OPT_X_TLS_DHFILE;
            break;
        case CFG_TLS_ECNAME:
            flag = LDAP_OPT_X_TLS_ECNAME;
            break;
#ifdef HAVE_GNUTLS
        case CFG_TLS_CRL_FILE:
            flag = LDAP_OPT_X_TLS_CRLFILE;
            break;
#endif
        case CFG_TLS_CACERT:
            flag = LDAP_OPT_X_TLS_CACERT;
            berval = 1;
            break;
        case CFG_TLS_CERT:
            flag = LDAP_OPT_X_TLS_CERT;
            berval = 1;
            break;
        case CFG_TLS_KEY:
            flag = LDAP_OPT_X_TLS_KEY;
            berval = 1;
            break;
        default:
            Debug( LDAP_DEBUG_ANY, "%s: "
                    "unknown tls_option <0x%x>\n",
                    c->log, c->type );
            return 1;
    }
    if ( c->op == SLAP_CONFIG_EMIT ) {
        return ldap_pvt_tls_get_option( ld, flag,
                berval ? (void *)&c->value_bv : (void *)&c->value_string );
    } else if ( c->op == LDAP_MOD_DELETE ) {
        config_push_cleanup( c, config_tls_cleanup );
        return ldap_pvt_tls_set_option( ld, flag, NULL );
    }
    if ( !berval ) ch_free( c->value_string );
    config_push_cleanup( c, config_tls_cleanup );
    rc = ldap_pvt_tls_set_option(
            ld, flag, berval ? (void *)&c->value_bv : (void *)c->argv[1] );
    if ( berval ) ch_free( c->value_bv.bv_val );
    return rc;
}

/* FIXME: this ought to be provided by libldap */
static int
config_tls_config( ConfigArgs *c )
{
    int i, flag;
    switch ( c->type ) {
        case CFG_TLS_CRLCHECK:
            flag = LDAP_OPT_X_TLS_CRLCHECK;
            break;
        case CFG_TLS_VERIFY:
            flag = LDAP_OPT_X_TLS_REQUIRE_CERT;
            break;
        case CFG_TLS_PROTOCOL_MIN:
            flag = LDAP_OPT_X_TLS_PROTOCOL_MIN;
            break;
        default:
            Debug( LDAP_DEBUG_ANY, "%s: "
                    "unknown tls_option <0x%x>\n",
                    c->log, c->type );
            return 1;
    }
    if ( c->op == SLAP_CONFIG_EMIT ) {
        return slap_tls_get_config( slap_tls_ld, flag, &c->value_string );
    } else if ( c->op == LDAP_MOD_DELETE ) {
        int i = 0;
        config_push_cleanup( c, config_tls_cleanup );
        return ldap_pvt_tls_set_option( slap_tls_ld, flag, &i );
    }
    ch_free( c->value_string );
    config_push_cleanup( c, config_tls_cleanup );
    if ( isdigit( (unsigned char)c->argv[1][0] ) &&
            c->type != CFG_TLS_PROTOCOL_MIN ) {
        if ( lutil_atoi( &i, c->argv[1] ) != 0 ) {
            Debug( LDAP_DEBUG_ANY, "%s: "
                    "unable to parse %s \"%s\"\n",
                    c->log, c->argv[0], c->argv[1] );
            return 1;
        }
        return ldap_pvt_tls_set_option( slap_tls_ld, flag, &i );
    } else {
        return ldap_pvt_tls_config( slap_tls_ld, flag, c->argv[1] );
    }
}
#endif

void
init_config_argv( ConfigArgs *c )
{
    c->argv = ch_calloc( ARGS_STEP + 1, sizeof(*c->argv) );
    c->argv_size = ARGS_STEP + 1;
}

ConfigTable *
config_find_keyword( ConfigTable *Conf, ConfigArgs *c )
{
    int i;

    for ( i = 0; Conf[i].name; i++ )
        if ( ( Conf[i].length &&
                     ( !strncasecmp(
                             c->argv[0], Conf[i].name, Conf[i].length ) ) ) ||
                ( !strcasecmp( c->argv[0], Conf[i].name ) ) )
            break;
    if ( !Conf[i].name ) return NULL;
    if ( (Conf[i].arg_type & ARGS_TYPES) == ARG_BINARY ) {
        size_t decode_len = LUTIL_BASE64_DECODE_LEN( c->linelen );
        ch_free( c->tline );
        c->tline = ch_malloc( decode_len + 1 );
        c->linelen = lutil_b64_pton( c->line, c->tline, decode_len );
        if ( c->linelen < 0 ) {
            ch_free( c->tline );
            c->tline = NULL;
            return NULL;
        }
        c->line = c->tline;
    }
    return Conf + i;
}

int
config_check_vals( ConfigTable *Conf, ConfigArgs *c, int check_only )
{
    int arg_user, arg_type, arg_syn, iarg;
    unsigned uiarg;
    long larg;
    unsigned long ularg;
    ber_len_t barg;

    if ( Conf->arg_type == ARG_IGNORED ) {
        Debug( LDAP_DEBUG_CONFIG, "%s: keyword <%s> ignored\n",
                c->log, Conf->name );
        return 0;
    }
    arg_type = Conf->arg_type & ARGS_TYPES;
    arg_user = Conf->arg_type & ARGS_USERLAND;
    arg_syn = Conf->arg_type & ARGS_SYNTAX;

    if ( Conf->min_args && ( c->argc < Conf->min_args ) ) {
        snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> missing <%s> argument",
                c->argv[0], Conf->what ? Conf->what : "" );
        Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: keyword %s\n",
                c->log, c->cr_msg );
        return ARG_BAD_CONF;
    }
    if ( Conf->max_args && ( c->argc > Conf->max_args ) ) {
        char *ignored = " ignored";

        snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> extra cruft after <%s>",
                c->argv[0], Conf->what );

        ignored = "";
        Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s%s.\n",
                c->log, c->cr_msg, ignored );
        return ARG_BAD_CONF;
    }
    if ( (arg_syn & ARG_PAREN) && *c->argv[1] != '(' /*')'*/ ) {
        snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> old format not supported",
                c->argv[0] );
        Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                c->log, c->cr_msg );
        return ARG_BAD_CONF;
    }
    if ( arg_type && !Conf->arg_item && !(arg_syn & ARG_OFFSET) ) {
        snprintf( c->cr_msg, sizeof(c->cr_msg),
                "<%s> invalid config_table, arg_item is NULL",
                c->argv[0] );
        Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                c->log, c->cr_msg );
        return ARG_BAD_CONF;
    }
    c->type = arg_user;
    memset( &c->values, 0, sizeof(c->values) );
    if ( arg_type == ARG_STRING ) {
        assert( c->argc == 2 );
        if ( !check_only ) c->value_string = ch_strdup( c->argv[1] );
    } else if ( arg_type == ARG_BERVAL ) {
        assert( c->argc == 2 );
        if ( !check_only ) ber_str2bv( c->argv[1], 0, 1, &c->value_bv );
    } else if ( arg_type == ARG_BINARY ) {
        assert( c->argc == 2 );
        if ( !check_only ) {
            c->value_bv.bv_len = c->linelen;
            c->value_bv.bv_val = ch_malloc( c->linelen );
            AC_MEMCPY( c->value_bv.bv_val, c->line, c->linelen );
        }
    } else { /* all numeric */
        int j;
        iarg = 0;
        larg = 0;
        barg = 0;
        switch ( arg_type ) {
            case ARG_INT:
                assert( c->argc == 2 );
                if ( lutil_atoix( &iarg, c->argv[1], 0 ) != 0 ) {
                    snprintf( c->cr_msg, sizeof(c->cr_msg),
                            "<%s> unable to parse \"%s\" as int",
                            c->argv[0], c->argv[1] );
                    Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                            c->log, c->cr_msg );
                    return ARG_BAD_CONF;
                }
                break;
            case ARG_UINT:
                assert( c->argc == 2 );
                if ( lutil_atoux( &uiarg, c->argv[1], 0 ) != 0 ) {
                    snprintf( c->cr_msg, sizeof(c->cr_msg),
                            "<%s> unable to parse \"%s\" as unsigned int",
                            c->argv[0], c->argv[1] );
                    Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                            c->log, c->cr_msg );
                    return ARG_BAD_CONF;
                }
                break;
            case ARG_LONG:
                assert( c->argc == 2 );
                if ( lutil_atolx( &larg, c->argv[1], 0 ) != 0 ) {
                    snprintf( c->cr_msg, sizeof(c->cr_msg),
                            "<%s> unable to parse \"%s\" as long",
                            c->argv[0], c->argv[1] );
                    Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                            c->log, c->cr_msg );
                    return ARG_BAD_CONF;
                }
                break;
            case ARG_ULONG:
                assert( c->argc == 2 );
                if ( LUTIL_ATOULX( &ularg, c->argv[1], 0 ) != 0 ) {
                    snprintf( c->cr_msg, sizeof(c->cr_msg),
                            "<%s> unable to parse \"%s\" as unsigned long",
                            c->argv[0], c->argv[1] );
                    Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                            c->log, c->cr_msg );
                    return ARG_BAD_CONF;
                }
                break;
            case ARG_BER_LEN_T: {
                unsigned long l;
                assert( c->argc == 2 );
                if ( lutil_atoulx( &l, c->argv[1], 0 ) != 0 ) {
                    snprintf( c->cr_msg, sizeof(c->cr_msg),
                            "<%s> unable to parse \"%s\" as ber_len_t",
                            c->argv[0], c->argv[1] );
                    Debug( LDAP_DEBUG_CONFIG|LDAP_DEBUG_NONE, "%s: %s\n",
                            c->log, c->cr_msg );
                    return ARG_BAD_CONF;
                }
                barg = (ber_len_t)l;
            } break;
            case ARG_ON_OFF:
                /* note: this is an explicit exception
                 * to the "need exactly 2 args" rule */
                if ( c->argc == 1 ) {
                    iarg = 1;
                } else if ( !strcasecmp( c->argv[1], "on" ) ||
                        !strcasecmp( c->argv[1], "true" ) ||
                        !strcasecmp( c->argv[1], "yes" ) ) {
                    iarg = 1;
                } else if ( !strcasecmp( c->argv[1], "off" ) ||
                        !strcasecmp( c->argv[1], "false" ) ||
                        !strcasecmp( c->argv[1], "no" ) ) {
                    iarg = 0;
                } else {
                    snprintf( c->cr_msg, sizeof(c->cr_msg),
                            "<%s> invalid value",
                            c->argv[0] );
                    Debug( LDAP_DEBUG_ANY|LDAP_DEBUG_NONE, "%s: %s\n",
                            c->log, c->cr_msg );
                    return ARG_BAD_CONF;
                }
                break;
        }
        j = (arg_type & ARG_NONZERO) ? 1 : 0;
        if ( iarg < j && larg < j && barg < (unsigned)j ) {
            larg = larg ? larg : ( barg ? (long)barg : iarg );
            snprintf( c->cr_msg, sizeof(c->cr_msg), "<%s> invalid value",
                    c->argv[0] );
            Debug( LDAP_DEBUG_ANY|LDAP_DEBUG_NONE, "%s: %s\n",
                    c->log, c->cr_msg );
            return ARG_BAD_CONF;
        }
        switch ( arg_type ) {
            case ARG_ON_OFF:
            case ARG_INT:
                c->value_int = iarg;
                break;
            case ARG_UINT:
                c->value_uint = uiarg;
                break;
            case ARG_LONG:
                c->value_long = larg;
                break;
            case ARG_ULONG:
                c->value_ulong = ularg;
                break;
            case ARG_BER_LEN_T:
                c->value_ber_t = barg;
                break;
        }
    }
    return 0;
}

int
config_set_vals( ConfigTable *Conf, ConfigArgs *c )
{
    int rc, arg_type;
    void *ptr = NULL;

    arg_type = Conf->arg_type;
    if ( arg_type & ARG_MAGIC ) {
        c->cr_msg[0] = '\0';
        rc = ( *( (ConfigDriver *)Conf->arg_item ) )( c );
        if ( rc ) {
            if ( !c->cr_msg[0] ) {
                snprintf( c->cr_msg, sizeof(c->cr_msg),
                        "<%s> handler exited with %d",
                        c->argv[0], rc );
                Debug( LDAP_DEBUG_CONFIG, "%s: %s!\n", c->log, c->cr_msg );
            }
            return ARG_BAD_CONF;
        }
        return 0;
    }
    if ( arg_type & ARG_OFFSET ) {
        {
            snprintf( c->cr_msg, sizeof(c->cr_msg),
                    "<%s> offset is missing base pointer",
                    c->argv[0] );
            Debug( LDAP_DEBUG_CONFIG, "%s: %s!\n", c->log, c->cr_msg );
            return ARG_BAD_CONF;
        }
        ptr = (void *)( (char *)ptr + (long)Conf->arg_item );
    } else if ( arg_type & ARGS_TYPES ) {
        ptr = Conf->arg_item;
    }
    if ( arg_type & ARGS_TYPES ) switch ( arg_type & ARGS_TYPES ) {
            case ARG_ON_OFF:
            case ARG_INT:
                *(int *)ptr = c->value_int;
                break;
            case ARG_UINT:
                *(unsigned *)ptr = c->value_uint;
                break;
            case ARG_LONG:
                *(long *)ptr = c->value_long;
                break;
            case ARG_ULONG:
                *(size_t *)ptr = c->value_ulong;
                break;
            case ARG_BER_LEN_T:
                *(ber_len_t *)ptr = c->value_ber_t;
                break;
            case ARG_STRING: {
                char *cc = *(char **)ptr;
                if ( cc ) {
                    if ( (arg_type & ARG_UNIQUE) &&
                            c->op == SLAP_CONFIG_ADD ) {
                        Debug( LDAP_DEBUG_CONFIG, "%s: already set %s!\n",
                                c->log, Conf->name );
                        return ARG_BAD_CONF;
                    }
                    ch_free( cc );
                }
                *(char **)ptr = c->value_string;
                break;
            }
            case ARG_BERVAL:
            case ARG_BINARY:
                *(struct berval *)ptr = c->value_bv;
                break;
        }
    return 0;
}

int
config_add_vals( ConfigTable *Conf, ConfigArgs *c )
{
    int rc, arg_type;

    arg_type = Conf->arg_type;
    if ( arg_type == ARG_IGNORED ) {
        Debug( LDAP_DEBUG_CONFIG, "%s: keyword <%s> ignored\n",
                c->log, Conf->name );
        return 0;
    }
    rc = config_check_vals( Conf, c, 0 );
    if ( rc ) return rc;
    return config_set_vals( Conf, c );
}

int
read_config_file(
        const char *fname,
        int depth,
        ConfigArgs *cf,
        ConfigTable *cft )
{
    FILE *fp;
    ConfigTable *ct;
    ConfigArgs *c;
    int rc;
    struct stat s;

    c = ch_calloc( 1, sizeof(ConfigArgs) );
    if ( c == NULL ) {
        return 1;
    }

    if ( depth ) {
        memcpy( c, cf, sizeof(ConfigArgs) );
    } else {
        c->depth = depth; /* XXX */
    }

    c->valx = -1;
    c->fname = fname;
    init_config_argv( c );

    if ( stat( fname, &s ) != 0 ) {
        char ebuf[128];
        int saved_errno = errno;
        ldap_syslog = 1;
        Debug( LDAP_DEBUG_ANY, "could not stat config file \"%s\": %s (%d)\n",
                fname, AC_STRERROR_R( saved_errno, ebuf, sizeof(ebuf) ),
                saved_errno );
        ch_free( c->argv );
        ch_free( c );
        return 1;
    }

    if ( !S_ISREG(s.st_mode) ) {
        ldap_syslog = 1;
        Debug( LDAP_DEBUG_ANY, "regular file expected, got \"%s\"\n", fname );
        ch_free( c->argv );
        ch_free( c );
        return 1;
    }

    fp = fopen( fname, "r" );
    if ( fp == NULL ) {
        char ebuf[128];
        int saved_errno = errno;
        ldap_syslog = 1;
        Debug( LDAP_DEBUG_ANY, "could not open config file \"%s\": %s (%d)\n",
                fname, AC_STRERROR_R( saved_errno, ebuf, sizeof(ebuf) ),
                saved_errno );
        ch_free( c->argv );
        ch_free( c );
        return 1;
    }

    Debug( LDAP_DEBUG_CONFIG, "reading config file %s\n", fname );

    fp_getline_init( c );

    c->tline = NULL;

    while ( fp_getline( fp, c ) ) {
        /* skip comments and blank lines */
        if ( c->line[0] == '#' || c->line[0] == '\0' ) {
            continue;
        }

        snprintf( c->log, sizeof(c->log), "%s: line %d",
                c->fname, c->lineno );

        c->argc = 0;
        ch_free( c->tline );
        if ( config_fp_parse_line( c ) ) {
            rc = 1;
            goto done;
        }

        if ( c->argc < 1 ) {
            Debug( LDAP_DEBUG_ANY, "%s: bad config line.\n", c->log );
            rc = 1;
            goto done;
        }

        c->op = SLAP_CONFIG_ADD;

        ct = config_find_keyword( cft, c );
        if ( ct ) {
            c->table = Cft_Global;
            rc = config_add_vals( ct, c );
            if ( !rc ) continue;

            if ( rc & ARGS_USERLAND ) {
                /* XXX a usertype would be opaque here */
                Debug( LDAP_DEBUG_CONFIG, "%s: unknown user type <%s>\n",
                        c->log, c->argv[0] );
                rc = 1;
                goto done;

            } else if ( rc == ARG_BAD_CONF ) {
                rc = 1;
                goto done;
            }

        } else {
            Debug( LDAP_DEBUG_ANY, "%s: unknown directive "
                    "<%s> outside backend info and database definitions.\n",
                    c->log, *c->argv );
            rc = 1;
            goto done;
        }
    }

    rc = 0;

done:
    ch_free( c->tline );
    fclose( fp );
    ch_free( c->argv );
    ch_free( c );
    return rc;
}

int
read_config( const char *fname, const char *dir )
{
    if ( !fname ) fname = LLOADD_DEFAULT_CONFIGFILE;

    cfn = ch_calloc( 1, sizeof(ConfigFile) );

    return read_config_file( fname, 0, NULL, config_back_cf_table );
}

/* restrictops, allows, disallows, requires, loglevel */

int
bverb_to_mask( struct berval *bword, slap_verbmasks *v )
{
    int i;
    for ( i = 0; !BER_BVISNULL( &v[i].word ); i++ ) {
        if ( !ber_bvstrcasecmp( bword, &v[i].word ) ) break;
    }
    return i;
}

int
verb_to_mask( const char *word, slap_verbmasks *v )
{
    struct berval bword;
    ber_str2bv( word, 0, 0, &bword );
    return bverb_to_mask( &bword, v );
}

int
verbs_to_mask( int argc, char *argv[], slap_verbmasks *v, slap_mask_t *m )
{
    int i, j;
    for ( i = 1; i < argc; i++ ) {
        j = verb_to_mask( argv[i], v );
        if ( BER_BVISNULL( &v[j].word ) ) return i;
        while ( !v[j].mask )
            j--;
        *m |= v[j].mask;
    }
    return 0;
}

/* Mask keywords that represent multiple bits should occur before single
 * bit keywords in the verbmasks array.
 */
int
mask_to_verbs( slap_verbmasks *v, slap_mask_t m, BerVarray *bva )
{
    int i, rc = 1;

    if ( m ) {
        for ( i = 0; !BER_BVISNULL( &v[i].word ); i++ ) {
            if ( !v[i].mask ) continue;
            if ( (m & v[i].mask) == v[i].mask ) {
                value_add_one( bva, &v[i].word );
                rc = 0;
                m ^= v[i].mask;
                if ( !m ) break;
            }
        }
    }
    return rc;
}

int
slap_verbmasks_init( slap_verbmasks **vp, slap_verbmasks *v )
{
    int i;

    assert( *vp == NULL );

    for ( i = 0; !BER_BVISNULL( &v[i].word ); i++ ) /* EMPTY */;

    *vp = ch_calloc( i + 1, sizeof(slap_verbmasks) );

    for ( i = 0; !BER_BVISNULL( &v[i].word ); i++ ) {
        ber_dupbv( &(*vp)[i].word, &v[i].word );
        *( (slap_mask_t *)&(*vp)[i].mask ) = v[i].mask;
    }

    BER_BVZERO( &(*vp)[i].word );

    return 0;
}

int
slap_verbmasks_destroy( slap_verbmasks *v )
{
    int i;

    assert( v != NULL );

    for ( i = 0; !BER_BVISNULL( &v[i].word ); i++ ) {
        ch_free( v[i].word.bv_val );
    }

    ch_free( v );

    return 0;
}

int
config_push_cleanup( ConfigArgs *ca, ConfigDriver *cleanup )
{
    /* Stub, cleanups only run in online config */
    return 0;
}

static slap_verbmasks tlskey[] = {
    { BER_BVC("no"), SB_TLS_OFF },
    { BER_BVC("yes"), SB_TLS_ON },
    { BER_BVC("critical"), SB_TLS_CRITICAL },
    { BER_BVNULL, 0 }
};

static slap_verbmasks crlkeys[] = {
    { BER_BVC("none"), LDAP_OPT_X_TLS_CRL_NONE },
    { BER_BVC("peer"), LDAP_OPT_X_TLS_CRL_PEER },
    { BER_BVC("all"), LDAP_OPT_X_TLS_CRL_ALL },
    { BER_BVNULL, 0 }
};

static slap_verbmasks vfykeys[] = {
    { BER_BVC("never"), LDAP_OPT_X_TLS_NEVER },
    { BER_BVC("allow"), LDAP_OPT_X_TLS_ALLOW },
    { BER_BVC("try"), LDAP_OPT_X_TLS_TRY },
    { BER_BVC("demand"), LDAP_OPT_X_TLS_DEMAND },
    { BER_BVC("hard"), LDAP_OPT_X_TLS_HARD },
    { BER_BVC("true"), LDAP_OPT_X_TLS_HARD },
    { BER_BVNULL, 0 }
};

static slap_verbmasks methkey[] = {
    { BER_BVC("none"), LDAP_AUTH_NONE },
    { BER_BVC("simple"), LDAP_AUTH_SIMPLE },
#ifdef HAVE_CYRUS_SASL
    { BER_BVC("sasl"), LDAP_AUTH_SASL },
#endif
    { BER_BVNULL, 0 }
};

int
slap_keepalive_parse(
        struct berval *val,
        void *bc,
        slap_cf_aux_table *tab0,
        const char *tabmsg,
        int unparse )
{
    if ( unparse ) {
        slap_keepalive *sk = (slap_keepalive *)bc;
        int rc = snprintf( val->bv_val, val->bv_len, "%d:%d:%d",
                sk->sk_idle, sk->sk_probes, sk->sk_interval );
        if ( rc < 0 ) {
            return -1;
        }

        if ( (unsigned)rc >= val->bv_len ) {
            return -1;
        }

        val->bv_len = rc;

    } else {
        char *s = val->bv_val;
        char *next;
        slap_keepalive *sk = (slap_keepalive *)bc;
        slap_keepalive sk2;

        if ( s[0] == ':' ) {
            sk2.sk_idle = 0;
            s++;

        } else {
            sk2.sk_idle = strtol( s, &next, 10 );
            if ( next == s || next[0] != ':' ) {
                return -1;
            }

            if ( sk2.sk_idle < 0 ) {
                return -1;
            }

            s = ++next;
        }

        if ( s[0] == ':' ) {
            sk2.sk_probes = 0;
            s++;

        } else {
            sk2.sk_probes = strtol( s, &next, 10 );
            if ( next == s || next[0] != ':' ) {
                return -1;
            }

            if ( sk2.sk_probes < 0 ) {
                return -1;
            }

            s = ++next;
        }

        if ( *s == '\0' ) {
            sk2.sk_interval = 0;

        } else {
            sk2.sk_interval = strtol( s, &next, 10 );
            if ( next == s || next[0] != '\0' ) {
                return -1;
            }

            if ( sk2.sk_interval < 0 ) {
                return -1;
            }
        }

        *sk = sk2;

        ber_memfree( val->bv_val );
        BER_BVZERO( val );
    }

    return 0;
}

static int
slap_sb_uri(
        struct berval *val,
        void *bcp,
        slap_cf_aux_table *tab0,
        const char *tabmsg,
        int unparse )
{
    slap_bindconf *bc = bcp;
    if ( unparse ) {
        if ( bc->sb_uri.bv_len >= val->bv_len ) return -1;
        val->bv_len = bc->sb_uri.bv_len;
        AC_MEMCPY( val->bv_val, bc->sb_uri.bv_val, val->bv_len );
    } else {
        bc->sb_uri = *val;
#ifdef HAVE_TLS
        if ( ldap_is_ldaps_url( val->bv_val ) ) bc->sb_tls_do_init = 1;
#endif
    }
    return 0;
}

static slap_cf_aux_table bindkey[] = {
    { BER_BVC("uri="), offsetof(Backend, b_bindconf.sb_uri), 'x', 1, slap_sb_uri },
    { BER_BVC("bindmethod="), offsetof(Backend, b_bindconf.sb_method), 'i', 0, methkey },
    { BER_BVC("timeout="), offsetof(Backend, b_bindconf.sb_timeout_api), 'i', 0, NULL },
    { BER_BVC("network-timeout="), offsetof(Backend, b_bindconf.sb_timeout_net), 'i', 0, NULL },
    { BER_BVC("binddn="), offsetof(Backend, b_bindconf.sb_binddn), 'b', 1, NULL },
    { BER_BVC("credentials="), offsetof(Backend, b_bindconf.sb_cred), 'b', 1, NULL },
    { BER_BVC("saslmech="), offsetof(Backend, b_bindconf.sb_saslmech), 'b', 0, NULL },
    { BER_BVC("secprops="), offsetof(Backend, b_bindconf.sb_secprops), 's', 0, NULL },
    { BER_BVC("realm="), offsetof(Backend, b_bindconf.sb_realm), 'b', 0, NULL },
    { BER_BVC("authcID="), offsetof(Backend, b_bindconf.sb_authcId), 'b', 1, NULL },
    { BER_BVC("authzID="), offsetof(Backend, b_bindconf.sb_authzId), 'b', 1, NULL },
    { BER_BVC("keepalive="), offsetof(Backend, b_bindconf.sb_keepalive), 'x', 0, (slap_verbmasks *)slap_keepalive_parse },

    { BER_BVC("numconns="), offsetof(Backend, b_numconns), 'i', 0, NULL },
    { BER_BVC("bindconns="), offsetof(Backend, b_numbindconns), 'i', 0, NULL },
    { BER_BVC("retry="), offsetof(Backend, b_retry_timeout), 'i', 0, NULL },
#ifdef HAVE_TLS
    { BER_BVC("starttls="), offsetof(Backend, b_bindconf.sb_tls), 'i', 0, tlskey },
    { BER_BVC("tls_cert="), offsetof(Backend, b_bindconf.sb_tls_cert), 's', 1, NULL },
    { BER_BVC("tls_key="), offsetof(Backend, b_bindconf.sb_tls_key), 's', 1, NULL },
    { BER_BVC("tls_cacert="), offsetof(Backend, b_bindconf.sb_tls_cacert), 's', 1, NULL },
    { BER_BVC("tls_cacertdir="), offsetof(Backend, b_bindconf.sb_tls_cacertdir), 's', 1, NULL },
    { BER_BVC("tls_reqcert="), offsetof(Backend, b_bindconf.sb_tls_reqcert), 's', 0, NULL },
    { BER_BVC("tls_reqsan="), offsetof(Backend, b_bindconf.sb_tls_reqsan), 's', 0, NULL },
    { BER_BVC("tls_cipher_suite="), offsetof(Backend, b_bindconf.sb_tls_cipher_suite), 's', 0, NULL },
    { BER_BVC("tls_protocol_min="), offsetof(Backend, b_bindconf.sb_tls_protocol_min), 's', 0, NULL },
    { BER_BVC("tls_ecname="), offsetof(Backend, b_bindconf.sb_tls_ecname), 's', 0, NULL },
#ifdef HAVE_OPENSSL
    { BER_BVC("tls_crlcheck="), offsetof(Backend, b_bindconf.sb_tls_crlcheck), 's', 0, NULL },
#endif
#endif
    { BER_BVNULL, 0, 0, 0, NULL }
};

/*
 * 's': char *
 * 'b': struct berval
 * 'i': int; if !NULL, compute using ((slap_verbmasks *)aux)
 * 'u': unsigned
 * 'I': long
 * 'U': unsigned long
 */

int
slap_cf_aux_table_parse(
        const char *word,
        void *dst,
        slap_cf_aux_table *tab0,
        LDAP_CONST char *tabmsg )
{
    int rc = SLAP_CONF_UNKNOWN;
    slap_cf_aux_table *tab;

    for ( tab = tab0; !BER_BVISNULL( &tab->key ); tab++ ) {
        if ( !strncasecmp( word, tab->key.bv_val, tab->key.bv_len ) ) {
            char **cptr;
            int *iptr, j;
            unsigned *uptr;
            long *lptr;
            unsigned long *ulptr;
            struct berval *bptr;
            const char *val = word + tab->key.bv_len;

            switch ( tab->type ) {
                case 's':
                    cptr = (char **)( (char *)dst + tab->off );
                    *cptr = ch_strdup( val );
                    rc = 0;
                    break;

                case 'b':
                    bptr = (struct berval *)( (char *)dst + tab->off );
                    assert( tab->aux == NULL );
                    ber_str2bv( val, 0, 1, bptr );
                    rc = 0;
                    break;

                case 'i':
                    iptr = (int *)( (char *)dst + tab->off );

                    if ( tab->aux != NULL ) {
                        slap_verbmasks *aux = (slap_verbmasks *)tab->aux;

                        assert( aux != NULL );

                        rc = 1;
                        for ( j = 0; !BER_BVISNULL( &aux[j].word ); j++ ) {
                            if ( !strcasecmp( val, aux[j].word.bv_val ) ) {
                                *iptr = aux[j].mask;
                                rc = 0;
                                break;
                            }
                        }

                    } else {
                        rc = lutil_atoix( iptr, val, 0 );
                    }
                    break;

                case 'u':
                    uptr = (unsigned *)( (char *)dst + tab->off );

                    rc = lutil_atoux( uptr, val, 0 );
                    break;

                case 'I':
                    lptr = (long *)( (char *)dst + tab->off );

                    rc = lutil_atolx( lptr, val, 0 );
                    break;

                case 'U':
                    ulptr = (unsigned long *)( (char *)dst + tab->off );

                    rc = lutil_atoulx( ulptr, val, 0 );
                    break;

                case 'x':
                    if ( tab->aux != NULL ) {
                        struct berval value;
                        slap_cf_aux_table_parse_x *func =
                                (slap_cf_aux_table_parse_x *)tab->aux;

                        ber_str2bv( val, 0, 1, &value );

                        rc = func( &value, (void *)( (char *)dst + tab->off ),
                                tab, tabmsg, 0 );

                    } else {
                        rc = 1;
                    }
                    break;
            }

            if ( rc ) {
                Debug( LDAP_DEBUG_ANY, "invalid %s value %s\n", tabmsg, word );
            }

            return rc;
        }
    }

    return rc;
}

int
slap_cf_aux_table_unparse(
        void *src,
        struct berval *bv,
        slap_cf_aux_table *tab0 )
{
    char buf[AC_LINE_MAX], *ptr;
    slap_cf_aux_table *tab;
    struct berval tmp;

    ptr = buf;
    for ( tab = tab0; !BER_BVISNULL( &tab->key ); tab++ ) {
        char **cptr;
        int *iptr, i;
        unsigned *uptr;
        long *lptr;
        unsigned long *ulptr;
        struct berval *bptr;

        cptr = (char **)( (char *)src + tab->off );

        switch ( tab->type ) {
            case 'b':
                bptr = (struct berval *)( (char *)src + tab->off );
                cptr = &bptr->bv_val;

            case 's':
                if ( *cptr ) {
                    *ptr++ = ' ';
                    ptr = lutil_strcopy( ptr, tab->key.bv_val );
                    if ( tab->quote ) *ptr++ = '"';
                    ptr = lutil_strcopy( ptr, *cptr );
                    if ( tab->quote ) *ptr++ = '"';
                }
                break;

            case 'i':
                iptr = (int *)( (char *)src + tab->off );

                if ( tab->aux != NULL ) {
                    slap_verbmasks *aux = (slap_verbmasks *)tab->aux;

                    for ( i = 0; !BER_BVISNULL( &aux[i].word ); i++ ) {
                        if ( *iptr == aux[i].mask ) {
                            *ptr++ = ' ';
                            ptr = lutil_strcopy( ptr, tab->key.bv_val );
                            ptr = lutil_strcopy( ptr, aux[i].word.bv_val );
                            break;
                        }
                    }

                } else {
                    *ptr++ = ' ';
                    ptr = lutil_strcopy( ptr, tab->key.bv_val );
                    ptr += snprintf( ptr, sizeof(buf) - ( ptr - buf ), "%d",
                            *iptr );
                }
                break;

            case 'u':
                uptr = (unsigned *)( (char *)src + tab->off );
                *ptr++ = ' ';
                ptr = lutil_strcopy( ptr, tab->key.bv_val );
                ptr += snprintf( ptr, sizeof(buf) - ( ptr - buf ), "%u",
                        *uptr );
                break;

            case 'I':
                lptr = (long *)( (char *)src + tab->off );
                *ptr++ = ' ';
                ptr = lutil_strcopy( ptr, tab->key.bv_val );
                ptr += snprintf( ptr, sizeof(buf) - ( ptr - buf ), "%ld",
                        *lptr );
                break;

            case 'U':
                ulptr = (unsigned long *)( (char *)src + tab->off );
                *ptr++ = ' ';
                ptr = lutil_strcopy( ptr, tab->key.bv_val );
                ptr += snprintf( ptr, sizeof(buf) - ( ptr - buf ), "%lu",
                        *ulptr );
                break;

            case 'x': {
                char *saveptr = ptr;
                *ptr++ = ' ';
                ptr = lutil_strcopy( ptr, tab->key.bv_val );
                if ( tab->quote ) *ptr++ = '"';
                if ( tab->aux != NULL ) {
                    struct berval value;
                    slap_cf_aux_table_parse_x *func =
                            (slap_cf_aux_table_parse_x *)tab->aux;
                    int rc;

                    value.bv_val = ptr;
                    value.bv_len = buf + sizeof(buf) - ptr;

                    rc = func( &value, (void *)( (char *)src + tab->off ), tab,
                            "(unparse)", 1 );
                    if ( rc == 0 ) {
                        if ( value.bv_len ) {
                            ptr += value.bv_len;
                        } else {
                            ptr = saveptr;
                            break;
                        }
                    }
                }
                if ( tab->quote ) *ptr++ = '"';
            } break;

            default:
                assert(0);
        }
    }
    tmp.bv_val = buf;
    tmp.bv_len = ptr - buf;
    ber_dupbv( bv, &tmp );
    return 0;
}

int
slap_tls_get_config( LDAP *ld, int opt, char **val )
{
#ifdef HAVE_TLS
    slap_verbmasks *keys;
    int i, ival;

    *val = NULL;
    switch ( opt ) {
        case LDAP_OPT_X_TLS_CRLCHECK:
            keys = crlkeys;
            break;
        case LDAP_OPT_X_TLS_REQUIRE_CERT:
            keys = vfykeys;
            break;
        case LDAP_OPT_X_TLS_PROTOCOL_MIN: {
            char buf[8];
            ldap_pvt_tls_get_option( ld, opt, &ival );
            snprintf( buf, sizeof(buf), "%d.%d",
                    ( ival >> 8 ) & 0xff, ival & 0xff );
            *val = ch_strdup( buf );
            return 0;
        }
        default:
            return -1;
    }
    ldap_pvt_tls_get_option( ld, opt, &ival );
    for ( i = 0; !BER_BVISNULL( &keys[i].word ); i++ ) {
        if ( keys[i].mask == ival ) {
            *val = ch_strdup( keys[i].word.bv_val );
            return 0;
        }
    }
#endif
    return -1;
}

int
bindconf_parse( const char *word, Backend *b )
{
    return slap_cf_aux_table_parse( word, b, bindkey, "bind config" );
}

int
bindconf_unparse( Backend *b, struct berval *bv )
{
    return slap_cf_aux_table_unparse( b, bv, bindkey );
}

void
bindconf_free( slap_bindconf *bc )
{
    if ( !BER_BVISNULL( &bc->sb_uri ) ) {
        ch_free( bc->sb_uri.bv_val );
        BER_BVZERO( &bc->sb_uri );
    }
    if ( !BER_BVISNULL( &bc->sb_binddn ) ) {
        ch_free( bc->sb_binddn.bv_val );
        BER_BVZERO( &bc->sb_binddn );
    }
    if ( !BER_BVISNULL( &bc->sb_cred ) ) {
        ch_free( bc->sb_cred.bv_val );
        BER_BVZERO( &bc->sb_cred );
    }
    if ( !BER_BVISNULL( &bc->sb_saslmech ) ) {
        ch_free( bc->sb_saslmech.bv_val );
        BER_BVZERO( &bc->sb_saslmech );
    }
    if ( bc->sb_secprops ) {
        ch_free( bc->sb_secprops );
        bc->sb_secprops = NULL;
    }
    if ( !BER_BVISNULL( &bc->sb_realm ) ) {
        ch_free( bc->sb_realm.bv_val );
        BER_BVZERO( &bc->sb_realm );
    }
    if ( !BER_BVISNULL( &bc->sb_authcId ) ) {
        ch_free( bc->sb_authcId.bv_val );
        BER_BVZERO( &bc->sb_authcId );
    }
    if ( !BER_BVISNULL( &bc->sb_authzId ) ) {
        ch_free( bc->sb_authzId.bv_val );
        BER_BVZERO( &bc->sb_authzId );
    }
#ifdef HAVE_TLS
    if ( bc->sb_tls_cert ) {
        ch_free( bc->sb_tls_cert );
        bc->sb_tls_cert = NULL;
    }
    if ( bc->sb_tls_key ) {
        ch_free( bc->sb_tls_key );
        bc->sb_tls_key = NULL;
    }
    if ( bc->sb_tls_cacert ) {
        ch_free( bc->sb_tls_cacert );
        bc->sb_tls_cacert = NULL;
    }
    if ( bc->sb_tls_cacertdir ) {
        ch_free( bc->sb_tls_cacertdir );
        bc->sb_tls_cacertdir = NULL;
    }
    if ( bc->sb_tls_reqcert ) {
        ch_free( bc->sb_tls_reqcert );
        bc->sb_tls_reqcert = NULL;
    }
    if ( bc->sb_tls_cipher_suite ) {
        ch_free( bc->sb_tls_cipher_suite );
        bc->sb_tls_cipher_suite = NULL;
    }
    if ( bc->sb_tls_protocol_min ) {
        ch_free( bc->sb_tls_protocol_min );
        bc->sb_tls_protocol_min = NULL;
    }
#ifdef HAVE_OPENSSL_CRL
    if ( bc->sb_tls_crlcheck ) {
        ch_free( bc->sb_tls_crlcheck );
        bc->sb_tls_crlcheck = NULL;
    }
#endif
    if ( bc->sb_tls_ctx ) {
        ldap_pvt_tls_ctx_free( bc->sb_tls_ctx );
        bc->sb_tls_ctx = NULL;
    }
#endif
}

void
bindconf_tls_defaults( slap_bindconf *bc )
{
#ifdef HAVE_TLS
    if ( bc->sb_tls_do_init ) {
        if ( !bc->sb_tls_cacert )
            ldap_pvt_tls_get_option( slap_tls_ld, LDAP_OPT_X_TLS_CACERTFILE,
                    &bc->sb_tls_cacert );
        if ( !bc->sb_tls_cacertdir )
            ldap_pvt_tls_get_option( slap_tls_ld, LDAP_OPT_X_TLS_CACERTDIR,
                    &bc->sb_tls_cacertdir );
        if ( !bc->sb_tls_cert )
            ldap_pvt_tls_get_option(
                    slap_tls_ld, LDAP_OPT_X_TLS_CERTFILE, &bc->sb_tls_cert );
        if ( !bc->sb_tls_key )
            ldap_pvt_tls_get_option(
                    slap_tls_ld, LDAP_OPT_X_TLS_KEYFILE, &bc->sb_tls_key );
        if ( !bc->sb_tls_cipher_suite )
            ldap_pvt_tls_get_option( slap_tls_ld, LDAP_OPT_X_TLS_CIPHER_SUITE,
                    &bc->sb_tls_cipher_suite );
        if ( !bc->sb_tls_reqcert ) bc->sb_tls_reqcert = ch_strdup( "demand" );
#ifdef HAVE_OPENSSL_CRL
        if ( !bc->sb_tls_crlcheck )
            slap_tls_get_config( slap_tls_ld, LDAP_OPT_X_TLS_CRLCHECK,
                    &bc->sb_tls_crlcheck );
#endif
    }
#endif
}

/* -------------------------------------- */

static char *
strtok_quote( char *line, char *sep, char **quote_ptr, int *iqp )
{
    int inquote;
    char *tmp;
    static char *next;

    *quote_ptr = NULL;
    if ( line != NULL ) {
        next = line;
    }
    while ( *next && strchr( sep, *next ) ) {
        next++;
    }

    if ( *next == '\0' ) {
        next = NULL;
        return NULL;
    }
    tmp = next;

    for ( inquote = 0; *next; ) {
        switch ( *next ) {
            case '"':
                if ( inquote ) {
                    inquote = 0;
                } else {
                    inquote = 1;
                }
                AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
                break;

            case '\\':
                if ( next[1] )
                    AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
                next++; /* dont parse the escaped character */
                break;

            default:
                if ( !inquote ) {
                    if ( strchr( sep, *next ) != NULL ) {
                        *quote_ptr = next;
                        *next++ = '\0';
                        return tmp;
                    }
                }
                next++;
                break;
        }
    }
    *iqp = inquote;

    return tmp;
}

static char buf[AC_LINE_MAX];
static char *line;
static size_t lmax, lcur;

#define CATLINE( buf ) \
    do { \
        size_t len = strlen( buf ); \
        while ( lcur + len + 1 > lmax ) { \
            lmax += AC_LINE_MAX; \
            line = (char *)ch_realloc( line, lmax ); \
        } \
        strcpy( line + lcur, buf ); \
        lcur += len; \
    } while (0)

static void
fp_getline_init( ConfigArgs *c )
{
    c->lineno = -1;
    buf[0] = '\0';
}

static int
fp_getline( FILE *fp, ConfigArgs *c )
{
    char *p;

    lcur = 0;
    CATLINE( buf );
    c->lineno++;

    /* avoid stack of bufs */
    if ( strncasecmp( line, "include", STRLENOF("include") ) == 0 ) {
        buf[0] = '\0';
        c->line = line;
        return 1;
    }

    while ( fgets( buf, sizeof(buf), fp ) ) {
        p = strchr( buf, '\n' );
        if ( p ) {
            if ( p > buf && p[-1] == '\r' ) {
                --p;
            }
            *p = '\0';
        }
        /* XXX ugly */
        c->line = line;
        if ( line[0] && ( p = line + strlen( line ) - 1 )[0] == '\\' &&
                p[-1] != '\\' ) {
            p[0] = '\0';
            lcur--;

        } else {
            if ( !isspace( (unsigned char)buf[0] ) ) {
                return 1;
            }
            buf[0] = ' ';
        }
        CATLINE( buf );
        c->lineno++;
    }

    buf[0] = '\0';
    c->line = line;
    return ( line[0] ? 1 : 0 );
}

int
config_fp_parse_line( ConfigArgs *c )
{
    char *token;
    static char *const hide[] = { "bindconf", NULL };
    static char *const raw[] = { NULL };
    char *quote_ptr;
    int i = (int)( sizeof(hide) / sizeof(hide[0]) ) - 1;
    int inquote = 0;

    c->tline = ch_strdup( c->line );
    c->linelen = strlen( c->line );
    token = strtok_quote( c->tline, " \t", &quote_ptr, &inquote );

    if ( token )
        for ( i = 0; hide[i]; i++ )
            if ( !strcasecmp( token, hide[i] ) ) break;
    if ( quote_ptr ) *quote_ptr = ' ';
    Debug( LDAP_DEBUG_CONFIG, "%s (%s%s)\n",
            c->log, hide[i] ? hide[i] : c->line, hide[i] ? " ***" : "" );
    if ( quote_ptr ) *quote_ptr = '\0';

    for ( ;; token = strtok_quote( NULL, " \t", &quote_ptr, &inquote ) ) {
        if ( c->argc >= c->argv_size ) {
            char **tmp;
            tmp = ch_realloc( c->argv,
                    ( c->argv_size + ARGS_STEP ) * sizeof(*c->argv) );
            if ( !tmp ) {
                Debug( LDAP_DEBUG_ANY, "%s: out of memory\n", c->log );
                return -1;
            }
            c->argv = tmp;
            c->argv_size += ARGS_STEP;
        }
        if ( token == NULL ) break;
        c->argv[c->argc++] = token;
    }
    c->argv[c->argc] = NULL;
    if ( inquote ) {
        /* these directives parse c->line independently of argv tokenizing */
        for ( i = 0; raw[i]; i++ )
            if ( !strcasecmp( c->argv[0], raw[i] ) ) return 0;

        Debug( LDAP_DEBUG_ANY, "%s: unterminated quoted string \"%s\"\n",
                c->log, c->argv[c->argc - 1] );
        return -1;
    }
    return 0;
}

void
config_destroy( void )
{
    free( line );
    if ( slapd_args_file ) free( slapd_args_file );
    if ( slapd_pid_file ) free( slapd_pid_file );
    loglevel_destroy();
}

/* See if the given URL (in plain and parsed form) matches
 * any of the server's listener addresses. Return matching
 * Listener or NULL for no match.
 */
Listener *
config_check_my_url( const char *url, LDAPURLDesc *lud )
{
    Listener **l = slapd_get_listeners();
    int i, isMe;

    /* Try a straight compare with Listener strings */
    for ( i = 0; l && l[i]; i++ ) {
        if ( !strcasecmp( url, l[i]->sl_url.bv_val ) ) {
            return l[i];
        }
    }

    isMe = 0;
    /* If hostname is empty, or is localhost, or matches
     * our hostname, this url refers to this host.
     * Compare it against listeners and ports.
     */
    if ( !lud->lud_host || !lud->lud_host[0] ||
            !strncasecmp(
                    "localhost", lud->lud_host, STRLENOF("localhost") ) ||
            !strcasecmp( global_host, lud->lud_host ) ) {
        for ( i = 0; l && l[i]; i++ ) {
            LDAPURLDesc *lu2;
            ldap_url_parse( l[i]->sl_url.bv_val, &lu2 );
            do {
                if ( strcasecmp( lud->lud_scheme, lu2->lud_scheme ) ) break;
                if ( lud->lud_port != lu2->lud_port ) break;
                /* Listener on ANY address */
                if ( !lu2->lud_host || !lu2->lud_host[0] ) {
                    isMe = 1;
                    break;
                }
                /* URL on ANY address */
                if ( !lud->lud_host || !lud->lud_host[0] ) {
                    isMe = 1;
                    break;
                }
                /* Listener has specific host, must
                 * match it
                 */
                if ( !strcasecmp( lud->lud_host, lu2->lud_host ) ) {
                    isMe = 1;
                    break;
                }
            } while (0);
            ldap_free_urldesc( lu2 );
            if ( isMe ) {
                return l[i];
            }
        }
    }
    return NULL;
}
