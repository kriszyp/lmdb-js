/* gnutls.c - Handle tls/ssl using GNUTLS. */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2007 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 */

#include "portable.h"

#if 1 /* HAVE_GNUTLS */

#include "ldap_config.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/param.h>
#include <ac/dirent.h>

#include "ldap-int.h"
#include "ldap_schema.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h>

#define DH_BITS (1024)

#ifdef LDAP_R_COMPILE
#  include <ldap_pvt_thread.h>

static int
ldap_pvt_gcry_mutex_init( void **priv )
{
	int err = 0;
	ldap_pvt_thread_mutex_t *lock = LDAP_MALLOC( sizeof( ldap_pvt_thread_mutex_t ));

	if ( !lock )
		err = ENOMEM;
	if ( !err ) {
		err = ldap_pvt_thread_mutex_init( lock );
		if ( err )
			LDAP_FREE( lock );
		else
			*priv = lock;
	}
	return err;
}
static int
ldap_pvt_gcry_mutex_destroy( void **lock )
{
	int err = ldap_pvt_thread_mutex_destroy( *lock );
	LDAP_FREE( *lock );
	return err;
}
static int
ldap_pvt_gcry_mutex_lock( void **lock )
{
	return ldap_pvt_thread_mutex_lock( *lock );
}
static int
ldap_pvt_gcry_mutex_unlock( void **lock )
{
	return ldap_pvt_thread_mutex_unlock( *lock );
}

static struct gcry_thread_cbs ldap_generic_thread_cbs = {
	GCRY_THREAD_OPTION_USER,
	NULL,
	ldap_pvt_gcry_mutex_init,
	ldap_pvt_gcry_mutex_destroy,
	ldap_pvt_gcry_mutex_lock,
	ldap_pvt_gcry_mutex_unlock,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};
#endif

/* sorta replacing SSL_CTX */
typedef struct ldap_pvt_tls_ctx {
	struct ldapoptions *lo;
	int *cipher_list;
	gnutls_certificate_credentials_t cred;
	gnutls_dh_params_t dh_params;
	unsigned long verify_depth;
	int refcount;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_t ref_mutex;
#endif
} ldap_pvt_tls_ctx_t;

/* sorta replacing SSL */
typedef struct ldap_pvt_gnutls_session {
	gnutls_session_t session;
	struct berval peer_der_dn;
} ldap_pvt_gnutls_session_t;

#define HAS_TLS( sb )	ber_sockbuf_ctrl( sb, LBER_SB_OPT_HAS_IO, \
				(void *)&sb_tls_sbio )

/* RFC2459 minimum required set of supported attribute types
 */
typedef struct oid_name {
	struct berval oid;
	struct berval name;
} oid_name;

#define	CN_OID	oids[0].oid.bv_val

static oid_name oids[] = {
	{ BER_BVC("2.5.4.3"), BER_BVC("cn") },
	{ BER_BVC("2.5.4.4"), BER_BVC("sn") },
	{ BER_BVC("2.5.4.6"), BER_BVC("c") },
	{ BER_BVC("2.5.4.7"), BER_BVC("l") },
	{ BER_BVC("2.5.4.8"), BER_BVC("st") },
	{ BER_BVC("2.5.4.10"), BER_BVC("o") },
	{ BER_BVC("2.5.4.11"), BER_BVC("ou") },
	{ BER_BVC("2.5.4.12"), BER_BVC("title") },
	{ BER_BVC("2.5.4.41"), BER_BVC("name") },
	{ BER_BVC("2.5.4.42"), BER_BVC("givenName") },
	{ BER_BVC("2.5.4.43"), BER_BVC("initials") },
	{ BER_BVC("2.5.4.44"), BER_BVC("generationQualifier") },
	{ BER_BVC("2.5.4.46"), BER_BVC("dnQualifier") },
	{ BER_BVC("1.2.840.113549.1.9.1"), BER_BVC("email") },
	{ BER_BVC("0.9.2342.19200300.100.1.25"), BER_BVC("dc") },
	{ BER_BVNULL, BER_BVNULL }
};

ldap_pvt_tls_ctx_t *
ldap_pvt_tls_ctx_new ( struct ldapoptions *lo )
{
	ldap_pvt_tls_ctx_t *ctx;

	ctx = ber_memcalloc ( 1, sizeof (*ctx) );
	if ( ctx ) {
		ctx->lo = lo;
		if ( gnutls_certificate_allocate_credentials( &ctx->cred ) < 0 ) {
			ber_memfree( ctx );
			return NULL;
		}
		ctx->refcount = 1;
#ifdef LDAP_R_COMPILE
		ldap_pvt_thread_mutex_init( &ctx->ref_mutex );
#endif
	}
	return ctx;
}

void
ldap_pvt_tls_ctx_free ( void *c )
{
	int refcount;
	ldap_pvt_tls_ctx_t *ctx = c;

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ctx->ref_mutex );
#endif
	refcount = --ctx->refcount;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ctx->ref_mutex );
#endif
	if ( refcount )
		return;
	gnutls_certificate_free_credentials( ctx->cred );
	ber_memfree ( ctx );
}

static void
ldap_pvt_tls_ctx_ref( ldap_pvt_tls_ctx_t * ctx )
{
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ctx->ref_mutex );
#endif
	ctx->refcount++;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ctx->ref_mutex );
#endif
}

ldap_pvt_gnutls_session_t *
ldap_pvt_gnutls_session_new ( ldap_pvt_tls_ctx_t * ctx, int is_server )
{
	ldap_pvt_gnutls_session_t *session;

	session = ber_memcalloc ( 1, sizeof (*session) );
	if ( !session )
		return NULL;

	gnutls_init( &session->session, is_server ? GNUTLS_SERVER : GNUTLS_CLIENT );
	gnutls_set_default_priority( session->session );
	if ( ctx->cred )
		gnutls_credentials_set( session->session, GNUTLS_CRD_CERTIFICATE, ctx->cred );
	
	if ( is_server ) {
		int flag = 0;
		if ( ctx->lo->ldo_tls_require_cert ) {
			flag = GNUTLS_CERT_REQUEST;
			if ( ctx->lo->ldo_tls_require_cert == LDAP_OPT_X_TLS_DEMAND ||
				ctx->lo->ldo_tls_require_cert == LDAP_OPT_X_TLS_HARD )
				flag = GNUTLS_CERT_REQUIRE;
			gnutls_certificate_server_set_request( session->session, flag );
		}
	}
	return session;
} 

void
ldap_pvt_gnutls_session_free ( ldap_pvt_gnutls_session_t * session )
{
	ber_memfree ( session );
}

#ifdef LDAP_R_COMPILE
static void
tls_init_threads( void )
{
	gcry_control (GCRYCTL_SET_THREAD_CBS, &ldap_generic_thread_cbs);
}
#endif

void
ldap_int_tls_destroy( struct ldapoptions *lo )
{
	if ( lo->ldo_tls_ctx ) {
		ldap_pvt_tls_ctx_free( lo->ldo_tls_ctx );
		lo->ldo_tls_ctx = NULL;
	}

	if ( lo->ldo_tls_certfile ) {
		LDAP_FREE( lo->ldo_tls_certfile );
		lo->ldo_tls_certfile = NULL;
	}
	if ( lo->ldo_tls_keyfile ) {
		LDAP_FREE( lo->ldo_tls_keyfile );
		lo->ldo_tls_keyfile = NULL;
	}
	if ( lo->ldo_tls_dhfile ) {
		LDAP_FREE( lo->ldo_tls_dhfile );
		lo->ldo_tls_dhfile = NULL;
	}
	if ( lo->ldo_tls_cacertfile ) {
		LDAP_FREE( lo->ldo_tls_cacertfile );
		lo->ldo_tls_cacertfile = NULL;
	}
	if ( lo->ldo_tls_cacertdir ) {
		LDAP_FREE( lo->ldo_tls_cacertdir );
		lo->ldo_tls_cacertdir = NULL;
	}
	if ( lo->ldo_tls_ciphersuite ) {
		LDAP_FREE( lo->ldo_tls_ciphersuite );
		lo->ldo_tls_ciphersuite = NULL;
	}
}

/*
 * Tear down the TLS subsystem. Should only be called once.
 */
void
ldap_pvt_tls_destroy( void )
{
	struct ldapoptions *lo = LDAP_INT_GLOBAL_OPT();

	ldap_int_tls_destroy( lo );

	gnutls_global_deinit();
}

/*
 * Initialize TLS subsystem. Should be called only once.
 */
int
ldap_pvt_tls_init( void )
{
	static int tls_initialized = 0;

	if ( tls_initialized++ ) return 0;

#ifdef LDAP_R_COMPILE
	tls_init_threads();
#endif
	gnutls_global_init ();
	return 0;
}

/*
 * initialize a new TLS context
 */
static int
ldap_int_tls_init_ctx( struct ldapoptions *lo, int is_server )
{
	int i, rc = 0;
	char *ciphersuite = lo->ldo_tls_ciphersuite;
	char *cacertfile = lo->ldo_tls_cacertfile;
	char *cacertdir = lo->ldo_tls_cacertdir;
	char *certfile = lo->ldo_tls_certfile;
	char *keyfile = lo->ldo_tls_keyfile;
	char *dhfile = lo->ldo_tls_dhfile;

	if ( lo->ldo_tls_ctx )
		return 0;

	ldap_pvt_tls_init();

	if ( is_server && !certfile && !keyfile && !cacertfile && !cacertdir ) {
		/* minimum configuration not provided */
		return LDAP_NOT_SUPPORTED;
	}

#ifdef HAVE_EBCDIC
	/* This ASCII/EBCDIC handling is a real pain! */
	if ( ciphersuite ) {
		ciphersuite = LDAP_STRDUP( ciphersuite );
		__atoe( ciphersuite );
	}
	if ( cacertfile ) {
		cacertfile = LDAP_STRDUP( cacertfile );
		__atoe( cacertfile );
	}
	if ( cacertdir ) {
		cacertdir = LDAP_STRDUP( cacertdir );
		__atoe( cacertdir );
	}
	if ( certfile ) {
		certfile = LDAP_STRDUP( certfile );
		__atoe( certfile );
	}
	if ( keyfile ) {
		keyfile = LDAP_STRDUP( keyfile );
		__atoe( keyfile );
	}
	if ( dhfile ) {
		dhfile = LDAP_STRDUP( dhfile );
		__atoe( dhfile );
	}
#endif
	lo->ldo_tls_ctx = ldap_pvt_tls_ctx_new ( lo );
        if ( lo->ldo_tls_ctx == NULL ) {
                Debug( LDAP_DEBUG_ANY,
		       "TLS: could not allocate default ctx.\n",
		       0,0,0);
                rc = -1;
                goto error_exit;
        }

	/* fixme convert ciphersuite spec formats? */
/* 	if ( lo->ldo_tls_ciphersuite && hm ) { */
/* 		Debug( LDAP_DEBUG_ANY, */
/* 			   "TLS: could not set cipher list %s.\n", */
/* 			   lo->ldo_tls_ciphersuite, 0, 0 ); */
/* 		tls_report_error(); */
/* 		rc = -1; */
/* 		goto error_exit; */
/* 	} */

	if (lo->ldo_tls_cacertdir != NULL) {
		Debug( LDAP_DEBUG_ANY, 
		       "TLS: warning: cacertdir not implemented for gnutls\n",
		       NULL, NULL, NULL );
	}

	if (lo->ldo_tls_cacertfile != NULL) {
		rc = gnutls_certificate_set_x509_trust_file( 
			((ldap_pvt_tls_ctx_t*) lo->ldo_tls_ctx)->cred,
			lo->ldo_tls_cacertfile,
			GNUTLS_X509_FMT_PEM );
		if ( rc < 0 ) goto error_exit;
	}

	if ( lo->ldo_tls_certfile && lo->ldo_tls_keyfile ) {
		rc = gnutls_certificate_set_x509_key_file( 
			((ldap_pvt_tls_ctx_t*) lo->ldo_tls_ctx)->cred,
			lo->ldo_tls_certfile,
			lo->ldo_tls_keyfile,
			GNUTLS_X509_FMT_PEM );
		if ( rc ) goto error_exit;
	} else if ( lo->ldo_tls_certfile || lo->ldo_tls_keyfile ) {
		Debug( LDAP_DEBUG_ANY, 
		       "TLS: only one of certfile and keyfile specified\n",
		       NULL, NULL, NULL );
		rc = 1;
		goto error_exit;
	}

	if ( lo->ldo_tls_dhfile ) {
		Debug( LDAP_DEBUG_ANY, 
		       "TLS: warning: ignoring dhfile\n", 
		       NULL, NULL, NULL );
	}

	gnutls_dh_params_init (&((ldap_pvt_tls_ctx_t*) 
				lo->ldo_tls_ctx)->dh_params);
	gnutls_dh_params_generate2 (((ldap_pvt_tls_ctx_t*) 
				     lo->ldo_tls_ctx)->dh_params, 
				    DH_BITS);

	/* fixme verify options */
/* 	i = SSL_VERIFY_NONE; */
/* 	if ( lo->ldo_tls_require_cert ) { */
/* 		i = SSL_VERIFY_PEER; */
/* 		if ( lo->ldo_tls_require_cert == LDAP_OPT_X_TLS_DEMAND || */
/* 			 lo->ldo_tls_require_cert == LDAP_OPT_X_TLS_HARD ) { */
/* 			i |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT; */
/* 		} */
/* 	} */

/* 	SSL_CTX_set_verify( lo->ldo_tls_ctx, i, */
/* 		lo->ldo_tls_require_cert == LDAP_OPT_X_TLS_ALLOW ? */
/* 		tls_verify_ok : tls_verify_cb ); */
/* 	SSL_CTX_set_tmp_rsa_callback( lo->ldo_tls_ctx, tls_tmp_rsa_cb ); */
/* 	if ( lo->ldo_tls_dhfile ) { */
/* 		SSL_CTX_set_tmp_dh_callback( lo->ldo_tls_ctx, tls_tmp_dh_cb ); */
/* 	} */

/* fixme crl check */

error_exit:
#ifdef HAVE_EBCDIC
	LDAP_FREE( ciphersuite );
	LDAP_FREE( cacertfile );
	LDAP_FREE( cacertdir );
	LDAP_FREE( certfile );
	LDAP_FREE( keyfile );
	LDAP_FREE( dhfile );
#endif
	return rc;
}

/*
 * initialize the default context
 */
int
ldap_pvt_tls_init_def_ctx( int is_server )
{
	return ldap_int_tls_init_ctx( LDAP_INT_GLOBAL_OPT(), is_server );
}

static ldap_pvt_gnutls_session_t *
alloc_handle( void *ctx_arg, int is_server )
{
	ldap_pvt_tls_ctx_t *ctx;
	ldap_pvt_gnutls_session_t *session;

	if ( ctx_arg ) {
		ctx = (ldap_pvt_tls_ctx_t *) ctx_arg;
	} else {
		struct ldapoptions *lo = LDAP_INT_GLOBAL_OPT();   
		if ( ldap_pvt_tls_init_def_ctx( is_server ) < 0 ) return NULL;
		ctx = lo->ldo_tls_ctx;
	}

	session = ldap_pvt_gnutls_session_new( ctx, is_server );
	if ( session == NULL ) {
		Debug( LDAP_DEBUG_ANY,"TLS: can't create ssl handle.\n",0,0,0);
		return NULL;
	}
	return session;
}

static int
update_flags( Sockbuf *sb, 
	      ldap_pvt_gnutls_session_t * session,
	      int rc )
{
	sb->sb_trans_needs_read  = 0;
	sb->sb_trans_needs_write = 0;

	if ( rc != GNUTLS_E_INTERRUPTED && rc != GNUTLS_E_AGAIN )
		return 0;

	switch (gnutls_record_get_direction (session->session)) {
	case 0: 
		sb->sb_trans_needs_read = 1;
		return 1;
	case 1:
		sb->sb_trans_needs_write = 1;
		return 1;
	}
	return 0;
}

/*
 * TLS support for LBER Sockbufs
 */

struct tls_data {
	ldap_pvt_gnutls_session_t	*session;
	Sockbuf_IO_Desc		*sbiod;
};

static ssize_t
sb_gtls_recv( gnutls_transport_ptr_t ptr, void *buf, size_t len )
{
	struct tls_data		*p;

	if ( buf == NULL || len <= 0 ) return 0;

	p = (struct tls_data *)ptr;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	return LBER_SBIOD_READ_NEXT( p->sbiod, buf, len );
}

static ssize_t
sb_gtls_send( gnutls_transport_ptr_t ptr, const void *buf, size_t len )
{
	struct tls_data		*p;
	
	if ( buf == NULL || len <= 0 ) return 0;
	
	p = (struct tls_data *)ptr;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	return LBER_SBIOD_WRITE_NEXT( p->sbiod, (char *)buf, len );
}

static int
sb_tls_setup( Sockbuf_IO_Desc *sbiod, void *arg )
{
	struct tls_data		*p;
	ldap_pvt_gnutls_session_t	*session = arg;

	assert( sbiod != NULL );

	p = LBER_MALLOC( sizeof( *p ) );
	if ( p == NULL ) {
		return -1;
	}
	
	gnutls_transport_set_ptr( session->session, (gnutls_transport_ptr)p );
	gnutls_transport_set_pull_function( session->session, sb_gtls_recv );
	gnutls_transport_set_push_function( session->session, sb_gtls_send );
	p->session = arg;
	p->sbiod = sbiod;
	sbiod->sbiod_pvt = p;
	return 0;
}

static int
sb_tls_remove( Sockbuf_IO_Desc *sbiod )
{
	struct tls_data		*p;
	
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );

	p = (struct tls_data *)sbiod->sbiod_pvt;
	gnutls_deinit ( p->session->session );
	LBER_FREE( p->session );
	LBER_FREE( sbiod->sbiod_pvt );
	sbiod->sbiod_pvt = NULL;
	return 0;
}

static int
sb_tls_close( Sockbuf_IO_Desc *sbiod )
{
	struct tls_data		*p;
	
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );

	p = (struct tls_data *)sbiod->sbiod_pvt;
	gnutls_bye ( p->session->session, GNUTLS_SHUT_RDWR );
	return 0;
}

static int
sb_tls_ctrl( Sockbuf_IO_Desc *sbiod, int opt, void *arg )
{
	struct tls_data		*p;
	
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );

	p = (struct tls_data *)sbiod->sbiod_pvt;
	
	if ( opt == LBER_SB_OPT_GET_SSL ) {
		*((ldap_pvt_gnutls_session_t **)arg) = p->session;
		return 1;
		
	} else if ( opt == LBER_SB_OPT_DATA_READY ) {
		if( gnutls_record_check_pending( p->session->session ) > 0 ) {
			return 1;
		}
	}
	
	return LBER_SBIOD_CTRL_NEXT( sbiod, opt, arg );
}

static ber_slen_t
sb_tls_read( Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	struct tls_data		*p;
	ber_slen_t		ret;
	int			err;

	assert( sbiod != NULL );
	assert( SOCKBUF_VALID( sbiod->sbiod_sb ) );

	p = (struct tls_data *)sbiod->sbiod_pvt;

	ret = gnutls_record_recv ( p->session->session, buf, len );
	switch (ret) {
	case GNUTLS_E_INTERRUPTED:
	case GNUTLS_E_AGAIN:
		sbiod->sbiod_sb->sb_trans_needs_read = 1;
		sock_errset(EWOULDBLOCK);
		ret = 0;
		break;
	case GNUTLS_E_REHANDSHAKE:
		for ( ret = gnutls_handshake ( p->session->session );
		      ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN;
		      ret = gnutls_handshake ( p->session->session ) );
		sbiod->sbiod_sb->sb_trans_needs_read = 1;
		ret = 0;
		break;
	default:
		sbiod->sbiod_sb->sb_trans_needs_read = 0;
	}
	return ret;
}

static ber_slen_t
sb_tls_write( Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	struct tls_data		*p;
	ber_slen_t		ret;
	int			err;

	assert( sbiod != NULL );
	assert( SOCKBUF_VALID( sbiod->sbiod_sb ) );

	p = (struct tls_data *)sbiod->sbiod_pvt;

	ret = gnutls_record_send ( p->session->session, (char *)buf, len );

	if ( ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN ) {
		sbiod->sbiod_sb->sb_trans_needs_write = 1;
		sock_errset(EWOULDBLOCK);
		ret = 0;
	} else {
		sbiod->sbiod_sb->sb_trans_needs_write = 0;
	}
	return ret;
}

static Sockbuf_IO sb_tls_sbio =
{
	sb_tls_setup,		/* sbi_setup */
	sb_tls_remove,		/* sbi_remove */
	sb_tls_ctrl,		/* sbi_ctrl */
	sb_tls_read,		/* sbi_read */
	sb_tls_write,		/* sbi_write */
	sb_tls_close		/* sbi_close */
};

/*
 * Call this to do a TLS connect on a sockbuf. ctx_arg can be
 * a SSL_CTX * or NULL, in which case the default ctx is used.
 *
 * Return value:
 *
 *  0 - Success. Connection is ready for communication.
 * <0 - Error. Can't create a TLS stream.
 * >0 - Partial success.
 *	  Do a select (using information from lber_pvt_sb_needs_{read,write}
 *		and call again.
 */

static int
ldap_int_tls_connect( LDAP *ld, LDAPConn *conn )
{
	Sockbuf *sb = conn->lconn_sb;
	int	err;
	ldap_pvt_gnutls_session_t	*ssl;

	if ( HAS_TLS( sb ) ) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&ssl );

	} else {
		struct ldapoptions *lo;
		ldap_pvt_tls_ctx_t *ctx;

		ctx = ld->ld_options.ldo_tls_ctx;

		ssl = alloc_handle( ctx, 0 );

		if ( ssl == NULL ) return -1;

#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)"tls_" );
#endif
		ber_sockbuf_add_io( sb, &sb_tls_sbio,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)ssl );

		lo = LDAP_INT_GLOBAL_OPT();   
		if( ctx == NULL ) {
			ctx = lo->ldo_tls_ctx;
			ldap_pvt_tls_ctx_ref( ctx );
			ld->ld_options.ldo_tls_ctx = ctx;
		}
		if ( ld->ld_options.ldo_tls_connect_cb )
			ld->ld_options.ldo_tls_connect_cb( ld, ssl, ctx,
			ld->ld_options.ldo_tls_connect_arg );
		if ( lo && lo->ldo_tls_connect_cb && lo->ldo_tls_connect_cb !=
			ld->ld_options.ldo_tls_connect_cb )
			lo->ldo_tls_connect_cb( ld, ssl, ctx, lo->ldo_tls_connect_arg );
	}

	err = gnutls_handshake( ssl->session );

#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif

	if ( err < 0 ) {
		if ( update_flags( sb, ssl, err )) {
			return 1;
		}

		if ( ld->ld_error ) {
			LDAP_FREE( ld->ld_error );
		}
		ld->ld_error = LDAP_STRDUP(gnutls_strerror( err ));
#ifdef HAVE_EBCDIC
		if ( ld->ld_error ) __etoa(ld->ld_error);
#endif

		Debug( LDAP_DEBUG_ANY,"TLS: can't connect: %s\n",
			ld->ld_error ? ld->ld_error : "" ,0,0);

		ber_sockbuf_remove_io( sb, &sb_tls_sbio,
			LBER_SBIOD_LEVEL_TRANSPORT );
#ifdef LDAP_DEBUG
		ber_sockbuf_remove_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT );
#endif
		return -1;
	}

	return 0;
}
/*
 * Call this to do a TLS accept on a sockbuf.
 * Everything else is the same as with tls_connect.
 */
int
ldap_pvt_tls_accept( Sockbuf *sb, void *ctx_arg )
{
	int	err;
	ldap_pvt_gnutls_session_t	*ssl;

	if ( HAS_TLS( sb ) ) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&ssl );

	} else {
		ssl = alloc_handle( ctx_arg, 1 );
		if ( ssl == NULL ) return -1;

#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)"tls_" );
#endif
		ber_sockbuf_add_io( sb, &sb_tls_sbio,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)ssl );
	}

	err = gnutls_handshake( ssl->session );

#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif
	if ( err < 0 ) {
		if ( update_flags( sb, ssl, err )) return 1;

		Debug( LDAP_DEBUG_ANY,"TLS: can't accept: %s.\n",
			gnutls_strerror( err ),0,0 );

		ber_sockbuf_remove_io( sb, &sb_tls_sbio,
			LBER_SBIOD_LEVEL_TRANSPORT );
#ifdef LDAP_DEBUG
		ber_sockbuf_remove_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT );
#endif
		return -1;
	}

	return 0;
}

int
ldap_pvt_tls_inplace ( Sockbuf *sb )
{
	return HAS_TLS( sb ) ? 1 : 0;
}

int
ldap_tls_inplace( LDAP *ld )
{
	Sockbuf		*sb = NULL;

	if ( ld->ld_defconn && ld->ld_defconn->lconn_sb ) {
		sb = ld->ld_defconn->lconn_sb;

	} else if ( ld->ld_sb ) {
		sb = ld->ld_sb;

	} else {
		return 0;
	}

	return ldap_pvt_tls_inplace( sb );
}

static void
x509_cert_get_dn( struct berval *cert, struct berval *dn, int get_subject )
{
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	ber_tag_t tag;
	ber_len_t len;
	ber_int_t i;

	ber_init2( ber, cert, LBER_USE_DER );
	tag = ber_skip_tag( ber, &len );	/* Sequence */
	tag = ber_skip_tag( ber, &len );	/* Sequence */
	tag = ber_skip_tag( ber, &len );	/* Context + Constructed (version) */
	if ( tag == 0xa0 )	/* Version is optional */
		tag = ber_get_int( ber, &i );	/* Int: Version */
	tag = ber_get_int( ber, &i );	/* Int: Serial */
	tag = ber_skip_tag( ber, &len );	/* Sequence: Signature */
	ber_skip_data( ber, len );
	if ( !get_subject ) {
		tag = ber_peek_tag( ber, &len );	/* Sequence: Issuer DN */
	} else {
		tag = ber_skip_tag( ber, &len );
		ber_skip_data( ber, len );
		tag = ber_skip_tag( ber, &len );	/* Sequence: Validity */
		ber_skip_data( ber, len );
		tag = ber_peek_tag( ber, &len );	/* Sequence: Subject DN */
	}
	len = ber_ptrlen( ber );
	dn->bv_val = cert->bv_val + len;
	dn->bv_len = cert->bv_len - len;
}

static int
tls_get_cert_dn( ldap_pvt_gnutls_session_t *session )
{
	if ( !session->peer_der_dn.bv_val ) {
		const gnutls_datum_t *peer_cert_list;
		int list_size;
		struct berval bv;

		peer_cert_list = gnutls_certificate_get_peers( session->session, 
							&list_size );
		if ( !peer_cert_list ) return LDAP_INVALID_CREDENTIALS;

		bv.bv_len = peer_cert_list->size;
		bv.bv_val = peer_cert_list->data;

		x509_cert_get_dn( &bv, &session->peer_der_dn, 1 );
	}
	return 0;
}

int
ldap_pvt_tls_get_peer_dn( void *s, struct berval *dn,
	LDAPDN_rewrite_dummy *func, unsigned flags )
{
	ldap_pvt_gnutls_session_t *session = s;
	int rc;

	rc = tls_get_cert_dn( session );
	if ( rc ) return rc;

	rc = ldap_X509dn2bv( &session->peer_der_dn, dn, 
			    (LDAPDN_rewrite_func *)func, flags);
	return rc;
}

/* what kind of hostname were we given? */
#define	IS_DNS	0
#define	IS_IP4	1
#define	IS_IP6	2

int
ldap_pvt_tls_check_hostname( LDAP *ld, void *s, const char *name_in )
{
	ldap_pvt_gnutls_session_t *session = s;
	int i, ret;
	const gnutls_datum_t *peer_cert_list;
	int list_size;
	struct berval bv;
	char altname[NI_MAXHOST];
	size_t altnamesize;

	gnutls_x509_crt_t cert;
	gnutls_datum_t *x;
	const char *name;
	char *ptr;
	char *domain = NULL;
#ifdef LDAP_PF_INET6
	struct in6_addr addr;
#else
	struct in_addr addr;
#endif
	int n, len1 = 0, len2 = 0;
	int ntype = IS_DNS;

	if( ldap_int_hostname &&
		( !name_in || !strcasecmp( name_in, "localhost" ) ) )
	{
		name = ldap_int_hostname;
	} else {
		name = name_in;
	}

	peer_cert_list = gnutls_certificate_get_peers( session->session, 
						&list_size );
	if ( !peer_cert_list ) {
		Debug( LDAP_DEBUG_ANY,
			"TLS: unable to get peer certificate.\n",
			0, 0, 0 );
		/* If this was a fatal condition, things would have
		 * aborted long before now.
		 */
		return LDAP_SUCCESS;
	}
	ret = gnutls_x509_crt_init( &cert );
	if ( ret < 0 )
		return LDAP_LOCAL_ERROR;
	ret = gnutls_x509_crt_import( cert, peer_cert_list, GNUTLS_X509_FMT_DER );
	if ( ret ) {
		gnutls_x509_crt_deinit( cert );
		return LDAP_LOCAL_ERROR;
	}

#ifdef LDAP_PF_INET6
	if (name[0] == '[' && strchr(name, ']')) {
		char *n2 = ldap_strdup(name+1);
		*strchr(n2, ']') = 2;
		if (inet_pton(AF_INET6, n2, &addr))
			ntype = IS_IP6;
		LDAP_FREE(n2);
	} else 
#endif
	if ((ptr = strrchr(name, '.')) && isdigit((unsigned char)ptr[1])) {
		if (inet_aton(name, (struct in_addr *)&addr)) ntype = IS_IP4;
	}
	
	if (ntype == IS_DNS) {
		len1 = strlen(name);
		domain = strchr(name, '.');
		if (domain) {
			len2 = len1 - (domain-name);
		}
	}

	for ( i=0, ret=0; ret >= 0; i++ ) {
		altnamesize = sizeof(altname);
		ret = gnutls_x509_crt_get_subject_alt_name( cert, i, 
			altname, &altnamesize, NULL );
		if ( ret < 0 ) break;

		/* ignore empty */
		if ( altnamesize == 0 ) continue;

		if ( ret == GNUTLS_SAN_DNSNAME ) {
			if (ntype != IS_DNS) continue;
	
			/* Is this an exact match? */
			if ((len1 == altnamesize) && !strncasecmp(name, altname, len1)) {
				break;
			}

			/* Is this a wildcard match? */
			if (domain && (altname[0] == '*') && (altname[1] == '.') &&
				(len2 == altnamesize-1) && !strncasecmp(domain, &altname[1], len2))
			{
				break;
			}
		} else if ( ret == GNUTLS_SAN_IPADDRESS ) {
			if (ntype == IS_DNS) continue;

#ifdef LDAP_PF_INET6
			if (ntype == IS_IP6 && altnamesize != sizeof(struct in6_addr)) {
				continue;
			} else
#endif
			if (ntype == IS_IP4 && altnamesize != sizeof(struct in_addr)) {
				continue;
			}
			if (!memcmp(altname, &addr, altnamesize)) {
				break;
			}
		}
	}
	if ( ret >= 0 ) {
		ret = LDAP_SUCCESS;
	} else {
		altnamesize = sizeof(altname);
		ret = gnutls_x509_crt_get_dn_by_oid( cert, CN_OID,
			0, 0, altname, &altnamesize );
		if ( ret < 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"TLS: unable to get common name from peer certificate.\n",
				0, 0, 0 );
			ret = LDAP_CONNECT_ERROR;
			if ( ld->ld_error ) {
				LDAP_FREE( ld->ld_error );
			}
			ld->ld_error = LDAP_STRDUP(
				_("TLS: unable to get CN from peer certificate"));

		} else {
			ret = LDAP_LOCAL_ERROR;
			if ( len1 == altnamesize && strncasecmp(name, altname, altnamesize) == 0 ) {
				ret = LDAP_SUCCESS;

			} else if (( altname[0] == '*' ) && ( altname[1] == '.' )) {
					/* Is this a wildcard match? */
				if( domain &&
					(len2 == altnamesize-1) && !strncasecmp(domain, &altname[1], len2)) {
					ret = LDAP_SUCCESS;
				}
			}
		}

		if( ret == LDAP_LOCAL_ERROR ) {
			altname[altnamesize] = '\0';
			Debug( LDAP_DEBUG_ANY, "TLS: hostname (%s) does not match "
				"common name in certificate (%s).\n", 
				name, altname, 0 );
			ret = LDAP_CONNECT_ERROR;
			if ( ld->ld_error ) {
				LDAP_FREE( ld->ld_error );
			}
			ld->ld_error = LDAP_STRDUP(
				_("TLS: hostname does not match CN in peer certificate"));
		}
	}
	gnutls_x509_crt_deinit( cert );
	return ret;
}

const char *
ldap_pvt_tls_get_peer_issuer( void *s )
{
#if 0	/* currently unused; see ldap_pvt_tls_get_peer_dn() if needed */
	gnutls_datum_t *x;
	gnutls_x509_dn *xn;
	char buf[2048], *p;

	x = SSL_get_peer_certificate((ldap_pvt_gnutls_session_t *)s);

	if (!x) return NULL;
	
	xn = X509_get_issuer_name(x);
	p = LDAP_STRDUP(X509_NAME_oneline(xn, buf, sizeof(buf)));
	X509_free(x);
	return p;
#else
	return NULL;
#endif
}

int
ldap_int_tls_config( LDAP *ld, int option, const char *arg )
{
	int i;

	switch( option ) {
	case LDAP_OPT_X_TLS_CACERTFILE:
	case LDAP_OPT_X_TLS_CACERTDIR:
	case LDAP_OPT_X_TLS_CERTFILE:
	case LDAP_OPT_X_TLS_KEYFILE:
	case LDAP_OPT_X_TLS_RANDOM_FILE:
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
	case LDAP_OPT_X_TLS_DHFILE:
		return ldap_pvt_tls_set_option( ld, option, (void *) arg );

	case LDAP_OPT_X_TLS_REQUIRE_CERT:
	case LDAP_OPT_X_TLS:
		i = -1;
		if ( strcasecmp( arg, "never" ) == 0 ) {
			i = LDAP_OPT_X_TLS_NEVER ;

		} else if ( strcasecmp( arg, "demand" ) == 0 ) {
			i = LDAP_OPT_X_TLS_DEMAND ;

		} else if ( strcasecmp( arg, "allow" ) == 0 ) {
			i = LDAP_OPT_X_TLS_ALLOW ;

		} else if ( strcasecmp( arg, "try" ) == 0 ) {
			i = LDAP_OPT_X_TLS_TRY ;

		} else if ( ( strcasecmp( arg, "hard" ) == 0 ) ||
			( strcasecmp( arg, "on" ) == 0 ) ||
			( strcasecmp( arg, "yes" ) == 0) ||
			( strcasecmp( arg, "true" ) == 0 ) )
		{
			i = LDAP_OPT_X_TLS_HARD ;
		}

		if (i >= 0) {
			return ldap_pvt_tls_set_option( ld, option, &i );
		}
		return -1;
	}
	return -1;
}

int
ldap_pvt_tls_get_option( LDAP *ld, int option, void *arg )
{
	struct ldapoptions *lo;

	if( ld != NULL ) {
		assert( LDAP_VALID( ld ) );

		if( !LDAP_VALID( ld ) ) {
			return LDAP_OPT_ERROR;
		}

		lo = &ld->ld_options;

	} else {
		/* Get pointer to global option structure */
		lo = LDAP_INT_GLOBAL_OPT();   
		if ( lo == NULL ) {
			return LDAP_NO_MEMORY;
		}
	}

	switch( option ) {
	case LDAP_OPT_X_TLS:
		*(int *)arg = lo->ldo_tls_mode;
		break;
	case LDAP_OPT_X_TLS_CTX:
		*(void **)arg = lo->ldo_tls_ctx;
		if ( lo->ldo_tls_ctx ) {
			ldap_pvt_tls_ctx_ref( lo->ldo_tls_ctx );
		}
		break;
	case LDAP_OPT_X_TLS_CACERTFILE:
		*(char **)arg = lo->ldo_tls_cacertfile ?
			LDAP_STRDUP( lo->ldo_tls_cacertfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CACERTDIR:
		*(char **)arg = lo->ldo_tls_cacertdir ?
			LDAP_STRDUP( lo->ldo_tls_cacertdir ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CERTFILE:
		*(char **)arg = lo->ldo_tls_certfile ?
			LDAP_STRDUP( lo->ldo_tls_certfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_KEYFILE:
		*(char **)arg = lo->ldo_tls_keyfile ?
			LDAP_STRDUP( lo->ldo_tls_keyfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_DHFILE:
		*(char **)arg = lo->ldo_tls_dhfile ?
			LDAP_STRDUP( lo->ldo_tls_dhfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		*(int *)arg = lo->ldo_tls_require_cert;
		break;
#ifdef HAVE_OPENSSL_CRL
	case LDAP_OPT_X_TLS_CRLCHECK:
		*(int *)arg = lo->ldo_tls_crlcheck;
		break;
#endif
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
		*(char **)arg = lo->ldo_tls_ciphersuite ?
			LDAP_STRDUP( lo->ldo_tls_ciphersuite ) : NULL;
		break;
	case LDAP_OPT_X_TLS_RANDOM_FILE:
		*(char **)arg = NULL;
		break;
	case LDAP_OPT_X_TLS_SSL_CTX: {
		void *retval = 0;
		if ( ld != NULL ) {
			LDAPConn *conn = ld->ld_defconn;
			if ( conn != NULL ) {
				Sockbuf *sb = conn->lconn_sb;
				retval = ldap_pvt_tls_sb_ctx( sb );
			}
		}
		*(void **)arg = retval;
		break;
	}
	case LDAP_OPT_X_TLS_CONNECT_CB:
		*(LDAP_TLS_CONNECT_CB **)arg = lo->ldo_tls_connect_cb;
		break;
	case LDAP_OPT_X_TLS_CONNECT_ARG:
		*(void **)arg = lo->ldo_tls_connect_arg;
		break;
	default:
		return -1;
	}
	return 0;
}

int
ldap_pvt_tls_set_option( LDAP *ld, int option, void *arg )
{
	struct ldapoptions *lo;

	if( ld != NULL ) {
		assert( LDAP_VALID( ld ) );

		if( !LDAP_VALID( ld ) ) {
			return LDAP_OPT_ERROR;
		}

		lo = &ld->ld_options;

	} else {
		/* Get pointer to global option structure */
		lo = LDAP_INT_GLOBAL_OPT();   
		if ( lo == NULL ) {
			return LDAP_NO_MEMORY;
		}
	}

	switch( option ) {
	case LDAP_OPT_X_TLS:
		if ( !arg ) return -1;

		switch( *(int *) arg ) {
		case LDAP_OPT_X_TLS_NEVER:
		case LDAP_OPT_X_TLS_DEMAND:
		case LDAP_OPT_X_TLS_ALLOW:
		case LDAP_OPT_X_TLS_TRY:
		case LDAP_OPT_X_TLS_HARD:
			if (lo != NULL) {
				lo->ldo_tls_mode = *(int *)arg;
			}

			return 0;
		}
		return -1;

	case LDAP_OPT_X_TLS_CTX:
		if ( lo->ldo_tls_ctx )
			ldap_pvt_tls_ctx_free( lo->ldo_tls_ctx );
		lo->ldo_tls_ctx = arg;
		ldap_pvt_tls_ctx_ref( lo->ldo_tls_ctx );
		return 0;
	case LDAP_OPT_X_TLS_CONNECT_CB:
		lo->ldo_tls_connect_cb = (LDAP_TLS_CONNECT_CB *)arg;
		return 0;
	case LDAP_OPT_X_TLS_CONNECT_ARG:
		lo->ldo_tls_connect_arg = arg;
		return 0;
	case LDAP_OPT_X_TLS_CACERTFILE:
		if ( lo->ldo_tls_cacertfile ) LDAP_FREE( lo->ldo_tls_cacertfile );
		lo->ldo_tls_cacertfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		return 0;
	case LDAP_OPT_X_TLS_CACERTDIR:
		if ( lo->ldo_tls_cacertdir ) LDAP_FREE( lo->ldo_tls_cacertdir );
		lo->ldo_tls_cacertdir = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		return 0;
	case LDAP_OPT_X_TLS_CERTFILE:
		if ( lo->ldo_tls_certfile ) LDAP_FREE( lo->ldo_tls_certfile );
		lo->ldo_tls_certfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		return 0;
	case LDAP_OPT_X_TLS_KEYFILE:
		if ( lo->ldo_tls_keyfile ) LDAP_FREE( lo->ldo_tls_keyfile );
		lo->ldo_tls_keyfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		return 0;
	case LDAP_OPT_X_TLS_DHFILE:
		if ( lo->ldo_tls_dhfile ) LDAP_FREE( lo->ldo_tls_dhfile );
		lo->ldo_tls_dhfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		return 0;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		if ( !arg ) return -1;
		switch( *(int *) arg ) {
		case LDAP_OPT_X_TLS_NEVER:
		case LDAP_OPT_X_TLS_DEMAND:
		case LDAP_OPT_X_TLS_ALLOW:
		case LDAP_OPT_X_TLS_TRY:
		case LDAP_OPT_X_TLS_HARD:
			lo->ldo_tls_require_cert = * (int *) arg;
			return 0;
		}
		return -1;
#ifdef HAVE_OPENSSL_CRL
	case LDAP_OPT_X_TLS_CRLCHECK:
		if ( !arg ) return -1;
		switch( *(int *) arg ) {
		case LDAP_OPT_X_TLS_CRL_NONE:
		case LDAP_OPT_X_TLS_CRL_PEER:
		case LDAP_OPT_X_TLS_CRL_ALL:
			lo->ldo_tls_crlcheck = * (int *) arg;
			return 0;
		}
		return -1;
#endif
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
		if ( lo->ldo_tls_ciphersuite ) LDAP_FREE( lo->ldo_tls_ciphersuite );
		lo->ldo_tls_ciphersuite = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		return 0;

	case LDAP_OPT_X_TLS_RANDOM_FILE:
		return 0;
		break;

	case LDAP_OPT_X_TLS_NEWCTX:
		if ( !arg ) return -1;
		if ( lo->ldo_tls_ctx )
			ldap_pvt_tls_ctx_free( lo->ldo_tls_ctx );
		lo->ldo_tls_ctx = NULL;
		return ldap_int_tls_init_ctx( lo, *(int *)arg );
	default:
		return -1;
	}
	return 0;
}

int
ldap_int_tls_start ( LDAP *ld, LDAPConn *conn, LDAPURLDesc *srv )
{
	Sockbuf *sb = conn->lconn_sb;
	char *host;
	void *ssl;

	if( srv ) {
		host = srv->lud_host;
	} else {
 		host = conn->lconn_server->lud_host;
	}

	/* avoid NULL host */
	if( host == NULL ) {
		host = "localhost";
	}

	(void) ldap_pvt_tls_init();

	/*
	 * Fortunately, the lib uses blocking io...
	 */
	if ( ldap_int_tls_connect( ld, conn ) < 0 ) {
		ld->ld_errno = LDAP_CONNECT_ERROR;
		return (ld->ld_errno);
	}

	ssl = ldap_pvt_tls_sb_ctx( sb );
	assert( ssl != NULL );

	/* 
	 * compare host with name(s) in certificate
	 */
	if (ld->ld_options.ldo_tls_require_cert != LDAP_OPT_X_TLS_NEVER) {
		ld->ld_errno = ldap_pvt_tls_check_hostname( ld, ssl, host );
		if (ld->ld_errno != LDAP_SUCCESS) {
			return ld->ld_errno;
		}
	}

	return LDAP_SUCCESS;
}

void *
ldap_pvt_tls_sb_ctx( Sockbuf *sb )
{
	void			*p;
	
	if (HAS_TLS( sb )) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&p );
		return p;
	}
	return NULL;
}

int
ldap_pvt_tls_get_strength( void *s )
{
	ldap_pvt_gnutls_session_t *session = s;
	gnutls_cipher_algorithm_t c;

	c = gnutls_cipher_get( session->session );
	return gnutls_cipher_get_key_size( c );
}

int
ldap_pvt_tls_get_my_dn( void *s, struct berval *dn, LDAPDN_rewrite_dummy *func, unsigned flags )
{
	ldap_pvt_gnutls_session_t *session = s;
	const gnutls_datum_t *x;
	struct berval bv, der_dn;
	int rc;

	x = gnutls_certificate_get_ours( session->session );

	if (!x) return LDAP_INVALID_CREDENTIALS;
	
	bv.bv_val = x->data;
	bv.bv_len = x->size;

	x509_cert_get_dn( &bv, &der_dn, 1 );
	rc = ldap_X509dn2bv(&der_dn, dn, (LDAPDN_rewrite_func *)func, flags );
	return rc;
}

int
ldap_start_tls( LDAP *ld,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls,
	int *msgidp )
{
	return ldap_extended_operation( ld, LDAP_EXOP_START_TLS,
		NULL, serverctrls, clientctrls, msgidp );
}

int
ldap_install_tls( LDAP *ld )
{
#ifndef HAVE_TLS
	return LDAP_NOT_SUPPORTED;
#else
	if ( ldap_tls_inplace( ld ) ) {
		return LDAP_LOCAL_ERROR;
	}

	return ldap_int_tls_start( ld, ld->ld_defconn, NULL );
#endif
}

int
ldap_start_tls_s ( LDAP *ld,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls )
{
#ifndef HAVE_TLS
	return LDAP_NOT_SUPPORTED;
#else
	int rc;
	char *rspoid = NULL;
	struct berval *rspdata = NULL;

	/* XXYYZ: this initiates operation only on default connection! */

	if ( ldap_tls_inplace( ld ) ) {
		return LDAP_LOCAL_ERROR;
	}

	rc = ldap_extended_operation_s( ld, LDAP_EXOP_START_TLS,
		NULL, serverctrls, clientctrls, &rspoid, &rspdata );

	if ( rspoid != NULL ) {
		LDAP_FREE(rspoid);
	}

	if ( rspdata != NULL ) {
		ber_bvfree( rspdata );
	}

	if ( rc == LDAP_SUCCESS ) {
		rc = ldap_int_tls_start( ld, ld->ld_defconn, NULL );
	}

	return rc;
#endif
}

/* These tags probably all belong in lber.h, but they're
 * not normally encountered when processing LDAP, so maybe
 * they belong somewhere else instead.
 */

#define LBER_TAG_OID		((ber_tag_t) 0x06UL)

/* Tags for string types used in a DirectoryString.
 *
 * Note that IA5string is not one of the defined choices for
 * DirectoryString in X.520, but it gets used for email AVAs.
 */
#define	LBER_TAG_UTF8		((ber_tag_t) 0x0cUL)
#define	LBER_TAG_PRINTABLE	((ber_tag_t) 0x13UL)
#define	LBER_TAG_TELETEX	((ber_tag_t) 0x14UL)
#define	LBER_TAG_IA5		((ber_tag_t) 0x16UL)
#define	LBER_TAG_UNIVERSAL	((ber_tag_t) 0x1cUL)
#define	LBER_TAG_BMP		((ber_tag_t) 0x1eUL)

static oid_name *
find_oid( struct berval *oid )
{
	int i;

	for ( i=0; !BER_BVISNULL( &oids[i].oid ); i++ ) {
		if ( oids[i].oid.bv_len != oid->bv_len ) continue;
		if ( !strcmp( oids[i].oid.bv_val, oid->bv_val ))
			return &oids[i];
	}
	return NULL;
}

/* Convert a structured DN from an X.509 certificate into an LDAPV3 DN.
 * x509_name must be raw DER. If func is non-NULL, the
 * constructed DN will use numeric OIDs to identify attributeTypes,
 * and the func() will be invoked to rewrite the DN with the given
 * flags.
 *
 * Otherwise the DN will use shortNames from a hardcoded table.
 */

int
ldap_X509dn2bv( void *x509_name, struct berval *bv, LDAPDN_rewrite_func *func,
	unsigned flags )
{
	LDAPDN	newDN;
	LDAPRDN	newRDN;
	LDAPAVA *newAVA, *baseAVA;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	char oids[8192], *oidptr = oids, *oidbuf = NULL;
	void *ptrs[2048];
	char *dn_end, *rdn_end;
	int i, navas, nrdns, rc = LDAP_SUCCESS;
	size_t dnsize, oidrem = sizeof(oids), oidsize = 0;
	int csize;
	ber_tag_t tag;
	ber_len_t len;
	oid_name *oidname;

	struct berval	Oid, Val, oid2, *in = x509_name;

	assert( bv != NULL );

	bv->bv_len = 0;
	bv->bv_val = NULL;

	navas = 0;
	nrdns = 0;

	/* A DN is a SEQUENCE of RDNs. An RDN is a SET of AVAs.
	 * An AVA is a SEQUENCE of attr and value.
	 * Count the number of AVAs and RDNs
	 */
	ber_init2( ber, in, LBER_USE_DER );
	tag = ber_peek_tag( ber, &len );
	if ( tag != LBER_SEQUENCE )
		return LDAP_DECODING_ERROR;

	for ( tag = ber_first_element( ber, &len, &dn_end );
		tag == LBER_SET;
		tag = ber_next_element( ber, &len, dn_end )) {
		nrdns++;
		for ( tag = ber_first_element( ber, &len, &rdn_end );
			tag == LBER_SEQUENCE;
			tag = ber_next_element( ber, &len, rdn_end )) {
			tag = ber_skip_tag( ber, &len );
			ber_skip_data( ber, len );
			navas++;
		}
	}

	/* Allocate the DN/RDN/AVA stuff as a single block */    
	dnsize = sizeof(LDAPRDN) * (nrdns+1);
	dnsize += sizeof(LDAPAVA *) * (navas+nrdns);
	dnsize += sizeof(LDAPAVA) * navas;
	if (dnsize > sizeof(ptrs)) {
		newDN = (LDAPDN)LDAP_MALLOC( dnsize );
		if ( newDN == NULL )
			return LDAP_NO_MEMORY;
	} else {
		newDN = (LDAPDN)(char *)ptrs;
	}
	
	newDN[nrdns] = NULL;
	newRDN = (LDAPRDN)(newDN + nrdns+1);
	newAVA = (LDAPAVA *)(newRDN + navas + nrdns);
	baseAVA = newAVA;

	/* Rewind and start extracting */
	ber_rewind( ber );

	tag = ber_first_element( ber, &len, &dn_end );
	for ( i = nrdns - 1; i >= 0; i-- ) {
		newDN[i] = newRDN;

		for ( tag = ber_first_element( ber, &len, &rdn_end );
			tag == LBER_SEQUENCE;
			tag = ber_next_element( ber, &len, rdn_end )) {

			*newRDN++ = newAVA;
			tag = ber_skip_tag( ber, &len );
			tag = ber_get_stringbv( ber, &Oid, 0 );
			if ( tag != LBER_TAG_OID ) {
				rc = LDAP_DECODING_ERROR;
				goto nomem;
			}

			oid2.bv_val = oidptr;
			oid2.bv_len = oidrem;
			ber_decode_oid( &Oid, &oid2 );
			oidname = find_oid( &oid2 );
			if ( !oidname ) {
				newAVA->la_attr = oid2;
				oidptr += oid2.bv_len + 1;
				oidrem -= oid2.bv_len + 1;

				/* Running out of OID buffer space? */
				if (oidrem < 128) {
					if ( oidsize == 0 ) {
						oidsize = sizeof(oids) * 2;
						oidrem = oidsize;
						oidbuf = LDAP_MALLOC( oidsize );
						if ( oidbuf == NULL ) goto nomem;
						oidptr = oidbuf;
					} else {
						char *old = oidbuf;
						oidbuf = LDAP_REALLOC( oidbuf, oidsize*2 );
						if ( oidbuf == NULL ) goto nomem;
						/* Buffer moved! Fix AVA pointers */
						if ( old != oidbuf ) {
							LDAPAVA *a;
							long dif = oidbuf - old;

							for (a=baseAVA; a<=newAVA; a++){
								if (a->la_attr.bv_val >= old &&
									a->la_attr.bv_val <= (old + oidsize))
									a->la_attr.bv_val += dif;
							}
						}
						oidptr = oidbuf + oidsize - oidrem;
						oidrem += oidsize;
						oidsize *= 2;
					}
				}
			} else {
				if ( func ) {
					newAVA->la_attr = oidname->oid;
				} else {
					newAVA->la_attr = oidname->name;
				}
			}
			tag = ber_get_stringbv( ber, &Val, 0 );
			switch(tag) {
			case LBER_TAG_UNIVERSAL:
				/* This uses 32-bit ISO 10646-1 */
				csize = 4; goto to_utf8;
			case LBER_TAG_BMP:
				/* This uses 16-bit ISO 10646-1 */
				csize = 2; goto to_utf8;
			case LBER_TAG_TELETEX:
				/* This uses 8-bit, assume ISO 8859-1 */
				csize = 1;
to_utf8:		rc = ldap_ucs_to_utf8s( &Val, csize, &newAVA->la_value );
				newAVA->la_flags |= LDAP_AVA_FREE_VALUE;
				if (rc != LDAP_SUCCESS) goto nomem;
				newAVA->la_flags = LDAP_AVA_NONPRINTABLE;
				break;
			case LBER_TAG_UTF8:
				newAVA->la_flags = LDAP_AVA_NONPRINTABLE;
				/* This is already in UTF-8 encoding */
			case LBER_TAG_IA5:
			case LBER_TAG_PRINTABLE:
				/* These are always 7-bit strings */
				newAVA->la_value = Val;
			default:
				;
			}
			newAVA->la_private = NULL;
			newAVA->la_flags = LDAP_AVA_STRING;
			newAVA++;
		}
		*newRDN++ = NULL;
		tag = ber_next_element( ber, &len, dn_end );
	}
		
	if ( func ) {
		rc = func( newDN, flags, NULL );
		if ( rc != LDAP_SUCCESS )
			goto nomem;
	}

	rc = ldap_dn2bv_x( newDN, bv, LDAP_DN_FORMAT_LDAPV3, NULL );

nomem:
	for (;baseAVA < newAVA; baseAVA++) {
		if (baseAVA->la_flags & LDAP_AVA_FREE_ATTR)
			LDAP_FREE( baseAVA->la_attr.bv_val );
		if (baseAVA->la_flags & LDAP_AVA_FREE_VALUE)
			LDAP_FREE( baseAVA->la_value.bv_val );
	}

	if ( oidsize != 0 )
		LDAP_FREE( oidbuf );
	if ( newDN != (LDAPDN)(char *) ptrs )
		LDAP_FREE( newDN );
	return rc;
}

#if 0
/* test driver - feed in a DER cert on stdin */
main( int argc, char *argv ) {
	char buf[8192];
	struct berval bv, bv2, dn;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	ber_tag_t tag;
	ber_len_t len;

	bv.bv_len = fread(buf, 1, sizeof(buf), stdin);
	bv.bv_val = buf;

	ber_init2( ber, &bv, LBER_USE_DER );
	tag = ber_skip_tag( ber, &len );	/* Sequence */
	tag = ber_skip_tag( ber, &len );	/* Sequence */
	tag = ber_skip_tag( ber, &len );	/* Context + Constructed (version) */
	if ( tag == 0xa0 )	/* Version is optional */
		tag = ber_get_int( ber, &len );	/* Int: Version */
	tag = ber_get_int( ber, &len );	/* Int: Serial */
	tag = ber_skip_tag( ber, &len );	/* Sequence: Signature */
	tag = ber_skip_tag( ber, &len );	/* : Signature */
	ber_skip_data( ber, len );
	tag = ber_skip_tag( ber, &len );	/* : Signature */
	ber_skip_data( ber, len );
	tag = ber_peek_tag( ber, &len );	/* Sequence: Issuer DN */
	len = ber_ptrlen( ber );
	bv2.bv_val = bv.bv_val + len;
	bv2.bv_len = bv.bv_len - len;
	X509dn2bv( &bv2, &dn, NULL, 0 );
	printf( "Issuer: %s\n", dn.bv_val );
}
#endif

#endif /* HAVE_GNUTLS */
