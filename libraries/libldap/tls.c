/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * tls.c - Handle tls/ssl using SSLeay or OpenSSL.
 */

#include "portable.h"
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

#ifdef HAVE_TLS

#ifdef LDAP_R_COMPILE
#include <ldap_pvt_thread.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#elif defined( HAVE_SSL_H )
#include <ssl.h>
#endif

static int  tls_opt_trace = 1;
static char *tls_opt_certfile = NULL;
static char *tls_opt_keyfile = NULL;
static char *tls_opt_cacertfile = NULL;
static char *tls_opt_cacertdir = NULL;
static int  tls_opt_require_cert = LDAP_OPT_X_TLS_DEMAND;
static char *tls_opt_ciphersuite = NULL;
static char *tls_opt_randfile = NULL;

#define HAS_TLS( sb )	ber_sockbuf_ctrl( sb, LBER_SB_OPT_HAS_IO, \
				(void *)&sb_tls_sbio )

static void tls_report_error( void );

static void tls_info_cb( const SSL *ssl, int where, int ret );
static int tls_verify_cb( int ok, X509_STORE_CTX *ctx );
static int tls_verify_ok( int ok, X509_STORE_CTX *ctx );
static RSA * tls_tmp_rsa_cb( SSL *ssl, int is_export, int key_length );
static STACK_OF(X509_NAME) * get_ca_list( char * bundle, char * dir );

#if 0	/* Currently this is not used by anyone */
static DH * tls_tmp_dh_cb( SSL *ssl, int is_export, int key_length );
#endif

static SSL_CTX *tls_def_ctx = NULL;

static int tls_seed_PRNG( const char *randfile );

#ifdef LDAP_R_COMPILE
/*
 * provide mutexes for the SSLeay library.
 */
static ldap_pvt_thread_mutex_t	tls_mutexes[CRYPTO_NUM_LOCKS];

static void tls_locking_cb( int mode, int type, const char *file, int line )
{
	if ( mode & CRYPTO_LOCK ) {
		ldap_pvt_thread_mutex_lock( &tls_mutexes[type] );
	} else {
		ldap_pvt_thread_mutex_unlock( &tls_mutexes[type] );
	}
}

/*
 * an extra mutex for the default ctx.
 */

static ldap_pvt_thread_mutex_t tls_def_ctx_mutex;

static void tls_init_threads( void )
{
	int i;

	for( i=0; i< CRYPTO_NUM_LOCKS ; i++ ) {
		ldap_pvt_thread_mutex_init( &tls_mutexes[i] );
	}
	CRYPTO_set_locking_callback( tls_locking_cb );
	/* FIXME: the thread id should be added somehow... */

	ldap_pvt_thread_mutex_init( &tls_def_ctx_mutex );
}
#endif /* LDAP_R_COMPILE */

/*
 * Tear down the TLS subsystem. Should only be called once.
 */
void
ldap_pvt_tls_destroy( void )
{
	SSL_CTX_free(tls_def_ctx);
	tls_def_ctx = NULL;

	EVP_cleanup();
	ERR_remove_state(0);
	ERR_free_strings();

	if ( tls_opt_certfile ) {
		LDAP_FREE( tls_opt_certfile );
		tls_opt_certfile = NULL;
	}
	if ( tls_opt_keyfile ) {
		LDAP_FREE( tls_opt_keyfile );
		tls_opt_keyfile = NULL;
	}
	if ( tls_opt_cacertfile ) {
		LDAP_FREE( tls_opt_cacertfile );
		tls_opt_cacertfile = NULL;
	}
	if ( tls_opt_cacertdir ) {
		LDAP_FREE( tls_opt_cacertdir );
		tls_opt_cacertdir = NULL;
	}
	if ( tls_opt_ciphersuite ) {
		LDAP_FREE( tls_opt_ciphersuite );
		tls_opt_ciphersuite = NULL;
	}
	if ( tls_opt_randfile ) {
		LDAP_FREE( tls_opt_randfile );
		tls_opt_randfile = NULL;
	}
}

/*
 * Initialize TLS subsystem. Should be called only once.
 */
int
ldap_pvt_tls_init( void )
{
	static int tls_initialized = 0;

	if ( tls_initialized ) return 0;
	tls_initialized = 1;

#ifdef HAVE_EBCDIC
	{
		char *file = LDAP_STRDUP( tls_opt_randfile );
		if ( file ) __atoe( file );
		(void) tls_seed_PRNG( file );
		LDAP_FREE( file );
	}
#else
	(void) tls_seed_PRNG( tls_opt_randfile );
#endif

#ifdef LDAP_R_COMPILE
	tls_init_threads();
#endif

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	/* FIXME: mod_ssl does this */
	X509V3_add_standard_extensions();
	return 0;
}

/*
 * initialize the default context
 */
int
ldap_pvt_tls_init_def_ctx( void )
{
	STACK_OF(X509_NAME) *calist;
	int rc = 0;
	char *ciphersuite = tls_opt_ciphersuite;
	char *cacertfile = tls_opt_cacertfile;
	char *cacertdir = tls_opt_cacertdir;
	char *certfile = tls_opt_certfile;
	char *keyfile = tls_opt_keyfile;

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
#endif

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &tls_def_ctx_mutex );
#endif
	if ( tls_def_ctx == NULL ) {
		int i;
		tls_def_ctx = SSL_CTX_new( SSLv23_method() );
		if ( tls_def_ctx == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_init_def_ctx: "
				"TLS could not allocate default ctx (%d).\n",
				ERR_peek_error(), 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
			   "TLS: could not allocate default ctx (%lu).\n",
				ERR_peek_error(),0,0);
#endif
			rc = -1;
			goto error_exit;
		}

		SSL_CTX_set_session_id_context( tls_def_ctx,
			(const unsigned char *) "OpenLDAP", sizeof("OpenLDAP")-1 );

		if ( tls_opt_ciphersuite &&
			!SSL_CTX_set_cipher_list( tls_def_ctx, ciphersuite ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_init_def_ctx: "
				"TLS could not set cipher list %s.\n",
				tls_opt_ciphersuite, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				   "TLS: could not set cipher list %s.\n",
				   tls_opt_ciphersuite, 0, 0 );
#endif
			tls_report_error();
			rc = -1;
			goto error_exit;
		}

		if (tls_opt_cacertfile != NULL || tls_opt_cacertdir != NULL) {
			if ( !SSL_CTX_load_verify_locations( tls_def_ctx,
					cacertfile, cacertdir ) ||
				!SSL_CTX_set_default_verify_paths( tls_def_ctx ) )
			{
#ifdef NEW_LOGGING
				LDAP_LOG ( TRANSPORT, ERR, 
					"ldap_pvt_tls_init_def_ctx: "
					"TLS could not load verify locations "
					"(file:`%s',dir:`%s').\n",
					tls_opt_cacertfile ? tls_opt_cacertfile : "",
					tls_opt_cacertdir ? tls_opt_cacertdir : "", 0 );
#else
				Debug( LDAP_DEBUG_ANY, "TLS: "
					"could not load verify locations (file:`%s',dir:`%s').\n",
					tls_opt_cacertfile ? tls_opt_cacertfile : "",
					tls_opt_cacertdir ? tls_opt_cacertdir : "",
					0 );
#endif
				tls_report_error();
				rc = -1;
				goto error_exit;
			}

			calist = get_ca_list( cacertfile, cacertdir );
			if ( !calist ) {
#ifdef NEW_LOGGING
				LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_init_def_ctx: "
					"TLS could not load client CA list (file: `%s',dir:`%s')\n",
					tls_opt_cacertfile ? tls_opt_cacertfile : "",
					tls_opt_cacertdir ? tls_opt_cacertdir : "", 0 );
#else
				Debug( LDAP_DEBUG_ANY, "TLS: "
					"could not load client CA list (file:`%s',dir:`%s').\n",
					tls_opt_cacertfile ? tls_opt_cacertfile : "",
					tls_opt_cacertdir ? tls_opt_cacertdir : "",
					0 );
#endif
				tls_report_error();
				rc = -1;
				goto error_exit;
			}

			SSL_CTX_set_client_CA_list( tls_def_ctx, calist );
		}

		if ( tls_opt_keyfile &&
			!SSL_CTX_use_PrivateKey_file( tls_def_ctx,
				keyfile, SSL_FILETYPE_PEM ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_init_def_ctx: "
				"TLS could not use key file `%s'.\n", tls_opt_keyfile, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"TLS: could not use key file `%s'.\n",
				tls_opt_keyfile,0,0);
#endif
			tls_report_error();
			rc = -1;
			goto error_exit;
		}

		if ( tls_opt_certfile &&
			!SSL_CTX_use_certificate_file( tls_def_ctx,
				certfile, SSL_FILETYPE_PEM ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_init_def_ctx: "
				"TLS could not use certificate `%s'.\n", 
				tls_opt_certfile, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"TLS: could not use certificate `%s'.\n",
				tls_opt_certfile,0,0);
#endif
			tls_report_error();
			rc = -1;
			goto error_exit;
		}

		if ( ( tls_opt_certfile || tls_opt_keyfile ) &&
			!SSL_CTX_check_private_key( tls_def_ctx ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, 
				"ldap_pvt_tls_init_def_ctx: TLS private key mismatch.\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"TLS: private key mismatch.\n",
				0,0,0);
#endif
			tls_report_error();
			rc = -1;
			goto error_exit;
		}

		if ( tls_opt_trace ) {
			SSL_CTX_set_info_callback( tls_def_ctx, tls_info_cb );
		}

		i = SSL_VERIFY_NONE;
		if ( tls_opt_require_cert ) {
			i = SSL_VERIFY_PEER;
			if ( tls_opt_require_cert == LDAP_OPT_X_TLS_DEMAND ||
				 tls_opt_require_cert == LDAP_OPT_X_TLS_HARD ) {
				i |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
			}
		}

		SSL_CTX_set_verify( tls_def_ctx, i,
			tls_opt_require_cert == LDAP_OPT_X_TLS_ALLOW ?
			tls_verify_ok : tls_verify_cb );
		SSL_CTX_set_tmp_rsa_callback( tls_def_ctx, tls_tmp_rsa_cb );
		/* SSL_CTX_set_tmp_dh_callback( tls_def_ctx, tls_tmp_dh_cb ); */
	}
error_exit:
	if ( rc == -1 && tls_def_ctx != NULL ) {
		SSL_CTX_free( tls_def_ctx );
		tls_def_ctx = NULL;
	}
#ifdef HAVE_EBCDIC
	LDAP_FREE( ciphersuite );
	LDAP_FREE( cacertfile );
	LDAP_FREE( cacertdir );
	LDAP_FREE( certfile );
	LDAP_FREE( keyfile );
#endif
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &tls_def_ctx_mutex );
#endif
	return rc;
}

static STACK_OF(X509_NAME) *
get_ca_list( char * bundle, char * dir )
{
	STACK_OF(X509_NAME) *ca_list = NULL;

	if ( bundle ) {
		ca_list = SSL_load_client_CA_file( bundle );
	}
#if defined(HAVE_DIRENT_H) || defined(dirent)
	if ( dir ) {
		int freeit = 0;

		if ( !ca_list ) {
			ca_list = sk_X509_NAME_new_null();
			freeit = 1;
		}
		if ( !SSL_add_dir_cert_subjects_to_stack( ca_list, dir ) &&
			freeit ) {
			sk_X509_NAME_free( ca_list );
			ca_list = NULL;
		}
	}
#endif
	return ca_list;
}

static SSL *
alloc_handle( void *ctx_arg )
{
	SSL_CTX	*ctx;
	SSL	*ssl;

	if ( ctx_arg ) {
		ctx = (SSL_CTX *) ctx_arg;
	} else {
		if ( ldap_pvt_tls_init_def_ctx() < 0 ) return NULL;
		ctx = tls_def_ctx;
	}

	ssl = SSL_new( ctx );
	if ( ssl == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR, 
			"alloc_handle: TLS can't create ssl handle.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,"TLS: can't create ssl handle.\n",0,0,0);
#endif
		return NULL;
	}
	return ssl;
}

static int
update_flags( Sockbuf *sb, SSL * ssl, int rc )
{
	int err = SSL_get_error(ssl, rc);

	sb->sb_trans_needs_read  = 0;
	sb->sb_trans_needs_write = 0;

	if (err == SSL_ERROR_WANT_READ) {
		sb->sb_trans_needs_read  = 1;
		return 1;

	} else if (err == SSL_ERROR_WANT_WRITE) {
		sb->sb_trans_needs_write = 1;
		return 1;

	} else if (err == SSL_ERROR_WANT_CONNECT) {
		return 1;
	}
	return 0;
}

/*
 * TLS support for LBER Sockbufs
 */

struct tls_data {
	SSL			*ssl;
	Sockbuf_IO_Desc		*sbiod;
};

static BIO_METHOD sb_tls_bio_method;

static int
sb_tls_setup( Sockbuf_IO_Desc *sbiod, void *arg )
{
	struct tls_data		*p;
	BIO			*bio;

	assert( sbiod != NULL );

	p = LBER_MALLOC( sizeof( *p ) );
	if ( p == NULL ) {
		return -1;
	}
	
	p->ssl = (SSL *)arg;
	p->sbiod = sbiod;
	bio = BIO_new( &sb_tls_bio_method );
	bio->ptr = (void *)p;
	SSL_set_bio( p->ssl, bio, bio );
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
	SSL_free( p->ssl );
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
	SSL_shutdown( p->ssl );
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
		*((SSL **)arg) = p->ssl;
		return 1;

	} else if ( opt == LBER_SB_OPT_DATA_READY ) {
		if( SSL_pending( p->ssl ) > 0 ) {
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

	ret = SSL_read( p->ssl, (char *)buf, len );
#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif
	err = SSL_get_error( p->ssl, ret );
	if (err == SSL_ERROR_WANT_READ ) {
		sbiod->sbiod_sb->sb_trans_needs_read = 1;
		errno = EWOULDBLOCK;
	}
	else
		sbiod->sbiod_sb->sb_trans_needs_read = 0;
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

	ret = SSL_write( p->ssl, (char *)buf, len );
#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif
	err = SSL_get_error( p->ssl, ret );
	if (err == SSL_ERROR_WANT_WRITE ) {
		sbiod->sbiod_sb->sb_trans_needs_write = 1;
		errno = EWOULDBLOCK;

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

static int
sb_tls_bio_create( BIO *b ) {
	b->init = 1;
	b->num = 0;
	b->ptr = NULL;
	b->flags = 0;
	return 1;
}

static int
sb_tls_bio_destroy( BIO *b )
{
	if ( b == NULL ) return 0;

	b->ptr = NULL;		/* sb_tls_remove() will free it */
	b->init = 0;
	b->flags = 0;
	return 1;
}

static int
sb_tls_bio_read( BIO *b, char *buf, int len )
{
	struct tls_data		*p;
	int			ret;
		
	if ( buf == NULL || len <= 0 ) return 0;

	p = (struct tls_data *)b->ptr;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	ret = LBER_SBIOD_READ_NEXT( p->sbiod, buf, len );

	BIO_clear_retry_flags( b );
	if ( ret < 0 ) {
		int err = errno;
		if ( err == EAGAIN || err == EWOULDBLOCK ) {
			BIO_set_retry_read( b );
		}
	}

	return ret;
}

static int
sb_tls_bio_write( BIO *b, const char *buf, int len )
{
	struct tls_data		*p;
	int			ret;
	
	if ( buf == NULL || len <= 0 ) return 0;
	
	p = (struct tls_data *)b->ptr;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	ret = LBER_SBIOD_WRITE_NEXT( p->sbiod, (char *)buf, len );

	BIO_clear_retry_flags( b );
	if ( ret < 0 ) {
		int err = errno;
		if ( err == EAGAIN || err == EWOULDBLOCK ) {
			BIO_set_retry_write( b );
		}
	}

	return ret;
}

static long
sb_tls_bio_ctrl( BIO *b, int cmd, long num, void *ptr )
{
	if ( cmd == BIO_CTRL_FLUSH ) {
		/* The OpenSSL library needs this */
		return 1;
	}
	return 0;
}

static int
sb_tls_bio_gets( BIO *b, char *buf, int len )
{
	return -1;
}

static int
sb_tls_bio_puts( BIO *b, const char *str )
{
	return sb_tls_bio_write( b, str, strlen( str ) );
}
	
static BIO_METHOD sb_tls_bio_method =
{
	( 100 | 0x400 ),		/* it's a source/sink BIO */
	"sockbuf glue",
	sb_tls_bio_write,
	sb_tls_bio_read,
	sb_tls_bio_puts,
	sb_tls_bio_gets,
	sb_tls_bio_ctrl,
	sb_tls_bio_create,
	sb_tls_bio_destroy
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
	SSL	*ssl;

	if ( HAS_TLS( sb ) ) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&ssl );

	} else {
		void *ctx = ld->ld_defconn
			? ld->ld_defconn->lconn_tls_ctx : NULL;

		ssl = alloc_handle( ctx );

		if ( ssl == NULL ) return -1;

#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)"tls_" );
#endif
		ber_sockbuf_add_io( sb, &sb_tls_sbio,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)ssl );

		if( ctx == NULL ) {
			conn->lconn_tls_ctx = tls_def_ctx;
		}
	}

	err = SSL_connect( ssl );

#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif

	if ( err <= 0 ) {
		if ( update_flags( sb, ssl, err )) {
			return 1;
		}

		if ((err = ERR_peek_error())) {
			char buf[256];
			ld->ld_error = LDAP_STRDUP(ERR_error_string(err, buf));
#ifdef HAVE_EBCDIC
			if ( ld->ld_error ) __etoa(ld->ld_error);
#endif
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR, 
			"ldap_int_tls_connect: TLS can't connect.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,"TLS: can't connect.\n",0,0,0);
#endif

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
	SSL	*ssl;

	if ( HAS_TLS( sb ) ) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&ssl );

	} else {
		ssl = alloc_handle( ctx_arg );
		if ( ssl == NULL ) return -1;

#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)"tls_" );
#endif
		ber_sockbuf_add_io( sb, &sb_tls_sbio,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)ssl );
	}

	err = SSL_accept( ssl );

#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif
	if ( err <= 0 ) {
		if ( update_flags( sb, ssl, err )) return 1;

#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR, 
			"ldap_pvt_tls_accept: TLS can't accept.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,"TLS: can't accept.\n",0,0,0 );
#endif

		tls_report_error();
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

static X509 *
tls_get_cert( SSL *s )
{
	/* If peer cert was bad, treat as if no cert was given */
	if (SSL_get_verify_result(s)) {
		/* If we can send an alert, do so */
		if (SSL_version(s) != SSL2_VERSION) {
			ssl3_send_alert(s,SSL3_AL_WARNING,SSL3_AD_BAD_CERTIFICATE);
		}
		return NULL;
	}
	return SSL_get_peer_certificate(s);
}

int
ldap_pvt_tls_get_peer_dn( void *s, struct berval *dn, LDAPDN_rewrite_dummy *func, unsigned flags )
{
	X509 *x;
	X509_NAME *xn;
	int rc;

	x = tls_get_cert((SSL *)s);

	if (!x) return LDAP_INVALID_CREDENTIALS;
	
	xn = X509_get_subject_name(x);
	rc = ldap_X509dn2bv(xn, dn, (LDAPDN_rewrite_func *)func, flags);
	X509_free(x);
	return rc;
}

char *
ldap_pvt_tls_get_peer_hostname( void *s )
{
	X509 *x;
	X509_NAME *xn;
	char buf[2048], *p;
	int ret;

	x = tls_get_cert((SSL *)s);
	if (!x) return NULL;
	
	xn = X509_get_subject_name(x);

	ret = X509_NAME_get_text_by_NID(xn, NID_commonName, buf, sizeof(buf));
	if( ret == -1 ) {
		X509_free(x);
		return NULL;
	}

	p = LDAP_STRDUP(buf);
	X509_free(x);
	return p;
}

/* what kind of hostname were we given? */
#define	IS_DNS	0
#define	IS_IP4	1
#define	IS_IP6	2

int
ldap_pvt_tls_check_hostname( LDAP *ld, void *s, const char *name_in )
{
	int i, ret = LDAP_LOCAL_ERROR;
	X509 *x;
	const char *name;
	char *ptr;
	int ntype = IS_DNS;
#ifdef LDAP_PF_INET6
	struct in6_addr addr;
#else
	struct in_addr addr;
#endif

	if( ldap_int_hostname &&
		( !name_in || !strcasecmp( name_in, "localhost" ) ) )
	{
		name = ldap_int_hostname;
	} else {
		name = name_in;
	}

	x = tls_get_cert((SSL *)s);
	if (!x) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR, 
			"ldap_pvt_tls_check_hostname: "
			"TLS unable to get peer certificate.\n" , 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"TLS: unable to get peer certificate.\n",
			0, 0, 0 );
#endif
		/* If this was a fatal condition, things would have
		 * aborted long before now.
		 */
		return LDAP_SUCCESS;
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
		if (inet_aton(name, (struct in_addr *)&addr))
			ntype = IS_IP4;
	}
	
	i = X509_get_ext_by_NID(x, NID_subject_alt_name, -1);
	if (i >= 0) {
		X509_EXTENSION *ex;
		STACK_OF(GENERAL_NAME) *alt;

		ex = X509_get_ext(x, i);
		alt = X509V3_EXT_d2i(ex);
		if (alt) {
			int n, len1 = 0, len2 = 0;
			char *domain = NULL;
			GENERAL_NAME *gn;

			if (ntype == IS_DNS) {
				len1 = strlen(name);
				domain = strchr(name, '.');
				if (domain) {
					len2 = len1 - (domain-name);
				}
			}
			n = sk_GENERAL_NAME_num(alt);
			for (i=0; i<n; i++) {
				char *sn;
				int sl;
				gn = sk_GENERAL_NAME_value(alt, i);
				if (gn->type == GEN_DNS) {
					if (ntype != IS_DNS) continue;

					sn = (char *) ASN1_STRING_data(gn->d.ia5);
					sl = ASN1_STRING_length(gn->d.ia5);

					/* Is this an exact match? */
					if ((len1 == sl) && !strncasecmp(name, sn, len1)) {
						break;
					}

					/* Is this a wildcard match? */
					if ((*sn == '*') && domain && (len2 == sl-1) &&
						!strncasecmp(domain, sn+1, len2)) {
						break;
					}

#if 0
					/* Is this a RFC 2459 style wildcard match? */
					if ((*sn == '.') && domain && (len2 == sl) &&
						!strncasecmp(domain, sn, len2)) {
						break;
					}
#endif
				} else if (gn->type == GEN_IPADD) {
					if (ntype == IS_DNS) continue;

					sn = (char *) ASN1_STRING_data(gn->d.ia5);
					sl = ASN1_STRING_length(gn->d.ia5);

#ifdef LDAP_PF_INET6
					if (ntype == IS_IP6 && sl != sizeof(struct in6_addr)) {
						continue;
					} else
#endif
					if (ntype == IS_IP4 && sl != sizeof(struct in_addr)) {
						continue;
					}
					if (!memcmp(sn, &addr, sl)) {
						break;
					}
				}
			}

			GENERAL_NAMES_free(alt);
			if (i < n) {	/* Found a match */
				ret = LDAP_SUCCESS;
			}
		}
	}

	if (ret != LDAP_SUCCESS) {
		X509_NAME *xn;
		char buf[2048];

		xn = X509_get_subject_name(x);

		if( X509_NAME_get_text_by_NID( xn, NID_commonName,
			buf, sizeof(buf)) == -1)
		{
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_check_hostname: "
				"TLS unable to get common name from peer certificate.\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"TLS: unable to get common name from peer certificate.\n",
				0, 0, 0 );
#endif
			ld->ld_error = LDAP_STRDUP(
				_("TLS: unable to get CN from peer certificate"));

		} else if (strcasecmp(name, buf)) {
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, "ldap_pvt_tls_check_hostname: "
				"TLS hostname (%s) does not match "
				"common name in certificate (%s).\n", name, buf, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "TLS: hostname (%s) does not match "
				"common name in certificate (%s).\n", 
				name, buf, 0 );
#endif
			ret = LDAP_CONNECT_ERROR;
			ld->ld_error = LDAP_STRDUP(
				_("TLS: hostname does not match CN in peer certificate"));

		} else {
			ret = LDAP_SUCCESS;
		}
	}
	X509_free(x);
	return ret;
}

const char *
ldap_pvt_tls_get_peer_issuer( void *s )
{
#if 0	/* currently unused; see ldap_pvt_tls_get_peer_dn() if needed */
	X509 *x;
	X509_NAME *xn;
	char buf[2048], *p;

	x = SSL_get_peer_certificate((SSL *)s);

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
		if ( ld == NULL ) {
			*(void **)arg = (void *) tls_def_ctx;
		} else {
			*(void **)arg = ld->ld_defconn->lconn_tls_ctx;
		}
		break;
	case LDAP_OPT_X_TLS_CACERTFILE:
		*(char **)arg = tls_opt_cacertfile ?
			LDAP_STRDUP( tls_opt_cacertfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CACERTDIR:
		*(char **)arg = tls_opt_cacertdir ?
			LDAP_STRDUP( tls_opt_cacertdir ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CERTFILE:
		*(char **)arg = tls_opt_certfile ?
			LDAP_STRDUP( tls_opt_certfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_KEYFILE:
		*(char **)arg = tls_opt_keyfile ?
			LDAP_STRDUP( tls_opt_keyfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		*(int *)arg = tls_opt_require_cert;
		break;
	case LDAP_OPT_X_TLS_RANDOM_FILE:
		*(char **)arg = tls_opt_randfile ?
			LDAP_STRDUP( tls_opt_randfile ) : NULL;
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
		if ( ld == NULL ) {
			tls_def_ctx = (SSL_CTX *) arg;

		} else {
			ld->ld_defconn->lconn_tls_ctx = arg;
		}
		return 0;
	}

	if ( ld != NULL ) {
		return -1;
	}

	switch( option ) {
	case LDAP_OPT_X_TLS_CACERTFILE:
		if ( tls_opt_cacertfile ) LDAP_FREE( tls_opt_cacertfile );
		tls_opt_cacertfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CACERTDIR:
		if ( tls_opt_cacertdir ) LDAP_FREE( tls_opt_cacertdir );
		tls_opt_cacertdir = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CERTFILE:
		if ( tls_opt_certfile ) LDAP_FREE( tls_opt_certfile );
		tls_opt_certfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_KEYFILE:
		if ( tls_opt_keyfile ) LDAP_FREE( tls_opt_keyfile );
		tls_opt_keyfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		switch( *(int *) arg ) {
		case LDAP_OPT_X_TLS_NEVER:
		case LDAP_OPT_X_TLS_DEMAND:
		case LDAP_OPT_X_TLS_ALLOW:
		case LDAP_OPT_X_TLS_TRY:
		case LDAP_OPT_X_TLS_HARD:
			tls_opt_require_cert = * (int *) arg;
			return 0;
		}
		return -1;
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
		if ( tls_opt_ciphersuite ) LDAP_FREE( tls_opt_ciphersuite );
		tls_opt_ciphersuite = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_RANDOM_FILE:
		if (tls_opt_randfile ) LDAP_FREE (tls_opt_randfile );
		tls_opt_randfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
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
	if (tls_opt_require_cert != LDAP_OPT_X_TLS_NEVER) {
		ld->ld_errno = ldap_pvt_tls_check_hostname( ld, ssl, host );
		if (ld->ld_errno != LDAP_SUCCESS) {
			return ld->ld_errno;
		}
	}

	return LDAP_SUCCESS;
}

/* Derived from openssl/apps/s_cb.c */
static void
tls_info_cb( const SSL *ssl, int where, int ret )
{
	int w;
	char *op;
	char *state = (char *) SSL_state_string_long( (SSL *)ssl );

	w = where & ~SSL_ST_MASK;
	if ( w & SSL_ST_CONNECT ) {
		op = "SSL_connect";
	} else if ( w & SSL_ST_ACCEPT ) {
		op = "SSL_accept";
	} else {
		op = "undefined";
	}

#ifdef HAVE_EBCDIC
	if ( state ) {
		state = LDAP_STRDUP( state );
		__etoa( state );
	}
#endif
	if ( where & SSL_CB_LOOP ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, DETAIL1, "tls_info_cb: "
			"TLS trace: %s:%s\n", op, state, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			   "TLS trace: %s:%s\n",
			   op, state, 0 );
#endif

	} else if ( where & SSL_CB_ALERT ) {
		char *atype = (char *) SSL_alert_type_string_long( ret );
		char *adesc = (char *) SSL_alert_desc_string_long( ret );
		op = ( where & SSL_CB_READ ) ? "read" : "write";
#ifdef HAVE_EBCDIC
		if ( atype ) {
			atype = LDAP_STRDUP( atype );
			__etoa( atype );
		}
		if ( adesc ) {
			adesc = LDAP_STRDUP( adesc );
			__etoa( adesc );
		}
#endif
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, DETAIL1, 
			"tls_info_cb: TLS trace: SSL3 alert %s:%s:%s\n", 
			op, atype, adesc );
#else
		Debug( LDAP_DEBUG_TRACE,
			   "TLS trace: SSL3 alert %s:%s:%s\n",
			   op, atype, adesc );
#endif
#ifdef HAVE_EBCDIC
		if ( atype ) LDAP_FREE( atype );
		if ( adesc ) LDAP_FREE( adesc );
#endif
	} else if ( where & SSL_CB_EXIT ) {
		if ( ret == 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, 
				"tls_info_cb: TLS trace: %s:failed in %s\n", 
				op, state, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				   "TLS trace: %s:failed in %s\n",
				   op, state, 0 );
#endif
		} else if ( ret < 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( TRANSPORT, ERR, 
				"tls_info_cb: TLS trace: %s:error in %s\n", 
				op, state, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				   "TLS trace: %s:error in %s\n",
				   op, state, 0 );
#endif
		}
	}
#ifdef HAVE_EBCDIC
	if ( state ) LDAP_FREE( state );
#endif
}

static int
tls_verify_cb( int ok, X509_STORE_CTX *ctx )
{
	X509 *cert;
	int errnum;
	int errdepth;
	X509_NAME *subject;
	X509_NAME *issuer;
	char *sname;
	char *iname;
	char *certerr = NULL;

	cert = X509_STORE_CTX_get_current_cert( ctx );
	errnum = X509_STORE_CTX_get_error( ctx );
	errdepth = X509_STORE_CTX_get_error_depth( ctx );

	/*
	 * X509_get_*_name return pointers to the internal copies of
	 * those things requested.  So do not free them.
	 */
	subject = X509_get_subject_name( cert );
	issuer = X509_get_issuer_name( cert );
	/* X509_NAME_oneline, if passed a NULL buf, allocate memomry */
	sname = X509_NAME_oneline( subject, NULL, 0 );
	iname = X509_NAME_oneline( issuer, NULL, 0 );
	if ( !ok ) certerr = (char *)X509_verify_cert_error_string( errnum );
#ifdef HAVE_EBCDIC
	if ( sname ) __etoa( sname );
	if ( iname ) __etoa( iname );
	if ( certerr ) {
		certerr = LDAP_STRDUP( certerr );
		__etoa( certerr );
	}
#endif
#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ERR,
		   "TLS certificate verification: depth: %d, err: %d, subject: %s,",
		   errdepth, errnum,
		   sname ? sname : "-unknown-" );
	LDAP_LOG( TRANSPORT, ERR, " issuer: %s\n", iname ? iname : "-unknown-", 0, 0 );
	if ( !ok ) {
		LDAP_LOG ( TRANSPORT, ERR, 
			"TLS certificate verification: Error, %s\n",
			certerr, 0, 0 );
	}
#else
	Debug( LDAP_DEBUG_TRACE,
		   "TLS certificate verification: depth: %d, err: %d, subject: %s,",
		   errdepth, errnum,
		   sname ? sname : "-unknown-" );
	Debug( LDAP_DEBUG_TRACE, " issuer: %s\n", iname ? iname : "-unknown-", 0, 0 );
	if ( !ok ) {
		Debug( LDAP_DEBUG_ANY,
			"TLS certificate verification: Error, %s\n",
			certerr, 0, 0 );
	}
#endif
	if ( sname )
		CRYPTO_free ( sname );
	if ( iname )
		CRYPTO_free ( iname );
#ifdef HAVE_EBCDIC
	if ( certerr ) LDAP_FREE( certerr );
#endif
	return ok;
}

static int
tls_verify_ok( int ok, X509_STORE_CTX *ctx )
{
	(void) tls_verify_cb( ok, ctx );
	return 1;
}

/* Inspired by ERR_print_errors in OpenSSL */
static void
tls_report_error( void )
{
	unsigned long l;
	char buf[200];
	const char *file;
	int line;

	while ( ( l = ERR_get_error_line( &file, &line ) ) != 0 ) {
		ERR_error_string_n( l, buf, sizeof( buf ) );
#ifdef HAVE_EBCDIC
		if ( file ) {
			file = LDAP_STRDUP( file );
			__etoa( (char *)file );
		}
		__etoa( buf );
#endif
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR, 
			"tls_report_error: TLS %s %s:%d\n", 
			buf, file, line );
#else
		Debug( LDAP_DEBUG_ANY, "TLS: %s %s:%d\n",
			buf, file, line );
#endif
#ifdef HAVE_EBCDIC
		if ( file ) LDAP_FREE( (void *)file );
#endif
	}
}

static RSA *
tls_tmp_rsa_cb( SSL *ssl, int is_export, int key_length )
{
	RSA *tmp_rsa;

	/* FIXME:  Pregenerate the key on startup */
	/* FIXME:  Who frees the key? */
	tmp_rsa = RSA_generate_key( key_length, RSA_F4, NULL, NULL );

	if ( !tmp_rsa ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, ERR, 
			"tls_tmp_rsa_cb: TLS Failed to generate temporary %d-bit %s "
			"RSA key\n", key_length, is_export ? "export" : "domestic", 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"TLS: Failed to generate temporary %d-bit %s RSA key\n",
			key_length, is_export ? "export" : "domestic", 0 );
#endif
		return NULL;
	}
	return tmp_rsa;
}

static int
tls_seed_PRNG( const char *randfile )
{
#ifndef URANDOM_DEVICE
	/* no /dev/urandom (or equiv) */
	long total=0;
	char buffer[MAXPATHLEN];

	if (randfile == NULL) {
		/* The seed file is $RANDFILE if defined, otherwise $HOME/.rnd.
		 * If $HOME is not set or buffer too small to hold the pathname,
		 * an error occurs.	- From RAND_file_name() man page.
		 * The fact is that when $HOME is NULL, .rnd is used.
		 */
		randfile = RAND_file_name( buffer, sizeof( buffer ) );

	} else if (RAND_egd(randfile) > 0) {
		/* EGD socket */
		return 0;
	}

	if (randfile == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, DETAIL1, 
			"tls_seed_PRNG: TLS Use configuration file or "
			"$RANDFILE to define seed PRNG\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"TLS: Use configuration file or $RANDFILE to define seed PRNG\n",
			0, 0, 0);
#endif
		return -1;
	}

	total = RAND_load_file(randfile, -1);

	if (RAND_status() == 0) {
#ifdef NEW_LOGGING
		LDAP_LOG ( TRANSPORT, DETAIL1, 
			"tls_seed_PRNG: TLS PRNG not been seeded with enough data\n", 
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"TLS: PRNG not been seeded with enough data\n",
			0, 0, 0);
#endif
		return -1;
	}

	/* assume if there was enough bits to seed that it's okay
	 * to write derived bits to the file
	 */
	RAND_write_file(randfile);

#endif

	return 0;
}

#if 0
static DH *
tls_tmp_dh_cb( SSL *ssl, int is_export, int key_length )
{
	return NULL;
}
#endif
#endif

void *
ldap_pvt_tls_sb_ctx( Sockbuf *sb )
{
#ifdef HAVE_TLS
	void			*p;
	
	if (HAS_TLS( sb )) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&p );
		return p;
	}
#endif

	return NULL;
}

int
ldap_pvt_tls_get_strength( void *s )
{
#ifdef HAVE_TLS
	SSL_CIPHER *c;

	c = SSL_get_current_cipher((SSL *)s);
	return SSL_CIPHER_get_bits(c, NULL);
#else
	return 0;
#endif
}


int
ldap_pvt_tls_get_my_dn( void *s, struct berval *dn, LDAPDN_rewrite_dummy *func, unsigned flags )
{
#ifdef HAVE_TLS
	X509 *x;
	X509_NAME *xn;
	int rc;

	x = SSL_get_certificate((SSL *)s);

	if (!x) return LDAP_INVALID_CREDENTIALS;
	
	xn = X509_get_subject_name(x);
	rc = ldap_X509dn2bv(xn, dn, (LDAPDN_rewrite_func *)func, flags );
	return rc;
#else
	return LDAP_NOT_SUPPORTED;
#endif
}

int
ldap_start_tls_s ( LDAP *ld,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls )
{
	int rc;

#ifdef HAVE_TLS
	char *rspoid = NULL;
	struct berval *rspdata = NULL;

	/* XXYYZ: this initiates operation only on default connection! */

	if ( ld->ld_sb != NULL && ldap_pvt_tls_inplace( ld->ld_sb ) != 0 ) {
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

#else
	rc = LDAP_NOT_SUPPORTED;
#endif
	return rc;
}

