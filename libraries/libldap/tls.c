/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * tls.c - Handle tls/ssl using SSLeay or OpenSSL.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/param.h>

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
#elif defined( HAVE_SSL_H )
#include <ssl.h>
#endif

static int  tls_opt_trace = 1;
static char *tls_opt_certfile = NULL;
static char *tls_opt_keyfile = NULL;
static char *tls_opt_cacertfile = NULL;
static char *tls_opt_cacertdir = NULL;
static int  tls_opt_require_cert = 0;
static char *tls_opt_ciphersuite = NULL;
static char *tls_opt_randfile = NULL;

#define HAS_TLS( sb )	ber_sockbuf_ctrl( sb, LBER_SB_OPT_HAS_IO, \
				(void *)&ldap_pvt_sockbuf_io_tls )

static void tls_report_error( void );

static void tls_info_cb( SSL *ssl, int where, int ret );
static int tls_verify_cb( int ok, X509_STORE_CTX *ctx );
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
 * Initialize TLS subsystem. Should be called only once.
 */
int
ldap_pvt_tls_init( void )
{
	static int tls_initialized = 0;

	if ( tls_initialized ) return 0;
	tls_initialized = 1;

	(void) tls_seed_PRNG( tls_opt_randfile );

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

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &tls_def_ctx_mutex );
#endif
	if ( tls_def_ctx == NULL ) {
		tls_def_ctx = SSL_CTX_new( SSLv23_method() );
		if ( tls_def_ctx == NULL ) {
			Debug( LDAP_DEBUG_ANY,
			       "TLS: could not allocate default ctx.\n",0,0,0);
			goto error_exit;
		}
		if ( tls_opt_ciphersuite &&
		     !SSL_CTX_set_cipher_list( tls_def_ctx,
			tls_opt_ciphersuite ) ) {
			Debug( LDAP_DEBUG_ANY,
			       "TLS: could not set cipher list %s.\n",
			       tls_opt_ciphersuite, 0, 0 );
			tls_report_error();
			goto error_exit;
		}
		if (tls_opt_cacertfile != NULL || tls_opt_cacertdir != NULL) {
			if ( !SSL_CTX_load_verify_locations( tls_def_ctx,
							     tls_opt_cacertfile,
							     tls_opt_cacertdir )
			     || !SSL_CTX_set_default_verify_paths( tls_def_ctx ) )
			{
				Debug( LDAP_DEBUG_ANY,
		 	"TLS: could not load verify locations (file:`%s',dir:`%s').\n",
				       tls_opt_cacertfile,tls_opt_cacertdir,0);
				tls_report_error();
				goto error_exit;
			}
			calist = get_ca_list( tls_opt_cacertfile, tls_opt_cacertdir );
			if ( !calist ) {
				Debug( LDAP_DEBUG_ANY,
		 	"TLS: could not load client CA list (file:`%s',dir:`%s').\n",
				       tls_opt_cacertfile,tls_opt_cacertdir,0);
				tls_report_error();
				goto error_exit;
			}
			SSL_CTX_set_client_CA_list( tls_def_ctx, calist );
		}
		if ( tls_opt_keyfile &&
		     !SSL_CTX_use_PrivateKey_file( tls_def_ctx,
						   tls_opt_keyfile,
						   SSL_FILETYPE_PEM ) ) {
			Debug( LDAP_DEBUG_ANY,
			       "TLS: could not use key file `%s'.\n",
			       tls_opt_keyfile,0,0);
			tls_report_error();
			goto error_exit;
		}
		if ( tls_opt_certfile &&
		     !SSL_CTX_use_certificate_file( tls_def_ctx,
						    tls_opt_certfile,
						    SSL_FILETYPE_PEM ) ) {
			Debug( LDAP_DEBUG_ANY,
			       "TLS: could not use certificate `%s'.\n",
			       tls_opt_certfile,0,0);
			tls_report_error();
			goto error_exit;
		}
		if ( ( tls_opt_certfile || tls_opt_keyfile ) &&
		     !SSL_CTX_check_private_key( tls_def_ctx ) ) {
			Debug( LDAP_DEBUG_ANY,
			       "TLS: private key mismatch.\n",
			       0,0,0);
			tls_report_error();
			goto error_exit;
		}
		if ( tls_opt_trace ) {
			SSL_CTX_set_info_callback( tls_def_ctx, tls_info_cb );
		}
		SSL_CTX_set_verify( tls_def_ctx,
			tls_opt_require_cert ?
			(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT) :
			SSL_VERIFY_NONE,
			tls_verify_cb );
		SSL_CTX_set_tmp_rsa_callback( tls_def_ctx, tls_tmp_rsa_cb );
		/* SSL_CTX_set_tmp_dh_callback( tls_def_ctx, tls_tmp_dh_cb ); */
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &tls_def_ctx_mutex );
#endif
	return 0;
error_exit:
	if ( tls_def_ctx != NULL ) {
		SSL_CTX_free( tls_def_ctx );
		tls_def_ctx = NULL;
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &tls_def_ctx_mutex );
#endif
	return -1;
}

static STACK_OF(X509_NAME) *
get_ca_list( char * bundle, char * dir )
{
	STACK_OF(X509_NAME) *ca_list = NULL;

	if ( bundle ) {
		ca_list = SSL_load_client_CA_file( bundle );
	}
	/*
	 * FIXME: We have now to go over all files in dir, load them
	 * and add every certificate there to ca_list.
	 */
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
		if ( ldap_pvt_tls_init_def_ctx() < 0 )
			return NULL;
		ctx = tls_def_ctx;
	}

	ssl = SSL_new( ctx );
	if ( ssl == NULL ) {
		Debug( LDAP_DEBUG_ANY,"TLS: can't create ssl handle.\n",0,0,0);
		return NULL;
	}

	if ( tls_opt_trace ) {
		SSL_set_info_callback( ssl, tls_info_cb );
	}
	return ssl;
}

static int
update_flags( Sockbuf *sb, SSL * ssl, int rc )
{
	int err = SSL_get_error(ssl, rc);

	sb->sb_trans_needs_read  = 0;
	sb->sb_trans_needs_write = 0;
	if (err == SSL_ERROR_WANT_READ)
	{
	    sb->sb_trans_needs_read  = 1;
	    return 1;
	} else if (err == SSL_ERROR_WANT_WRITE)
	{
	    sb->sb_trans_needs_write = 1;
	    return 1;
	} else if (err == SSL_ERROR_WANT_CONNECT)
	{
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

extern BIO_METHOD ldap_pvt_sb_bio_method;

static int
sb_tls_setup( Sockbuf_IO_Desc *sbiod, void *arg )
{
	struct tls_data		*p;
	BIO			*bio;

	assert( sbiod != NULL );

	p = LBER_MALLOC( sizeof( *p ) );
	if ( p == NULL )
		return -1;
	
	p->ssl = (SSL *)arg;
	p->sbiod = sbiod;
	bio = BIO_new( &ldap_pvt_sb_bio_method );
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
#ifdef WIN32
		errno = EWOULDBLOCK;
#endif
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
#ifdef WIN32
		errno = EWOULDBLOCK;
#endif
	}
	else
		sbiod->sbiod_sb->sb_trans_needs_write = 0;
	return ret;
}

Sockbuf_IO ldap_pvt_sockbuf_io_tls =
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
	if ( b == NULL )
		return 0;

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
		
	if ( buf == NULL || len <= 0 )
		return 0;

	p = (struct tls_data *)b->ptr;

	if ( p == NULL || p->sbiod == NULL )
		return 0;

	ret = LBER_SBIOD_READ_NEXT( p->sbiod, buf, len );

	BIO_clear_retry_flags( b );
	if ( ret < 0 && errno == EWOULDBLOCK )
		BIO_set_retry_read( b );

	return ret;
}

static int
sb_tls_bio_write( BIO *b, char *buf, int len )
{
	struct tls_data		*p;
	int			ret;
	
	if ( buf == NULL || len <= 0 )
		return 0;
	
	p = (struct tls_data *)b->ptr;

	if ( p == NULL || p->sbiod == NULL )
		return 0;

	ret = LBER_SBIOD_WRITE_NEXT( p->sbiod, buf, len );

	BIO_clear_retry_flags( b );
	if ( ret < 0 && errno == EWOULDBLOCK )
		BIO_set_retry_write( b );

	return ret;
}

static long
sb_tls_bio_ctrl( BIO *b, int cmd, long num, char *ptr )
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
sb_tls_bio_puts( BIO *b, char *str )
{
	return sb_tls_bio_write( b, str, strlen( str ) );
}
	
BIO_METHOD ldap_pvt_sb_bio_method =
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

int
ldap_pvt_tls_connect( LDAP *ld, Sockbuf *sb, void *ctx_arg )
{
	int	err;
	SSL	*ssl;

	if ( HAS_TLS( sb ) ) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&ssl );
	} else {
		ssl = alloc_handle( ctx_arg );
		if ( ssl == NULL )
			return -1;
#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)"tls_" );
#endif
		ber_sockbuf_add_io( sb, &ldap_pvt_sockbuf_io_tls,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)ssl );
	}

	err = SSL_connect( ssl );

#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif
	if ( err <= 0 ) {
		if ( update_flags( sb, ssl, err ))
			return 1;
		if ((err = ERR_peek_error())) {
			char buf[256];
			ld->ld_error = LDAP_STRDUP(ERR_error_string(err, buf));
		}
		Debug( LDAP_DEBUG_ANY,"TLS: can't connect.\n",0,0,0);
		ber_sockbuf_remove_io( sb, &ldap_pvt_sockbuf_io_tls,
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
		if ( ssl == NULL )
			return -1;
#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)"tls_" );
#endif
		ber_sockbuf_add_io( sb, &ldap_pvt_sockbuf_io_tls,
			LBER_SBIOD_LEVEL_TRANSPORT, (void *)ssl );
	}

	err = SSL_accept( ssl );

#ifdef HAVE_WINSOCK
	errno = WSAGetLastError();
#endif
	if ( err <= 0 ) {
		if ( update_flags( sb, ssl, err ))
			return 1;
		Debug( LDAP_DEBUG_ANY,"TLS: can't accept.\n",0,0,0 );
		tls_report_error();
		ber_sockbuf_remove_io( sb, &ldap_pvt_sockbuf_io_tls,
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
	if ( HAS_TLS( sb ) )
		return(1);
	return(0);
}

void *
ldap_pvt_tls_sb_handle( Sockbuf *sb )
{
	void			*p;
	
	if (HAS_TLS( sb )) {
		ber_sockbuf_ctrl( sb, LBER_SB_OPT_GET_SSL, (void *)&p );
		return p;
	}

	return NULL;
}

void *
ldap_pvt_tls_get_handle( LDAP *ld )
{
	return ldap_pvt_tls_sb_handle( ld->ld_sb );
}

int
ldap_pvt_tls_get_strength( void *s )
{
    SSL_CIPHER *c;

    c = SSL_get_current_cipher((SSL *)s);
    return SSL_CIPHER_get_bits(c, NULL);
}


const char *
ldap_pvt_tls_get_peer( void *s )
{
    X509 *x;
    X509_NAME *xn;
    char buf[2048], *p;

    x = SSL_get_peer_certificate((SSL *)s);

    if (!x)
    	return NULL;
    
    xn = X509_get_subject_name(x);
    p = LDAP_STRDUP(X509_NAME_oneline(xn, buf, sizeof(buf)));
    X509_free(x);
    return p;
}

const char *
ldap_pvt_tls_get_peer_issuer( void *s )
{
#if 0	/* currently unused; see ldap_pvt_tls_get_peer() if needed */
    X509 *x;
    X509_NAME *xn;
    char buf[2048], *p;

    x = SSL_get_peer_certificate((SSL *)s);

    if (!x)
    	return NULL;
    
    xn = X509_get_issuer_name(x);
    p = LDAP_STRDUP(X509_NAME_oneline(xn, buf, sizeof(buf)));
    X509_free(x);
    return p;
#else
    return NULL;
#endif
}

int
ldap_int_tls_config( struct ldapoptions *lo, int option, const char *arg )
{
	int i;

	switch( option ) {
	case LDAP_OPT_X_TLS_CACERTFILE:
	case LDAP_OPT_X_TLS_CACERTDIR:
	case LDAP_OPT_X_TLS_CERTFILE:
	case LDAP_OPT_X_TLS_KEYFILE:
	case LDAP_OPT_X_TLS_RANDOM_FILE:
		return ldap_pvt_tls_set_option( NULL, option, (void *) arg );
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		i = ( ( strcasecmp( arg, "on" ) == 0 ) ||
		      ( strcasecmp( arg, "yes" ) == 0) ||
		      ( strcasecmp( arg, "true" ) == 0 ) );
		return ldap_pvt_tls_set_option( NULL, option, (void *) &i );
	case LDAP_OPT_X_TLS:
		i = -1;
		if ( strcasecmp( arg, "never" ) == 0 )
			i = LDAP_OPT_X_TLS_NEVER ;
		if ( strcasecmp( arg, "demand" ) == 0 )
			i = LDAP_OPT_X_TLS_DEMAND ;
		if ( strcasecmp( arg, "allow" ) == 0 )
			i = LDAP_OPT_X_TLS_ALLOW ;
		if ( strcasecmp( arg, "try" ) == 0 )
			i = LDAP_OPT_X_TLS_TRY ;
		if ( strcasecmp( arg, "hard" ) == 0 )
			i = LDAP_OPT_X_TLS_HARD ;
		if (i >= 0)
			return ldap_pvt_tls_set_option( lo, option, &i );
		return -1;
	}

	return -1;
}

int
ldap_pvt_tls_get_option( struct ldapoptions *lo, int option, void *arg )
{
	switch( option ) {
	case LDAP_OPT_X_TLS:
		*(int *)arg = lo->ldo_tls_mode;
		break;
	case LDAP_OPT_X_TLS_CERT:
		if ( lo == NULL )
			*(void **)arg = (void *) tls_def_ctx;
		else
			*(void **)arg = lo->ldo_tls_ctx;
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
		*(char **)arg = tls_opt_randfile;
		break;
	default:
		return -1;
	}
	return 0;
}

int
ldap_pvt_tls_set_option( struct ldapoptions *lo, int option, void *arg )
{
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

	case LDAP_OPT_X_TLS_CERT:
		if ( lo == NULL ) {
			tls_def_ctx = (SSL_CTX *) arg;

		} else {
			lo->ldo_tls_ctx = arg;
		}
		return 0;
	}

	if ( lo != NULL ) {
		return -1;
	}

	switch( option ) {
	case LDAP_OPT_X_TLS_CACERTFILE:
		if ( tls_opt_cacertfile ) free( tls_opt_cacertfile );
		tls_opt_cacertfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CACERTDIR:
		if ( tls_opt_cacertdir ) free( tls_opt_cacertdir );
		tls_opt_cacertdir = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CERTFILE:
		if ( tls_opt_certfile ) free( tls_opt_certfile );
		tls_opt_certfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_KEYFILE:
		if ( tls_opt_keyfile ) free( tls_opt_keyfile );
		tls_opt_keyfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		tls_opt_require_cert = * (int *) arg;
		break;
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
		if ( tls_opt_ciphersuite ) free( tls_opt_ciphersuite );
		tls_opt_ciphersuite = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_RANDOM_FILE:
		if (tls_opt_randfile ) free (tls_opt_randfile );
		tls_opt_randfile = arg ? LDAP_STRDUP( (char *) arg ) : NULL;
		break;
	default:
		return -1;
	}
	return 0;
}

int
ldap_pvt_tls_start ( LDAP *ld, Sockbuf *sb, void *ctx_arg )
{
	(void) ldap_pvt_tls_init();

	/*
	 * Fortunately, the lib uses blocking io...
	 */
	if ( ldap_pvt_tls_connect( ld, sb, ctx_arg ) < 0 ) {
		return LDAP_CONNECT_ERROR;
	}

	/* FIXME: hostname of server must be compared with name in
	 * certificate....
	 */

	return LDAP_SUCCESS;
}

/* Derived from openssl/apps/s_cb.c */
static void
tls_info_cb( SSL *ssl, int where, int ret )
{
	int w;
	char *op;

	w = where & ~SSL_ST_MASK;
	if ( w & SSL_ST_CONNECT ) {
		op = "SSL_connect";
	} else if ( w & SSL_ST_ACCEPT ) {
		op = "SSL_accept";
	} else {
		op = "undefined";
	}

        if ( where & SSL_CB_LOOP ) {
		Debug( LDAP_DEBUG_TRACE,
		       "TLS trace: %s:%s\n",
		       op, SSL_state_string_long( ssl ), 0 );
	} else if ( where & SSL_CB_ALERT ) {
                op = ( where & SSL_CB_READ ) ? "read" : "write";
		Debug( LDAP_DEBUG_TRACE,
		       "TLS trace: SSL3 alert %s:%s:%s\n",
		       op,
		       SSL_alert_type_string_long( ret ),
		       SSL_alert_desc_string_long( ret) );
	} else if ( where & SSL_CB_EXIT ) {
                if ( ret == 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			       "TLS trace: %s:failed in %s\n",
			       op, SSL_state_string_long( ssl ), 0 );
                } else if ( ret < 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			       "TLS trace: %s:error in %s\n",
			       op, SSL_state_string_long( ssl ), 0 );
		}
	}
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
	Debug( LDAP_DEBUG_TRACE,
	       "TLS certificate verification: depth: %d, subject: %s, issuer: %s\n",
	       errdepth,
	       sname ? sname : "-unknown-",
	       iname ? iname : "-unknown-" );
	if ( sname )
		CRYPTO_free ( sname );
	if ( iname )
		CRYPTO_free ( iname );

	return ok;
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
			Debug( LDAP_DEBUG_ANY, "TLS: %s %s:%d\n",
			       ERR_error_string( l, buf ), file, line );
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
		Debug( LDAP_DEBUG_ANY,
			"TLS: Failed to generate temporary %d-bit %s RSA key\n",
			key_length, is_export ? "export" : "domestic", 0 );
		return NULL;
	}
	return tmp_rsa;
}

static int
tls_seed_PRNG( const char *randfile )
{
#ifndef URANDOM_DEVICE
	/* no /dev/urandom (or equiv) */
	char buffer[MAXPATHLEN];

	if (randfile == NULL) {
		/* The seed file is $RANDFILE if defined, otherwise $HOME/.rnd.
		 * If $HOME is not set or buffer too small to hold the pathname,
		 * an error occurs.    - From RAND_file_name() man page.
		 * The fact is that when $HOME is NULL, .rnd is used.
		 */
		randfile = RAND_file_name( buffer, sizeof( buffer ) );

	} else if (RAND_egd(randfile) > 0) {
		/* EGD socket */
		return 0;
	}

	if (randfile == NULL) {
		Debug( LDAP_DEBUG_ANY,
			"TLS: Use configuration file or $RANDFILE to define seed PRNG",
			0, 0, 0);
		return -1;
	}

	RAND_load_file(randfile, -1);

	if (RAND_status() == 0) {
		Debug( LDAP_DEBUG_ANY,
			"TLS: PRNG not been seeded with enough data",
			0, 0, 0);
		return -1;
	}
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

int
ldap_start_tls_s ( LDAP *ld,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls )
{
#ifdef HAVE_TLS
	int rc;
	char *rspoid = NULL;
	struct berval *rspdata = NULL;

	/* XXYYZ: this initiates operaton only on default connection! */

	if ( ldap_pvt_tls_inplace( ld->ld_sb ) != 0 ) {
		return LDAP_LOCAL_ERROR;
	}

	rc = ldap_extended_operation_s( ld, LDAP_EXOP_START_TLS,
		NULL, serverctrls, clientctrls, &rspoid, &rspdata );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( rspoid != NULL ) {
		LDAP_FREE(rspoid);
	}

	if ( rspdata != NULL ) {
		ber_bvfree( rspdata );
	}

	rc = ldap_pvt_tls_start( ld, ld->ld_sb, ld->ld_options.ldo_tls_ctx );
	return rc;
#else
	return LDAP_NOT_SUPPORTED;
#endif
}

