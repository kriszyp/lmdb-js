/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * tls.c - Handle tls/ssl using SSLeay or OpenSSL.
 */

#include "portable.h"

#ifdef HAVE_TLS

#include <stdio.h>
#include <stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap-int.h"

#ifdef LDAP_R_COMPILE
#include <ldap_pvt_thread.h>
#endif

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#elif defined( HAVE_SSL_H )
#include <ssl.h>
#endif

static char *tls_opt_certfile = NULL;
static char *tls_opt_keyfile = NULL;
static char *tls_opt_cacertfile = NULL;
static char *tls_opt_cacertdir = NULL;
static int  tls_opt_require_cert = 0;
static char *tls_opt_ciphersuite = NULL;

#define HAS_TLS( sb ) ((sb)->sb_io==&tls_io)

static int tls_setup( Sockbuf *sb, void *arg );
static int tls_remove( Sockbuf *sb );
static ber_slen_t tls_read( Sockbuf *sb, void *buf, ber_len_t len );
static ber_slen_t tls_write( Sockbuf *sb, void *buf, ber_len_t len );
static int tls_close( Sockbuf *sb );
static int tls_report_error( void );

static Sockbuf_IO tls_io=
{
   tls_setup,
   tls_remove,
   tls_read,
   tls_write,
   tls_close
};

static int tls_verify_cb( int ok, X509_STORE_CTX *ctx );

static SSL_CTX *tls_def_ctx = NULL;

#ifdef LDAP_R_COMPILE
/*
 * provide mutexes for the SSLeay library.
 */
static ldap_pvt_thread_mutex_t	tls_mutexes[CRYPTO_NUM_LOCKS];

static void tls_locking_cb( int mode, int type, const char *file, int line )
{
	if ( mode & CRYPTO_LOCK ) {
		ldap_pvt_thread_mutex_lock( tls_mutexes+type );
	} else {
		ldap_pvt_thread_mutex_unlock( tls_mutexes+type );
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
		ldap_pvt_thread_mutex_init( tls_mutexes+i );
	}
	CRYPTO_set_locking_callback( tls_locking_cb );
	/* FIXME: the thread id should be added somehow... */

	ldap_pvt_thread_mutex_init( &tls_def_ctx_mutex );
}
#endif /* LDAP_R_COMPILE */

/*
 * Initialize tls system. Should be called only once.
 */
int
ldap_pvt_tls_init( void )
{
	static int tls_initialized = 0;

	if ( tls_initialized )
		return -1;
#ifdef LDAP_R_COMPILE
	tls_init_threads();
#endif
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	return 0;
}

/*
 * initialize the default context
 */
int
ldap_pvt_tls_init_def_ctx( void )
{
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
		if ( !SSL_CTX_load_verify_locations( tls_def_ctx,
						     tls_opt_cacertfile,
						     tls_opt_cacertdir ) ||
		     !SSL_CTX_set_default_verify_paths( tls_def_ctx ) ) {
			Debug( LDAP_DEBUG_ANY,
	 	"TLS: could not load verify locations (file:`%s',dir:`%s').\n",
			       tls_opt_cacertfile,tls_opt_cacertdir,0);
			tls_report_error();
			goto error_exit;
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
		SSL_CTX_set_verify( tls_def_ctx, (tls_opt_require_cert) ?
			(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT) :
			SSL_VERIFY_PEER, tls_verify_cb );
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &tls_def_ctx_mutex );
#endif
	return 0;
error_exit:
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &tls_def_ctx_mutex );
#endif
	return -1;
}

static SSL *
alloc_handle( Sockbuf *sb, void *ctx_arg )
{
	int	err;
	SSL_CTX	*ctx;
	SSL	*ssl;

	if ( ctx_arg ) {
		ctx = (SSL_CTX *) ctx_arg;
	} else {
		if ( ldap_pvt_tls_init_def_ctx() < 0 )
			return NULL;
		ctx=tls_def_ctx;
	}

	ssl = SSL_new( ctx );
	if ( ssl == NULL ) {
		Debug( LDAP_DEBUG_ANY,"TLS: can't create ssl handle.\n",0,0,0);
		return NULL;
	}

	sb->sb_iodata = ssl;
	SSL_set_fd( ssl, ber_pvt_sb_get_desc( sb ) );
	return ssl;
}

static void
update_flags( Sockbuf *sb, SSL * ssl )
{
	sb->sb_trans_needs_read  = SSL_want_read(ssl) ? 1 : 0;
	sb->sb_trans_needs_write = SSL_want_write(ssl) ? 1 : 0;
}

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
ldap_pvt_tls_connect( Sockbuf *sb, void *ctx_arg )
{
	int	err;
	SSL	*ssl;

	if ( HAS_TLS( sb ) ) {
		ssl = (SSL *) sb->sb_iodata;
	} else {
		ssl = alloc_handle( sb, ctx_arg );
		if ( ssl == NULL )
			return -1;
		ber_pvt_sb_clear_io( sb );
		ber_pvt_sb_set_io( sb, &tls_io, (void *)ssl );
	}

	err = SSL_connect( ssl );

	if ( err <= 0 ) {
		if (
#ifdef EWOULDBLOCK
		    (errno==EWOULDBLOCK) ||
#endif
#ifdef EAGAIN
		    (errno==EAGAIN) ||
#endif
		    (0)) {
			update_flags( sb, ssl );
			return 1;
		}
		Debug( LDAP_DEBUG_ANY,"TLS: can't connect.\n",0,0,0);
		ber_pvt_sb_clear_io( sb );
		ber_pvt_sb_set_io( sb, &ber_pvt_sb_io_tcp, NULL );
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
		ssl = (SSL *) sb->sb_iodata;
	} else {
		ssl = alloc_handle( sb, ctx_arg );
		if ( ssl == NULL )
			return -1;
		ber_pvt_sb_clear_io( sb );
		ber_pvt_sb_set_io( sb, &tls_io, (void *)ssl );
	}

	err = SSL_accept( ssl );

	if ( err <= 0 ) {
		if ( !SSL_want_nothing( ssl ) ) {
			update_flags( sb, ssl );
			return 1;
		}
		Debug( LDAP_DEBUG_ANY,"TLS: can't accept.\n",0,0,0 );
		tls_report_error();
		ber_pvt_sb_clear_io( sb );
		ber_pvt_sb_set_io( sb, &ber_pvt_sb_io_tcp, NULL );
		return -1;
	}
	return 0;
}

const char *
ldap_pvt_tls_get_peer( LDAP *ld )
{
}

const char *
ldap_pvt_tls_get_peer_issuer( LDAP *ld )
{
}

int
ldap_pvt_tls_config( struct ldapoptions *lo, int option, const char *arg )
{
	int i;

	switch( option ) {
	case LDAP_OPT_X_TLS_CACERTFILE:
	case LDAP_OPT_X_TLS_CACERTDIR:
	case LDAP_OPT_X_TLS_CERTFILE:
	case LDAP_OPT_X_TLS_KEYFILE:
		return ldap_pvt_tls_set_option( NULL, option, (void *) arg );
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		i = ( ( strcasecmp( arg, "on" ) == 0 ) ||
		      ( strcasecmp( arg, "yes" ) == 0) ||
		      ( strcasecmp( arg, "true" ) == 0 ) );
		return ldap_pvt_tls_set_option( NULL, option, (void *) &i );
	case LDAP_OPT_X_TLS:
		if ( strcasecmp( arg, "never" ) == 0 )
			return ldap_pvt_tls_set_option( lo, option,
				LDAP_OPT_X_TLS_NEVER );
		if ( strcasecmp( arg, "demand" ) == 0 )
			return ldap_pvt_tls_set_option( lo, option,
				LDAP_OPT_X_TLS_DEMAND );
		if ( strcasecmp( arg, "allow" ) == 0 )
			return ldap_pvt_tls_set_option( lo, option,
				LDAP_OPT_X_TLS_ALLOW );
		if ( strcasecmp( arg, "try" ) == 0 )
			return ldap_pvt_tls_set_option( lo, option,
				LDAP_OPT_X_TLS_TRY );
		if ( strcasecmp( arg, "hard" ) == 0 )
			return ldap_pvt_tls_set_option( lo, option,
				LDAP_OPT_X_TLS_HARD );
		return -1;
	default:
		return -1;
	}
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
			arg = (void *) tls_def_ctx;
		else
			arg = lo->ldo_tls_ctx;
		break;
	case LDAP_OPT_X_TLS_CACERTFILE:
		*(char **)arg = tls_opt_cacertfile ?
			strdup( tls_opt_cacertfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CACERTDIR:
		*(char **)arg = tls_opt_cacertdir ?
			strdup( tls_opt_cacertdir ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CERTFILE:
		*(char **)arg = tls_opt_certfile ?
			strdup( tls_opt_certfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_KEYFILE:
		*(char **)arg = tls_opt_keyfile ?
			strdup( tls_opt_keyfile ) : NULL;
		break;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		*(int *)arg = tls_opt_require_cert;
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
			lo->ldo_tls_mode = *(int *)arg;
			break;
		default:
			return -1;
		}
		break;
	case LDAP_OPT_X_TLS_CERT:
		if ( lo == NULL )
			tls_def_ctx = (SSL_CTX *) arg;
		else
			lo->ldo_tls_ctx = arg;
		break;
	}
	if ( lo != NULL )
		return -1;
	switch( option ) {
	case LDAP_OPT_X_TLS_CACERTFILE:
		if ( tls_opt_cacertfile ) free( tls_opt_cacertfile );
		tls_opt_cacertfile = arg ? strdup( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CACERTDIR:
		if ( tls_opt_cacertdir ) free( tls_opt_cacertdir );
		tls_opt_cacertdir = arg ? strdup( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_CERTFILE:
		if ( tls_opt_certfile ) free( tls_opt_certfile );
		tls_opt_certfile = arg ? strdup( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_KEYFILE:
		if ( tls_opt_keyfile ) free( tls_opt_keyfile );
		tls_opt_keyfile = arg ? strdup( (char *) arg ) : NULL;
		break;
	case LDAP_OPT_X_TLS_REQUIRE_CERT:
		tls_opt_require_cert = * (int *) arg;
		break;
	case LDAP_OPT_X_TLS_CIPHER_SUITE:
		if ( tls_opt_ciphersuite ) free( tls_opt_ciphersuite );
		tls_opt_ciphersuite = arg ? strdup( (char *) arg ) : NULL;
		break;
	default:
		return -1;
	}
	return 0;
}

static int
tls_setup( Sockbuf *sb, void *arg )
{
	sb->sb_iodata = arg;
	return 0;
}

static int
tls_remove( Sockbuf *sb )
{
	SSL_free( (SSL *) sb->sb_iodata );
	return 0;
}

static ber_slen_t
tls_write( Sockbuf *sb, void *buf, ber_len_t sz )
{
	int ret = SSL_write( (SSL *)sb->sb_iodata, buf, sz );

	update_flags(sb, (SSL *)sb->sb_iodata );
	return ret;
}

static ber_slen_t
tls_read( Sockbuf *sb, void *buf, ber_len_t sz )
{
	int ret = SSL_read( (SSL *)sb->sb_iodata, buf, sz );

	update_flags(sb, (SSL *)sb->sb_iodata );
	return ret;
}

static int
tls_close( Sockbuf *sb )
{
	tcp_close( ber_pvt_sb_get_desc( sb ) );
	return 0;
}

static int
tls_verify_cb( int ok, X509_STORE_CTX *ctx )
{
	return 1;
}

/* Inspired by ERR_print_errors in OpenSSL */
static int
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

#else
static int dummy;
#endif
