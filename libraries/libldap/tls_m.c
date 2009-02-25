/* tls_m.c - Handle tls/ssl using Mozilla NSS. */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2008-2009 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS: written by Howard Chu.
 */

#include "portable.h"

#ifdef HAVE_MOZNSS

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
#include "ldap-tls.h"

#ifdef LDAP_R_COMPILE
#include <ldap_pvt_thread.h>
#endif

#include <nspr.h>
#include <nss.h>
#include <ssl.h>

typedef struct tlsm_ctx {
	PRFileDesc *tc_model;
	int tc_refcnt;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_t tc_refmutex;
#endif
} tlsm_ctx;

typedef PRFileDesc tlsm_session;

static PRDescIdentity	tlsm_layer_id;

static const PRIOMethods tlsm_PR_methods;

extern tls_impl ldap_int_tls_impl;

static int tslm_did_init;

#ifdef LDAP_R_COMPILE

static void
tlsm_thr_init( void )
{
}

#endif /* LDAP_R_COMPILE */

/*
 * Initialize TLS subsystem. Should be called only once.
 */
static int
tlsm_init( void )
{
	PR_Init(0, 0, 0);

	tlsm_layer_id = PR_GetUniqueIdentity("OpenLDAP");

	if ( !NSS_IsInitialized() ) {
		tlsm_did_init = 1;

		NSS_NoDB_Init("");

		NSS_SetDomesticPolicy();
	}

	/* No cipher suite handling for now */

	return 0;
}

/*
 * Tear down the TLS subsystem. Should only be called once.
 */
static void
tlsm_destroy( void )
{
	/* Only if we did the actual initialization */
	if ( tlsm_did_init ) {
		tlsm_did_init = 0;

		NSS_Shutdown();
	}

	PR_Cleanup();
}

static tls_ctx *
tlsm_ctx_new ( struct ldapoptions *lo )
{
	tlsm_ctx *ctx;

	ctx = LDAP_MALLOC( sizeof (*ctx) );
	if ( ctx ) {
		PRFileDesc *fd = PR_CreateIOLayerStub(tlsm_layer_id, &tlsm_PR_methods);
		if ( fd ) {
			ctx->tc_model = SSL_ImportFD( NULL, fd );
			if ( ctx->tc_model ) {
				ctx->tc_refcnt = 1;
#ifdef LDAP_R_COMPILE
				ldap_pvt_thread_mutex_init( &ctx->tc_refmutex );
#endif
			} else {
				PR_DELETE( fd );
				LDAP_FREE( ctx );
				ctx = NULL;
			}
		} else {
			LDAP_FREE( ctx );
			ctx = NULL;
		}
	}
	return (tls_ctx *)ctx;
}

static void
tlsm_ctx_ref( tls_ctx *ctx )
{
	tlsm_ctx *c = (tlsm_ctx *)ctx;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &c->tc_refmutex );
#endif
	c->tc_refcnt++;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &c->tc_refmutex );
#endif
}

static void
tlsm_ctx_free ( tls_ctx *ctx )
{
	tlsm_ctx *c = (tlsm_ctx *)ctx;
	int refcount;

	if ( !c ) return;

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &c->tc_refmutex );
#endif
	refcount = --c->tc_refcnt;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &c->tc_refmutex );
#endif
	if ( refcount )
		return;
	PR_Close( c->tc_model );
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_destroy( &c->tc_refmutex );
#endif
	LDAP_FREE( c );
}

/*
 * initialize a new TLS context
 */
static int
tlsm_ctx_init( struct ldapoptions *lo, struct ldaptls *lt, int is_server )
{
	tlsm_ctx *ctx = lo->ldo_tls_ctx;
	int rc;

	SSL_OptionSet( ctx->tc_model, SSL_SECURITY, PR_TRUE );
	SSL_OptionSet( ctx->tc_model, SSL_HANDSHAKE_AS_CLIENT, !is_server );
	SSL_OptionSet( ctx->tc_model, SSL_HANDSHAKE_AS_SERVER, is_server );

	/* See SECMOD_OpenUserDB() */
#if 0
 	if ( lo->ldo_tls_ciphersuite &&
		tlsm_parse_ciphers( ctx, lt->lt_ciphersuite )) {
 		Debug( LDAP_DEBUG_ANY,
 			   "TLS: could not set cipher list %s.\n",
 			   lo->ldo_tls_ciphersuite, 0, 0 );
		return -1;
 	}

	if (lo->ldo_tls_cacertdir != NULL) {
		Debug( LDAP_DEBUG_ANY, 
		       "TLS: warning: cacertdir not implemented for gnutls\n",
		       NULL, NULL, NULL );
	}

	if (lo->ldo_tls_cacertfile != NULL) {
		rc = gnutls_certificate_set_x509_trust_file( 
			ctx->cred,
			lt->lt_cacertfile,
			GNUTLS_X509_FMT_PEM );
		if ( rc < 0 ) return -1;
	}

	if ( lo->ldo_tls_certfile && lo->ldo_tls_keyfile ) {
		rc = gnutls_certificate_set_x509_key_file( 
			ctx->cred,
			lt->lt_certfile,
			lt->lt_keyfile,
			GNUTLS_X509_FMT_PEM );
		if ( rc ) return -1;
	} else if ( lo->ldo_tls_certfile || lo->ldo_tls_keyfile ) {
		Debug( LDAP_DEBUG_ANY, 
		       "TLS: only one of certfile and keyfile specified\n",
		       NULL, NULL, NULL );
		return -1;
	}

	if ( lo->ldo_tls_dhfile ) {
		Debug( LDAP_DEBUG_ANY, 
		       "TLS: warning: ignoring dhfile\n", 
		       NULL, NULL, NULL );
	}

	if ( lo->ldo_tls_crlfile ) {
		rc = gnutls_certificate_set_x509_crl_file( 
			ctx->cred,
			lt->lt_crlfile,
			GNUTLS_X509_FMT_PEM );
		if ( rc < 0 ) return -1;
		rc = 0;
	}
	if ( is_server ) {
		gnutls_dh_params_init(&ctx->dh_params);
		gnutls_dh_params_generate2(ctx->dh_params, DH_BITS);
	}
#endif
	return 0;
}

static tls_session *
tlsm_session_new ( tls_ctx * ctx, int is_server )
{
	tlsm_ctx *c = (tlsm_ctx *)ctx;
	tlsm_session *session;
	PRFileDesc *fd;

	fd = PR_CreateIOLayerStub(tlsm_layer_id, &tlsm_PR_methods);
	if ( !fd ) {
		return NULL;
	}

	session = SSL_ImportFD( c->tc_model, fd );
	if ( !session ) {
		PR_DELETE( fd );
		return NULL;
	}

	SSL_ResetHandshake( session, is_server );

	return (tls_session *)session;
} 

static int
tlsm_session_accept( tls_session *session )
{
	tlsm_session *s = (tlsm_session *)session;

	return SSL_ForceHandshake( s );
}

static int
tlsm_session_connect( LDAP *ld, tls_session *session )
{
	tlsm_session *s = (tlsm_session *)session;
	int rc;

	/* By default, NSS checks the cert hostname for us */
	rc = SSL_SetURL( s, ld->ld_options.ldo_defludp->lud_host );
	return SSL_ForceHandshake( s );
}

static int
tlsm_session_upflags( Sockbuf *sb, tls_session *session, int rc )
{
	/* Should never happen */
	rc = PR_GetError();

	if ( rc != PR_PENDING_INTERRUPT_ERROR && rc != PR_WOULD_BLOCK_ERROR )
		return 0;
	return 0;
}

static char *
tlsm_session_errmsg( int rc, char *buf, size_t len )
{
	int i;

	rc = PR_GetError();
	i = PR_GetErrorTextLength();
	if ( i > len ) {
		char *msg = LDAP_MALLOC( i+1 );
		PR_GetErrorText( msg );
		memcpy( buf, msg, len );
		LDAP_FREE( msg );
	} else if ( i ) {
		PR_GetErrorText( buf );
	}

	return i ? buf : NULL;
}

static int
tlsm_session_my_dn( tls_session *session, struct berval *der_dn )
{
	tlsm_session *s = (tlsm_session *)session;
	CERTCertificate *cert;

	cert = SSL_LocalCertificate( s );
	if (!cert) return LDAP_INVALID_CREDENTIALS;

	der_dn->bv_val = cert->derSubject.data;
	der_dn->bv_len = cert->derSubject.len;
	CERT_DestroyCertificate( cert );
	return 0;
}

static int
tlsm_session_peer_dn( tls_session *session, struct berval *der_dn )
{
	tlsm_session *s = (tlsm_session *)session;
	CERTCertificate *cert;

	cert = SSL_PeerCertificate( s );
	if (!cert) return LDAP_INVALID_CREDENTIALS;
	
	der_dn->bv_val = cert->derSubject.data;
	der_dn->bv_len = cert->derSubject.len;
	CERT_DestroyCertificate( cert );
	return 0;
}

/* what kind of hostname were we given? */
#define	IS_DNS	0
#define	IS_IP4	1
#define	IS_IP6	2

static int
tlsm_session_chkhost( LDAP *ld, tls_session *session, const char *name_in )
{
/* NSS already does a hostname check */
#if 0
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
	time_t now = time(0);

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
		*strchr(n2, ']') = 0;
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
#endif
}

static int
tlsm_session_strength( tls_session *session )
{
	tlsm_session *s = (tlsm_session *)session;
	int rc, keySize;

	rc = SSL_SecurityStatus( s, NULL, NULL, NULL, &keySize,
		NULL, NULL );
	return rc ? 0 : keySize;
}

/*
 * TLS support for LBER Sockbufs
 */

struct tls_data {
	tlsm_session		*session;
	Sockbuf_IO_Desc		*sbiod;
};


static PRStatus PR_CALLBACK
tlsm_PR_Close(PRFileDesc *fd)
{
	return PR_SUCCESS;
}

static int PR_CALLBACK
tlsm_PR_Recv(PRFileDesc *fd, void *buf, PRInt32 len, PRIntn flags,
	 PRIntervalTime timeout)
{
	struct tls_data		*p;

	if ( buf == NULL || len <= 0 ) return 0;

	p = (struct tls_data *)fd->secret;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	return LBER_SBIOD_READ_NEXT( p->sbiod, buf, len );
}

static int PR_CALLBACK
tlsm_PR_Send(PRFileDesc *fd, const void *buf, PRInt32 len, PRIntn flags,
	 PRIntervalTime timeout)
{
	struct tls_data		*p;

	if ( buf == NULL || len <= 0 ) return 0;

	p = (struct tls_data *)fd->secret;

	if ( p == NULL || p->sbiod == NULL ) {
		return 0;
	}

	return LBER_SBIOD_WRITE_NEXT( p->sbiod, (char *)buf, len );
}

static int PR_CALLBACK
tlsm_PR_Read(PRFileDesc *fd, void *buf, PRInt32 len)
{
	return tlsm_PR_Recv( fd, buf, len, 0, PR_INTERVAL_NO_TIMEOUT );
}

static int PR_CALLBACK
tlsm_PR_Write(PRFileDesc *fd, const void *buf, PRInt32 len)
{
	return tlsm_PR_Send( fd, buf, len, 0, PR_INTERVAL_NO_TIMEOUT );
}

static PRStatus PR_CALLBACK
tlsm_PR_GetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
	struct tls_data		*p;
	int rc;
	ber_socklen_t len;

	p = (struct tls_data *)fd->secret;

	if ( p == NULL || p->sbiod == NULL ) {
		return PR_FAILURE;
	}
	len = sizeof(PRNetAddr);
	return getpeername( p->sbiod->sbiod_sb->sb_fd, (struct sockaddr *)addr, &len );
}

static PRStatus PR_CALLBACK
tlsm_PR_prs_unimp()
{
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return PR_FAILURE;
}

static PRFileDesc * PR_CALLBACK
tlsm_PR_pfd_unimp()
{
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return NULL;
}

static PRInt16 PR_CALLBACK
tlsm_PR_i16_unimp()
{
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return SECFailure;
}

static PRInt32 PR_CALLBACK
tlsm_PR_i32_unimp()
{
    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    return SECFailure;
}

static PRInt64 PR_CALLBACK
tlsm_PR_i64_unimp()
{
    PRInt64 res;

    PR_SetError(PR_NOT_IMPLEMENTED_ERROR, 0);
    LL_I2L(res, -1L);
    return res;
}

static const PRIOMethods tlsm_PR_methods = {
    PR_DESC_LAYERED,
    tlsm_PR_Close,			/* close        */
    tlsm_PR_Read,			/* read         */
    tlsm_PR_Write,			/* write        */
    tlsm_PR_i32_unimp,		/* available    */
    tlsm_PR_i64_unimp,		/* available64  */
    tlsm_PR_prs_unimp,		/* fsync        */
    tlsm_PR_i32_unimp,		/* seek         */
    tlsm_PR_i64_unimp,		/* seek64       */
    tlsm_PR_prs_unimp,		/* fileInfo     */
    tlsm_PR_prs_unimp,		/* fileInfo64   */
    tlsm_PR_i32_unimp,		/* writev       */
    tlsm_PR_prs_unimp,		/* connect      */
    tlsm_PR_pfd_unimp,		/* accept       */
    tlsm_PR_prs_unimp,		/* bind         */
    tlsm_PR_prs_unimp,		/* listen       */
    (PRShutdownFN)tlsm_PR_Close,			/* shutdown     */
    tlsm_PR_Recv,			/* recv         */
    tlsm_PR_Send,			/* send         */
    tlsm_PR_i32_unimp,		/* recvfrom     */
    tlsm_PR_i32_unimp,		/* sendto       */
    (PRPollFN)tlsm_PR_i16_unimp,	/* poll         */
    tlsm_PR_i32_unimp,		/* acceptread   */
    tlsm_PR_i32_unimp,		/* transmitfile */
    tlsm_PR_prs_unimp,		/* getsockname  */
    tlsm_PR_GetPeerName,	/* getpeername  */
    tlsm_PR_i32_unimp,		/* getsockopt   OBSOLETE */
    tlsm_PR_i32_unimp,		/* setsockopt   OBSOLETE */
    tlsm_PR_i32_unimp,		/* getsocketoption   */
    tlsm_PR_i32_unimp,		/* setsocketoption   */
    tlsm_PR_i32_unimp,		/* Send a (partial) file with header/trailer*/
    (PRConnectcontinueFN)tlsm_PR_prs_unimp,		/* connectcontinue */
    tlsm_PR_i32_unimp,		/* reserved for future use */
    tlsm_PR_i32_unimp,		/* reserved for future use */
    tlsm_PR_i32_unimp,		/* reserved for future use */
    tlsm_PR_i32_unimp		/* reserved for future use */
};

static int
tlsm_sb_setup( Sockbuf_IO_Desc *sbiod, void *arg )
{
	struct tls_data		*p;
	tlsm_session	*session = arg;
	PRFileDesc *fd;

	assert( sbiod != NULL );

	p = LBER_MALLOC( sizeof( *p ) );
	if ( p == NULL ) {
		return -1;
	}

	fd = PR_GetIdentitiesLayer( session, tlsm_layer_id );
	if ( !fd ) {
		LBER_FREE( p );
		return -1;
	}

	fd->secret = (PRFilePrivate *)p;
	p->session = session;
	p->sbiod = sbiod;
	sbiod->sbiod_pvt = p;
	return 0;
}

static int
tlsm_sb_remove( Sockbuf_IO_Desc *sbiod )
{
	struct tls_data		*p;
	
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );

	p = (struct tls_data *)sbiod->sbiod_pvt;
	PR_Close( p->session );
	LBER_FREE( sbiod->sbiod_pvt );
	sbiod->sbiod_pvt = NULL;
	return 0;
}

static int
tlsm_sb_close( Sockbuf_IO_Desc *sbiod )
{
	struct tls_data		*p;
	
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );

	p = (struct tls_data *)sbiod->sbiod_pvt;
	PR_Shutdown( p->session, PR_SHUTDOWN_BOTH );
	return 0;
}

static int
tlsm_sb_ctrl( Sockbuf_IO_Desc *sbiod, int opt, void *arg )
{
	struct tls_data		*p;
	
	assert( sbiod != NULL );
	assert( sbiod->sbiod_pvt != NULL );

	p = (struct tls_data *)sbiod->sbiod_pvt;
	
	if ( opt == LBER_SB_OPT_GET_SSL ) {
		*((tlsm_session **)arg) = p->session;
		return 1;
		
	} else if ( opt == LBER_SB_OPT_DATA_READY ) {
        PRPollDesc pd = { p->session, PR_POLL_READ, 0 };
        if( PR_Poll( &pd, 1, 1 ) > 0 ) {
            return 1;
		}
	}
	
	return LBER_SBIOD_CTRL_NEXT( sbiod, opt, arg );
}

static ber_slen_t
tlsm_sb_read( Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	struct tls_data		*p;
	ber_slen_t		ret;
	int			err;

	assert( sbiod != NULL );
	assert( SOCKBUF_VALID( sbiod->sbiod_sb ) );

	p = (struct tls_data *)sbiod->sbiod_pvt;

	ret = PR_Recv( p->session, buf, len, 0, PR_INTERVAL_NO_TIMEOUT );
	if ( ret < 0 ) {
		err = PR_GetError();
		if ( err == PR_PENDING_INTERRUPT_ERROR || err == PR_WOULD_BLOCK_ERROR ) {
			sbiod->sbiod_sb->sb_trans_needs_read = 1;
			sock_errset(EWOULDBLOCK);
		}
	} else {
		sbiod->sbiod_sb->sb_trans_needs_read = 0;
	}
	return ret;
}

static ber_slen_t
tlsm_sb_write( Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len)
{
	struct tls_data		*p;
	ber_slen_t		ret;
	int			err;

	assert( sbiod != NULL );
	assert( SOCKBUF_VALID( sbiod->sbiod_sb ) );

	p = (struct tls_data *)sbiod->sbiod_pvt;

	ret = PR_Send( p->session, (char *)buf, len, 0, PR_INTERVAL_NO_TIMEOUT );
	if ( ret < 0 ) {
		err = PR_GetError();
		if ( err == PR_PENDING_INTERRUPT_ERROR || err == PR_WOULD_BLOCK_ERROR ) {
			sbiod->sbiod_sb->sb_trans_needs_write = 1;
			sock_errset(EWOULDBLOCK);
			ret = 0;
		}
	} else {
		sbiod->sbiod_sb->sb_trans_needs_write = 0;
	}
	return ret;
}

static Sockbuf_IO tlsm_sbio =
{
	tlsm_sb_setup,		/* sbi_setup */
	tlsm_sb_remove,		/* sbi_remove */
	tlsm_sb_ctrl,		/* sbi_ctrl */
	tlsm_sb_read,		/* sbi_read */
	tlsm_sb_write,		/* sbi_write */
	tlsm_sb_close		/* sbi_close */
};

tls_impl ldap_int_moznss_impl = {
	"MozNSS",

	tlsm_init,
	tlsm_destroy,

	tlsm_ctx_new,
	tlsm_ctx_ref,
	tlsm_ctx_free,
	tlsm_ctx_init,

	tlsm_session_new,
	tlsm_session_connect,
	tlsm_session_accept,
	tlsm_session_upflags,
	tlsm_session_errmsg,
	tlsm_session_my_dn,
	tlsm_session_peer_dn,
	tlsm_session_chkhost,
	tlsm_session_strength,

	&tlsm_sbio,

#ifdef LDAP_R_COMPILE
	tlsm_thr_init,
#else
	NULL,
#endif

	0
};

#endif /* HAVE_MOZNSS */
