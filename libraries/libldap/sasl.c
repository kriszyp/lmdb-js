/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 *	BindRequest ::= SEQUENCE {
 *		version		INTEGER,
 *		name		DistinguishedName,	 -- who
 *		authentication	CHOICE {
 *			simple		[0] OCTET STRING -- passwd
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
 *			krbv42ldap	[1] OCTET STRING
 *			krbv42dsa	[2] OCTET STRING
#endif
 *			sasl		[3] SaslCredentials	-- LDAPv3
 *		}
 *	}
 *
 *	BindResponse ::= SEQUENCE {
 *		COMPONENTS OF LDAPResult,
 *		serverSaslCreds		OCTET STRING OPTIONAL -- LDAPv3
 *	}
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"


/*
 * ldap_sasl_bind - bind to the ldap server (and X.500).  The dn, mechanism, and
 * credentials of the entry to which to bind are supplied.  The message id
 * of the request initiated is provided upon successful (LDAP_SUCCESS) return.
 *
 * Example:
 *	ldap_sasl_bind( ld, "cn=manager, o=university of michigan, c=us",
 *	    "mechanism", "secret", NULL, NULL, &msgid )
 */

int
ldap_sasl_bind(
	LDAP			*ld,
	LDAP_CONST char	*dn,
	LDAP_CONST char	*mechanism,
	struct berval	*cred,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls,
	int				*msgidp )
{
	BerElement	*ber;
	int rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_sasl_bind\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( msgidp != NULL );

	if( msgidp == NULL ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return ld->ld_errno;
	}

	if( mechanism == LDAP_SASL_SIMPLE ) {
		if( dn == NULL && cred != NULL ) {
			/* use default binddn */
			dn = ld->ld_defbinddn;
		}

	} else if( ld->ld_version < LDAP_VERSION3 ) {
		ld->ld_errno = LDAP_NOT_SUPPORTED;
		return ld->ld_errno;
	}

	if ( dn == NULL ) {
		dn = "";
	}

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return ld->ld_errno;
	}

	assert( BER_VALID( ber ) );

	if( mechanism == LDAP_SASL_SIMPLE ) {
		/* simple bind */
		rc = ber_printf( ber, "{it{istO}" /*}*/,
			++ld->ld_msgid, LDAP_REQ_BIND,
			ld->ld_version, dn, LDAP_AUTH_SIMPLE,
			cred );
		
	} else if ( cred == NULL ) {
		/* SASL bind w/o creditials */
		rc = ber_printf( ber, "{it{ist{s}}" /*}*/,
			++ld->ld_msgid, LDAP_REQ_BIND,
			ld->ld_version, dn, LDAP_AUTH_SASL,
			mechanism );

	} else {
		/* SASL bind w/ creditials */
		rc = ber_printf( ber, "{it{ist{sO}}" /*}*/,
			++ld->ld_msgid, LDAP_REQ_BIND,
			ld->ld_version, dn, LDAP_AUTH_SASL,
			mechanism, cred );
	}

	if( rc == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( -1 );
	}

	/* Put Server Controls */
	if( ldap_int_put_controls( ld, sctrls, ber ) != LDAP_SUCCESS ) {
		ber_free( ber, 1 );
		return ld->ld_errno;
	}

	if ( ber_printf( ber, /*{*/ "}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return ld->ld_errno;
	}

#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULL ) {
		ldap_flush_cache( ld );
	}
#endif /* !LDAP_NOCACHE */

	/* send the message */
	*msgidp = ldap_send_initial_request( ld, LDAP_REQ_BIND, dn, ber );

	if(*msgidp < 0)
		return ld->ld_errno;

	return LDAP_SUCCESS;
}


int
ldap_sasl_bind_s(
	LDAP			*ld,
	LDAP_CONST char	*dn,
	LDAP_CONST char	*mechanism,
	struct berval	*cred,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls,
	struct berval	**servercredp )
{
	int	rc, msgid;
	LDAPMessage	*result;
	struct berval	*scredp = NULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_sasl_bind_s\n", 0, 0, 0 );

	/* do a quick !LDAPv3 check... ldap_sasl_bind will do the rest. */
	if( servercredp != NULL ) {
		if (ld->ld_version < LDAP_VERSION3) {
			ld->ld_errno = LDAP_NOT_SUPPORTED;
			return ld->ld_errno;
		}
		*servercredp = NULL;
	}

	rc = ldap_sasl_bind( ld, dn, mechanism, cred, sctrls, cctrls, &msgid );

	if ( rc != LDAP_SUCCESS ) {
		return( rc );
	}

	if ( ldap_result( ld, msgid, 1, NULL, &result ) == -1 ) {
		return( ld->ld_errno );	/* ldap_result sets ld_errno */
	}

	/* parse the results */
	scredp = NULL;
	if( servercredp != NULL ) {
		rc = ldap_parse_sasl_bind_result( ld, result, &scredp, 0 );
	}

	if( rc != LDAP_SUCCESS ) {
		ldap_msgfree( result );
		return( rc );
	}

	rc = ldap_result2error( ld, result, 1 );

	if( rc == LDAP_SUCCESS ) {
		if( servercredp != NULL ) {
			*servercredp = scredp;
		}

	} else if (scredp != NULL ) {
		ber_bvfree(scredp);
	}

	return rc;
}


/*
* Parse BindResponse:
*
*   BindResponse ::= [APPLICATION 1] SEQUENCE {
*     COMPONENTS OF LDAPResult,
*     serverSaslCreds  [7] OCTET STRING OPTIONAL }
*
*   LDAPResult ::= SEQUENCE {
*     resultCode      ENUMERATED,
*     matchedDN       LDAPDN,
*     errorMessage    LDAPString,
*     referral        [3] Referral OPTIONAL }
*/

int
ldap_parse_sasl_bind_result(
	LDAP			*ld,
	LDAPMessage		*res,
	struct berval	**servercredp,
	int				freeit )
{
	ber_int_t errcode;
	struct berval* scred;

	ber_tag_t tag;
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_parse_sasl_bind_result\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( res != NULL );

	if ( ld == NULL || res == NULL ) {
		return LDAP_PARAM_ERROR;
	}

	if( servercredp != NULL ) {
		if( ld->ld_version < LDAP_VERSION2 ) {
			return LDAP_NOT_SUPPORTED;
		}
		*servercredp = NULL;
	}

	if( res->lm_msgtype != LDAP_RES_BIND ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return ld->ld_errno;
	}

	scred = NULL;

	if ( ld->ld_error ) {
		LDAP_FREE( ld->ld_error );
		ld->ld_error = NULL;
	}
	if ( ld->ld_matched ) {
		LDAP_FREE( ld->ld_matched );
		ld->ld_matched = NULL;
	}

	/* parse results */

	ber = ber_dup( res->lm_ber );

	if( ber == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return ld->ld_errno;
	}

	if ( ld->ld_version < LDAP_VERSION2 ) {
		tag = ber_scanf( ber, "{ia}",
			&errcode, &ld->ld_error );

		if( tag == LBER_ERROR ) {
			ber_free( ber, 0 );
			ld->ld_errno = LDAP_DECODING_ERROR;
			return ld->ld_errno;
		}

	} else {
		ber_len_t len;

		tag = ber_scanf( ber, "{iaa" /*}*/,
			&errcode, &ld->ld_matched, &ld->ld_error );

		if( tag == LBER_ERROR ) {
			ber_free( ber, 0 );
			ld->ld_errno = LDAP_DECODING_ERROR;
			return ld->ld_errno;
		}

		tag = ber_peek_tag(ber, &len);

		if( tag == LDAP_TAG_REFERRAL ) {
			/* skip 'em */
			if( ber_scanf( ber, "x" ) == LBER_ERROR ) {
				ber_free( ber, 0 );
				ld->ld_errno = LDAP_DECODING_ERROR;
				return ld->ld_errno;
			}

			tag = ber_peek_tag(ber, &len);
		}

		if( tag == LDAP_TAG_SASL_RES_CREDS ) {
			if( ber_scanf( ber, "O", &scred ) == LBER_ERROR ) {
				ber_free( ber, 0 );
				ld->ld_errno = LDAP_DECODING_ERROR;
				return ld->ld_errno;
			}
		}
	}

	ber_free( ber, 0 );

	if ( servercredp != NULL ) {
		*servercredp = scred;

	} else if ( scred != NULL ) {
		ber_bvfree( scred );
	}

	ld->ld_errno = errcode;

	if ( freeit ) {
		ldap_msgfree( res );
	}

	return( ld->ld_errno );
}

#ifdef HAVE_CYRUS_SASL
/*
* Various Cyrus SASL related stuff.
*/

static int sasl_setup( Sockbuf *sb, void *arg );
static int sasl_remove( Sockbuf *sb );
static ber_slen_t sasl_read( Sockbuf *sb, void *buf, ber_len_t len );
static ber_slen_t sasl_write( Sockbuf *sb, void *buf, ber_len_t len );
static int sasl_close( Sockbuf *sb );

static Sockbuf_IO sasl_io=
{
sasl_setup,
sasl_remove,
sasl_read,
sasl_write,
sasl_close
}; 

#define HAS_SASL( sb ) ((sb)->sb_io==&sasl_io)

static char *
array2str( char **a )
{
	char *s, **v, *p;
	int len = 0;

	for ( v = a; *v != NULL; v++ ) {
		len += strlen( *v ) + 1; /* for a space */
	}

	if ( len == 0 ) {
		return NULL;
	}

	s = LDAP_MALLOC ( len ); /* last space holds \0 */

	if ( s == NULL ) {
		return NULL;	
	}

	p = s;
	for ( v = a; *v != NULL; v++ ) {
		int len;

		if ( v != a ) {
			strncpy( p, " ", 1 );
			++p;
		}
		len = strlen( *v );
		strncpy( p, *v, len );
		p += len;
	}

	*p = '\0';

	return s;
}

int ldap_pvt_sasl_init( void )
{
	/* XXX not threadsafe */
	static int sasl_initialized = 0;

	if ( sasl_initialized ) {
		return 0;
	}
#ifndef CSRIMALLOC
	sasl_set_alloc( ber_memalloc, ber_memcalloc, ber_memrealloc, ber_memfree );
#endif /* CSRIMALLOC */

	if ( sasl_client_init( NULL ) == SASL_OK ) {
		sasl_initialized = 1;
		return 0;
	}

	return -1;
}

int ldap_pvt_sasl_install( Sockbuf *sb, void *ctx_arg )
{
	/* don't install the stuff unless security has been negotiated */

	if ( !HAS_SASL( sb ) ) {
		ber_pvt_sb_clear_io( sb );
		ber_pvt_sb_set_io( sb, &sasl_io, ctx_arg );
	}

	return 0;
}

static int sasl_setup( Sockbuf *sb, void *arg )
{
	sb->sb_iodata = arg;
	return 0;
}

static int sasl_remove( Sockbuf *sb )
{
	return 0;
}

static ber_slen_t sasl_read( Sockbuf *sb, void *buf, ber_len_t buflen )
{
	char *recv_tok;
	unsigned recv_tok_len;
	sasl_conn_t *conn = (sasl_conn_t *)sb->sb_iodata;

	if ((ber_pvt_sb_io_tcp.sbi_read)( sb, buf, buflen ) != buflen ) {
		return -1;
	}

	if ( sasl_decode( conn, buf, buflen, &recv_tok, &recv_tok_len ) != SASL_OK ) {
		return -1;
	}

	if ( recv_tok_len > buflen ) {
		LDAP_FREE( recv_tok );
		return -1;
	}

	memcpy( buf, recv_tok, recv_tok_len );	

	LDAP_FREE( recv_tok );

	return recv_tok_len;
}

static ber_slen_t sasl_write( Sockbuf *sb, void *buf, ber_len_t len )
{
	char *wrapped_tok;
	unsigned wrapped_tok_len;
	sasl_conn_t *conn = (sasl_conn_t *)sb->sb_iodata;

	if ( sasl_encode( conn, (const char *)buf, len,
		&wrapped_tok, &wrapped_tok_len ) != SASL_OK ) {
		return -1;
	}

	if ((ber_pvt_sb_io_tcp.sbi_write)( sb, wrapped_tok, wrapped_tok_len ) != wrapped_tok_len ) {
		LDAP_FREE( wrapped_tok );
		return -1;
	}

	LDAP_FREE( wrapped_tok );

	return len;
}

static int sasl_close( Sockbuf *sb )
{
	(ber_pvt_sb_io_tcp.sbi_close)( sb );
}

int
ldap_pvt_sasl_err2ldap( int saslerr )
{
	int rc;

	switch (saslerr) {
		case SASL_CONTINUE:
			rc = LDAP_SASL_BIND_IN_PROGRESS;
			break;
		case SASL_OK:
			rc = LDAP_SUCCESS;
			break;
		case SASL_FAIL:
			rc = LDAP_OPERATIONS_ERROR;
			break;
		case SASL_NOMEM:
			rc = LDAP_NO_MEMORY;
			break;
		case SASL_NOMECH:
			rc = LDAP_AUTH_METHOD_NOT_SUPPORTED;
			break;
		case SASL_BADAUTH:
			rc = LDAP_INVALID_CREDENTIALS;
			break;
		case SASL_NOAUTHZ:
			rc = LDAP_INSUFFICIENT_ACCESS;
			break;
		case SASL_TOOWEAK:
		case SASL_ENCRYPT:
			rc = LDAP_INAPPROPRIATE_AUTH;
			break;
		default:
			rc = LDAP_OPERATIONS_ERROR;
			break;
	}

	return rc;
}

int
ldap_pvt_sasl_getmechs ( LDAP *ld, LDAP_CONST char *desired, char **pmechlist )
{
	/* we need to query the server for supported mechs anyway */
	LDAPMessage *res, *e;
	char *attrs[] = { "supportedSASLMechanisms", NULL };
	char **values, *mechlist, **p;
	int rc;

	rc = ldap_search_s( ld, NULL, LDAP_SCOPE_BASE,
		"(objectclass=*)", attrs, 0, &res );

	if ( rc != LDAP_SUCCESS ) {
		return ld->ld_errno;
	}
		
	e = ldap_first_entry( ld, res );
	if ( e == NULL ) {
		if ( ld->ld_errno == LDAP_SUCCESS ) {
			ld->ld_errno = LDAP_UNAVAILABLE;
		}
		return ld->ld_errno;
	}

	values = ldap_get_values( ld, e, "supportedSASLMechanisms" );
	if ( values == NULL ) {
		ld->ld_errno = LDAP_NO_SUCH_ATTRIBUTE;
		ldap_msgfree( res );
		return ld->ld_errno;
	}

	if ( desired != NULL ) {
		rc = LDAP_INAPPROPRIATE_AUTH;

		for ( p = values; *p != NULL; p++ ) {
			if ( strcmp( *p, desired ) == 0 ) {
				rc = LDAP_SUCCESS;
				break;
			}
		}

		if ( rc == LDAP_SUCCESS ) {
			/* just return this */
			*pmechlist = LDAP_STRDUP( desired );
			return LDAP_SUCCESS;
		} else {
			/* couldn't find it */
			ld->ld_errno = LDAP_INAPPROPRIATE_AUTH;
			return ld->ld_errno;
		}
	}

	mechlist = array2str( values );
	if ( mechlist == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		ldap_value_free( values );
		ldap_msgfree( res );
		return ld->ld_errno;
	} 

	ldap_value_free( values );
	ldap_msgfree( res );

	*pmechlist = mechlist;

	return LDAP_SUCCESS;
}

int
ldap_pvt_sasl_bind(
	LDAP			*ld,
	LDAP_CONST char		*dn,
	LDAP_CONST char		*mechanism,
	LDAP_CONST sasl_callback_t	*callbacks,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls )
{
	int	saslrc, rc, msgid, ssf = 0;
	struct berval ccred, *scred;
	char *mechlist = NULL;
	char *host;
	sasl_interact_t *client_interact = NULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_pvt_sasl_bind\n", 0, 0, 0 );

	/* do a quick !LDAPv3 check... ldap_sasl_bind will do the rest. */
	if (ld->ld_version < LDAP_VERSION3) {
		ld->ld_errno = LDAP_NOT_SUPPORTED;
		return ld->ld_errno;
	}

	/*
	 * This connects to the host, side effect being that
	 * ldap_host_connected_to() works.
	 */
	rc = ldap_pvt_sasl_getmechs( ld, mechanism, &mechlist );
	if ( rc != LDAP_SUCCESS ) {
		return ld->ld_errno;
	}

	/* XXX this doesn't work with PF_LOCAL hosts */
	host = ldap_host_connected_to( &ld->ld_sb );

	if ( host == NULL ) {
		LDAP_FREE( mechlist );
		ld->ld_errno = LDAP_UNAVAILABLE;
		return ld->ld_errno;
	}

	if ( ld->ld_sasl_context != NULL ) {
		LDAP_FREE( mechlist );
		sasl_dispose( &ld->ld_sasl_context );
	}

	saslrc = sasl_client_new( "ldap", host, callbacks, 0, &ld->ld_sasl_context );

	LDAP_FREE( host );

	if ( (saslrc != SASL_OK) && (saslrc != SASL_CONTINUE) ) {
		LDAP_FREE( mechlist );
		ld->ld_errno = ldap_pvt_sasl_err2ldap( rc );
		sasl_dispose( &ld->ld_sasl_context );
		return ld->ld_errno;
	}

	ccred.bv_val = NULL;
	ccred.bv_len = 0;

	saslrc = sasl_client_start( ld->ld_sasl_context,
		mechlist,
		NULL,
		&client_interact,
		&ccred.bv_val,
		(unsigned int *)&ccred.bv_len,
		&mechanism );

	LDAP_FREE( mechlist );

	if ( (saslrc != SASL_OK) && (saslrc != SASL_CONTINUE) ) {
		ld->ld_errno = ldap_pvt_sasl_err2ldap( saslrc );
		sasl_dispose( &ld->ld_sasl_context );
		return ld->ld_errno;
	}

	scred = NULL;

	do {
		sasl_interact_t *client_interact = NULL;

		rc = ldap_sasl_bind_s( ld, dn, mechanism, &ccred, sctrls, cctrls, &scred );
		if ( rc == LDAP_SUCCESS ) {
			break;
		} else if ( rc != LDAP_SASL_BIND_IN_PROGRESS ) {
			if ( ccred.bv_val != NULL ) {
				LDAP_FREE( ccred.bv_val );
			}
			sasl_dispose( &ld->ld_sasl_context );
			return ld->ld_errno;
		}

		if ( ccred.bv_val != NULL ) {
			LDAP_FREE( ccred.bv_val );
			ccred.bv_val = NULL;
		}

		saslrc = sasl_client_step( ld->ld_sasl_context,
			(scred == NULL) ? NULL : scred->bv_val,
			(scred == NULL) ? 0 : scred->bv_len,
			&client_interact,
			&ccred.bv_val,
			(unsigned int *)&ccred.bv_len );

		ber_bvfree( scred );

		if ( (saslrc != SASL_OK) && (saslrc != SASL_CONTINUE) ) {
			ld->ld_errno = ldap_pvt_sasl_err2ldap( saslrc );
			sasl_dispose( &ld->ld_sasl_context );
			return ld->ld_errno;
		}
	} while ( rc == LDAP_SASL_BIND_IN_PROGRESS );

	assert ( rc == LDAP_SUCCESS );

	if ( sasl_getprop( ld->ld_sasl_context, SASL_SSF, (void **)&ssf )
		== SASL_OK && ssf ) {
		ldap_pvt_sasl_install( &ld->ld_sb, ld->ld_sasl_context );
	}

	return rc;
}

/* based on sample/sample-client.c */
static int
ldap_pvt_sasl_getsecret(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
{
	struct berval *passphrase = (struct berval *)context;
	size_t len;           

	if ( conn == NULL || psecret == NULL || id != SASL_CB_PASS ) {
		return SASL_BADPARAM;
	}

	len = (passphrase != NULL) ? (size_t)passphrase->bv_len: 0;

	*psecret = (sasl_secret_t *) LDAP_MALLOC( sizeof( sasl_secret_t ) + len );
	if ( *psecret == NULL ) {
		return SASL_NOMEM;
	}

	(*psecret)->len = passphrase->bv_len;

	if ( passphrase != NULL ) {
		memcpy((*psecret)->data, passphrase->bv_val, len);
	}

	return SASL_OK;
}

static int
ldap_pvt_sasl_getsimple(void *context, int id, const char **result, int *len)
{
	const char *value = (const char *)context;

	if ( result == NULL ) {
		return SASL_BADPARAM;
	}

	switch ( id ) {
		case SASL_CB_USER:
		case SASL_CB_AUTHNAME:
			*result = value;
			if ( len )
				*len = value ? strlen( value ) : 0;
			break;
		case SASL_CB_LANGUAGE:
			*result = NULL;
			if ( len )
				*len = 0;
			break;
		default:
			return SASL_BADPARAM;
	}

	return SASL_OK;
}

/*
 * ldap_negotiated_sasl_bind_s - bind to the ldap server (and X.500) using SASL
 * authentication.  The dn and password of the entry to which to bind are
 * supplied.  LDAP_SUCCESS is returned upon success, the ldap error code
 * otherwise.
 *
 * Example:
 *	ldap_negotiated_sasl_bind_s( ld, NULL,
 *	    "dn:cn=manager", NULL, "GSSAPI", NULL, NULL, NULL );
 */
int
ldap_negotiated_sasl_bind_s(
        LDAP *ld,
	LDAP_CONST char *dn, /* usually NULL */
        LDAP_CONST char *authorizationId,
        LDAP_CONST char *authenticationId,  
        LDAP_CONST char *saslMechanism,     
        struct berval *passPhrase,        
        LDAPControl **serverControls,
        LDAPControl **clientControls)
{
	sasl_callback_t callbacks[4];
	int rc;

	callbacks[0].id = SASL_CB_USER;
	callbacks[0].proc = ldap_pvt_sasl_getsimple;
	callbacks[0].context = (void *)authorizationId;
	callbacks[1].id = SASL_CB_AUTHNAME;
	callbacks[1].proc = ldap_pvt_sasl_getsimple;
	callbacks[1].context = (void *)authenticationId;
	callbacks[2].id = SASL_CB_PASS;
	callbacks[2].proc = ldap_pvt_sasl_getsecret;
	callbacks[2].context = (void *)passPhrase;
	callbacks[3].id = SASL_CB_LIST_END;
	callbacks[3].proc = NULL;
	callbacks[3].context = NULL;

	rc = ldap_pvt_sasl_bind(ld, dn, saslMechanism, callbacks, serverControls, clientControls);

	return rc;
}
#endif /* HAVE_CYRUS_SASL */
