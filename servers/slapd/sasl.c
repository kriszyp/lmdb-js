/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>

#include <lber.h>
#include <ldap_log.h>

#include "slap.h"

#ifdef HAVE_CYRUS_SASL
#include <limits.h>

#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#else
#include <sasl.h>
#endif

#if SASL_VERSION_MAJOR >= 2
#include <lutil.h>
#define	SASL_CONST const
#else
#define	SASL_CONST
#endif

#include <ldap_pvt.h>

#ifdef SLAPD_SPASSWD
#include <lutil.h>
#endif

/* Flags for telling slap_sasl_getdn() what type of identity is being passed */
#define FLAG_GETDN_FINAL   1
#define FLAG_GETDN_AUTHCID 2
#define FLAG_GETDN_AUTHZID 4

static sasl_security_properties_t sasl_secprops;

static int
slap_sasl_log(
	void *context,
	int priority,
	const char *message) 
{
	Connection *conn = context;
	int level;
	const char * label;

	if ( message == NULL ) {
		return SASL_BADPARAM;
	}

	switch (priority) {
#if SASL_VERSION_MAJOR >= 2
	case SASL_LOG_NONE:
		level = LDAP_DEBUG_NONE;
		label = "None";
		break;
	case SASL_LOG_ERR:
		level = LDAP_DEBUG_ANY;
		label = "Error";
		break;
	case SASL_LOG_FAIL:
		level = LDAP_DEBUG_ANY;
		label = "Failure";
		break;
	case SASL_LOG_WARN:
		level = LDAP_DEBUG_TRACE;
		label = "Warning";
		break;
	case SASL_LOG_NOTE:
		level = LDAP_DEBUG_TRACE;
		label = "Notice";
		break;
	case SASL_LOG_DEBUG:
		level = LDAP_DEBUG_TRACE;
		label = "Debug";
		break;
	case SASL_LOG_TRACE:
		level = LDAP_DEBUG_TRACE;
		label = "Trace";
		break;
	case SASL_LOG_PASS:
		level = LDAP_DEBUG_TRACE;
		label = "Password Trace";
		break;
#else
	case SASL_LOG_ERR:
		level = LDAP_DEBUG_ANY;
		label = "Error";
		break;
	case SASL_LOG_WARNING:
		level = LDAP_DEBUG_TRACE;
		label = "Warning";
		break;
	case SASL_LOG_INFO:
		level = LDAP_DEBUG_TRACE;
		label = "Info";
		break;
#endif
	default:
		return SASL_BADPARAM;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"SASL [conn=%ld] %s: %s\n",
		conn ? conn->c_connid : -1,
		label, message ));
#else
	Debug( level, "SASL [conn=%ld] %s: %s\n",
		conn ? conn->c_connid: -1,
		label, message );
#endif


	return SASL_OK;
}


/* Take any sort of identity string and return a DN with the "dn:" prefix. The
   string returned in *dn is in its own allocated memory, and must be free'd 
   by the calling process.
   -Mark Adamson, Carnegie Mellon
*/

#define	SET_DN	1
#define	SET_U	2

static struct berval ext_bv = { sizeof("EXTERNAL")-1, "EXTERNAL" };

int slap_sasl_getdn( Connection *conn, char *id,
	char *user_realm, struct berval *dn, int flags )
{
	char *c1;
	int rc, len, is_dn = 0;
	sasl_conn_t *ctx;
	struct berval dn2;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_getdn: conn %d id=%s\n",
		conn ? conn->c_connid : -1,
		id ? (*id ? id : "<empty>") : "NULL" ));
#else
	Debug( LDAP_DEBUG_ARGS, "slap_sasl_getdn: id=%s\n", 
      id?(*id?id:"<empty>"):"NULL",0,0 );
#endif

	dn->bv_val = NULL;
	dn->bv_len = 0;

	/* Blatantly anonymous ID */
	if( id &&
		( id[sizeof( "anonymous" )-1] == '\0'
			|| id[sizeof( "anonymous" )-1] == '@' ) &&
		!strncasecmp( id, "anonymous", sizeof( "anonymous" )-1) ) {
		return( LDAP_SUCCESS );
	}
	ctx = conn->c_sasl_context;
	len = strlen( id );

	/* An authcID needs to be converted to authzID form */
	if( flags & FLAG_GETDN_AUTHCID ) {
		if( sasl_external_x509dn_convert
			&& conn->c_sasl_bind_mech.bv_len == ext_bv.bv_len
			&& ( strcasecmp( ext_bv.bv_val, conn->c_sasl_bind_mech.bv_val ) == 0 ) 
			&& id[0] == '/' )
		{
			/* check SASL external for X.509 style DN and */
			/* convert to dn:<dn> form */
			dn->bv_val = ldap_dcedn2dn( id );
			dn->bv_len = strlen(dn->bv_val);
			is_dn = SET_DN;

		} else {
			/* convert to u:<username> form */
			ber_str2bv( id, len, 1, dn );
			is_dn = SET_U;
		}
	}
	if( !is_dn ) {
		if( !strncasecmp( id, "u:", sizeof("u:")-1 )) {
			is_dn = SET_U;
			ber_str2bv( id+2, len-2, 1, dn );
		} else if ( !strncasecmp( id, "dn:", sizeof("dn:")-1) ) {
			is_dn = SET_DN;
			ber_str2bv( id+3, len-3, 1, dn );
		}
	}

	/* An authzID must be properly prefixed */
	if( (flags & FLAG_GETDN_AUTHZID) && !is_dn ) {
		free( dn->bv_val );
		dn->bv_val = NULL;
		dn->bv_len = 0;
		return( LDAP_INAPPROPRIATE_AUTH );
	}

	/* Username strings */
	if( is_dn == SET_U ) {
		char *p;
		len = dn->bv_len + sizeof("uid=")-1 + sizeof(",cn=auth")-1;

 		if( user_realm && *user_realm ) {
 			len += strlen( user_realm ) + sizeof(",cn=")-1;
		}

		if( conn->c_sasl_bind_mech.bv_len ) {
			len += conn->c_sasl_bind_mech.bv_len + sizeof(",cn=")-1;
		}

		/* Build the new dn */
		c1 = dn->bv_val;
		dn->bv_val = ch_malloc( len );
		p = slap_strcopy( dn->bv_val, "uid=" );
		p = slap_strcopy( p, c1 );
		ch_free( c1 );

		if( user_realm ) {
			p = slap_strcopy( p, ",cn=" );
			p = slap_strcopy( p, user_realm );
		}
		if( conn->c_sasl_bind_mech.bv_len ) {
			p = slap_strcopy( p, ",cn=" );
			p = slap_strcopy( p, conn->c_sasl_bind_mech.bv_val );
		}
		p = slap_strcopy( p, ",cn=auth" );
		dn->bv_len = p - dn->bv_val;
		is_dn = SET_DN;

#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
			"slap_sasl_getdn: u:id converted to %s.\n", dn->bv_val ));
#else
		Debug( LDAP_DEBUG_TRACE, "getdn: u:id converted to %s\n", dn->bv_val,0,0 );
#endif
	}

	/* DN strings that are a cn=auth identity to run through regexp */
	if( is_dn == SET_DN && ( ( flags & FLAG_GETDN_FINAL ) == 0 ) )
	{
		slap_sasl2dn( dn, &dn2 );
		if( dn2.bv_val ) {
			ch_free( dn->bv_val );
			*dn = dn2;
#ifdef NEW_LOGGING
			LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
				"slap_sasl_getdn: dn:id converted to %s.\n", dn->bv_val ));
#else
			Debug( LDAP_DEBUG_TRACE, "getdn: dn:id converted to %s\n",
				dn->bv_val, 0, 0 );
#endif
		}
	}

	if( flags & FLAG_GETDN_FINAL ) {
		/* omit "dn:" prefix */
		is_dn = 0;
	} else {
		rc = dnNormalize2( NULL, dn, &dn2 );
		free(dn->bv_val);
		if ( rc != LDAP_SUCCESS ) {
			*dn = slap_empty_bv;
			return rc;
		}
		*dn = dn2;
	}

	/* Attach the "dn:" prefix if needed */
	if ( is_dn == SET_DN ) {
		c1 = ch_malloc( dn->bv_len + sizeof("dn:") );
		strcpy( c1, "dn:" );
		strcpy( c1 + 3, dn->bv_val );
		free( dn->bv_val );
		dn->bv_val = c1;
		dn->bv_len += 3;
	}

	return( LDAP_SUCCESS );
}

#if SASL_VERSION_MAJOR >= 2
static int
slap_sasl_checkpass(
	sasl_conn_t *sconn,
	void *context,
	const char *username,
	const char *pass,
	unsigned passlen,
	struct propctx *propctx)
{
	Connection *conn = (Connection *)context;
	struct berval dn, cred;
	int rc;
	BerVarray vals, bv;

	cred.bv_val = (char *)pass;
	cred.bv_len = passlen;

	/* XXX can we do both steps at once? */
	rc = slap_sasl_getdn( conn, (char *)username, NULL, &dn,
		FLAG_GETDN_AUTHCID | FLAG_GETDN_FINAL );
	if ( rc != LDAP_SUCCESS ) {
		sasl_seterror( sconn, 0, ldap_err2string( rc ) );
		return SASL_NOUSER;
	}

	if ( dn.bv_len == 0 ) {
		sasl_seterror( sconn, 0,
			"No password is associated with the Root DSE" );
		if ( dn.bv_val != NULL ) {
			ch_free( dn.bv_val );
		}
		return SASL_NOUSER;
	}

	rc = backend_attribute( NULL, NULL, NULL, NULL, &dn,
		slap_schema.si_ad_userPassword, &vals);
	if ( rc != LDAP_SUCCESS ) {
		ch_free( dn.bv_val );
		sasl_seterror( sconn, 0, ldap_err2string( rc ) );
		return SASL_NOVERIFY;
	}

	rc = SASL_NOVERIFY;

	if ( vals != NULL ) {
		for ( bv = vals; bv->bv_val != NULL; bv++ ) {
			if ( !lutil_passwd( bv, &cred, NULL ) ) {
				rc = SASL_OK;
				break;
			}
		}
		ber_bvarray_free( vals );
	}

	if ( rc != SASL_OK ) {
		sasl_seterror( sconn, 0,
			ldap_err2string( LDAP_INVALID_CREDENTIALS ) );
	}

	ch_free( dn.bv_val );

	return rc;
}

static int
slap_sasl_canonicalize(
	sasl_conn_t *sconn,
	void *context,
	const char *in,
	unsigned inlen,
	unsigned flags,
	const char *user_realm,
	char *out,
	unsigned out_max,
	unsigned *out_len)
{
	Connection *conn = (Connection *)context;
	struct berval dn;
	int rc;

	*out_len = 0;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_canonicalize: conn %d %s=\"%s\"\n",
			conn ? conn->c_connid : -1,
			(flags == SASL_CU_AUTHID) ? "authcid" : "authzid",
			in ? in : "<empty>" ));
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Canonicalize [conn=%ld]: "
		"%s=\"%s\"\n",
			conn ? conn->c_connid : -1,
			(flags == SASL_CU_AUTHID) ? "authcid" : "authzid",
			in ? in : "<empty>" );
#endif

	rc = slap_sasl_getdn( conn, (char *)in, (char *)user_realm, &dn,
		(flags == SASL_CU_AUTHID) ? FLAG_GETDN_AUTHCID : FLAG_GETDN_AUTHZID );
	if ( rc != LDAP_SUCCESS ) {
		sasl_seterror( sconn, 0, ldap_err2string( rc ) );
		return SASL_NOAUTHZ;
	}		

	if ( out_max < dn.bv_len ) {
		return SASL_BUFOVER;
	}

	AC_MEMCPY( out, dn.bv_val, dn.bv_len );
	out[dn.bv_len] = '\0';

	*out_len = dn.bv_len;

	ch_free( dn.bv_val );

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_canonicalize: conn %d %s=\"%s\"\n",
			conn ? conn->c_connid : -1,
			(flags == SASL_CU_AUTHID) ? "authcDN" : "authzDN",
			out ));
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Canonicalize [conn=%ld]: "
		"%s=\"%s\"\n",
			conn ? conn->c_connid : -1,
			(flags == SASL_CU_AUTHID) ? "authcDN" : "authzDN",
			out );
#endif

	return SASL_OK;
}

static int
slap_sasl_authorize(
	sasl_conn_t *sconn,
	void *context,
	const char *requested_user,
	unsigned rlen,
	const char *auth_identity,
	unsigned alen,
	const char *def_realm,
	unsigned urlen,
	struct propctx *propctx)
{
	Connection *conn = (Connection *)context;
	struct berval authcDN, authzDN;
	int rc;

	authcDN.bv_val = (char *)auth_identity;
	authcDN.bv_len = alen;

	authzDN.bv_val = (char *)requested_user;
	authzDN.bv_len = rlen;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_authorize: conn %d authcDN=\"%s\" authzDN=\"%s\"\n",
			conn ? conn->c_connid : -1, authcDN.bv_val, authzDN.bv_val));
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Authorize [conn=%ld]: "
		"authcDN=\"%s\" authzDN=\"%s\"\n",
		conn ? conn->c_connid : -1, authcDN.bv_val, authzDN.bv_val );
#endif

	rc = slap_sasl_authorized( &authcDN, &authzDN );
	if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_INFO,
			   "slap_sasl_authorize: conn %ld  authorization disallowed (%d)\n",
			   (long)(conn ? conn->c_connid : -1), rc ));
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
			" authorization disallowed (%d)\n",
			(long) (conn ? conn->c_connid : -1), rc, 0 );
#endif

		sasl_seterror( sconn, 0, "not authorized" );
		return SASL_NOAUTHZ;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_authorize: conn %d authorization allowed\n",
		   (long)(conn ? conn->c_connid : -1 ) ));
#else
	Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		" authorization allowed\n",
		(long) (conn ? conn->c_connid : -1), 0, 0 );
#endif

	return SASL_OK;
} 
#else
static int
slap_sasl_authorize(
	void *context,
	const char *authcid,
	const char *authzid,
	const char **user,
	const char **errstr)
{
	struct berval authcDN, authzDN;
	int rc;
	Connection *conn = context;
	char *realm;

	*user = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_authorize: conn %d	 authcid=\"%s\" authzid=\"%s\"\n",
		   conn ? conn->c_connid : -1,
		   authcid ? authcid : "<empty>",
		   authzid ? authzid : "<empty>" ));
#else
	Debug( LDAP_DEBUG_ARGS, "SASL Authorize [conn=%ld]: "
		"authcid=\"%s\" authzid=\"%s\"\n",
		(long) (conn ? conn->c_connid : -1),
		authcid ? authcid : "<empty>",
		authzid ? authzid : "<empty>" );
#endif

	/* Figure out how much data we have for the dn */
	rc = sasl_getprop( conn->c_sasl_context, SASL_REALM, (void **)&realm );
	if( rc != SASL_OK && rc != SASL_NOTDONE ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
			"slap_sasl_authorize: getprop(REALM) failed.\n" ));
#else
		Debug(LDAP_DEBUG_TRACE,
			"authorize: getprop(REALM) failed!\n", 0,0,0);
#endif
		*errstr = "Could not extract realm";
		return SASL_NOAUTHZ;
	}

	/* Convert the identities to DN's. If no authzid was given, client will
	   be bound as the DN matching their username */
	rc = slap_sasl_getdn( conn, (char *)authcid, realm, &authcDN, FLAG_GETDN_AUTHCID );
	if( rc != LDAP_SUCCESS ) {
		*errstr = ldap_err2string( rc );
		return SASL_NOAUTHZ;
	}
	if( ( authzid == NULL ) || !strcmp( authcid,authzid ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
			   "slap_sasl_authorize: conn %d  Using authcDN=%s\n",
			   conn ? conn->c_connid : -1, authcDN.bv_val ));
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		 "Using authcDN=%s\n", (long) (conn ? conn->c_connid : -1), authcDN.bv_val,0 );
#endif

		*user = authcDN.bv_val;
		*errstr = NULL;
		return SASL_OK;
	}
	rc = slap_sasl_getdn( conn, (char *)authzid, realm, &authzDN, FLAG_GETDN_AUTHZID );
	if( rc != LDAP_SUCCESS ) {
		ch_free( authcDN.bv_val );
		*errstr = ldap_err2string( rc );
		return SASL_NOAUTHZ;
	}

	rc = slap_sasl_authorized( &authcDN, &authzDN );
	if( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_INFO,
			   "slap_sasl_authorize: conn %ld  authorization disallowed (%d)\n",
			   (long)(conn ? conn->c_connid : -1), rc ));
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
			" authorization disallowed (%d)\n",
			(long) (conn ? conn->c_connid : -1), rc, 0 );
#endif

		*errstr = "not authorized";
		ch_free( authcDN.bv_val );
		ch_free( authzDN.bv_val );
		return SASL_NOAUTHZ;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_authorize: conn %d authorization allowed\n",
		   (long)(conn ? conn->c_connid : -1 ) ));
#else
	Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		" authorization allowed\n",
		(long) (conn ? conn->c_connid : -1), 0, 0 );
#endif


	ch_free( authcDN.bv_val );
	*user = authzDN.bv_val;
	*errstr = NULL;
	return SASL_OK;
}
#endif /* SASL_VERSION_MAJOR >= 2 */

static int
slap_sasl_err2ldap( int saslerr )
{
	int rc;

	switch (saslerr) {
		case SASL_CONTINUE:
			rc = LDAP_SASL_BIND_IN_PROGRESS;
			break;
		case SASL_FAIL:
			rc = LDAP_OTHER;
			break;
		case SASL_NOMEM:
			rc = LDAP_OTHER;
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
			rc = LDAP_OTHER;
			break;
	}

	return rc;
}
#endif


int slap_sasl_init( void )
{
#ifdef HAVE_CYRUS_SASL
	int rc;
	static sasl_callback_t server_callbacks[] = {
		{ SASL_CB_LOG, &slap_sasl_log, NULL },
		{ SASL_CB_LIST_END, NULL, NULL }
	};

	sasl_set_alloc(
		ch_malloc,
		ch_calloc,
		ch_realloc,
		ch_free ); 

	sasl_set_mutex(
		ldap_pvt_sasl_mutex_new,
		ldap_pvt_sasl_mutex_lock,
		ldap_pvt_sasl_mutex_unlock,
		ldap_pvt_sasl_mutex_dispose );

	/* should provide callbacks for logging */
	/* server name should be configurable */
	rc = sasl_server_init( server_callbacks, "slapd" );

	if( rc != SASL_OK ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_INFO,
			   "slap_sasl_init: init failed.\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "sasl_server_init failed\n",
			0, 0, 0 );
#endif

		return -1;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_INFO,
		   "slap_sasl_init: initialized!\n"));
#else
	Debug( LDAP_DEBUG_TRACE, "slap_sasl_init: initialized!\n",
		0, 0, 0 );
#endif


	/* default security properties */
	memset( &sasl_secprops, '\0', sizeof(sasl_secprops) );
	sasl_secprops.max_ssf = INT_MAX;
	sasl_secprops.maxbufsize = 65536;
	sasl_secprops.security_flags = SASL_SEC_NOPLAINTEXT|SASL_SEC_NOANONYMOUS;
#endif

	return 0;
}

int slap_sasl_destroy( void )
{
#ifdef HAVE_CYRUS_SASL
	sasl_done();
#endif
	free( global_host );
	global_host = NULL;

	return 0;
}

int slap_sasl_open( Connection *conn )
{
	int cb, sc = LDAP_SUCCESS;
#if SASL_VERSION_MAJOR >= 2
	char *ipremoteport = NULL, *iplocalport = NULL;
#endif

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = NULL;
	sasl_callback_t *session_callbacks;

	assert( conn->c_sasl_context == NULL );
	assert( conn->c_sasl_extra == NULL );

	conn->c_sasl_layers = 0;

	session_callbacks =
#if SASL_VERSION_MAJOR >= 2
		ch_calloc( 5, sizeof(sasl_callback_t));
#else
		ch_calloc( 3, sizeof(sasl_callback_t));
#endif
	conn->c_sasl_extra = session_callbacks;

	session_callbacks[cb=0].id = SASL_CB_LOG;
	session_callbacks[cb].proc = &slap_sasl_log;
	session_callbacks[cb++].context = conn;

	session_callbacks[cb].id = SASL_CB_PROXY_POLICY;
	session_callbacks[cb].proc = &slap_sasl_authorize;
	session_callbacks[cb++].context = conn;

#if SASL_VERSION_MAJOR >= 2
	session_callbacks[cb].id = SASL_CB_CANON_USER;
	session_callbacks[cb].proc = &slap_sasl_canonicalize;
	session_callbacks[cb++].context = conn;

	/* XXXX: this should be conditional */
	session_callbacks[cb].id = SASL_CB_SERVER_USERDB_CHECKPASS;
	session_callbacks[cb].proc = &slap_sasl_checkpass;
	session_callbacks[cb++].context = conn;
#endif

	session_callbacks[cb].id = SASL_CB_LIST_END;
	session_callbacks[cb].proc = NULL;
	session_callbacks[cb++].context = NULL;

	if( global_host == NULL ) {
		global_host = ldap_pvt_get_fqdn( NULL );
	}

	/* create new SASL context */
#if SASL_VERSION_MAJOR >= 2
	if ( conn->c_sock_name.bv_len != 0 &&
	     strncmp( conn->c_sock_name.bv_val, "IP=", 3 ) == 0) {
		char *p;

		iplocalport = ch_strdup( conn->c_sock_name.bv_val + 3 );
		/* Convert IPv6 addresses to address;port syntax. */
		p = strrchr( iplocalport, ' ' );
		if ( p != NULL ) {
			*p = ';';
		}
	}
	if ( conn->c_peer_name.bv_len != 0 &&
	     strncmp( conn->c_peer_name.bv_val, "IP=", 3 ) == 0) {
		char *p;

		ipremoteport = ch_strdup( conn->c_peer_name.bv_val + 3 );
		/* Convert IPv6 addresses to address;port syntax. */
		p = strrchr( ipremoteport, ' ' );
		if ( p != NULL ) {
			*p = ';';
		}
	}
	sc = sasl_server_new( "ldap", global_host, global_realm,
		iplocalport, ipremoteport, session_callbacks, 0, &ctx );
	if ( iplocalport != NULL ) {
		ch_free( iplocalport );
	}
	if ( ipremoteport != NULL ) {
		ch_free( ipremoteport );
	}
#else
	sc = sasl_server_new( "ldap", global_host, global_realm,
		session_callbacks, SASL_SECURITY_LAYER, &ctx );
#endif

	if( sc != SASL_OK ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
			   "slap_sasl_open: sasl_server_new failed: %d\n", sc ));
#else
		Debug( LDAP_DEBUG_ANY, "sasl_server_new failed: %d\n",
			sc, 0, 0 );
#endif

		return -1;
	}

	conn->c_sasl_context = ctx;

	if( sc == SASL_OK ) {
		sc = sasl_setprop( ctx,
			SASL_SEC_PROPS, &sasl_secprops );

		if( sc != SASL_OK ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
				   "slap_sasl_open: sasl_setprop failed: %d \n", sc ));
#else
			Debug( LDAP_DEBUG_ANY, "sasl_setprop failed: %d\n",
				sc, 0, 0 );
#endif

			slap_sasl_close( conn );
			return -1;
		}
	}

	sc = slap_sasl_err2ldap( sc );
#endif
	return sc;
}

int slap_sasl_external(
	Connection *conn,
	slap_ssf_t ssf,
	const char *auth_id )
{
#if SASL_VERSION_MAJOR >= 2
	int sc;
	sasl_conn_t *ctx = conn->c_sasl_context;

	if ( ctx == NULL ) {
		return LDAP_UNAVAILABLE;
	}

	sc = sasl_setprop( ctx, SASL_SSF_EXTERNAL, &ssf );

	if ( sc != SASL_OK ) {
		return LDAP_OTHER;
	}

	sc = sasl_setprop( ctx, SASL_AUTH_EXTERNAL, auth_id );

	if ( sc != SASL_OK ) {
		return LDAP_OTHER;
	}

#elif defined(HAVE_CYRUS_SASL)
	int sc;
	sasl_conn_t *ctx = conn->c_sasl_context;
	sasl_external_properties_t extprops;

	if ( ctx == NULL ) {
		return LDAP_UNAVAILABLE;
	}

	memset( &extprops, '\0', sizeof(extprops) );
	extprops.ssf = ssf;
	extprops.auth_id = (char *) auth_id;

	sc = sasl_setprop( ctx, SASL_SSF_EXTERNAL,
		(void *) &extprops );

	if ( sc != SASL_OK ) {
		return LDAP_OTHER;
	}
#endif

	return LDAP_SUCCESS;
}

int slap_sasl_reset( Connection *conn )
{
#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;

	if( ctx != NULL ) {
	}
#endif
	/* must return "anonymous" */
	return LDAP_SUCCESS;
}

char ** slap_sasl_mechs( Connection *conn )
{
	char **mechs = NULL;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;

	if( ctx != NULL ) {
		int sc;
		SASL_CONST char *mechstr;

		sc = sasl_listmech( ctx,
			NULL, NULL, ",", NULL,
			&mechstr, NULL, NULL );

		if( sc != SASL_OK ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
				"slap_sasl_mechs: sasl_listmech failed: %d\n", sc ));
#else
			Debug( LDAP_DEBUG_ANY, "slap_sasl_listmech failed: %d\n",
				sc, 0, 0 );
#endif

			return NULL;
		}

		mechs = str2charray( mechstr, "," );

#if SASL_VERSION_MAJOR < 2
		ch_free( mechstr );
#endif
	}
#endif

	return mechs;
}

int slap_sasl_close( Connection *conn )
{
#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;

	if( ctx != NULL ) {
		sasl_dispose( &ctx );
	}

	conn->c_sasl_context = NULL;

	free( conn->c_sasl_extra );
	conn->c_sasl_extra = NULL;
#endif

	return LDAP_SUCCESS;
}

int slap_sasl_bind(
    Connection		*conn,
    Operation		*op,  
    struct berval	*dn,  
    struct berval	*ndn,
    struct berval	*cred,
	struct berval			*edn,
	slap_ssf_t		*ssfp )
{
	int rc = 1;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;
	struct berval response;
	unsigned reslen = 0;
	const char *errstr = NULL;
	int sc;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"sasl_bind: conn %ld dn=\"%s\" mech=%s datalen=%ld\n",
		conn->c_connid,
		dn->bv_len ? dn->bv_val : "",
		conn->c_sasl_bind_in_progress ? "<continuing>" : conn->c_sasl_bind_mech.bv_val,
		cred ? cred->bv_len : 0 ));
#else
	Debug(LDAP_DEBUG_ARGS,
		"==> sasl_bind: dn=\"%s\" mech=%s datalen=%ld\n",
		dn->bv_len ? dn->bv_val : "",
		conn->c_sasl_bind_in_progress ? "<continuing>":conn->c_sasl_bind_mech.bv_val,
		cred ? cred->bv_len : 0 );
#endif


	if( ctx == NULL ) {
		send_ldap_result( conn, op, LDAP_UNAVAILABLE,
			NULL, "SASL unavailable on this session", NULL, NULL );
		return rc;
	}

#if SASL_VERSION_MAJOR >= 2
#define	START( ctx, mech, cred, clen, resp, rlen, err ) \
	sasl_server_start( ctx, mech, cred, clen, resp, rlen )
#define	STEP( ctx, cred, clen, resp, rlen, err ) \
	sasl_server_step( ctx, cred, clen, resp, rlen )
#else
#define	START( ctx, mech, cred, clen, resp, rlen, err ) \
	sasl_server_start( ctx, mech, cred, clen, resp, rlen, err )
#define	STEP( ctx, cred, clen, resp, rlen, err ) \
	sasl_server_step( ctx, cred, clen, resp, rlen, err )
#endif

	if ( !conn->c_sasl_bind_in_progress ) {
		sc = START( ctx,
			conn->c_sasl_bind_mech.bv_val,
			cred->bv_len ? cred->bv_val : "",
			cred->bv_len,
			(SASL_CONST char **)&response.bv_val, &reslen, &errstr );

	} else {
		sc = STEP( ctx,
			cred->bv_val, cred->bv_len,
			(SASL_CONST char **)&response.bv_val, &reslen, &errstr );
	}

	response.bv_len = reslen;

	if ( sc == SASL_OK ) {
		char *username = NULL;
		char *realm = NULL;

#if SASL_VERSION_MAJOR >= 2
		sc = sasl_getprop( ctx, SASL_DEFUSERREALM, (const void **)&realm );
#else
		sc = sasl_getprop( ctx, SASL_REALM, (void **)&realm );
#endif
		sc = sasl_getprop( ctx,
			SASL_USERNAME, (SASL_CONST void **)&username );

		if ( sc != SASL_OK ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
				"slap_sasl_bind: getprop(USERNAME) failed: %d\n", sc ));
#else
			Debug(LDAP_DEBUG_TRACE,
				"slap_sasl_bind: getprop(USERNAME) failed!\n",
				0, 0, 0);
#endif


			send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
				NULL, "no SASL username", NULL, NULL );

		} else {
			rc = slap_sasl_getdn( conn, username, realm, edn, FLAG_GETDN_FINAL );

			if( rc == LDAP_SUCCESS ) {
				sasl_ssf_t *ssf = NULL;
				(void) sasl_getprop( ctx, SASL_SSF, (void *)&ssf );
				*ssfp = ssf ? *ssf : 0;

				if( *ssfp ) {
					ldap_pvt_thread_mutex_lock( &conn->c_mutex );
					conn->c_sasl_layers++;
					ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
				}

				send_ldap_sasl( conn, op, rc,
					NULL, NULL, NULL, NULL,
					response.bv_len ? &response : NULL );

			} else {
				send_ldap_result( conn, op, rc,
					NULL, errstr, NULL, NULL );
			}
		}

	} else if ( sc == SASL_CONTINUE ) {
		send_ldap_sasl( conn, op, rc = LDAP_SASL_BIND_IN_PROGRESS,
			NULL, NULL, NULL, NULL, &response );

	} else {
		send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
			NULL, errstr, NULL, NULL );
	}

#if SASL_VERSION_MAJOR < 2
	if( response.bv_len ) {
		ch_free( response.bv_val );
	}
#endif

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_bind: rc=%d\n", rc ));
#else
	Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: rc=%d\n", rc, 0, 0);
#endif


#else
	send_ldap_result( conn, op, rc = LDAP_UNAVAILABLE,
		NULL, "SASL not supported", NULL, NULL );
#endif

	return rc;
}

char* slap_sasl_secprops( const char *in )
{
#ifdef HAVE_CYRUS_SASL
	int rc = ldap_pvt_sasl_secprops( in, &sasl_secprops );

	return rc == LDAP_SUCCESS ? NULL : "Invalid security properties";
#else
	return "SASL not supported";
#endif
}
