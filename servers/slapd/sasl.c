/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <ac/stdlib.h>
#include <stdio.h>

#include "slap.h"
#include "proto-slap.h"

#include <lber.h>
#include <ldap_log.h>

#ifdef HAVE_CYRUS_SASL
#include <limits.h>
#include <sasl.h>

#include <ldap_pvt.h>

#ifdef SLAPD_SPASSWD
#include <lutil.h>
#endif

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
	default:
		return SASL_BADPARAM;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "SASL [conn=%d] %s: %s\n",
		   conn ? conn->c_connid : -1,
		   label, message ));
#else
	Debug( level, "SASL [conn=%d] %s: %s\n",
		conn ? conn->c_connid: -1,
		label, message );
#endif


	return SASL_OK;
}


/* Take any sort of identity string and return a DN with the "dn:" prefix. The
   string returned in *dnptr is in its own allocated memory, and must be free'd 
   by the calling process.
   -Mark Adamson, Carnegie Mellon
*/

int slap_sasl_getdn( Connection *conn, char *id, char **dnptr, int flags )
{
	char *c, *c1, *dn=NULL;
	int rc, len, len1;
	sasl_conn_t *ctx;


#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_getdn: conn %d id=%s\n",
		   conn ? conn->c_connid : -1,
		   id ? (*id ? id : "<empty>") : "NULL" ));
#else
	Debug( LDAP_DEBUG_ARGS, "slap_sasl_getdn: id=%s\n", 
      id?(*id?id:"<empty>"):"NULL",0,0 );
#endif


	/* Blatantly anonymous ID */
	len = strlen( "anonymous" );
	if( id && !strncasecmp( id, "anonymous", len) && 
		( id[len] == '\0' || id[len] == '@' ) ) {
		*dnptr = NULL;
		return( LDAP_SUCCESS );
	}
	ctx = conn->c_sasl_context;
	dn = ch_strdup( id );
	len = strlen( id );

	/* An authcID will need to be prefixed with u: */
	if( flags & FLAG_GETDN_AUTHCID ) {
		dn = ch_realloc( dn, len+3 );
		memmove( dn+2, dn, len+1 );
		dn[0] = 'u';
		dn[1] = ':';
		len += 2;
	}

	/* An authzID must be properly prefixed */
	if( flags & FLAG_GETDN_AUTHZID && strncasecmp( dn, "u:", 2 ) &&
	  strncasecmp( dn, "dn:", 3 ) ) {
		ch_free( dn );
		*dnptr = NULL;
		return( LDAP_INAPPROPRIATE_AUTH );
	}

	/* Username strings */
	len1  = strlen( ",cn=auth" );
	if( !strncasecmp( dn, "u:", 2 ) ) {
		len += strlen( "dn:uid=" ) + len1;

		/* Figure out how much data we have for the dn */
		rc = sasl_getprop( ctx,	SASL_REALM, (void **)&c );
		if( rc != SASL_OK ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
				   "slap_sasl_getdn: getprop(REALM) failed.\n" ));
#else
			Debug(LDAP_DEBUG_TRACE,
				"getdn: getprop(REALM) failed!\n", 0,0,0);
#endif

			ch_free( dn );
			*dnptr = NULL;
			return( LDAP_OPERATIONS_ERROR );
		}
		if( c ) {
			len += strlen( c ) + strlen(",cn=" );
		}
		if( conn->c_sasl_bind_mech ) {
			len += strlen( conn->c_sasl_bind_mech ) + strlen( ",cn=mech" );
		}

		/* Build the new dn */
		c1 = dn;
		dn = ch_malloc( len );
		len = sprintf( dn, "dn:uid=%s", c1+2 );
		ch_free( c1 );

		if( c ) {
			len += sprintf( dn+len, ",cn=%s", c );
		}
		if( conn->c_sasl_bind_mech ) {
			len += sprintf( dn+len, ",cn=%s", conn->c_sasl_bind_mech );
		}
		strcpy(	dn+len, ",cn=auth" );
		len += len1;
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
			   "getdn: u:id converted to %s.\n", dn ));
#else
		Debug( LDAP_DEBUG_TRACE, "getdn: u:id converted to %s\n", dn,0,0 );
#endif

	}

	/* DN strings that are a cn=auth identity to run through regexp */
	if( !strncasecmp( dn, "dn:", 3) && ( ( flags & FLAG_GETDN_FINAL ) == 0 ) ) {
		c1 = slap_sasl2dn( dn + 3 );
		if( c1 ) {
			ch_free( dn );
			dn = c1;
			/* Reaffix the dn: prefix if it was removed */
			if( strncasecmp( dn, "dn:", 3) ) {
				c1 = dn;
				dn = ch_malloc( strlen( c1 ) + 4 );
				sprintf( dn, "dn:%s", c1 );
				ch_free( c1 );
			}
#ifdef NEW_LOGGING
			LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
				   "slap_sasl_getdn: dn:id converted to %s.\n", dn ));
#else
			Debug( LDAP_DEBUG_TRACE, "getdn: dn:id converted to %s\n", dn,0,0 );
#endif

		}
	}

	if( ( flags & FLAG_GETDN_FINAL ) == 0 )	 {
		dn_normalize( dn );
	}

	*dnptr = dn;
	return( LDAP_SUCCESS );
}



static int
slap_sasl_authorize(
	void *context,
	const char *authcid,
	const char *authzid,
	const char **user,
	const char **errstr)
{
	char *authcDN, *authzDN;
	int rc;
	Connection *conn = context;

	*user = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sas_authorize: conn %d	 authcid=\"%s\" authzid=\"%s\"\n",
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


	/* Convert the identities to DN's. If no authzid was given, client will
	   be bound as the DN matching their username */
	rc = slap_sasl_getdn( conn, (char *)authcid, &authcDN, FLAG_GETDN_AUTHCID );
	if( rc != LDAP_SUCCESS ) {
		*errstr = ldap_err2string( rc );
		return SASL_NOAUTHZ;
	}
	if( ( authzid == NULL ) || !strcmp( authcid,authzid ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
			   "slap_sasl_authorize: conn %d  Using authcDN=%s\n",
			   conn ? conn->c_connid : -1, authcDN ));
#else
		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		 "Using authcDN=%s\n", (long) (conn ? conn->c_connid : -1), authcDN,0 );
#endif

		*user = authcDN;
		*errstr = NULL;
		return SASL_OK;
	}
	rc = slap_sasl_getdn( conn, (char *)authzid, &authzDN, FLAG_GETDN_AUTHZID );
	if( rc != LDAP_SUCCESS ) {
		ch_free( authcDN );
		*errstr = ldap_err2string( rc );
		return SASL_NOAUTHZ;
	}

	rc = slap_sasl_authorized( authcDN, authzDN );
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
		ch_free( authcDN );
		ch_free( authzDN );
		return SASL_NOAUTHZ;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_authorize: conn %d authorization allowed\n",
		   (long)(conn ? conn->c_connid : -1 ) );
#else
	Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
		" authorization allowed\n",
		(long) (conn ? conn->c_connid : -1), 0, 0 );
#endif


	ch_free( authcDN );
	*user = authzDN;
	*errstr = NULL;
	return SASL_OK;
}


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
	return 0;
}

int slap_sasl_open( Connection *conn )
{
	int sc = LDAP_SUCCESS;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = NULL;
	sasl_callback_t *session_callbacks;

	assert( conn->c_sasl_context == NULL );
	assert( conn->c_sasl_extra == NULL );

	conn->c_sasl_layers = 0;

	session_callbacks =
		ch_calloc( 3, sizeof(sasl_callback_t));
	conn->c_sasl_extra = session_callbacks;

	session_callbacks[0].id = SASL_CB_LOG;
	session_callbacks[0].proc = &slap_sasl_log;
	session_callbacks[0].context = conn;

	session_callbacks[1].id = SASL_CB_PROXY_POLICY;
	session_callbacks[1].proc = &slap_sasl_authorize;
	session_callbacks[1].context = conn;

	session_callbacks[2].id = SASL_CB_LIST_END;
	session_callbacks[2].proc = NULL;
	session_callbacks[2].context = NULL;

	if( global_host == NULL ) {
		global_host = ldap_pvt_get_fqdn( NULL );
	}

	/* create new SASL context */
	sc = sasl_server_new( "ldap", global_host, global_realm,
		session_callbacks, SASL_SECURITY_LAYER, &ctx );

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
#ifdef HAVE_CYRUS_SASL
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
		char *mechstr;

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

		ch_free( mechstr );
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
    const char		*dn,  
    const char		*ndn,
    struct berval	*cred,
	char				**edn,
	slap_ssf_t			*ssfp )
{
	int rc = 1;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;
	struct berval response;
	unsigned reslen;
	const char *errstr;
	int sc;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "sasl_bind: conn %ld dn=\"%s\" mech=%s datalen=%d\n",
		   conn->c_connid, dn,
		   conn->c_sasl_bind_in_progress ? "<continuing>" : conn->c_sasl_bind_mech,
		   cred ? cred->bv_len : 0 ));
#else
	Debug(LDAP_DEBUG_ARGS,
	  "==> sasl_bind: dn=\"%s\" mech=%s datalen=%d\n", dn,
	  conn->c_sasl_bind_in_progress ? "<continuing>":conn->c_sasl_bind_mech,
	  cred ? cred->bv_len : 0 );
#endif


	if( ctx == NULL ) {
		send_ldap_result( conn, op, LDAP_UNAVAILABLE,
			NULL, "SASL unavailable on this session", NULL, NULL );
		return rc;
	}

	if ( !conn->c_sasl_bind_in_progress ) {
		sc = sasl_server_start( ctx,
			conn->c_sasl_bind_mech,
			cred->bv_val, cred->bv_len,
			(char **)&response.bv_val, &reslen, &errstr );

	} else {
		sc = sasl_server_step( ctx,
			cred->bv_val, cred->bv_len,
			(char **)&response.bv_val, &reslen, &errstr );
	}

	response.bv_len = reslen;

	if ( sc == SASL_OK ) {
		char *username = NULL;

		sc = sasl_getprop( ctx,
			SASL_USERNAME, (void **)&username );

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
			rc = slap_sasl_getdn( conn, username, edn, FLAG_GETDN_FINAL );

			if( rc == LDAP_SUCCESS ) {
				int i;
				sasl_ssf_t *ssf = NULL;
				(void) sasl_getprop( ctx, SASL_SSF, (void *)&ssf );
				*ssfp = ssf ? *ssf : 0;

				if( *ssfp ) {
					ldap_pvt_thread_mutex_lock( &conn->c_mutex );
					conn->c_sasl_layers++;
					ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
				}

				/* Store the authorization DN as a subjectDN */
				if ( *edn ) {
					i = 2;
					do {
						i++;
						(*edn)[i-3] = (*edn)[i];
					} while( (*edn)[i] );
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
