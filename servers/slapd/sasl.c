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

	Debug( level, "SASL [conn=%d] %s: %s\n",
		conn ? conn->c_connid: -1,
		label, message );

	return SASL_OK;
}

static int
slap_sasl_authorize(
	void *context,
	const char *authcid,
	const char *authzid,
	const char **user,
	const char **errstr)
{
	char *cuser;
	int rc;
	Connection *conn = context;

	*user = NULL;

	if ( authcid == NULL || *authcid == '\0' ) {
		*errstr = "empty authentication identity";

		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
			"empty authentication identity\n",
			(long) (conn ? conn->c_connid : -1),
			0, 0 );
		return SASL_BADAUTH;
	}

	Debug( LDAP_DEBUG_ARGS, "SASL Authorize [conn=%ld]: "
		"authcid=\"%s\" authzid=\"%s\"\n",
		(long) (conn ? conn->c_connid : -1),
		authcid ? authcid : "<empty>",
		authzid ? authzid : "<empty>" );

	if ( authzid == NULL || *authzid == '\0' ||
		strcmp( authcid, authzid ) == 0 )
	{
		size_t len = sizeof("u:") + strlen( authcid );

		cuser = ch_malloc( len );
		strcpy( cuser, "u:" );
		strcpy( &cuser[sizeof("u:")-1], authcid );

		*user = cuser;

		Debug( LDAP_DEBUG_TRACE, "SASL Authorize [conn=%ld]: "
			"\"%s\" as \"%s\"\n", 
			(long) (conn ? conn->c_connid : -1),
			authcid, cuser );

		return SASL_OK;
	}

	rc = slap_sasl_authorized( conn, authcid, authzid );
	Debug( LDAP_DEBUG_TRACE, "SASL Authorization returned %d\n", rc,0,0);
	if( rc ) {
		*errstr = "not authorized";
		return SASL_NOAUTHZ;
	}

	cuser = ch_strdup( authzid );
	dn_normalize( cuser );
	*errstr = NULL;
	*user = cuser;
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
		Debug( LDAP_DEBUG_ANY, "sasl_server_init failed\n",
			0, 0, 0 );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "slap_sasl_init: initialized!\n",
		0, 0, 0 );

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
		Debug( LDAP_DEBUG_ANY, "sasl_server_new failed: %d\n",
			sc, 0, 0 );
		return -1;
	}

	conn->c_sasl_context = ctx;

	if( sc == SASL_OK ) {
		sc = sasl_setprop( ctx,
			SASL_SEC_PROPS, &sasl_secprops );

		if( sc != SASL_OK ) {
			Debug( LDAP_DEBUG_ANY, "sasl_setprop failed: %d\n",
				sc, 0, 0 );
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
			Debug( LDAP_DEBUG_ANY, "slap_sasl_listmech failed: %d\n",
				sc, 0, 0 );
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
    Connection          *conn,
    Operation           *op,  
    const char          *dn,  
    const char          *ndn,
    struct berval       *cred,
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

	Debug(LDAP_DEBUG_ARGS,
	  "==> sasl_bind: dn=\"%s\" mech=%s datalen=%d\n", dn,
	  conn->c_sasl_bind_in_progress ? "<continuing>":conn->c_sasl_bind_mech,
	  cred ? cred->bv_len : 0 );

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
			Debug(LDAP_DEBUG_TRACE,
				"slap_sasl_bind: getprop(USERNAME) failed!\n",
				0, 0, 0);

			send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
				NULL, "no SASL username", NULL, NULL );

		} else if ( username == NULL || *username == '\0' ) {
			Debug(LDAP_DEBUG_TRACE,
				"slap_sasl_bind: getprop(USERNAME) returned NULL!\n",
				0, 0, 0);

			send_ldap_result( conn, op, rc = LDAP_INSUFFICIENT_ACCESS,
				NULL, "no SASL username", NULL, NULL );

		} else {
			char *realm = NULL;
			sasl_ssf_t *ssf = NULL;

			(void) sasl_getprop( ctx,
				SASL_REALM, (void **)&realm );

			(void) sasl_getprop( ctx,
				SASL_SSF, (void *)&ssf );

			Debug(LDAP_DEBUG_TRACE,
				"slap_sasl_bind: username=\"%s\" realm=\"%s\" ssf=%lu\n",
				username ? username : "",
				realm ? realm : "",
				(unsigned long) ( ssf ? *ssf : 0 ) );

			*ssfp = ssf ? *ssf : 0;

			rc = LDAP_SUCCESS;

			if( username == NULL || (
				!strncasecmp( username, "anonymous", sizeof("anonymous")-1 ) &&
				( username[sizeof("anonymous")-1] == '\0' ||
				  username[sizeof("anonymous")-1] == '@' ) ) )
			{
				Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: anonymous\n",
					0, 0, 0);

			} else if ( username[0] == 'u' && username[1] == ':'
				&& username[2] != '\0'
				&& strpbrk( &username[2], "+=,;\"\\ \t") == NULL )
			{
				*edn = ch_malloc( sizeof( "uid= + realm=" )
					+ strlen( &username[2] )
					+ ( realm ? strlen( realm ) : 0 ) );

				strcpy( *edn, "uid=" );
				strcat( *edn, &username[2] );

				if( realm && *realm ) {
					strcat( *edn, " + realm=" );
					strcat( *edn, realm );
				}

				Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: authzdn: \"%s\"\n",
					*edn, 0, 0);

			}

			if( rc == LDAP_SUCCESS ) {
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

	Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: rc=%d\n", rc, 0, 0);

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
