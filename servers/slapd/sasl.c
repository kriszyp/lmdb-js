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

static char *sasl_host = NULL;
static sasl_security_properties_t sasl_secprops;


static int
sasl_cb_log(
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
slap_sasl_proxy_policy(
	void *context,
	const char *authcid,
	const char *authzid,
	const char **user,
	const char **errstr)
{
	char *canon = NULL;

	if ( !authcid || *authcid ) {
		*errstr = "empty authentication identity";
		return SASL_BADAUTH;
	}

	if ( !authzid || *authzid ) {
		size_t len = sizeof("u:") + strlen( authcid );
		canon = ch_malloc( len );
		strcpy( canon, "u:" );
		strcpy( &canon[sizeof("u:")-1], authcid );

		*user = canon;
		return SASL_OK;
	}

	*errstr = "no proxy policy";
    return SASL_BADAUTH;
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
	sasl_conn_t *server = NULL;
	sasl_callback_t server_callbacks[] = {
		{ SASL_CB_LOG, &sasl_cb_log, NULL },
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

	if( sasl_host == NULL ) {
		static char hostname[MAXHOSTNAMELEN+1];

		if( gethostname( hostname, MAXHOSTNAMELEN ) == 0 ) {
			hostname[MAXHOSTNAMELEN] = '\0';
			sasl_host = hostname;
		}
	}

	Debug( LDAP_DEBUG_TRACE,
		"slap_sasl_init: %s initialized!\n",
		sasl_host, 0, 0 );

	/* default security properties */
	memset( &sasl_secprops, '\0', sizeof(sasl_secprops) );
    sasl_secprops.max_ssf = UINT_MAX;
    sasl_secprops.maxbufsize = 65536;
    sasl_secprops.security_flags = SASL_SEC_NOPLAINTEXT|SASL_SEC_NOANONYMOUS;

#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = server;
#else
	sasl_dispose( &server );
#endif

#endif
	return 0;
}

int slap_sasl_destroy( void )
{
#ifdef HAVE_CYRUS_SASL
#ifdef SLAPD_SPASSWD
	sasl_dispose( &lutil_passwd_sasl_conn );
#endif
	sasl_done();
#endif
	return 0;
}

int slap_sasl_open( Connection *conn )
{
	int sc = LDAP_SUCCESS;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = NULL;
	sasl_callback_t session_callbacks[] = {
		{ SASL_CB_LOG, &sasl_cb_log, conn },
		{ SASL_CB_PROXY_POLICY, &slap_sasl_proxy_policy, conn },
		{ SASL_CB_LIST_END, NULL, NULL }
	};

	/* create new SASL context */
	sc = sasl_server_new( "ldap", sasl_host, global_realm,
		session_callbacks,
#ifdef LDAP_SASL_SECURITY_LAYER
		SASL_SECURITY_LAYER,
#else
		0,
#endif
		&ctx );


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
	unsigned ssf,
	char *auth_id )
{
#ifdef HAVE_CYRUS_SASL
	int sc;
	sasl_conn_t *ctx = conn->c_sasl_context;
	sasl_external_properties_t extprops;

	if ( ctx == NULL ) {
		return LDAP_UNAVAILABLE;
	}

	memset( &extprops, 0L, sizeof(extprops) );
	extprops.ssf = ssf;
	extprops.auth_id = auth_id;

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
#endif
	return LDAP_SUCCESS;
}

int slap_sasl_bind(
    Connection          *conn,
    Operation           *op,  
    const char          *dn,  
    const char          *ndn,
    const char          *mech,
    struct berval       *cred,
	char				**edn )
{
	int rc = 1;

#ifdef HAVE_CYRUS_SASL
	sasl_conn_t *ctx = conn->c_sasl_context;
	struct berval response;
	unsigned reslen;
	const char *errstr;
	int sc;

	Debug(LDAP_DEBUG_ARGS,
		"==> sasl_bind: dn=\"%s\" mech=%s cred->bv_len=%d\n",
		dn, mech, cred ? cred->bv_len : 0 );

	if( ctx == NULL ) {
		send_ldap_result( conn, op, LDAP_UNAVAILABLE,
			NULL, "SASL unavailable on this session", NULL, NULL );
		return rc;
	}

	if ( mech != NULL ) {
		sc = sasl_server_start( ctx,
			mech,
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
			sasl_ssf_t ssf = 0;

			(void) sasl_getprop( ctx,
				SASL_REALM, (void **)&realm );

			(void) sasl_getprop( ctx,
				SASL_SSF, (void *)&ssf );

			Debug(LDAP_DEBUG_TRACE,
				"slap_sasl_bind: username=\"%s\" realm=\"%s\" ssf=%lu\n",
				username ? username : "",
				realm ? realm : "",
				(unsigned long) ssf );

			if( !strncasecmp( username, "anonymous", sizeof("anonyous")-1 ) &&
				( ( username[sizeof("anonymous")] == '\0' ) ||
				  ( username[sizeof("anonymous")] == '@' ) ) )
			{
				Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: anonymous\n",
					0, 0, 0);

			} else {
				*edn = ch_malloc( sizeof( "uid= + realm=" )
					+ ( username ? strlen( username ) : 0 )
					+ ( realm ? strlen( realm ) : 0 ) );

				strcpy( *edn, "uid=" );
				strcat( *edn, username );

				if( realm && *realm ) {
					strcat( *edn, " + realm=" );
					strcat( *edn, realm );
				}

				Debug(LDAP_DEBUG_TRACE, "<== slap_sasl_bind: authzdn: \"%s\"\n",
					*edn, 0, 0);
			}

			send_ldap_sasl( conn, op, rc = LDAP_SUCCESS,
				NULL, NULL, NULL, NULL, &response );
		}

	} else if ( sc == SASL_CONTINUE ) {
		send_ldap_sasl( conn, op, rc = LDAP_SASL_BIND_IN_PROGRESS,
			NULL, NULL, NULL, NULL,  &response );

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

