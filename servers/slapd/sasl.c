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

char **supportedSASLMechanisms = NULL;
char *sasl_host = NULL;

#ifdef HAVE_CYRUS_SASL

#ifdef SLAPD_SPASSWD
#include <lutil.h>
#endif

static void *slap_sasl_mutex_new(void)
{
	ldap_pvt_thread_mutex_t *mutex;

	mutex = (ldap_pvt_thread_mutex_t *) ch_malloc( sizeof(ldap_pvt_thread_mutex_t) );
	if ( ldap_pvt_thread_mutex_init( mutex ) == 0 ) {
		return mutex;
	}
	return NULL;
}

static int slap_sasl_mutex_lock(void *mutex)
{
	return ldap_pvt_thread_mutex_lock( (ldap_pvt_thread_mutex_t *)mutex );
}

static int slap_sasl_mutex_unlock(void *mutex)
{
	return ldap_pvt_thread_mutex_unlock( (ldap_pvt_thread_mutex_t *)mutex );
}

static void slap_sasl_mutex_dispose(void *mutex)
{
	(void) ldap_pvt_thread_mutex_destroy( (ldap_pvt_thread_mutex_t *)mutex );
	free( mutex );
}

static int
slap_sasl_err2ldap( int saslerr )
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


int sasl_init( void )
{
	int rc;
	char *mechs;
	sasl_conn_t *server = NULL;

	sasl_set_alloc( ch_malloc, ch_calloc, ch_realloc, ch_free ); 

	sasl_set_mutex(
		slap_sasl_mutex_new,
		slap_sasl_mutex_lock,
		slap_sasl_mutex_unlock,
		slap_sasl_mutex_dispose );

	rc = sasl_server_init( NULL, "slapd" );

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

	rc = sasl_server_new( "ldap", sasl_host, NULL, NULL,
		SASL_SECURITY_LAYER, 
		&server );

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_server_new failed\n",
			0, 0, 0 );
		return -1;
	}

#ifdef RESTRICT_SASL
	{
		sasl_security_properties_t secprops;
		memset(&secprops, 0, sizeof(secprops));
		secprops.security_flags = SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS;
		secprops.property_names = NULL;
		secprops.property_values = NULL;
	
		rc = sasl_setprop( server, SASL_SEC_PROPS, &secprops );

		if( rc != SASL_OK ) {
			Debug( LDAP_DEBUG_ANY, "sasl_setprop failed\n",
				0, 0, 0 );
			return -1;
		}
	}
#endif

	rc = sasl_listmech( server, NULL, NULL, ",", NULL,
		&mechs, NULL, NULL);

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_listmech failed: %d\n",
			rc, 0, 0 );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "SASL mechanisms: %s\n",
		mechs, 0, 0 );

	supportedSASLMechanisms = str2charray( mechs, "," );

#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = server;
#else
	sasl_dispose( &server );
#endif

	return 0;
}

int sasl_destroy( void )
{
#ifdef SLAPD_SPASSWD
	sasl_dispose( &lutil_passwd_sasl_conn );
#endif
	charray_free( supportedSASLMechanisms );
	return 0;
}

#ifdef HAVE_CYRUS_SASL
int sasl_bind(
    Connection          *conn,
    Operation           *op,  
    char                *dn,  
    char                *ndn,
    char                *mech,
    struct berval       *cred,
	char				**edn )
{
	struct berval response;
	const char *errstr;
	int sc;
	int rc = 1;

	Debug(LDAP_DEBUG_ARGS, "==> sasl_bind: dn=%s, mech=%s, cred->bv_len=%d\n",
		dn, mech, cred ? cred->bv_len : 0 );

	if ( conn->c_sasl_bind_context == NULL ) {
		sasl_callback_t callbacks[4];
		int cbnum = 0;

#if 0
		if (be->be_sasl_authorize) {
			callbacks[cbnum].id = SASL_CB_PROXY_POLICY;
			callbacks[cbnum].proc = be->be_sasl_authorize;
			callbacks[cbnum].context = be;
			++cbnum;
		}

		if (be->be_sasl_getsecret) {
			callbacks[cbnum].id = SASL_CB_SERVER_GETSECRET;
			callbacks[cbnum].proc = be->be_sasl_getsecret;
			callbacks[cbnum].context = be;
			++cbnum;
		}

		if (be->be_sasl_putsecret) {
			callbacks[cbnum].id = SASL_CB_SERVER_PUTSECRET;
			callbacks[cbnum].proc = be->be_sasl_putsecret;
			callbacks[cbnum].context = be;
			++cbnum;
		}
#endif

		callbacks[cbnum].id = SASL_CB_LIST_END;
		callbacks[cbnum].proc = NULL;
		callbacks[cbnum].context = NULL;

		/* create new SASL context */
		sc = sasl_server_new( "ldap", sasl_host, global_realm,
			callbacks, SASL_SECURITY_LAYER, &conn->c_sasl_bind_context );

		if( sc != SASL_OK ) {
			send_ldap_result( conn, op, rc = LDAP_AUTH_METHOD_NOT_SUPPORTED,
				NULL, NULL, NULL, NULL );
		} else {
			conn->c_authmech = ch_strdup( mech );
			sc = sasl_server_start( conn->c_sasl_bind_context, conn->c_authmech,
				cred->bv_val, cred->bv_len, (char **)&response.bv_val,
				(unsigned *)&response.bv_len, &errstr );
			if ( (sc != SASL_OK) && (sc != SASL_CONTINUE) ) {
				send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
					NULL, errstr, NULL, NULL );
			}
		}
	} else {
		sc = sasl_server_step( conn->c_sasl_bind_context, cred->bv_val, cred->bv_len,
			(char **)&response.bv_val, (unsigned *)&response.bv_len, &errstr );
		if ( (sc != SASL_OK) && (sc != SASL_CONTINUE) ) {
			send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
				NULL, errstr, NULL, NULL );
		}
	}

	if ( sc == SASL_OK ) {
		char *authzid;

		if ( ( sc = sasl_getprop( conn->c_sasl_bind_context, SASL_USERNAME,
			(void **)&authzid ) ) != SASL_OK ) {
			send_ldap_result( conn, op, rc = slap_sasl_err2ldap( sc ),
				NULL, NULL, NULL, NULL );

		} else {
			Debug(LDAP_DEBUG_TRACE, "<== sasl_bind: username=%s\n",
				authzid, 0, 0);

			if( strncasecmp( authzid, "anonymous", sizeof("anonyous")-1 ) &&
				( ( authzid[sizeof("anonymous")] == '\0' ) ||
				( authzid[sizeof("anonymous")] == '@' ) ) )
			{
				*edn = ch_malloc( sizeof( "authzid=" ) + strlen( authzid ) );
				strcpy( *edn, "authzid=" );
				strcat( *edn, authzid );
			}

			send_ldap_result( conn, op, rc = LDAP_SUCCESS,
				NULL, NULL, NULL, NULL );
		}

	} else if ( sc == SASL_CONTINUE ) {
		send_ldap_sasl( conn, op, rc = LDAP_SASL_BIND_IN_PROGRESS,
			NULL, NULL, NULL, NULL,  &response );
	} 

	if ( sc != SASL_CONTINUE && conn->c_sasl_bind_context != NULL ) {
		sasl_dispose( &conn->c_sasl_bind_context );
		conn->c_sasl_bind_context = NULL;
	}

	Debug(LDAP_DEBUG_TRACE, "<== sasl_bind: rc=%d\n", rc, 0, 0);

	return rc;
}
#endif /* HAVE_CYRUS_SASL */

#else
/* no SASL support */
int sasl_bind(
    Connection          *conn,
    Operation           *op,  
    char                *dn,  
    char                *ndn,
    char                *mech,
    struct berval       *cred,
	char				**edn )
{
	int rc;

	send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
		NULL, "SASL unavailable", NULL, NULL );

	return rc;
}

int sasl_init( void ) { return 0; }
int sasl_destroy( void ) { return 0; }
#endif
