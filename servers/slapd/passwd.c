/* bind.c - ldbm backend bind and unbind routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"

#include <lutil.h>

static int passwd_main(
	SLAP_EXTOP_CALLBACK_FN ext_callback,
	Connection *conn, Operation *op, char *oid,
	struct berval *reqdata, struct berval **rspdata, char **text )
{
	int rc;
	BerElement *ber;
	struct berval *cred = NULL;
	ber_int_t type;

	assert( oid != NULL );
	assert( strcmp( LDAP_EXOP_X_MODIFY_PASSWD, oid ) == 0 );

	if( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		*text = ch_strdup("only authenicated users may change passwords");
		return LDAP_STRONG_AUTH_REQUIRED;
	}

	if( reqdata == NULL || reqdata->bv_len == 0 ) {
		*text = ch_strdup("data missing");
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( reqdata );

	if( ber == NULL ) {
		*text = ch_strdup("password decoding error");
		return LDAP_PROTOCOL_ERROR;
	}

	rc = ber_scanf(ber, "{iO}", &type, &cred );
	ber_free( ber, 1 );

	if( rc == LBER_ERROR ) {
		*text = ch_strdup("data decoding error");
		return LDAP_PROTOCOL_ERROR;
	}

	if( cred == NULL || cred->bv_len == 0 ) {
		*text = ch_strdup("password missing");
		return LDAP_PROTOCOL_ERROR;
	}

	if( type != 0 ) {
		ber_bvfree( cred );
		*text = ch_strdup("password type unknown");
		return LDAP_PROTOCOL_ERROR;
	}

	if( conn->c_authz_backend != NULL &&
		conn->c_authz_backend->be_extended )
	{
		rc = conn->c_authz_backend->be_extended(
			conn->c_authz_backend,
			conn, op,
			oid, cred, rspdata, text );

	} else {
		*text = ch_strdup("operation not supported for current user");
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

	ber_bvfree( cred );
	return rc;
}

int
slap_passwd_init( void )
{
	return load_extop( LDAP_EXOP_X_MODIFY_PASSWD, passwd_main );
}

int
slap_passwd_check(
	Attribute *a,
	struct berval *cred )
{
	int     i;
	for ( i = 0; a->a_vals[i] != NULL; i++ ) {
		int result;

#ifdef SLAPD_CRYPT
		ldap_pvt_thread_mutex_lock( &crypt_mutex );
#endif

		result = lutil_passwd( a->a_vals[i], cred, NULL );

#ifdef SLAPD_CRYPT
		ldap_pvt_thread_mutex_unlock( &crypt_mutex );
#endif

		return result;
	}

	return( 1 );
}

struct berval * slap_passwd_generate(
	struct berval * cred )
{
	char* hash = default_passwd_hash ? default_passwd_hash : "{SSHA}";

	struct berval *new;

#ifdef SLAPD_CRYPT
	ldap_pvt_thread_mutex_lock( &crypt_mutex );
#endif

	new = lutil_passwd_generate( cred , hash );
	
#ifdef SLAPD_CRYPT
	ldap_pvt_thread_mutex_unlock( &crypt_mutex );
#endif

	return new;
}
