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

	assert( oid != NULL );
	assert( strcmp( LDAP_EXOP_X_MODIFY_PASSWD, oid ) == 0 );

	if( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		*text = ch_strdup("only authenicated users may change passwords");
		return LDAP_STRONG_AUTH_REQUIRED;
	}

	if( reqdata == NULL || reqdata->bv_len == 0 ) {
		*text = ch_strdup("request data missing");
		return LDAP_PROTOCOL_ERROR;
	}

	if( conn->c_authz_backend != NULL &&
		conn->c_authz_backend->be_extended )
	{
		rc = conn->c_authz_backend->be_extended(
			conn->c_authz_backend,
			conn, op, oid, reqdata, rspdata, text );

	} else {
		*text = ch_strdup("operation not supported for current user");
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

	return rc;
}

int slap_passwd_parse( struct berval *reqdata,
	struct berval **id,
	struct berval **old,
	struct berval **new,
	char **text )
{
	int rc = LDAP_SUCCESS;
	ber_tag_t tag;
	ber_len_t len;
	BerElement *ber;

	assert( reqdata != NULL );

	ber = ber_init( reqdata );

	if( ber == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ber_init failed\n",
			0, 0, 0 );
		*text = ch_strdup("password decoding error");
		return LDAP_PROTOCOL_ERROR;
	}

	tag = ber_scanf(ber, "{" /*}*/);

	if( tag == LBER_ERROR ) {
		goto decoding_error;
	}

	tag = ber_peek_tag( ber, &len );

	if( tag == LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID ) {
		if( id == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID not allowed.\n",
				0, 0, 0 );
			*text = "user must change own password";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "O", id );

		if( tag == LBER_ERROR ) {
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID parse failed.\n",
				0, 0, 0 );
			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len);
	}

	if( tag == LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD ) {
		if( old == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: OLD not allowed.\n",
				0, 0, 0 );
			*text = "use bind to verify old password";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "O", old );

		if( tag == LBER_ERROR ) {
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID parse failed.\n",
				0, 0, 0 );
			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len);
	}

	if( tag == LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW ) {
		if( new == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: NEW not allowed.\n",
				0, 0, 0 );
			*text = "user specified passwords disallowed";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "O", new );

		if( tag == LBER_ERROR ) {
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: OLD parse failed.\n",
				0, 0, 0 );
			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len );
	}

	if( len != 0 ) {
decoding_error:
		Debug( LDAP_DEBUG_TRACE,
			"slap_passwd_parse: decoding error, len=%ld\n",
			(long) len, 0, 0 );

		*text = ch_strdup("data decoding error");
		rc = LDAP_PROTOCOL_ERROR;
	}

done:
	if( rc != LDAP_SUCCESS ) {
		if( id != NULL ) {
			ber_bvfree( *id );
			*id = NULL;
		}

		if( old != NULL ) {
			ber_bvfree( *old );
			*old = NULL;
		}

		if( new != NULL ) {
			ber_bvfree( *new );
			*new = NULL;
		}
	}

	ber_free( ber, 1 );
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
