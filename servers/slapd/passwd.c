/* bind.c - ldbm backend bind and unbind routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

int passwd_extop(
	Connection *conn, Operation *op,
	const char *reqoid,
	struct berval *reqdata,
	char **rspoid,
	struct berval **rspdata,
	LDAPControl ***rspctrls,
	const char **text,
	struct berval ***refs )
{
	int rc;

	assert( reqoid != NULL );
	assert( strcmp( LDAP_EXOP_X_MODIFY_PASSWD, reqoid ) == 0 );

	if( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		*text = "only authenicated users may change passwords";
		return LDAP_STRONG_AUTH_REQUIRED;
	}

	if( conn->c_authz_backend != NULL && conn->c_authz_backend->be_extended ) {
		if( conn->c_authz_backend->be_restrictops & SLAP_RESTRICT_OP_MODIFY ) {
			*text = "authorization database is read only";
			rc = LDAP_UNWILLING_TO_PERFORM;

		} else if( conn->c_authz_backend->be_update_ndn != NULL ) {
			/* we SHOULD return a referral in this case */
			*refs = conn->c_authz_backend->be_update_refs;
			rc = LDAP_REFERRAL;

		} else {
			rc = conn->c_authz_backend->be_extended(
				conn->c_authz_backend, conn, op,
				reqoid, reqdata,
				rspoid, rspdata, rspctrls,
				text, refs );
		}

	} else {
		*text = "operation not supported for current user";
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

	return rc;
}

int slap_passwd_parse( struct berval *reqdata,
	struct berval **id,
	struct berval **oldpass,
	struct berval **newpass,
	const char **text )
{
	int rc = LDAP_SUCCESS;
	ber_tag_t tag;
	ber_len_t len;
	BerElement *ber;

	if( reqdata == NULL ) {
		return LDAP_SUCCESS;
	}

	ber = ber_init( reqdata );

	if( ber == NULL ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "slap_passwd_parse: ber_init failed\n" ));
#else
		Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ber_init failed\n",
			0, 0, 0 );
#endif

		*text = "password decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	tag = ber_scanf( ber, "{" /*}*/ );

	if( tag != LBER_ERROR ) {
		tag = ber_peek_tag( ber, &len );
	}

	if( tag == LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID ) {
		if( id == NULL ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "slap_passwd_parse: ID not allowed.\n"));
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID not allowed.\n",
				0, 0, 0 );
#endif

			*text = "user must change own password";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "O", id );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "slap_passwd_parse:  ID parse failed.\n"));
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID parse failed.\n",
				0, 0, 0 );
#endif

			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len);
	}

	if( tag == LDAP_TAG_EXOP_X_MODIFY_PASSWD_OLD ) {
		if( oldpass == NULL ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "slap_passwd_parse: OLD not allowed.\n" ));
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: OLD not allowed.\n",
				0, 0, 0 );
#endif

			*text = "use bind to verify old password";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "O", oldpass );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "slap_passwd_parse:  ID parse failed.\n" ));
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID parse failed.\n",
				0, 0, 0 );
#endif

			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len);
	}

	if( tag == LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW ) {
		if( newpass == NULL ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "slap_passwd_parse:  NEW not allowed.\n" ));
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: NEW not allowed.\n",
				0, 0, 0 );
#endif

			*text = "user specified passwords disallowed";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "O", newpass );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "slap_passwd_parse:  OLD parse failed.\n"));
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: OLD parse failed.\n",
				0, 0, 0 );
#endif

			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len );
	}

	if( len != 0 ) {
decoding_error:
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "slap_passwd_parse: decoding error, len=%ld\n", (long)len ));
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_passwd_parse: decoding error, len=%ld\n",
			(long) len, 0, 0 );
#endif


		*text = "data decoding error";
		rc = LDAP_PROTOCOL_ERROR;
	}

done:
	if( rc != LDAP_SUCCESS ) {
		if( id != NULL ) {
			ber_bvfree( *id );
			*id = NULL;
		}

		if( oldpass != NULL ) {
			ber_bvfree( *oldpass );
			*oldpass = NULL;
		}

		if( newpass != NULL ) {
			ber_bvfree( *newpass );
			*newpass = NULL;
		}
	}

	ber_free( ber, 1 );
	return rc;
}

struct berval * slap_passwd_return(
	struct berval		*cred )
{
	int rc;
	struct berval *bv;
	BerElement *ber = ber_alloc_t(LBER_USE_DER);

	assert( cred != NULL );

#ifdef NEW_LOGGING
        LDAP_LOG(( "operation", LDAP_LEVEL_ENTRY,
                   "slap_passwd_return: %ld\n",(long)cred->bv_len ));
#else
	Debug( LDAP_DEBUG_TRACE, "slap_passwd_return: %ld\n",
		(long) cred->bv_len, 0, 0 );
#endif


	if( ber == NULL ) return NULL;
	
	rc = ber_printf( ber, "{tON}",
		LDAP_TAG_EXOP_X_MODIFY_PASSWD_GEN, cred );

	if( rc == -1 ) {
		ber_free( ber, 1 );
		return NULL;
	}

	(void) ber_flatten( ber, &bv );

	ber_free( ber, 1 );

	return bv;
}

int
slap_passwd_check(
	Connection *conn,
	Attribute *a,
	struct berval *cred )
{
	int     i;
	int result = 1;

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_lock( &passwd_mutex );
#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = conn->c_sasl_context;
#endif
#endif

	for ( i = 0; a->a_vals[i] != NULL; i++ ) {
		if( !lutil_passwd( a->a_vals[i], cred, NULL ) ) {
			result = 0;
			break;
		}
	}

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = NULL;
#endif
	ldap_pvt_thread_mutex_unlock( &passwd_mutex );
#endif

	return result;
}

struct berval * slap_passwd_generate( void )
{
#ifdef NEW_LOGGING
    LDAP_LOG(( "operation", LDAP_LEVEL_ENTRY,
               "slap_passwd_generate: begin\n" ));
#else
	Debug( LDAP_DEBUG_TRACE, "slap_passwd_generate\n", 0, 0, 0 );
#endif


	/*
	 * generate passwords of only 8 characters as some getpass(3)
	 * implementations truncate at 8 characters.
	 */
	return lutil_passwd_generate( 8 );
}

struct berval * slap_passwd_hash(
	struct berval * cred )
{
	char* hash = default_passwd_hash ? default_passwd_hash : "{SSHA}";

	struct berval *new;

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_lock( &passwd_mutex );
#endif

	new = lutil_passwd_hash( cred , hash );
	
#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_unlock( &passwd_mutex );
#endif

	return new;
}
