/* bind.c - ldbm backend bind and unbind routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"

#include <lber_pvt.h>
#include <lutil.h>

int passwd_extop(
	Operation *op,
	SlapReply *rs )
{
	assert( ber_bvcmp( &slap_EXOP_MODIFY_PASSWD, &op->ore_reqoid ) == 0 );

	if( op->o_dn.bv_len == 0 ) {
		rs->sr_text = "only authenticated users may change passwords";
		return LDAP_STRONG_AUTH_REQUIRED;
	}

	ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
	op->o_bd = op->o_conn->c_authz_backend;
	ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );

	if( op->o_bd && !op->o_bd->be_extended ) {
		rs->sr_text = "operation not supported for current user";
		return LDAP_UNWILLING_TO_PERFORM;
	}

	if (backend_check_restrictions( op, rs,
			(struct berval *)&slap_EXOP_MODIFY_PASSWD ) != LDAP_SUCCESS) {
		return rs->sr_err;
	}

	if( op->o_bd == NULL ) {
#ifdef HAVE_CYRUS_SASL
		rs->sr_err = slap_sasl_setpass( op, rs );
#else
		rs->sr_text = "no authz backend";
		rs->sr_err = LDAP_OTHER;
#endif

#ifndef SLAPD_MULTIMASTER
	/* This does not apply to multi-master case */
	} else if( op->o_bd->be_update_ndn.bv_len ) {
		/* we SHOULD return a referral in this case */
		BerVarray defref = NULL;
		if ( op->o_bd->be_syncinfo ) {
			defref = op->o_bd->be_syncinfo->si_provideruri_bv;
		} else {
			defref = referral_rewrite( op->o_bd->be_update_refs,
				NULL, NULL, LDAP_SCOPE_DEFAULT );
		}
		rs->sr_ref = defref;
		rs->sr_err = LDAP_REFERRAL;
#endif /* !SLAPD_MULTIMASTER */

	} else {
		rs->sr_err = op->o_bd->be_extended( op, rs );
	}

	return rs->sr_err;
}

int slap_passwd_parse( struct berval *reqdata,
	struct berval *id,
	struct berval *oldpass,
	struct berval *newpass,
	const char **text )
{
	int rc = LDAP_SUCCESS;
	ber_tag_t tag;
	ber_len_t len;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	if( reqdata == NULL ) {
		return LDAP_SUCCESS;
	}

	if( reqdata->bv_len == 0 ) {
		*text = "empty request data field";
		return LDAP_PROTOCOL_ERROR;
	}

	/* ber_init2 uses reqdata directly, doesn't allocate new buffers */
	ber_init2( ber, reqdata, 0 );

	tag = ber_scanf( ber, "{" /*}*/ );

	if( tag != LBER_ERROR ) {
		tag = ber_peek_tag( ber, &len );
	}

	if( tag == LDAP_TAG_EXOP_MODIFY_PASSWD_ID ) {
		if( id == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "slap_passwd_parse: ID not allowed.\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID not allowed.\n",
				0, 0, 0 );
#endif

			*text = "user must change own password";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "m", id );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "slap_passwd_parse:  ID parse failed.\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID parse failed.\n",
				0, 0, 0 );
#endif

			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len);
	}

	if( tag == LDAP_TAG_EXOP_MODIFY_PASSWD_OLD ) {
		if( oldpass == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "slap_passwd_parse: OLD not allowed.\n" , 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: OLD not allowed.\n",
				0, 0, 0 );
#endif

			*text = "use bind to verify old password";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "m", oldpass );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "slap_passwd_parse:  ID parse failed.\n" , 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: ID parse failed.\n",
				0, 0, 0 );
#endif

			goto decoding_error;
		}

		tag = ber_peek_tag( ber, &len );
	}

	if( tag == LDAP_TAG_EXOP_MODIFY_PASSWD_NEW ) {
		if( newpass == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "slap_passwd_parse:  NEW not allowed.\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "slap_passwd_parse: NEW not allowed.\n",
				0, 0, 0 );
#endif

			*text = "user specified passwords disallowed";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

		tag = ber_scanf( ber, "m", newpass );

		if( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR,
			   "slap_passwd_parse:  OLD parse failed.\n", 0, 0, 0 );
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
		LDAP_LOG( OPERATION, ERR, 
			"slap_passwd_parse: decoding error, len=%ld\n", (long)len, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_passwd_parse: decoding error, len=%ld\n",
			(long) len, 0, 0 );
#endif

		*text = "data decoding error";
		rc = LDAP_PROTOCOL_ERROR;
	}

done:
	return rc;
}

struct berval * slap_passwd_return(
	struct berval		*cred )
{
	int rc;
	struct berval *bv = NULL;
	BerElementBuffer berbuf;
	/* opaque structure, size unknown but smaller than berbuf */
	BerElement *ber = (BerElement *)&berbuf;

	assert( cred != NULL );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"slap_passwd_return: %ld\n",(long)cred->bv_len, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "slap_passwd_return: %ld\n",
		(long) cred->bv_len, 0, 0 );
#endif
	
	ber_init_w_nullc( ber, LBER_USE_DER );

	rc = ber_printf( ber, "{tON}",
		LDAP_TAG_EXOP_MODIFY_PASSWD_GEN, cred );

	if( rc >= 0 ) {
		(void) ber_flatten( ber, &bv );
	}

	ber_free_buf( ber );

	return bv;
}

int
slap_passwd_check(
	Connection *conn,
	Attribute *a,
	struct berval *cred,
	const char **text )
{
	int result = 1;
	struct berval *bv;

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_lock( &passwd_mutex );
#ifdef SLAPD_SPASSWD
	lutil_passwd_sasl_conn = conn->c_sasl_authctx;
#endif
#endif

	for ( bv = a->a_vals; bv->bv_val != NULL; bv++ ) {
		if( !lutil_passwd( bv, cred, NULL, text ) ) {
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

void
slap_passwd_generate( struct berval *pass )
{
	struct berval *tmp;
#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "slap_passwd_generate: begin\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "slap_passwd_generate\n", 0, 0, 0 );
#endif
	/*
	 * generate passwords of only 8 characters as some getpass(3)
	 * implementations truncate at 8 characters.
	 */
	tmp = lutil_passwd_generate( 8 );
	if (tmp) {
		*pass = *tmp;
		free(tmp);
	} else {
		pass->bv_val = NULL;
		pass->bv_len = 0;
	}
}

void
slap_passwd_hash(
	struct berval * cred,
	struct berval * new,
	const char **text )
{
	struct berval *tmp;
#ifdef LUTIL_SHA1_BYTES
	char* hash = default_passwd_hash ?  default_passwd_hash : "{SSHA}";
#else
	char* hash = default_passwd_hash ?  default_passwd_hash : "{SMD5}";
#endif
	

#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_lock( &passwd_mutex );
#endif

	tmp = lutil_passwd_hash( cred , hash, text );
	
#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
	ldap_pvt_thread_mutex_unlock( &passwd_mutex );
#endif

	if( tmp == NULL ) {
		new->bv_len = 0;
		new->bv_val = NULL;
	}

	*new = *tmp;
	free( tmp );
	return;
}
