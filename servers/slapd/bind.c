/* bind.c - decode an ldap bind operation and pass it to a backend db */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "slap.h"

int
do_bind(
    Connection	*conn,
    Operation	*op
)
{
	BerElement	*ber = op->o_ber;
	ber_int_t		version;
	ber_tag_t method;
	char		*mech;
	char		*dn;
	char *ndn;
	ber_tag_t	tag;
	int			rc = LDAP_SUCCESS;
	char	*text;
	struct berval	cred;
	Backend		*be;

	Debug( LDAP_DEBUG_TRACE, "do_bind\n", 0, 0, 0 );

	dn = NULL;
	ndn = NULL;
	mech = NULL;
	cred.bv_val = NULL;

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	/*
	 * Force to connection to "anonymous" until bind succeeds.
	 */

	if ( conn->c_cdn != NULL ) {
		free( conn->c_cdn );
		conn->c_cdn = NULL;
	}

	if ( conn->c_dn != NULL ) {
		free( conn->c_dn );
		conn->c_dn = NULL;
	}

	conn->c_authc_backend = NULL;
	conn->c_authz_backend = NULL;

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	if ( op->o_dn != NULL ) {
		free( op->o_dn );
		op->o_dn = ch_strdup( "" );
	}

	if ( op->o_ndn != NULL ) {
		free( op->o_ndn );
		op->o_ndn = ch_strdup( "" );
	}

	/*
	 * Parse the bind request.  It looks like this:
	 *
	 *	BindRequest ::= SEQUENCE {
	 *		version		INTEGER,		 -- version
	 *		name		DistinguishedName,	 -- dn
	 *		authentication	CHOICE {
	 *			simple		[0] OCTET STRING -- passwd
	 *			krbv42ldap	[1] OCTET STRING
	 *			krbv42dsa	[2] OCTET STRING
	 *			SASL		[3] SaslCredentials
	 *		}
	 *	}
	 *
	 *	SaslCredentials ::= SEQUENCE {
     *		mechanism           LDAPString,
     *		credentials         OCTET STRING OPTIONAL
	 *	}
	 */

	tag = ber_scanf( ber, "{iat" /*}*/, &version, &dn, &method );

	if ( tag == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "bind: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto cleanup;
	}

	op->o_protocol = version;

	if( method != LDAP_AUTH_SASL ) {
		tag = ber_scanf( ber, /*{*/ "o}", &cred );

	} else {
		tag = ber_scanf( ber, "{a" /*}*/, &mech );

		if ( tag != LBER_ERROR ) {
			ber_len_t len;
			tag = ber_peek_tag( ber, &len );

			if ( tag == LDAP_TAG_LDAPCRED ) { 
				tag = ber_scanf( ber, "o", &cred );
			}

			if ( tag != LBER_ERROR ) {
				tag = ber_scanf( ber, /*{{*/ "}}" );
			}
		}
	}

	if ( tag == LBER_ERROR ) {
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR,
    		"decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_bind: get_ctrls failed\n", 0, 0, 0 );
		goto cleanup;
	} 

	ndn = ch_strdup( dn );

	if ( dn_normalize( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "bind: invalid dn (%s)\n", dn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	if( method == LDAP_AUTH_SASL ) {
		Debug( LDAP_DEBUG_TRACE, "do_sasl_bind: dn (%s) mech %s\n",
			dn, mech, NULL );
	} else {
		Debug( LDAP_DEBUG_TRACE, "do_bind: version=%ld dn=\"%s\" method=%ld\n",
			(unsigned long) version, dn, (unsigned long) method );
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d BIND dn=\"%s\" method=%ld\n",
	    op->o_connid, op->o_opid, ndn, (unsigned long) method, 0 );

	if ( version < LDAP_VERSION_MIN || version > LDAP_VERSION_MAX ) {
		Debug( LDAP_DEBUG_ANY, "do_bind: unknown version=%ld\n",
			(unsigned long) version, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "requested protocol version not supported", NULL, NULL );
		goto cleanup;
	}

	/* we set connection version regardless of whether bind succeeds
	 * or not.
	 */
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );
	conn->c_protocol = version;
	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	if ( method == LDAP_AUTH_SASL ) {
		char *edn;

		if ( version < LDAP_VERSION3 ) {
			Debug( LDAP_DEBUG_ANY, "do_bind: sasl with LDAPv%ld\n",
				(unsigned long) version, 0, 0 );
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "SASL bind requires LDAPv3" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}

		if( mech == NULL || *mech == '\0' ) {
			Debug( LDAP_DEBUG_ANY,
				"do_bind: no sasl mechanism provided\n",
				0, 0, 0 );
			send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
				NULL, "no SASL mechanism provided", NULL, NULL );
			goto cleanup;
		}

		if( !charray_inlist( supportedSASLMechanisms, mech ) ) {
			Debug( LDAP_DEBUG_ANY,
				"do_bind: sasl mechanism=\"%s\" not supported.\n",
				mech, 0, 0 );
			send_ldap_result( conn, op, rc = LDAP_AUTH_METHOD_NOT_SUPPORTED,
				NULL, "SASL mechanism not supported", NULL, NULL );
			goto cleanup;
		}

		ldap_pvt_thread_mutex_lock( &conn->c_mutex );

		if ( conn->c_sasl_bind_mech != NULL ) {
			if((strcmp(conn->c_sasl_bind_mech, mech) != 0)) {
				/* mechanism changed, cancel in progress bind */
#ifdef HAVE_CYRUS_SASL
				sasl_dispose(&conn->c_sasl_bind_context);
				conn->c_sasl_bind_context = NULL;
#endif
			}
			free( conn->c_sasl_bind_mech );
			conn->c_sasl_bind_mech = NULL;

#ifdef LDAP_DEBUG
#ifdef HAVE_CYRUS_SASL
		} else {
			assert( conn->c_sasl_bind_context == NULL );
#endif
#endif
		}

		ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

		edn = NULL;
		rc = sasl_bind( conn, op, dn, ndn, mech, &cred, &edn );

		if( rc == LDAP_SUCCESS && edn != NULL ) {
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );
#ifdef HAVE_CYRUS_SASL
			assert( conn->c_sasl_bind_context == NULL );
#endif
			conn->c_dn = edn;
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

		} else if ( rc == LDAP_SASL_BIND_IN_PROGRESS ) {
#ifdef HAVE_CYRUS_SASL
			assert( conn->c_sasl_bind_context != NULL );
#endif
			conn->c_sasl_bind_mech = mech;
			mech = NULL;

#ifdef HAVE_CYRUS_SASL
		} else {
			assert( conn->c_sasl_bind_context != NULL );
#endif
		}

		goto cleanup;

	} else {
		/* Not SASL, cancel any in-progress bind */
		ldap_pvt_thread_mutex_lock( &conn->c_mutex );

		if ( conn->c_sasl_bind_mech != NULL ) {
			assert( conn->c_sasl_bind_in_progress );

			free(conn->c_sasl_bind_mech);
			conn->c_sasl_bind_mech = NULL;

#ifdef HAVE_CYRUS_SASL
			assert( conn->c_sasl_bind_context != NULL );
			sasl_dispose(&conn->c_sasl_bind_context);
			conn->c_sasl_bind_context = NULL;
#endif
		} else {
			assert( !conn->c_sasl_bind_in_progress );
#ifdef HAVE_CYRUS_SASL
			assert( conn->c_sasl_bind_context == NULL );
#endif
		}

		ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
	}

	/* accept "anonymous" binds */
	if ( cred.bv_len == 0 || ndn == NULL || *ndn == '\0' ) {
		/*
		 * we already forced connection to "anonymous",
		 * just need to send success
		 */
		send_ldap_result( conn, op, LDAP_SUCCESS,
			NULL, NULL, NULL, NULL );
		Debug( LDAP_DEBUG_TRACE, "do_bind: v%d anonymous bind\n",
	   		version, 0, 0 );
		goto cleanup;
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */

	if ( (be = select_backend( ndn )) == NULL ) {
		if ( default_referral ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				NULL, NULL, default_referral, NULL );

		} else {
			/* noSuchObject is not allowed to be returned by bind */
			send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
				NULL, NULL, NULL, NULL );
		}

		goto cleanup;
	}

	conn->c_authz_backend = be;

	/* make sure this backend recongizes critical controls */
	rc = backend_check_controls( be, conn, op, &text ) ;

	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto cleanup;
	}

	if ( be->be_bind ) {
		int ret;
		/* alias suffix */
		char *edn = NULL;

		/* deref suffix alias if appropriate */
		ndn = suffix_alias( be, ndn );

		ret = (*be->be_bind)( be, conn, op, dn, ndn,
			method, mech, &cred, &edn );

		if ( ret == 0 ) {
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );

			conn->c_cdn = dn;
			dn = NULL;

			if(edn != NULL) {
				conn->c_dn = edn;
			} else {
				conn->c_dn = ndn;
				ndn = NULL;
			}

			Debug( LDAP_DEBUG_TRACE, "do_bind: v%d bind: \"%s\" to \"%s\"\n",
	    		version, conn->c_cdn, conn->c_dn );

			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

			/* send this here to avoid a race condition */
			send_ldap_result( conn, op, LDAP_SUCCESS,
				NULL, NULL, NULL, NULL );

		} else if (edn != NULL) {
			free( edn );
		}

	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "bind function not implemented", NULL, NULL );
	}

cleanup:
	if( dn != NULL ) {
		free( dn );
	}
	if( ndn != NULL ) {
		free( ndn );
	}
	if ( mech != NULL ) {
		free( mech );
	}
	if ( cred.bv_val != NULL ) {
		free( cred.bv_val );
	}

	return rc;
}
