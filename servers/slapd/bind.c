/* bind.c - decode an ldap bind operation and pass it to a backend db */

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

#include "slap.h"

void
do_bind(
    Connection	*conn,
    Operation	*op
)
{
	BerElement	*ber = op->o_ber;
	ber_int_t		version;
	ber_tag_t method;
	char		*mech;
	char		*cdn, *ndn;
	ber_tag_t	rc;
	struct berval	cred;
	Backend		*be;

	Debug( LDAP_DEBUG_TRACE, "do_bind\n", 0, 0, 0 );

	/*
	 * Parse the bind request.  It looks like this:
	 *
	 *	BindRequest ::= SEQUENCE {
	 *		version		INTEGER,		 -- version
	 *		name		DistinguishedName,	 -- dn
	 *		authentication	CHOICE {
	 *			simple		[0] OCTET STRING -- passwd
	 *			krbv42ldap	[1] OCTET STRING
	 *			krbv42dsa	[1] OCTET STRING
	 *		}
	 *	}
	 */

	rc = ber_scanf( ber, "{iat" /*}*/, &version, &cdn, &method );

	if ( rc == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "bind: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
		    "decoding error" );
		return;
	}

	mech = NULL;
	cred.bv_val = NULL;

	if( method != LDAP_AUTH_SASL ) {
		rc = ber_scanf( ber, /*{*/ "o}", &cred );

	} else {
		rc = ber_scanf( ber, "{a" /*}*/, &mech );

		if ( rc != LBER_ERROR ) {
			ber_len_t len;
			rc = ber_peek_tag( ber, &len );

			if ( rc == LDAP_TAG_LDAPCRED ) { 
				rc = ber_scanf( ber, "o", &cred );
			}

			if ( rc != LBER_ERROR ) {
				rc = ber_scanf( ber, /*{{*/ "}}" );
			}
		}
	}

	if ( rc == LBER_ERROR ) {
		if ( cdn != NULL ) {
			free( cdn );
		}
		if ( mech != NULL ) {
			free( mech );
		}
		if ( cred.bv_val != NULL ) {
			free( cred.bv_val );
		}

		Debug( LDAP_DEBUG_ANY, "bind: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
    		"decoding error" );

		return;
	}

#ifdef GET_CTRLS
	if( get_ctrls( conn, op, 1 ) == -1 ) {
		if ( cdn != NULL ) {
			free( cdn );
		}
		if ( mech != NULL ) {
			free( mech );
		}
		if ( cred.bv_val != NULL ) {
			free( cred.bv_val );
		}
		Debug( LDAP_DEBUG_ANY, "do_add: get_ctrls failed\n", 0, 0, 0 );
		return;
	} 
#endif

	Debug( LDAP_DEBUG_TRACE, "do_bind: version %d dn (%s) method %d\n",
	    version, cdn, method );

	ndn = dn_normalize_case( ch_strdup( cdn ) );

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d BIND dn=\"%s\" method=%d\n",
	    conn->c_connid, op->o_opid, ndn, method, 0 );

	if ( version < LDAP_VERSION_MIN || version > LDAP_VERSION_MAX ) {
		if ( cdn != NULL ) {
			free( cdn );
		}
		if ( ndn != NULL ) {
			free( ndn );
		}
		if ( mech != NULL ) {
			free( mech );
		}
		if ( cred.bv_val != NULL ) {
			free( cred.bv_val );
		}

		Debug( LDAP_DEBUG_ANY, "unknown version %d\n", version, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
		    "version not supported" );
		return;
	}

	/* accept null binds */
	if ( ndn == NULL || *ndn == '\0' ) {
		if ( cdn != NULL ) {
			free( cdn );
		}
		if ( ndn != NULL ) {
			free( ndn );
		}
		if ( mech != NULL ) {
			free( mech );
		}
		if ( cred.bv_val != NULL ) {
			free( cred.bv_val );
		}

		ldap_pvt_thread_mutex_lock( &conn->c_mutex );

		conn->c_protocol = version;

		if ( conn->c_cdn != NULL ) {
			free( conn->c_cdn );
			conn->c_cdn = NULL;
		}

		if ( conn->c_dn != NULL ) {
			free( conn->c_dn );
			conn->c_dn = NULL;
		}

		ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

		send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );
		return;
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */

	if ( (be = select_backend( ndn )) == NULL ) {
		free( cdn );
		free( ndn );
		if ( cred.bv_val != NULL ) {
			free( cred.bv_val );
		}
		if ( cred.bv_len == 0 ) {
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );

			conn->c_protocol = version;

			if ( conn->c_cdn != NULL ) {
				free( conn->c_cdn );
				conn->c_cdn = NULL;
			}

			if ( conn->c_dn != NULL ) {
				free( conn->c_dn );
				conn->c_dn = NULL;
			}

			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

			send_ldap_result( conn, op, LDAP_SUCCESS,
				NULL, NULL );
		} else if ( default_referral && *default_referral ) {
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS,
				NULL, default_referral );
		} else {
			send_ldap_result( conn, op, LDAP_INVALID_CREDENTIALS,
				NULL, default_referral );
		}
		return;
	}

	if ( be->be_bind ) {
		/* alias suffix */
		char *edn;

		ndn = suffixAlias( ndn, op, be );

		if ( (*be->be_bind)( be, conn, op, ndn, method, mech, &cred, &edn ) == 0 ) {
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );

			conn->c_protocol = version;

			if ( conn->c_cdn != NULL ) {
				free( conn->c_cdn );
			}

			conn->c_cdn = cdn;
			cdn = NULL;

			if ( conn->c_dn != NULL ) {
				free( conn->c_dn );
			}

			if(edn != NULL) {
				conn->c_dn = edn;
			} else {
				conn->c_dn = ndn;
				ndn = NULL;
			}

			Debug( LDAP_DEBUG_TRACE, "do_bind: bound \"%s\" to \"%s\"\n",
	    		conn->c_cdn, conn->c_dn, method );

			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

			/* send this here to avoid a race condition */
			send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL );

		} else if (edn != NULL) {
			free( edn );
		}

	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	if( cdn != NULL ) {
		free( cdn );
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
}
