/* bind.c - decode an ldap bind operation and pass it to a backend db */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
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
#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif


int
do_bind(
    Operation	*op,
    SlapReply	*rs )
{
	BerElement *ber = op->o_ber;
	ber_int_t version;
	ber_tag_t method;
	struct berval mech = BER_BVNULL;
	struct berval dn = BER_BVNULL;
	ber_tag_t tag;
	Backend *be = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_bind: conn %d\n", op->o_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_bind\n", 0, 0, 0 );
#endif

	/*
	 * Force to connection to "anonymous" until bind succeeds.
	 */
	ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
	if ( op->o_conn->c_sasl_bind_in_progress ) {
		be = op->o_conn->c_authz_backend;
	}
	if ( op->o_conn->c_dn.bv_len ) {
		/* log authorization identity demotion */
		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu op=%lu BIND anonymous mech=implicit ssf=0\n",
			op->o_connid, op->o_opid, 0, 0, 0 );
	}
	connection2anonymous( op->o_conn );
	if ( op->o_conn->c_sasl_bind_in_progress ) {
		op->o_conn->c_authz_backend = be;
	}
	ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );
	if ( op->o_dn.bv_val != NULL ) {
		free( op->o_dn.bv_val );
		op->o_dn.bv_val = ch_strdup( "" );
		op->o_dn.bv_len = 0;
	}
	if ( op->o_ndn.bv_val != NULL ) {
		free( op->o_ndn.bv_val );
		op->o_ndn.bv_val = ch_strdup( "" );
		op->o_ndn.bv_len = 0;
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
	 *		mechanism	    LDAPString,
	 *		credentials	    OCTET STRING OPTIONAL
	 *	}
	 */

	tag = ber_scanf( ber, "{imt" /*}*/, &version, &dn, &method );

	if ( tag == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_bind: conn %d  ber_scanf failed\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "bind: ber_scanf failed\n", 0, 0, 0 );
#endif
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto cleanup;
	}

	op->o_protocol = version;
	op->orb_method = method;

	if( op->orb_method != LDAP_AUTH_SASL ) {
		tag = ber_scanf( ber, /*{*/ "m}", &op->orb_cred );

	} else {
		tag = ber_scanf( ber, "{m" /*}*/, &mech );

		if ( tag != LBER_ERROR ) {
			ber_len_t len;
			tag = ber_peek_tag( ber, &len );

			if ( tag == LDAP_TAG_LDAPCRED ) { 
				tag = ber_scanf( ber, "m", &op->orb_cred );
			} else {
				tag = LDAP_TAG_LDAPCRED;
				op->orb_cred.bv_val = NULL;
				op->orb_cred.bv_len = 0;
			}

			if ( tag != LBER_ERROR ) {
				tag = ber_scanf( ber, /*{{*/ "}}" );
			}
		}
	}

	if ( tag == LBER_ERROR ) {
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		rs->sr_err = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_bind: conn %d  get_ctrls failed\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_bind: get_ctrls failed\n", 0, 0, 0 );
#endif
		goto cleanup;
	} 

	/* We use the tmpmemctx here because it speeds up normalization.
	 * However, we must dup with regular malloc when storing any
	 * resulting DNs in the op or conn structures.
	 */
	rs->sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn,
		op->o_tmpmemctx );
	if ( rs->sr_err != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_bind: conn %d  invalid dn (%s)\n", 
			op->o_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "bind: invalid dn (%s)\n",
			dn.bv_val, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_INVALID_DN_SYNTAX, "invalid DN" );
		goto cleanup;
	}

	if( op->orb_method == LDAP_AUTH_SASL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION,	 DETAIL1, 
			"do_sasl_bind: conn %d  dn (%s) mech %s\n", 
			op->o_connid, op->o_req_dn.bv_val, mech.bv_val );
#else
		Debug( LDAP_DEBUG_TRACE, "do_sasl_bind: dn (%s) mech %s\n",
			op->o_req_dn.bv_val, mech.bv_val, NULL );
#endif

	} else {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, DETAIL1, 
			"do_bind: version=%ld dn=\"%s\" method=%ld\n",
			(unsigned long) version, op->o_req_dn.bv_val,
			(unsigned long) op->orb_method );
#else
		Debug( LDAP_DEBUG_TRACE,
			"do_bind: version=%ld dn=\"%s\" method=%ld\n",
			(unsigned long) version, op->o_req_dn.bv_val,
			(unsigned long) op->orb_method );
#endif
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu BIND dn=\"%s\" method=%ld\n",
	    op->o_connid, op->o_opid, op->o_req_dn.bv_val,
		(unsigned long) op->orb_method, 0 );

	if ( version < LDAP_VERSION_MIN || version > LDAP_VERSION_MAX ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_bind: conn %d  unknown version = %ld\n",
			op->o_connid, (unsigned long)version, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_bind: unknown version=%ld\n",
			(unsigned long) version, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
			"requested protocol version not supported" );
		goto cleanup;

	} else if (!( global_allows & SLAP_ALLOW_BIND_V2 ) &&
		version < LDAP_VERSION3 )
	{
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
			"historical protocol version requested, use LDAPv3 instead" );
		goto cleanup;
	}

	/*
	 * we set connection version regardless of whether bind succeeds or not.
	 */
	ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
	op->o_conn->c_protocol = version;
	ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );

	/* check for inappropriate controls */
	if( get_manageDSAit( op ) == SLAP_CRITICAL_CONTROL ) {
		send_ldap_error( op, rs,
			LDAP_UNAVAILABLE_CRITICAL_EXTENSION,
			"manageDSAit control inappropriate" );
		goto cleanup;
	}

	/* Set the bindop for the benefit of in-directory SASL lookups */
	op->o_conn->c_sasl_bindop = op;

	if ( op->orb_method == LDAP_AUTH_SASL ) {
		if ( version < LDAP_VERSION3 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				"do_bind: conn %d  sasl with LDAPv%ld\n",
				op->o_connid, (unsigned long)version , 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_bind: sasl with LDAPv%ld\n",
				(unsigned long) version, 0, 0 );
#endif
			send_ldap_discon( op, rs,
				LDAP_PROTOCOL_ERROR, "SASL bind requires LDAPv3" );
			rs->sr_err = SLAPD_DISCONNECT;
			goto cleanup;
		}

		if( mech.bv_len == 0 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				   "do_bind: conn %d  no SASL mechanism provided\n",
				   op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"do_bind: no sasl mechanism provided\n",
				0, 0, 0 );
#endif
			send_ldap_error( op, rs, LDAP_AUTH_METHOD_NOT_SUPPORTED,
				"no SASL mechanism provided" );
			goto cleanup;
		}

		/* check restrictions */
		if( backend_check_restrictions( op, rs, &mech ) != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
			goto cleanup;
		}

		ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
		if ( op->o_conn->c_sasl_bind_in_progress ) {
			if( !bvmatch( &op->o_conn->c_sasl_bind_mech, &mech ) ) {
				/* mechanism changed between bind steps */
				slap_sasl_reset(op->o_conn);
			}
		} else {
			ber_dupbv(&op->o_conn->c_sasl_bind_mech, &mech);
		}
		ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );

		rs->sr_err = slap_sasl_bind( op, rs );

		ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
		if( rs->sr_err == LDAP_SUCCESS ) {
			ber_dupbv(&op->o_conn->c_dn, &op->orb_edn);
			if( op->orb_edn.bv_len != 0 ) {
				/* edn is always normalized already */
				ber_dupbv( &op->o_conn->c_ndn, &op->o_conn->c_dn );
			}
			op->o_tmpfree( op->orb_edn.bv_val, op->o_tmpmemctx );
			BER_BVZERO( &op->orb_edn );
			op->o_conn->c_authmech = op->o_conn->c_sasl_bind_mech;
			BER_BVZERO( &op->o_conn->c_sasl_bind_mech );
			op->o_conn->c_sasl_bind_in_progress = 0;

			op->o_conn->c_sasl_ssf = op->orb_ssf;
			if( op->orb_ssf > op->o_conn->c_ssf ) {
				op->o_conn->c_ssf = op->orb_ssf;
			}

			if( op->o_conn->c_dn.bv_len != 0 ) {
				ber_len_t max = sockbuf_max_incoming_auth;
				ber_sockbuf_ctrl( op->o_conn->c_sb,
					LBER_SB_OPT_SET_MAX_INCOMING, &max );
			}

			/* log authorization identity */
			Statslog( LDAP_DEBUG_STATS,
				"conn=%lu op=%lu BIND dn=\"%s\" mech=%s ssf=%d\n",
				op->o_connid, op->o_opid,
				op->o_conn->c_dn.bv_val ? op->o_conn->c_dn.bv_val : "<empty>",
				op->o_conn->c_authmech.bv_val, op->orb_ssf );

#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, DETAIL1, 
				"do_bind: SASL/%s bind: dn=\"%s\" ssf=%d\n",
				op->o_conn->c_authmech.bv_val,
				op->o_conn->c_dn.bv_val ? op->o_conn->c_dn.bv_val : "<empty>",
				op->orb_ssf );
#else
			Debug( LDAP_DEBUG_TRACE,
				"do_bind: SASL/%s bind: dn=\"%s\" ssf=%d\n",
				op->o_conn->c_authmech.bv_val,
				op->o_conn->c_dn.bv_val ? op->o_conn->c_dn.bv_val : "<empty>",
				op->orb_ssf );
#endif

		} else if ( rs->sr_err == LDAP_SASL_BIND_IN_PROGRESS ) {
			op->o_conn->c_sasl_bind_in_progress = 1;

		} else {
			if ( op->o_conn->c_sasl_bind_mech.bv_val ) {
				free( op->o_conn->c_sasl_bind_mech.bv_val );
				op->o_conn->c_sasl_bind_mech.bv_val = NULL;
				op->o_conn->c_sasl_bind_mech.bv_len = 0;
			}
			op->o_conn->c_sasl_bind_in_progress = 0;
		}

#ifdef LDAP_SLAPI
#define	pb	op->o_pb
		/*
		 * Normally post-operation plugins are called only after the
		 * backend operation. Because the front-end performs SASL
		 * binds on behalf of the backend, we'll make a special
		 * exception to call the post-operation plugins after a
		 * SASL bind.
		 */
		if ( pb ) {
			slapi_int_pblock_set_operation( pb, op );
			slapi_pblock_set( pb, SLAPI_BIND_TARGET, (void *)dn.bv_val );
			slapi_pblock_set( pb, SLAPI_BIND_METHOD, (void *)op->orb_method );
			slapi_pblock_set( pb, SLAPI_BIND_CREDENTIALS, (void *)&op->orb_cred );
			slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)(0) );
			(void) slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_POST_BIND_FN, pb );
		}
#endif /* LDAP_SLAPI */

		ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );

		goto cleanup;

	} else {
		/* Not SASL, cancel any in-progress bind */
		ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );

		if ( op->o_conn->c_sasl_bind_mech.bv_val != NULL ) {
			free(op->o_conn->c_sasl_bind_mech.bv_val);
			op->o_conn->c_sasl_bind_mech.bv_val = NULL;
			op->o_conn->c_sasl_bind_mech.bv_len = 0;
		}
		op->o_conn->c_sasl_bind_in_progress = 0;

		slap_sasl_reset( op->o_conn );
		ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );
	}

	if ( op->orb_method == LDAP_AUTH_SIMPLE ) {
		ber_str2bv( "SIMPLE", sizeof("SIMPLE")-1, 0, &mech );
		/* accept "anonymous" binds */
		if ( op->orb_cred.bv_len == 0 || op->o_req_ndn.bv_len == 0 ) {
			rs->sr_err = LDAP_SUCCESS;

			if( op->orb_cred.bv_len &&
				!( global_allows & SLAP_ALLOW_BIND_ANON_CRED ))
			{
				/* cred is not empty, disallow */
				rs->sr_err = LDAP_INVALID_CREDENTIALS;

			} else if ( op->o_req_ndn.bv_len &&
				!( global_allows & SLAP_ALLOW_BIND_ANON_DN ))
			{
				/* DN is not empty, disallow */
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				rs->sr_text =
					"unauthenticated bind (DN with no password) disallowed";

			} else if ( global_disallows & SLAP_DISALLOW_BIND_ANON ) {
				/* disallow */
				rs->sr_err = LDAP_INAPPROPRIATE_AUTH;
				rs->sr_text = "anonymous bind disallowed";

			} else {
				backend_check_restrictions( op, rs, &mech );
			}

			/*
			 * we already forced connection to "anonymous",
			 * just need to send success
			 */
			send_ldap_result( op, rs );
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, DETAIL1, 
				"do_bind: conn %d  v%d anonymous bind\n",
				op->o_connid, version , 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "do_bind: v%d anonymous bind\n",
				version, 0, 0 );
#endif
			goto cleanup;

		} else if ( global_disallows & SLAP_DISALLOW_BIND_SIMPLE ) {
			/* disallow simple authentication */
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "unwilling to perform simple authentication";

			send_ldap_result( op, rs );
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, INFO, 
				"do_bind: conn %d  v%d simple bind(%s) disallowed\n",
				op->o_connid, version, op->o_req_ndn.bv_val );
#else
			Debug( LDAP_DEBUG_TRACE,
				"do_bind: v%d simple bind(%s) disallowed\n",
				version, op->o_req_ndn.bv_val, 0 );
#endif
			goto cleanup;
		}

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	} else if ( op->orb_method == LDAP_AUTH_KRBV41 ) {
		if ( global_disallows & SLAP_DISALLOW_BIND_KRBV4 ) {
			/* disallow krbv4 authentication */
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			rs->sr_text = "unwilling to perform Kerberos V4 bind";

			send_ldap_result( op, rs );

#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, DETAIL1, 
				"do_bind: conn %d  v%d Kerberos V4 (step 1) bind refused\n",
				op->o_connid, version , 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"do_bind: v%d Kerberos V4 (step 1) bind refused\n",
				version, 0, 0 );
#endif
			goto cleanup;
		}
		ber_str2bv( "KRBV4", sizeof("KRBV4")-1, 0, &mech );

	} else if ( op->orb_method == LDAP_AUTH_KRBV42 ) {
		rs->sr_err = LDAP_AUTH_METHOD_NOT_SUPPORTED;
		rs->sr_text = "Kerberos V4 (step 2) bind not supported";
		send_ldap_result( op, rs );

#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, DETAIL1, 
			"do_bind: conn %d  v%d Kerberos V4 (step 2) bind refused\n",
			op->o_connid, version , 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"do_bind: v%d Kerberos V4 (step 2) bind refused\n",
			version, 0, 0 );
#endif
		goto cleanup;
#endif

	} else {
		rs->sr_err = LDAP_AUTH_METHOD_NOT_SUPPORTED;
		rs->sr_text = "unknown authentication method";

		send_ldap_result( op, rs );
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"do_bind: conn %ld  v%d unknown authentication method (%ld)\n",
			op->o_connid, version, op->orb_method );
#else
		Debug( LDAP_DEBUG_TRACE,
			"do_bind: v%d unknown authentication method (%ld)\n",
			version, op->orb_method, 0 );
#endif
		goto cleanup;
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */

	if ( (op->o_bd = select_backend( &op->o_req_ndn, 0, 0 )) == NULL ) {
		if ( default_referral ) {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
			if (!rs->sr_ref) rs->sr_ref = default_referral;

			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			if (rs->sr_ref != default_referral) ber_bvarray_free( rs->sr_ref );

		} else {
			/* noSuchObject is not allowed to be returned by bind */
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			send_ldap_result( op, rs );
		}

		goto cleanup;
	}

	/* check restrictions */
	if( backend_check_restrictions( op, rs, NULL ) != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		goto cleanup;
	}

#ifdef LDAP_SLAPI
	if ( pb ) {
		int rc;
		slapi_int_pblock_set_operation( pb, op );
		slapi_pblock_set( pb, SLAPI_BIND_TARGET, (void *)dn.bv_val );
		slapi_pblock_set( pb, SLAPI_BIND_METHOD, (void *)op->orb_method );
		slapi_pblock_set( pb, SLAPI_BIND_CREDENTIALS, (void *)&op->orb_cred );
		slapi_pblock_set( pb, SLAPI_MANAGEDSAIT, (void *)(0) );
		slapi_pblock_set( pb, SLAPI_CONN_DN, (void *)(0) );

		rc = slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_PRE_BIND_FN, pb );

#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO,
			"do_bind: Bind preoperation plugin returned %d\n",
			rs->sr_err, 0, 0);
#else
		Debug(LDAP_DEBUG_TRACE,
			"do_bind: Bind preoperation plugin returned %d.\n",
			rs->sr_err, 0, 0);
#endif

		switch ( rc ) {
		case SLAPI_BIND_SUCCESS:
			/* Continue with backend processing */
			break;
		case SLAPI_BIND_FAIL:
			/* Failure, server sends result */
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			send_ldap_result( op, rs );
			goto cleanup;
			break;
		case SLAPI_BIND_ANONYMOUS:
			/* SLAPI_BIND_ANONYMOUS is undocumented XXX */
		default:
			/* Authoritative, plugin sent result, or no plugins called. */
			if ( slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE,
				(void *)&rs->sr_err) != 0 )
			{
				rs->sr_err = LDAP_OTHER;
			}

			op->orb_edn.bv_val = NULL;
			op->orb_edn.bv_len = 0;

			if ( rs->sr_err == LDAP_SUCCESS ) {
				slapi_pblock_get( pb, SLAPI_CONN_DN,
					(void *)&op->orb_edn.bv_val );
				if ( op->orb_edn.bv_val == NULL ) {
					if ( rc == 1 ) {
						/* No plugins were called; continue. */
						break;
					}
				} else {
					op->orb_edn.bv_len = strlen( op->orb_edn.bv_val );
				}
				rs->sr_err = dnPrettyNormal( NULL, &op->orb_edn,
					&op->o_req_dn, &op->o_req_ndn, op->o_tmpmemctx );
				ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
				ber_dupbv(&op->o_conn->c_dn, &op->o_req_dn);
				ber_dupbv(&op->o_conn->c_ndn, &op->o_req_ndn);
				op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
				op->o_req_dn.bv_val = NULL;
				op->o_req_dn.bv_len = 0;
				op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );
				op->o_req_ndn.bv_val = NULL;
				op->o_req_ndn.bv_len = 0;
				if ( op->o_conn->c_dn.bv_len != 0 ) {
					ber_len_t max = sockbuf_max_incoming_auth;
					ber_sockbuf_ctrl( op->o_conn->c_sb,
						LBER_SB_OPT_SET_MAX_INCOMING, &max );
				}
				/* log authorization identity */
				Statslog( LDAP_DEBUG_STATS,
					"conn=%lu op=%lu BIND dn=\"%s\" mech=%s (SLAPI) ssf=0\n",
					op->o_connid, op->o_opid,
					op->o_conn->c_dn.bv_val ? op->o_conn->c_dn.bv_val : "<empty>",
					mech.bv_val, 0 );
				ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );
			}
			goto cleanup;
			break;
		}
	}
#endif /* LDAP_SLAPI */

	if( op->o_bd->be_bind ) {
		rs->sr_err = (op->o_bd->be_bind)( op, rs );

		if ( rs->sr_err == 0 ) {
			ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );

			if( op->o_conn->c_authz_backend == NULL ) {
				op->o_conn->c_authz_backend = op->o_bd;
			}

			/* be_bind returns regular/global edn */
			if( op->orb_edn.bv_len ) {
				op->o_conn->c_dn = op->orb_edn;
			} else {
				ber_dupbv(&op->o_conn->c_dn, &op->o_req_dn);
			}

			ber_dupbv( &op->o_conn->c_ndn, &op->o_req_ndn );

			if( op->o_conn->c_dn.bv_len != 0 ) {
				ber_len_t max = sockbuf_max_incoming_auth;
				ber_sockbuf_ctrl( op->o_conn->c_sb,
					LBER_SB_OPT_SET_MAX_INCOMING, &max );
			}

			/* log authorization identity */
			Statslog( LDAP_DEBUG_STATS,
				"conn=%lu op=%lu BIND dn=\"%s\" mech=%s ssf=0\n",
				op->o_connid, op->o_opid,
				op->o_conn->c_dn.bv_val, mech.bv_val, 0 );

#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, DETAIL1, 
				"do_bind: v%d bind: \"%s\" to \"%s\" \n",
				version, op->o_conn->c_dn.bv_val, op->o_conn->c_dn.bv_val );
#else
			Debug( LDAP_DEBUG_TRACE,
				"do_bind: v%d bind: \"%s\" to \"%s\"\n",
				version, dn.bv_val, op->o_conn->c_dn.bv_val );
#endif

			ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );

			/* send this here to avoid a race condition */
			send_ldap_result( op, rs );

		} else if (op->orb_edn.bv_val != NULL) {
			free( op->orb_edn.bv_val );
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"operation not supported within naming context" );
	}

#ifdef LDAP_SLAPI
	if ( pb != NULL &&
		slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_POST_BIND_FN, pb ) < 0 )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO,
			"do_bind: Bind postoperation plugins failed\n",
			0, 0, 0);
#else
		Debug(LDAP_DEBUG_TRACE,
			"do_bind: Bind postoperation plugins failed.\n",
			0, 0, 0);
#endif
	}
#endif /* LDAP_SLAPI */

cleanup:
	if ( rs->sr_err == LDAP_SUCCESS ) {
		if ( op->orb_method != LDAP_AUTH_SASL ) {
			ber_dupbv( &op->o_conn->c_authmech, &mech );
		}
		op->o_conn->c_authtype = op->orb_method;
	}

	op->o_conn->c_sasl_bindop = NULL;

	if( op->o_req_dn.bv_val != NULL ) {
		slap_sl_free( op->o_req_dn.bv_val, op->o_tmpmemctx );
		op->o_req_dn.bv_val = NULL;
	}
	if( op->o_req_ndn.bv_val != NULL ) {
		slap_sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );
		op->o_req_ndn.bv_val = NULL;
	}

	return rs->sr_err;
}
