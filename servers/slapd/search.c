/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
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
do_search(
    Connection	*conn,	/* where to send results */
    Operation	*op	/* info about the op to which we're responding */
) {
	int		i;
	ber_int_t	scope, deref, attrsonly;
	ber_int_t	sizelimit, timelimit;
	struct berval base = { 0, NULL };
	struct berval *pbase = NULL;
	struct berval *nbase = NULL;
	char		*fstr = NULL;
	Filter		*filter = NULL;
	char		**attrs = NULL;
	Backend		*be;
	int			rc;
	const char	*text;
	int			manageDSAit;

#ifdef NEW_LOGGING
	LDAP_LOG(( "operation", LDAP_LEVEL_ENTRY,
		"do_search: conn %d\n", conn->c_connid ));
#else
	Debug( LDAP_DEBUG_TRACE, "do_search\n", 0, 0, 0 );
#endif

	/*
	 * Parse the search request.  It looks like this:
	 *
	 *	SearchRequest := [APPLICATION 3] SEQUENCE {
	 *		baseObject	DistinguishedName,
	 *		scope		ENUMERATED {
	 *			baseObject	(0),
	 *			singleLevel	(1),
	 *			wholeSubtree	(2)
	 *		},
	 *		derefAliases	ENUMERATED {
	 *			neverDerefaliases	(0),
	 *			derefInSearching	(1),
	 *			derefFindingBaseObj	(2),
	 *			alwaysDerefAliases	(3)
	 *		},
	 *		sizelimit	INTEGER (0 .. 65535),
	 *		timelimit	INTEGER (0 .. 65535),
	 *		attrsOnly	BOOLEAN,
	 *		filter		Filter,
	 *		attributes	SEQUENCE OF AttributeType
	 *	}
	 */

	/* baseObject, scope, derefAliases, sizelimit, timelimit, attrsOnly */
	if ( ber_scanf( op->o_ber, "{oiiiib" /*}*/,
		&base, &scope, &deref, &sizelimit,
	    &timelimit, &attrsonly ) == LBER_ERROR )
	{
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto return_results;
	}

	switch( scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
		break;
	default:
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "invalid scope", NULL, NULL );
		goto return_results;
	}

	switch( deref ) {
	case LDAP_DEREF_NEVER:
	case LDAP_DEREF_FINDING:
	case LDAP_DEREF_SEARCHING:
	case LDAP_DEREF_ALWAYS:
		break;
	default:
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "invalid deref", NULL, NULL );
		goto return_results;
	}

	rc = dnPretty( NULL, &base, &pbase );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_INFO,
			"do_search: conn %d  invalid dn (%s)\n",
			conn->c_connid, base.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"do_search: invalid dn (%s)\n", base.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto return_results;
	}

	rc = dnNormalize( NULL, &base, &nbase );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_INFO,
			"do_searc: conn %d  invalid dn (%s)\n",
			conn->c_connid, base.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"do_search: invalid dn (%s)\n", base.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto return_results;
	}


#ifdef NEW_LOGGING
	LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
		"do_search \"%s\" %d %d %d %d %d\n", base.bv_val, scope,
		deref, sizelimit, timelimit, attrsonly ));
#else
	Debug( LDAP_DEBUG_ARGS, "SRCH \"%s\" %d %d", base.bv_val, scope, deref );
	Debug( LDAP_DEBUG_ARGS, "    %d %d %d\n", sizelimit, timelimit,
	    attrsonly);
#endif

	/* filter - returns a "normalized" version */
	rc = get_filter( conn, op->o_ber, &filter, &fstr, &text );
	if( rc != LDAP_SUCCESS ) {
		if( rc == SLAPD_DISCONNECT ) {
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, text );
		} else {
			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );
		}
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
		"do_search: conn %d	filter: %s\n", conn->c_connid, fstr ));
#else
	Debug( LDAP_DEBUG_ARGS, "    filter: %s\n", fstr, 0, 0 );
#endif


	/* attributes */
	if ( ber_scanf( op->o_ber, /*{*/ "{v}}", &attrs ) == LBER_ERROR ) {
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding attrs error" );
		rc = SLAPD_DISCONNECT;
		goto return_results;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_INFO,
			"do_search: conn %d  get_ctrls failed (%d)\n",
			conn->c_connid, rc ));
#else
		Debug( LDAP_DEBUG_ANY, "do_search: get_ctrls failed\n", 0, 0, 0 );
#endif

		goto return_results;
	} 

	rc = LDAP_SUCCESS;

#ifdef NEW_LOGGING
	LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
		"do_search: conn %d	attrs:", conn->c_connid ));
#else
	Debug( LDAP_DEBUG_ARGS, "    attrs:", 0, 0, 0 );
#endif


	if ( attrs != NULL ) {
		for ( i = 0; attrs[i] != NULL; i++ ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
				"do_search:	   %s", attrs[i] ));
#else
			Debug( LDAP_DEBUG_ARGS, " %s", attrs[i], 0, 0 );
#endif

		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "operation", LDAP_LEVEL_ARGS, "\n" ));
#else
	Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );
#endif

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%d SRCH base=\"%s\" scope=%d filter=\"%s\"\n",
	    op->o_connid, op->o_opid, pbase->bv_val, scope, fstr );

	manageDSAit = get_manageDSAit( op );

	if ( scope == LDAP_SCOPE_BASE ) {
		Entry *entry = NULL;

		if ( strcasecmp( nbase->bv_val, LDAP_ROOT_DSE ) == 0 ) {
#ifdef LDAP_CONNECTIONLESS
			/* Ignore LDAPv2 CLDAP DSE queries */
			if (op->o_protocol==LDAP_VERSION2 && conn->c_is_udp) {
				goto return_results;
			}
#endif
			/* check restrictions */
			rc = backend_check_restrictions( NULL, conn, op, NULL, &text ) ;
			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto return_results;
			}

			rc = root_dse_info( conn, &entry, &text );
		}

#if defined( SLAPD_SCHEMA_DN )
		else if ( strcasecmp( nbase->bv_val, SLAPD_SCHEMA_DN ) == 0 ) {
			/* check restrictions */
			rc = backend_check_restrictions( NULL, conn, op, NULL, &text ) ;
			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto return_results;
			}

			rc = schema_info( &entry, &text );
		}
#endif

		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc,
				NULL, text, NULL, NULL );
			goto return_results;

		} else if ( entry != NULL ) {
			rc = test_filter( NULL, conn, op,
				entry, filter );

			if( rc == LDAP_COMPARE_TRUE ) {
				send_search_entry( NULL, conn, op,
					entry, attrs, attrsonly, NULL );
			}
			entry_free( entry );

			send_ldap_result( conn, op, LDAP_SUCCESS,
				NULL, NULL, NULL, NULL );

			goto return_results;
		}
	}

	if( nbase->bv_len == 0 && default_search_nbase != NULL ) {
		ch_free( base.bv_val );
		ch_free( nbase->bv_val );
		base.bv_val = ch_strdup( default_search_base );
		base.bv_len = strlen( default_search_nbase );
		nbase->bv_val = ch_strdup( default_search_nbase );
		nbase->bv_len = strlen( default_search_nbase );
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( nbase->bv_val, manageDSAit, 1 )) == NULL ) {
		struct berval **ref = referral_rewrite( default_referral,
			NULL, pbase->bv_val, scope );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, ref ? ref : default_referral, NULL );

		ber_bvecfree( ref );
		goto return_results;
	}

	/* check restrictions */
	rc = backend_check_restrictions( be, conn, op, NULL, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto return_results;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, pbase->bv_val, nbase->bv_val );
	if ( rc != LDAP_SUCCESS ) {
		goto return_results;
	}

	/* deref the base if needed */
	suffix_alias( be, nbase );

	/* actually do the search and send the result(s) */
	if ( be->be_search ) {
		(*be->be_search)( be, conn, op, pbase->bv_val, nbase->bv_val,
			scope, deref, sizelimit,
		    timelimit, filter, fstr, attrs, attrsonly );
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext", NULL, NULL );
	}

return_results:;
	free( base.bv_val );
	if( pbase != NULL) ber_bvfree( pbase );
	if( nbase != NULL) ber_bvfree( nbase );

	if( fstr != NULL) free( fstr );
	if( filter != NULL) filter_free( filter );
	if ( attrs != NULL ) {
		charray_free( attrs );
	}

	return rc;
}
