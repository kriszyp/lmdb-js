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
    Connection	*conn,	/* where to send results		       */
    Operation	*op	/* info about the op to which we're responding */
) {
	int		i;
	ber_int_t		scope, deref, attrsonly;
	ber_int_t		sizelimit, timelimit;
	char		*base = NULL, *nbase = NULL, *fstr = NULL;
	Filter		*filter = NULL;
	char		**attrs = NULL;
	Backend		*be;
	int			rc;
	const char		*text;
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
	if ( ber_scanf( op->o_ber, "{aiiiib" /*}*/,
		&base, &scope, &deref, &sizelimit,
	    &timelimit, &attrsonly ) == LBER_ERROR ) {
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

	nbase = ch_strdup( base );

	if( dn_normalize( nbase ) == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX,
			NULL, "invalid DN", NULL, NULL );
		goto return_results;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
		   "do_search \"%s\" %d %d %d %d %d\n", base, scope,
		   deref, sizelimit, timelimit, attrsonly ));
#else
	Debug( LDAP_DEBUG_ARGS, "SRCH \"%s\" %d %d", base, scope, deref );
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

	rc = 0;

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
	    op->o_connid, op->o_opid, base, scope, fstr );

	manageDSAit = get_manageDSAit( op );

	if( scope != LDAP_SCOPE_BASE && nbase[0] == '\0' &&
		default_search_nbase != NULL )
	{
		ch_free( base );
		ch_free( nbase );
		base = ch_strdup( default_search_base );
		nbase = ch_strdup( default_search_nbase );
	}

	/* Select backend */
	be = select_backend( nbase, manageDSAit );

	/* check restrictions */
	rc = backend_check_restrictions( be, conn, op, NULL, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto return_results;
	}

	if ( scope == LDAP_SCOPE_BASE ) {
		Entry *entry = NULL;

		if ( strcasecmp( nbase, LDAP_ROOT_DSE ) == 0 ) {
			rc = root_dse_info( conn, &entry, &text );
		}

#if defined( SLAPD_MONITOR_DN )
		else if ( strcasecmp( nbase, SLAPD_MONITOR_DN ) == 0 ) {
			rc = monitor_info( &entry, &text );
		}
#endif

#if defined( SLAPD_CONFIG_DN )
		else if ( strcasecmp( nbase, SLAPD_CONFIG_DN ) == 0 ) {
			rc = config_info( &entry, &text );
		}
#endif

#if defined( SLAPD_SCHEMA_DN )
		else if ( strcasecmp( nbase, SLAPD_SCHEMA_DN ) == 0 ) {
			rc= schema_info( &entry, &text );
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
				send_search_entry( &backends[0], conn, op,
					entry, attrs, attrsonly, NULL );
			}
			entry_free( entry );

			send_ldap_result( conn, op, LDAP_SUCCESS,
				NULL, NULL, NULL, NULL );

			goto return_results;
		}
	}

	if ( be == NULL ) {
		/* no backend, return a referral (or noSuchObject) */
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );

		goto return_results;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, base, nbase );
	if ( rc != LDAP_SUCCESS ) {
		goto return_results;
	}

	/* deref the base if needed */
	nbase = suffix_alias( be, nbase );

	/* actually do the search and send the result(s) */
	if ( be->be_search ) {
		(*be->be_search)( be, conn, op, base, nbase, scope, deref, sizelimit,
		    timelimit, filter, fstr, attrs, attrsonly );
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext", NULL, NULL );
	}

return_results:;
	if( base != NULL) free( base );
	if( nbase != NULL) free( nbase );
	if( fstr != NULL) free( fstr );
	if( filter != NULL) filter_free( filter );
	if ( attrs != NULL ) {
		charray_free( attrs );
	}

	return rc;
}
