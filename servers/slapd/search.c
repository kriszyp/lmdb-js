/* $OpenLDAP$ */
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
do_search(
    Connection	*conn,	/* where to send results 		       */
    Operation	*op	/* info about the op to which we're responding */
)
{
	int		i, err;
	ber_int_t		scope, deref, attrsonly;
	ber_int_t		sizelimit, timelimit;
	char		*base = NULL, *nbase = NULL, *fstr = NULL;
	Filter		*filter = NULL;
	char		**attrs = NULL;
	Backend		*be;
	int			rc;

	Debug( LDAP_DEBUG_TRACE, "do_search\n", 0, 0, 0 );

	if( op->o_bind_in_progress ) {
		Debug( LDAP_DEBUG_ANY, "do_search: SASL bind in progress.\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_SASL_BIND_IN_PROGRESS,
			NULL, "SASL bind in progress", NULL, NULL );
		return LDAP_SASL_BIND_IN_PROGRESS;
	}

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
	if ( ber_scanf( op->o_ber, "{aiiiib",
		&base, &scope, &deref, &sizelimit,
	    &timelimit, &attrsonly ) == LBER_ERROR ) {
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto return_results;
	}

	switch( scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
		break;
	default:
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			NULL, "invalid scope", NULL, NULL );
		rc = -1;
		goto return_results;
	}

	switch( deref ) {
	case LDAP_DEREF_NEVER:
	case LDAP_DEREF_FINDING:
	case LDAP_DEREF_SEARCHING:
	case LDAP_DEREF_ALWAYS:
		break;
	default:
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			NULL, "invalid deref", NULL, NULL );
		rc = -1;
		goto return_results;
	}

	nbase = ch_strdup( base );

	if( dn_normalize( nbase ) == NULL ) {
		send_ldap_result( conn, op, LDAP_INVALID_DN_SYNTAX,
			NULL, "invalid DN", NULL, NULL );
		rc = -1;
		goto return_results;
	}

	Debug( LDAP_DEBUG_ARGS, "SRCH \"%s\" %d %d", base, scope, deref );
	Debug( LDAP_DEBUG_ARGS, "    %d %d %d\n", sizelimit, timelimit,
	    attrsonly);

	/* filter - returns a "normalized" version */
	if ( (err = get_filter( conn, op->o_ber, &filter, &fstr )) != 0 ) {
		if( err == -1 ) {
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decode error" );
		} else {
			send_ldap_result( conn, op, err,
				NULL, "Bad search filter", NULL, NULL );
		}
		rc = -1;
		goto return_results;
	}

	Debug( LDAP_DEBUG_ARGS, "    filter: %s\n", fstr, 0, 0 );

	/* attributes */
	if ( ber_scanf( op->o_ber, /*{*/ "{v}}", &attrs ) == LBER_ERROR ) {
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto return_results;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_search: get_ctrls failed\n", 0, 0, 0 );
		goto return_results;
	} 

	rc = 0;

	Debug( LDAP_DEBUG_ARGS, "    attrs:", 0, 0, 0 );

	if ( attrs != NULL ) {
		for ( i = 0; attrs[i] != NULL; i++ ) {
			attr_normalize( attrs[i] );
			Debug( LDAP_DEBUG_ARGS, " %s", attrs[i], 0, 0 );
		}
	}

	Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%ld op=%d SRCH base=\"%s\" scope=%d filter=\"%s\"\n",
	    op->o_connid, op->o_opid, base, scope, fstr );

	if ( scope == LDAP_SCOPE_BASE ) {
#if defined( SLAPD_MONITOR_DN )
		if ( strcmp( nbase, SLAPD_MONITOR_DN ) == 0 ) {
			monitor_info( conn, op, attrs, attrsonly );
			goto return_results;
		}
#endif

#if defined( SLAPD_CONFIG_DN )
		if ( strcmp( nbase, SLAPD_CONFIG_DN ) == 0 ) {
			config_info( conn, op, attrs, attrsonly );
			goto return_results;
		}
#endif

#if defined( SLAPD_SCHEMA_DN )
		if ( strcmp( nbase, SLAPD_SCHEMA_DN ) == 0 ) {
			schema_info( conn, op, attrs, attrsonly );
			goto return_results;
		}
#endif

		if ( strcmp( nbase, LDAP_ROOT_DSE ) == 0 ) {
			root_dse_info( conn, op, attrs, attrsonly );
			goto return_results;
		}
	}

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( nbase )) == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );

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
			NULL, "Function not implemented", NULL, NULL );
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
