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
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "ldapconfig.h"

extern int	get_filter();
extern Backend	*select_backend();

extern char	*default_referral;

void
do_search( conn, op )
    Connection	*conn;	/* where to send results 		       */
    Operation	*op;	/* info about the op to which we're responding */
{
	int		i, err;
	int		scope, deref, attrsonly;
	int		sizelimit, timelimit;
	char		*base, *fstr;
	Filter		*filter;
	char		**attrs;
	Backend		*be;

	Debug( LDAP_DEBUG_TRACE, "do_search\n", 0, 0, 0 );

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
	if ( ber_scanf( op->o_ber, "{aiiiib", &base, &scope, &deref, &sizelimit,
	    &timelimit, &attrsonly ) == LBER_ERROR ) {
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}
	if ( scope != LDAP_SCOPE_BASE && scope != LDAP_SCOPE_ONELEVEL
	    && scope != LDAP_SCOPE_SUBTREE ) {
		free( base );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
		    "Unknown search scope" );
		return;
	}
	(void) dn_normalize( base );

	Debug( LDAP_DEBUG_ARGS, "SRCH \"%s\" %d %d", base, scope, deref );
	Debug( LDAP_DEBUG_ARGS, "    %d %d %d\n", sizelimit, timelimit,
	    attrsonly);

	/* filter - returns a "normalized" version */
	filter = NULL;
	fstr = NULL;
	if ( (err = get_filter( conn, op->o_ber, &filter, &fstr )) != 0 ) {
		if ( fstr != NULL ) {
			free( fstr );
		}
		free( base );
		send_ldap_result( conn, op, err, NULL, "Bad search filter" );
		return;
	}
	Debug( LDAP_DEBUG_ARGS, "    filter: %s\n", fstr, 0, 0 );

	/* attributes */
	attrs = NULL;
	if ( ber_scanf( op->o_ber, "{v}}", &attrs ) == LBER_ERROR ) {
		free( base );
		free( fstr );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}
	Debug( LDAP_DEBUG_ARGS, "    attrs:", 0, 0, 0 );
	if ( attrs != NULL ) {
		for ( i = 0; attrs[i] != NULL; i++ ) {
			attr_normalize( attrs[i] );
			Debug( LDAP_DEBUG_ARGS, " %s", attrs[i], 0, 0 );
		}
	}
	Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
	    "conn=%d op=%d SRCH base=\"%s\" scope=%d filter=\"%s\"\n",
	    conn->c_connid, op->o_opid, base, scope, fstr );

#if defined( SLAPD_MONITOR_DN ) || defined( SLAPD_CONFIG_DN ) || defined( SLAPD_SCHEMA_DN )
	if ( scope == LDAP_SCOPE_BASE ) {
#if defined( SLAPD_MONITOR_DN )
		if ( strcasecmp( base, SLAPD_MONITOR_DN ) == 0 ) {
			free( base );
			free( fstr );
			monitor_info( conn, op );
			return;
		}
#endif
#if defined( SLAPD_CONFIG_DN )
		if ( strcasecmp( base, SLAPD_CONFIG_DN ) == 0 ) {
			free( base );
			free( fstr );
			config_info( conn, op );
			return;
		}
#endif
#if defined( SLAPD_SCHEMA_DN )
		if ( strcasecmp( base, SLAPD_SCHEMA_DN ) == 0 ) {
			free( base );
			free( fstr );
			schema_info( conn, op );
			return;
		}
#endif
	}
#endif /* monitor or config or schema dn */

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( base )) == NULL ) {
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );

		free( base );
		free( fstr );
		filter_free( filter );
		if ( attrs != NULL ) {
			charray_free( attrs );
		}
		return;
	}

	/* actually do the search and send the result(s) */
	if ( be->be_search != NULL ) {
		(*be->be_search)( be, conn, op, base, scope, deref, sizelimit,
		    timelimit, filter, fstr, attrs, attrsonly );
	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	free( base );
	free( fstr );
	filter_free( filter );
	if ( attrs != NULL ) {
		charray_free( attrs );
	}
}
