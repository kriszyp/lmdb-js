/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  search.c
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_log.h"

/*
 * ldap_search_ext - initiate an ldap search operation.
 *
 * Parameters:
 *
 *	ld		LDAP descriptor
 *	base		DN of the base object
 *	scope		the search scope - one of LDAP_SCOPE_BASE,
 *			    LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE
 *	filter		a string containing the search filter
 *			(e.g., "(|(cn=bob)(sn=bob))")
 *	attrs		list of attribute types to return for matches
 *	attrsonly	1 => attributes only 0 => attributes and values
 *
 * Example:
 *	char	*attrs[] = { "mail", "title", 0 };
 *	ldap_search_ext( ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, "cn~=bob",
 *	    attrs, attrsonly, sctrls, ctrls, timeout, sizelimit,
 *		&msgid );
 */
int
ldap_search_ext(
	LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct timeval *timeout,
	int sizelimit,
	int *msgidp )
{
	int rc;
	BerElement	*ber;
	int timelimit;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_search_ext\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_search_ext\n", 0, 0, 0 );
#endif

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	/* check client controls */
	rc = ldap_int_client_controls( ld, cctrls );
	if( rc != LDAP_SUCCESS ) return rc;

	/*
	 * if timeout is provided, both tv_sec and tv_usec must
	 * be non-zero
	 */
	if( timeout != NULL ) {
		if( timeout->tv_sec == 0 && timeout->tv_usec == 0 ) {
			return LDAP_PARAM_ERROR;
		}

		/* timelimit must be non-zero if timeout is provided */
		timelimit = timeout->tv_sec != 0 ? timeout->tv_sec : 1;

	} else {
		/* no timeout, no timelimit */
		timelimit = -1;
	}

	ber = ldap_build_search_req( ld, base, scope, filter, attrs,
	    attrsonly, sctrls, cctrls, timelimit, sizelimit ); 

	if ( ber == NULL ) {
		return ld->ld_errno;
	}

#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULL ) {
		if ( ldap_check_cache( ld, LDAP_REQ_SEARCH, ber ) == 0 ) {
			ber_free( ber, 1 );
			ld->ld_errno = LDAP_SUCCESS;
			*msgidp = ld->ld_msgid;
			return ld->ld_errno;
		}
		ldap_add_request_to_cache( ld, LDAP_REQ_SEARCH, ber );
	}
#endif /* LDAP_NOCACHE */

	/* send the message */
	*msgidp = ldap_send_initial_request( ld, LDAP_REQ_SEARCH, base, ber );

	if( *msgidp < 0 )
		return ld->ld_errno;

	return LDAP_SUCCESS;
}

int
ldap_search_ext_s(
	LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct timeval *timeout,
	int sizelimit,
	LDAPMessage **res )
{
	int rc;
	int	msgid;

	rc = ldap_search_ext( ld, base, scope, filter, attrs, attrsonly,
		sctrls, cctrls, timeout, sizelimit, &msgid );

	if ( rc != LDAP_SUCCESS ) {
		return( rc );
	}

	rc = ldap_result( ld, msgid, 1, timeout, res );

	if( rc <= 0 ) {
		/* error(-1) or timeout(0) */
		return( ld->ld_errno );
	}

	if( rc == LDAP_RES_SEARCH_REFERENCE || rc == LDAP_RES_EXTENDED_PARTIAL ) {
		return( ld->ld_errno );
	}

	return( ldap_result2error( ld, *res, 0 ) );
}

/*
 * ldap_search - initiate an ldap search operation.
 *
 * Parameters:
 *
 *	ld		LDAP descriptor
 *	base		DN of the base object
 *	scope		the search scope - one of LDAP_SCOPE_BASE,
 *			    LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE
 *	filter		a string containing the search filter
 *			(e.g., "(|(cn=bob)(sn=bob))")
 *	attrs		list of attribute types to return for matches
 *	attrsonly	1 => attributes only 0 => attributes and values
 *
 * Example:
 *	char	*attrs[] = { "mail", "title", 0 };
 *	msgid = ldap_search( ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, "cn~=bob",
 *	    attrs, attrsonly );
 */
int
ldap_search(
	LDAP *ld, LDAP_CONST char *base, int scope, LDAP_CONST char *filter,
	char **attrs, int attrsonly )
{
	BerElement	*ber;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_search\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_search\n", 0, 0, 0 );
#endif

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	ber = ldap_build_search_req( ld, base, scope, filter, attrs,
	    attrsonly, NULL, NULL, -1, -1 ); 

	if ( ber == NULL ) {
		return( -1 );
	}

#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULL ) {
		if ( ldap_check_cache( ld, LDAP_REQ_SEARCH, ber ) == 0 ) {
			ber_free( ber, 1 );
			ld->ld_errno = LDAP_SUCCESS;
			return( ld->ld_msgid );
		}
		ldap_add_request_to_cache( ld, LDAP_REQ_SEARCH, ber );
	}
#endif /* LDAP_NOCACHE */

	/* send the message */
	return ( ldap_send_initial_request( ld, LDAP_REQ_SEARCH, base, ber ));
}


BerElement *
ldap_build_search_req(
	LDAP *ld,
	LDAP_CONST char *base,
	ber_int_t scope,
	LDAP_CONST char *filter,
	char **attrs,
	ber_int_t attrsonly,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	ber_int_t timelimit,
	ber_int_t sizelimit )
{
	BerElement	*ber;
	int		err;

	/*
	 * Create the search request.  It looks like this:
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
	 * wrapped in an ldap message.
	 */

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		return( NULL );
	}

	if ( base == NULL ) {
		/* no base provided, use session default base */
		base = ld->ld_options.ldo_defbase;

		if ( base == NULL ) {
			/* no session default base, use top */
			base = "";
		}
	}

#ifdef LDAP_CONNECTIONLESS
	if ( LDAP_IS_UDP(ld) ) {
	    err = ber_write( ber, ld->ld_options.ldo_peer,
		    sizeof(struct sockaddr), 0);
	}
	if ( LDAP_IS_UDP(ld) && ld->ld_options.ldo_version == LDAP_VERSION2) {
	    char *dn = ld->ld_options.ldo_cldapdn;
	    if (!dn) dn = "";
	    err = ber_printf( ber, "{ist{seeiib", ++ld->ld_msgid, dn,
		LDAP_REQ_SEARCH, base, (ber_int_t) scope, ld->ld_deref,
		(sizelimit < 0) ? ld->ld_sizelimit : sizelimit,
		(timelimit < 0) ? ld->ld_timelimit : timelimit,
		attrsonly );
	} else
#endif
	{
	    err = ber_printf( ber, "{it{seeiib", ++ld->ld_msgid,
		LDAP_REQ_SEARCH, base, (ber_int_t) scope, ld->ld_deref,
		(sizelimit < 0) ? ld->ld_sizelimit : sizelimit,
		(timelimit < 0) ? ld->ld_timelimit : timelimit,
		attrsonly );
	}

	if ( err == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	if( filter == NULL ) {
		filter = "(objectclass=*)";
	}

	err = ldap_pvt_put_filter( ber, filter );

	if ( err  == -1 ) {
		ld->ld_errno = LDAP_FILTER_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	if ( ber_printf( ber, /*{*/ "{v}N}", attrs ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	/* Put Server Controls */
	if( ldap_int_put_controls( ld, sctrls, ber ) != LDAP_SUCCESS ) {
		ber_free( ber, 1 );
		return( NULL );
	}

	if ( ber_printf( ber, /*{*/ "N}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	return( ber );
}

int
ldap_search_st(
	LDAP *ld, LDAP_CONST char *base, int scope,
	LDAP_CONST char *filter, char **attrs,
	int attrsonly, struct timeval *timeout, LDAPMessage **res )
{
	int	msgid;

	if ( (msgid = ldap_search( ld, base, scope, filter, attrs, attrsonly ))
	    == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, timeout, res ) == -1 )
		return( ld->ld_errno );

	if ( ld->ld_errno == LDAP_TIMEOUT ) {
		(void) ldap_abandon( ld, msgid );
		ld->ld_errno = LDAP_TIMEOUT;
		return( ld->ld_errno );
	}

	return( ldap_result2error( ld, *res, 0 ) );
}

int
ldap_search_s(
	LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPMessage **res )
{
	int	msgid;

	if ( (msgid = ldap_search( ld, base, scope, filter, attrs, attrsonly ))
	    == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, *res, 0 ) );
}

