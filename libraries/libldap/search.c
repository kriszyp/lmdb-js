/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

static char *find_right_paren LDAP_P((
	char *s ));

static char *put_complex_filter LDAP_P((
	BerElement *ber,
	char *str,
	ber_tag_t tag,
	int not ));

static int put_filter LDAP_P((
	BerElement *ber,
	char *str ));

static int put_simple_filter LDAP_P((
	BerElement *ber,
	char *str ));

static int put_substring_filter LDAP_P((
	BerElement *ber,
	char *type,
	char *str ));

static int put_filter_list LDAP_P((
	BerElement *ber,
	char *str ));

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
 *	ldap_search_ext( ld, "c=us@o=UM", LDAP_SCOPE_SUBTREE, "cn~=bob",
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
	BerElement	*ber;
	int timelimit;

	Debug( LDAP_DEBUG_TRACE, "ldap_search_ext\n", 0, 0, 0 );

	/*
	 * if timeout is provided, use only tv_sec as timelimit.
	 * otherwise, use default.
	 */
	timelimit = (timeout != NULL)
			?  timelimit = timeout->tv_sec
			: -1;

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

	if ( ldap_result( ld, msgid, 1, timeout, res ) == -1 )
		return( ld->ld_errno );

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
 *	msgid = ldap_search( ld, "c=us@o=UM", LDAP_SCOPE_SUBTREE, "cn~=bob",
 *	    attrs, attrsonly );
 */
int
ldap_search(
	LDAP *ld, LDAP_CONST char *base, int scope, LDAP_CONST char *filter,
	char **attrs, int attrsonly )
{
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_search\n", 0, 0, 0 );

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
	LDAP_CONST char *base_in,
	ber_int_t scope,
	LDAP_CONST char *filter_in,
	char **attrs,
	ber_int_t attrsonly,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	ber_int_t timelimit,
	ber_int_t sizelimit )
{
	BerElement	*ber;
	int		err;
	char	*base;
	char	*filter;

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

	if ( base_in == NULL ) {
		/* no base provided, use session default base */
		base = ld->ld_options.ldo_defbase;
	} else {
		base = (char *) base_in;
	}

	if ( base == NULL ) {
		/* no session default base, use top */
	    base = "";
	}

#ifdef LDAP_CONNECTIONLESS
	if ( ld->ld_cldapnaddr > 0 ) {
	    err = ber_printf( ber, "{ist{seeiib", ++ld->ld_msgid,
			ld->ld_cldapdn, LDAP_REQ_SEARCH, base, scope, ld->ld_deref,
			(sizelimit < 0) ? ld->ld_sizelimit : sizelimit,
			(timelimit < 0) ? ld->ld_timelimit : timelimit,
			attrsonly );
	} else {
#endif /* LDAP_CONNECTIONLESS */
		err = ber_printf( ber, "{it{seeiib", ++ld->ld_msgid,
		    LDAP_REQ_SEARCH, base, (ber_int_t) scope, ld->ld_deref,
			(sizelimit < 0) ? ld->ld_sizelimit : sizelimit,
			(timelimit < 0) ? ld->ld_timelimit : timelimit,
		    attrsonly );
#ifdef LDAP_CONNECTIONLESS
	}
#endif /* LDAP_CONNECTIONLESS */

	if ( err == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	filter = LDAP_STRDUP( filter_in );
	err = put_filter( ber, filter );
	LDAP_FREE( filter );

	if ( err  == -1 ) {
		ld->ld_errno = LDAP_FILTER_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	if ( ber_printf( ber, /*{*/ "{v}}", attrs ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	/* Put Server Controls */
	if( ldap_int_put_controls( ld, sctrls, ber ) != LDAP_SUCCESS ) {
		ber_free( ber, 1 );
		return( NULL );
	}

	if ( ber_printf( ber, /*{*/ "}", attrs ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULL );
	}

	return( ber );
}

static char *
find_right_paren( char *s )
{
	int	balance, escape;

	balance = 1;
	escape = 0;
	while ( *s && balance ) {
		if ( escape == 0 ) {
			if ( *s == '(' )
				balance++;
			else if ( *s == ')' )
				balance--;
		}
		if ( *s == '\\' && ! escape )
			escape = 1;
		else
			escape = 0;
		if ( balance )
			s++;
	}

	return( *s ? s : NULL );
}

static char *
put_complex_filter( BerElement *ber, char *str, ber_tag_t tag, int not )
{
	char	*next;

	/*
	 * We have (x(filter)...) with str sitting on
	 * the x.  We have to find the paren matching
	 * the one before the x and put the intervening
	 * filters by calling put_filter_list().
	 */

	/* put explicit tag */
	if ( ber_printf( ber, "t{" /*}*/, tag ) == -1 )
		return( NULL );

	str++;
	if ( (next = find_right_paren( str )) == NULL )
		return( NULL );

	*next = '\0';
	if ( put_filter_list( ber, str ) == -1 )
		return( NULL );
	*next++ = ')';

	/* flush explicit tagged thang */
	if ( ber_printf( ber, /*{*/ "}" ) == -1 )
		return( NULL );

	return( next );
}

static int
put_filter( BerElement *ber, char *str )
{
	char	*next, *tmp, *s, *d;
	int	parens, balance, escape, gotescape;

	/*
	 * A Filter looks like this:
	 *      Filter ::= CHOICE {
	 *              and             [0]     SET OF Filter,
	 *              or              [1]     SET OF Filter,
	 *              not             [2]     Filter,
	 *              equalityMatch   [3]     AttributeValueAssertion,
	 *              substrings      [4]     SubstringFilter,
	 *              greaterOrEqual  [5]     AttributeValueAssertion,
	 *              lessOrEqual     [6]     AttributeValueAssertion,
	 *              present         [7]     AttributeType,
	 *              approxMatch     [8]     AttributeValueAssertion,
	 *				extensibleMatch [9]		MatchingRuleAssertion -- LDAPv3
	 *      }
	 *
	 *      SubstringFilter ::= SEQUENCE {
	 *              type               AttributeType,
	 *              SEQUENCE OF CHOICE {
	 *                      initial          [0] IA5String,
	 *                      any              [1] IA5String,
	 *                      final            [2] IA5String
	 *              }
	 *      }
	 *
	 *		MatchingRuleAssertion ::= SEQUENCE {	-- LDAPv3
	 *			matchingRule    [1] MatchingRuleId OPTIONAL,
	 *			type            [2] AttributeDescription OPTIONAL,
	 *			matchValue      [3] AssertionValue,
	 *			dnAttributes    [4] BOOLEAN DEFAULT FALSE }
	 *
	 * Note: tags in a choice are always explicit
	 */

	Debug( LDAP_DEBUG_TRACE, "put_filter \"%s\"\n", str, 0, 0 );

	gotescape = parens = 0;
	while ( *str ) {
		switch ( *str ) {
		case '(':
			str++;
			parens++;
			switch ( *str ) {
			case '&':
				Debug( LDAP_DEBUG_TRACE, "put_filter: AND\n",
				    0, 0, 0 );

				if ( (str = put_complex_filter( ber, str,
				    LDAP_FILTER_AND, 0 )) == NULL )
					return( -1 );

				parens--;
				break;

			case '|':
				Debug( LDAP_DEBUG_TRACE, "put_filter: OR\n",
				    0, 0, 0 );

				if ( (str = put_complex_filter( ber, str,
				    LDAP_FILTER_OR, 0 )) == NULL )
					return( -1 );

				parens--;
				break;

			case '!':
				Debug( LDAP_DEBUG_TRACE, "put_filter: NOT\n",
				    0, 0, 0 );

				if ( (str = put_complex_filter( ber, str,
				    LDAP_FILTER_NOT, 1 )) == NULL )
					return( -1 );

				parens--;
				break;

			default:
				Debug( LDAP_DEBUG_TRACE, "put_filter: simple\n",
				    0, 0, 0 );

				balance = 1;
				escape = 0;
				next = str;
				while ( *next && balance ) {
					if ( escape == 0 ) {
						if ( *next == '(' )
							balance++;
						else if ( *next == ')' )
							balance--;
					}
					if ( *next == '\\' && ! escape )
						gotescape = escape = 1;
					else
						escape = 0;
					if ( balance )
						next++;
				}
				if ( balance != 0 )
					return( -1 );

				*next = '\0';
				tmp = LDAP_STRDUP( str );
				if ( gotescape ) {
					escape = 0;
					for ( s = d = tmp; *s; s++ ) {
						if ( *s != '\\' || escape ) {
							*d++ = *s;
							escape = 0;
						} else {
							escape = 1;
						}
					}
					*d = '\0';
				}
				if ( put_simple_filter( ber, tmp ) == -1 ) {
					LDAP_FREE( tmp );
					return( -1 );
				}
				LDAP_FREE( tmp );
				*next++ = ')';
				str = next;
				parens--;
				break;
			}
			break;

		case ')':
			Debug( LDAP_DEBUG_TRACE, "put_filter: end\n", 0, 0,
			    0 );
			if ( ber_printf( ber, /*[*/ "]" ) == -1 )
				return( -1 );
			str++;
			parens--;
			break;

		case ' ':
			str++;
			break;

		default:	/* assume it's a simple type=value filter */
			Debug( LDAP_DEBUG_TRACE, "put_filter: default\n", 0, 0,
			    0 );
			next = strchr( str, '\0' );
			tmp = LDAP_STRDUP( str );
			if ( strchr( tmp, '\\' ) != NULL ) {
				escape = 0;
				for ( s = d = tmp; *s; s++ ) {
					if ( *s != '\\' || escape ) {
						*d++ = *s;
						escape = 0;
					} else {
						escape = 1;
					}
				}
				*d = '\0';
			}
			if ( put_simple_filter( ber, tmp ) == -1 ) {
				LDAP_FREE( tmp );
				return( -1 );
			}
			LDAP_FREE( tmp );
			str = next;
			break;
		}
	}

	return( parens ? -1 : 0 );
}

/*
 * Put a list of filters like this "(filter1)(filter2)..."
 */

static int
put_filter_list( BerElement *ber, char *str )
{
	char	*next;
	char	save;

	Debug( LDAP_DEBUG_TRACE, "put_filter_list \"%s\"\n", str, 0, 0 );

	while ( *str ) {
		while ( *str && isspace( (unsigned char) *str ) )
			str++;
		if ( *str == '\0' )
			break;

		if ( (next = find_right_paren( str + 1 )) == NULL )
			return( -1 );
		save = *++next;

		/* now we have "(filter)" with str pointing to it */
		*next = '\0';
		if ( put_filter( ber, str ) == -1 )
			return( -1 );
		*next = save;

		str = next;
	}

	return( 0 );
}

static int
put_simple_filter(
	BerElement *ber,
	char *str )
{
	char		*s;
	char		*value, savechar;
	ber_tag_t	ftype;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "put_simple_filter \"%s\"\n", str, 0, 0 );

	if ( (s = strchr( str, '=' )) == NULL )
		return( -1 );
	value = s + 1;
	*s-- = '\0';
	savechar = *s;

	switch ( *s ) {
	case '<':
		ftype = LDAP_FILTER_LE;
		*s = '\0';
		break;
	case '>':
		ftype = LDAP_FILTER_GE;
		*s = '\0';
		break;
	case '~':
		ftype = LDAP_FILTER_APPROX;
		*s = '\0';
		break;
	case ':':	/* LDAPv3 extended filter */
		ftype = LDAP_FILTER_EXTENDED;
		return -1;
		break;
	default:
		if ( strchr( value, '*' ) == NULL ) {
			ftype = LDAP_FILTER_EQUALITY;
		} else if ( strcmp( value, "*" ) == 0 ) {
			ftype = LDAP_FILTER_PRESENT;
		} else {
			rc = put_substring_filter( ber, str, value );
			*(value-1) = '=';
			return( rc );
		}
		break;
	}

	if ( ftype == LDAP_FILTER_PRESENT ) {
		rc = ber_printf( ber, "ts", ftype, str );
	} else {
		rc = ber_printf( ber, "t{ss}", ftype, str, value );
	}

	*s = savechar;
	*(value-1) = '=';
	return( rc == -1 ? rc : 0 );
}

static int
put_substring_filter( BerElement *ber, char *type, char *val )
{
	char		*nextstar, gotstar = 0;
	ber_tag_t	ftype = LDAP_FILTER_SUBSTRINGS;

	Debug( LDAP_DEBUG_TRACE, "put_substring_filter \"%s=%s\"\n", type,
	    val, 0 );

	if ( ber_printf( ber, "t{s{", ftype, type ) == -1 )
		return( -1 );

	while ( val != NULL ) {
		if ( (nextstar = strchr( val, '*' )) != NULL )
			*nextstar++ = '\0';

		if ( gotstar == 0 ) {
			ftype = LDAP_SUBSTRING_INITIAL;
		} else if ( nextstar == NULL ) {
			ftype = LDAP_SUBSTRING_FINAL;
		} else {
			ftype = LDAP_SUBSTRING_ANY;
		}
		if ( *val != '\0' ) {
			if ( ber_printf( ber, "ts", ftype, val ) == -1 )
				return( -1 );
		}

		gotstar = 1;
		if ( nextstar != NULL )
			*(nextstar-1) = '*';
		val = nextstar;
	}

	if ( ber_printf( ber, /* {{ */ "}}" ) == -1 )
		return( -1 );

	return( 0 );
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

