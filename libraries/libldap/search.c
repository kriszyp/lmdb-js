/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  search.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#endif /* DOS */

#if !defined(MACOS) && !defined(DOS) && !defined( _WIN32 )
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#endif
#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

#ifdef NEEDPROTOS
static char *find_right_paren( char *s );
static char *put_complex_filter( BerElement *ber, char *str,
	unsigned long tag, int not );
static int put_filter( BerElement *ber, char *str );
static int put_simple_filter( BerElement *ber, char *str );
static int put_substring_filter( BerElement *ber, char *type, char *str );
static int put_filter_list( BerElement *ber, char *str );
#else
static char *find_right_paren();
static char *put_complex_filter();
static int put_filter();
static int put_simple_filter();
static int put_substring_filter();
static int put_filter_list();
#endif /* NEEDPROTOS */

/*
 * ldap_search - initiate an ldap (and X.500) search operation.  Parameters:
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
ldap_search( LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly )
{
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_search\n", 0, 0, 0 );

	if (( ber = ldap_build_search_req( ld, base, scope, filter, attrs,
	    attrsonly )) == NULLBER ) {
		return( -1 );
	}

#ifndef NO_CACHE
	if ( ld->ld_cache != NULL ) {
		if ( check_cache( ld, LDAP_REQ_SEARCH, ber ) == 0 ) {
			ber_free( ber, 1 );
			ld->ld_errno = LDAP_SUCCESS;
			return( ld->ld_msgid );
		}
		add_request_to_cache( ld, LDAP_REQ_SEARCH, ber );
	}
#endif /* NO_CACHE */

	/* send the message */
	return ( send_initial_request( ld, LDAP_REQ_SEARCH, base, ber ));
}


BerElement *
ldap_build_search_req( LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly )
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
	if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
		return( NULLBER );
	}

	if ( base == NULL ) {
	    base = "";
	}

#ifdef CLDAP
	if ( ld->ld_sb.sb_naddr > 0 ) {
	    err = ber_printf( ber, "{ist{seeiib", ++ld->ld_msgid,
		ld->ld_cldapdn, LDAP_REQ_SEARCH, base, scope, ld->ld_deref,
		ld->ld_sizelimit, ld->ld_timelimit, attrsonly );
	} else {
#endif /* CLDAP */
		err = ber_printf( ber, "{it{seeiib", ++ld->ld_msgid,
		    LDAP_REQ_SEARCH, base, scope, ld->ld_deref,
		    ld->ld_sizelimit, ld->ld_timelimit, attrsonly );
#ifdef CLDAP
	}
#endif /* CLDAP */

	if ( err == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	filter = strdup( filter );
	err = put_filter( ber, filter );
	free( filter );

	if ( err  == -1 ) {
		ld->ld_errno = LDAP_FILTER_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
	}

	if ( ber_printf( ber, "{v}}}", attrs ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( NULLBER );
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
put_complex_filter( BerElement *ber, char *str, unsigned long tag, int not )
{
	char	*next;

	/*
	 * We have (x(filter)...) with str sitting on
	 * the x.  We have to find the paren matching
	 * the one before the x and put the intervening
	 * filters by calling put_filter_list().
	 */

	/* put explicit tag */
	if ( ber_printf( ber, "t{", tag ) == -1 )
		return( NULL );
/*
	if ( !not && ber_printf( ber, "{" ) == -1 )
		return( NULL );
*/

	str++;
	if ( (next = find_right_paren( str )) == NULL )
		return( NULL );

	*next = '\0';
	if ( put_filter_list( ber, str ) == -1 )
		return( NULL );
	*next++ = ')';

	/* flush explicit tagged thang */
	if ( ber_printf( ber, "}" ) == -1 )
		return( NULL );
/*
	if ( !not && ber_printf( ber, "}" ) == -1 )
		return( NULL );
*/

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
	 *              present         [7]     AttributeType,,
	 *              approxMatch     [8]     AttributeValueAssertion
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
				tmp = strdup( str );
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
					free( tmp );
					return( -1 );
				}
				free( tmp );
				*next++ = ')';
				str = next;
				parens--;
				break;
			}
			break;

		case ')':
			Debug( LDAP_DEBUG_TRACE, "put_filter: end\n", 0, 0,
			    0 );
			if ( ber_printf( ber, "]" ) == -1 )
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
			tmp = strdup( str );
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
				free( tmp );
				return( -1 );
			}
			free( tmp );
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
		while ( *str && isspace( *str ) )
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
put_simple_filter( BerElement *ber, char *str )
{
	char		*s;
	char		*value, savechar;
	unsigned long	ftype;
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
	unsigned long	ftype;

	Debug( LDAP_DEBUG_TRACE, "put_substring_filter \"%s=%s\"\n", type,
	    val, 0 );

	if ( ber_printf( ber, "t{s{", LDAP_FILTER_SUBSTRINGS, type ) == -1 )
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

	if ( ber_printf( ber, "}}" ) == -1 )
		return( -1 );

	return( 0 );
}

int
ldap_search_st( LDAP *ld, char *base, int scope, char *filter, char **attrs,
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
ldap_search_s( LDAP *ld, char *base, int scope, char *filter, char **attrs,
	int attrsonly, LDAPMessage **res )
{
	int	msgid;

	if ( (msgid = ldap_search( ld, base, scope, filter, attrs, attrsonly ))
	    == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, *res, 0 ) );
}

