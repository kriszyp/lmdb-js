/* dn.c - routines for dealing with distinguished names */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "portable.h"
#include "slap.h"

static char	**dn_explode();

#define DNSEPARATOR(c)	(c == ',' || c == ';')
#define SEPARATOR(c)	(c == ',' || c == ';' || c == '+')
#define SPACE(c)	(c == ' ' || c == '\n')
#define NEEDSESCAPE(c)	(c == '\\' || c == '"')
#define B4TYPE		0
#define INTYPE		1
#define B4EQUAL		2
#define B4VALUE		3
#define INVALUE		4
#define INQUOTEDVALUE	5
#define B4SEPARATOR	6

/*
 * dn_normalize - put dn into a canonical format.  the dn is
 * normalized in place, as well as returned.
 */

char *
dn_normalize( char *dn )
{
	char	*d, *s;
	int	state, gotesc;

	/* Debug( LDAP_DEBUG_TRACE, "=> dn_normalize \"%s\"\n", dn, 0, 0 ); */

	gotesc = 0;
	state = B4TYPE;
	for ( d = s = dn; *s; s++ ) {
		switch ( state ) {
		case B4TYPE:
			if ( ! SPACE( *s ) ) {
				state = INTYPE;
				*d++ = *s;
			}
			break;
		case INTYPE:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				*d++ = *s;
			}
			break;
		case B4EQUAL:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*d++ = *s;
			}
			break;
		case B4VALUE:
			if ( *s == '"' ) {
				state = INQUOTEDVALUE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) { 
				state = INVALUE;
				*d++ = *s;
			}
			break;
		case INVALUE:
			if ( !gotesc && SEPARATOR( *s ) ) {
				while ( SPACE( *(d - 1) ) )
					d--;
				state = B4TYPE;
				if ( *s == '+' ) {
					*d++ = *s;
				} else {
					*d++ = ',';
				}
			} else if ( gotesc && !NEEDSESCAPE( *s ) &&
			    !SEPARATOR( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case INQUOTEDVALUE:
			if ( !gotesc && *s == '"' ) {
				state = B4SEPARATOR;
				*d++ = *s;
			} else if ( gotesc && !NEEDSESCAPE( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case B4SEPARATOR:
			if ( SEPARATOR( *s ) ) {
				state = B4TYPE;
				*d++ = *s;
			}
			break;
		default:
			Debug( LDAP_DEBUG_ANY,
			    "dn_normalize - unknown state %d\n", state, 0, 0 );
			break;
		}
		if ( *s == '\\' ) {
			gotesc = 1;
		} else {
			gotesc = 0;
		}
	}
	*d = '\0';

	/* Debug( LDAP_DEBUG_TRACE, "<= dn_normalize \"%s\"\n", dn, 0, 0 ); */
	return( dn );
}

/*
 * dn_normalize_case - put dn into a canonical form suitable for storing
 * in a hash database.  this involves normalizing the case as well as
 * the format.  the dn is normalized in place as well as returned.
 */

char *
dn_normalize_case( char *dn )
{
	char	*s;

	/* normalize format */
	dn_normalize( dn );

	/* normalize case */
	for ( s = dn; *s; s++ ) {
		*s = TOUPPER( *s );
	}

	return( dn );
}

/*
 * dn_parent - return a copy of the dn of dn's parent
 */

char *
dn_parent(
    Backend	*be,
    char	*dn
)
{
	char	*s;
	int	inquote, gotesc;

	if ( dn == NULL || *dn == '\0' || be_issuffix( be, dn ) ) {
		return( NULL );
	}

	/*
	 * no =, assume it is a dns name, like blah@some.domain.name
	 * if the blah@ part is there, return some.domain.name.  if
	 * it's just some.domain.name, return domain.name.
	 */
	if ( strchr( dn, '=' ) == NULL ) {
		if ( (s = strchr( dn, '@' )) == NULL ) {
			if ( (s = strchr( dn, '.' )) == NULL ) {
				return( NULL );
			}
		}
		if ( *(s + 1) == '\0' ) {
			return( NULL );
		} else {
			return( strdup( s + 1 ) );
		}
	}

	/*
	 * else assume it is an X.500-style name, which looks like
	 * foo=bar,sha=baz,...
	 */

	inquote = 0;
	for ( s = dn; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) )
				s++;
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' )
				inquote = 0;
		} else {
			if ( *s == '"' )
				inquote = 1;
			else if ( DNSEPARATOR( *s ) )
				return( strdup( s + 1 ) );
		}
	}

	return( strdup("") );
}

/*
 * dn_issuffix - tells whether suffix is a suffix of dn.  both dn
 * and suffix must be normalized.
 */

int
dn_issuffix(
    char	*dn,
    char	*suffix
)
{
	int	dnlen, suffixlen;

	if ( dn == NULL ) {
		return( 0 );
	}

	suffixlen = strlen( suffix );
	dnlen = strlen( dn );

	if ( suffixlen > dnlen ) {
		return( 0 );
	}

	return( strcasecmp( dn + dnlen - suffixlen, suffix ) == 0 );
}

/*
 * dn_type - tells whether the given dn is an X.500 thing or DNS thing
 * returns (defined in slap.h):	DN_DNS          dns-style thing
 *                            	DN_X500         x500-style thing
 */

int
dn_type( char *dn )
{
	return( strchr( dn, '=' ) == NULL ? DN_DNS : DN_X500 );
}

char *
dn_upcase( char *dn )
{
	char    *s;

	/* normalize case */
	for ( s = dn; *s; s++ ) {
		*s = TOUPPER( *s );
	}

	return( dn );
}
