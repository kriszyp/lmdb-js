/* dn.c - routines for dealing with distinguished names */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

#if 0
/* this should wait for UTF-8 routines */

#define B4LEADTYPE		0
#define B4TYPE			1
#define INOIDTYPE		2
#define INKEYTYPE		3
#define B4EQUAL			4
#define B4VALUE			5
#define INVALUE			6
#define INQUOTEDVALUE	7
#define B4SEPARATOR		8

/*
 * ldap_dn_normalize - put dn into a canonical format
 * and return it.
 */

char *
ldap_dn_normalize( const char *dn )
{
	char	*d, *s;
	int	state, gotesc;
	char *ndn;

	if( dn == NULL ) {
		return NULL;
	}

	ndn = LDAP_STRDUP( dn );

	if( ndn == NULL ) {
		return NULL;
	}

	gotesc = 0;
	state = B4LEADTYPE;
	for ( d = s = ndn; *s; s++ ) {
		switch ( state ) {
		case B4LEADTYPE:
		case B4TYPE:
			if ( LDAP_LEADOIDCHAR(*s) ) {
				state = INOIDTYPE;
				*d++ = *s;
			} else if ( LDAP_LEADKEYCHAR(*s) ) {
				state = INKEYTYPE;
				*d++ = *s;
			} else if ( ! LDAP_SPACE( *s ) ) {
				dn = NULL;
				state = INKEYTYPE;
				*d++ = *s;
			}
			break;

		case INOIDTYPE:
			if ( LDAP_OIDCHAR(*s) ) {
				*d++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( LDAP_SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				dn = NULL;
				*d++ = *s;
			}
			break;

		case INKEYTYPE:
			if ( LDAP_KEYCHAR(*s) ) {
				*d++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( LDAP_SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				dn = NULL;
				*d++ = *s;
			}
			break;

		case B4EQUAL:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( ! LDAP_SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*d++ = *s;
				dn = NULL;
			}
			break;

		case B4VALUE:
			if ( *s == '"' ) {
				state = INQUOTEDVALUE;
				*d++ = *s;
			} else if ( ! LDAP_SPACE( *s ) ) { 
				state = INVALUE;
				*d++ = *s;
			}
			break;

		case INVALUE:
			if ( !gotesc && LDAP_SEPARATOR( *s ) ) {
				while ( LDAP_SPACE( *(d - 1) ) )
					d--;
				state = B4TYPE;
				if ( *s == '+' ) {
					*d++ = *s;
				} else {
					*d++ = ',';
				}
			} else if ( gotesc && !LDAP_NEEDSESCAPE( *s ) &&
			    !LDAP_SEPARATOR( *s ) ) {
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
			} else if ( gotesc && !LDAP_NEEDSESCAPE( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case B4SEPARATOR:
			if ( LDAP_SEPARATOR( *s ) ) {
				state = B4TYPE;
				*d++ = *s;
			}
			break;
		default:
			dn = NULL;
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

	if( gotesc ) {
		/* shouldn't be left in escape */
		dn = NULL;
	}

	/* check end state */
	switch( state ) {
	case B4LEADTYPE:	/* looking for first type */
	case B4SEPARATOR:	/* looking for separator */
	case INVALUE:		/* inside value */
		break;
	default:
		dn = NULL;
	}

	if( dn == NULL ) {
		return( ndn );
		ndn = NULL;
	}

	return( ndn );
}

/*
 * ldap_dn_parent - return a copy of the dn of dn's parent
 */

char *
ldap_dn_parent(
    const char *dn
)
{
	const char	*s;
	int	inquote;

	if( dn == NULL ) {
		return NULL;
	}

	while(*dn && LDAP_SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
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
			return( LDAP_STRDUP( &s[1] ) );
		}
	}

	/*
	 * else assume it is an X.500-style name, which looks like
	 * foo=bar,sha=baz,...
	 */

	inquote = 0;
	for ( s = dn; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) ) {
				s++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *s == '"' ) {
				inquote = 1;
			} else if ( LDAP_DNSEPARATOR( *s ) ) {
				return( LDAP_STRDUP( &s[1] ) );
			}
		}
	}

	return( LDAP_STRDUP( "" ) );
}

char * ldap_dn_rdn( 
    const char	*dn )
{
	char	*s;
	char	*rdn;
	int	inquote;

	if( dn == NULL ) {
		return NULL;
	}

	while(*dn && LDAP_SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
		return( NULL );
	}

	rdn = LDAP_STRDUP( dn );

	if( rdn == NULL ) {
		return NULL;
	}

#ifdef DNS_DN
	/*
	 * no =, assume it is a dns name, like blah@some.domain.name
	 * if the blah@ part is there, return some.domain.name.  if
	 * it's just some.domain.name, return domain.name.
	 */
	if ( strchr( rdn, '=' ) == NULL ) {
		if ( (s = strchr( rdn, '@' )) == NULL ) {
			if ( (s = strchr( rdn, '.' )) == NULL ) {
				return( rdn );
			}
		}
		*s = '\0';
		return( rdn );
	}
#endif

	/*
	 * else assume it is an X.500-style name, which looks like
	 * foo=bar,sha=baz,...
	 */

	inquote = 0;

	for ( s = rdn; *s; s++ ) {
		if ( *s == '\\' ) {
			if ( *(s + 1) ) {
				s++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *s == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *s == '"' ) {
				inquote = 1;
			} else if ( LDAP_DNSEPARATOR( *s ) ) {
				*s = '\0';
				return( rdn );
			}
		}
	}

	return( rdn );
}

#endif
