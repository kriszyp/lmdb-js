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

#include "slap.h"

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
 * dn_normalize - put dn into a canonical format.  the dn is
 * normalized in place, as well as returned if valid.
 */

char *
dn_normalize( char *dn )
{
	char	*d, *s;
	int	state, gotesc;

	gotesc = 0;
	state = B4LEADTYPE;
	for ( d = s = dn; *s; s++ ) {
		switch ( state ) {
		case B4LEADTYPE:
		case B4TYPE:
			if ( LEADOIDCHAR(*s) ) {
				state = INOIDTYPE;
				*d++ = *s;
			} else if ( LEADKEYCHAR(*s) ) {
				state = INKEYTYPE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) {
				dn = NULL;
				state = INKEYTYPE;
				*d++ = *s;
			}
			break;

		case INOIDTYPE:
			if ( OIDCHAR(*s) ) {
				*d++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				dn = NULL;
				*d++ = *s;
			}
			break;

		case INKEYTYPE:
			if ( KEYCHAR(*s) ) {
				*d++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( SPACE( *s ) ) {
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
			} else if ( ! SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*d++ = *s;
				dn = NULL;
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

	return( dn );
}

/*
 * dn_normalize_case - put dn into a canonical form suitable for storing
 * in a hash database.  this involves normalizing the case as well as
 * the format.  the dn is normalized in place as well as returned if valid.
 */

char *
dn_normalize_case( char *dn )
{
	str2upper( dn );

	/* normalize format */
	dn = dn_normalize( dn );

	/* and upper case it */
	return( dn );
}

/*
 * dn_parent - return a copy of the dn of dn's parent
 */

char *
dn_parent(
    Backend	*be,
    const char	*dn
)
{
	const char	*s;
	int	inquote;

	if( dn == NULL ) {
		return NULL;
	}

	while(*dn && SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
		return( NULL );
	}

	if ( be != NULL && be_issuffix( be, dn ) ) {
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
			return( ch_strdup( &s[1] ) );
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
			} else if ( DNSEPARATOR( *s ) ) {
				return( ch_strdup( &s[1] ) );
			}
		}
	}

	return( ch_strdup( "" ) );
}

char * dn_rdn( 
    Backend	*be,
    char	*dn )
{
	char	*s;
	int	inquote;

	if( dn == NULL ) {
		return NULL;
	}

	while(*dn && SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
		return( NULL );
	}

	if ( be != NULL && be_issuffix( be, dn ) ) {
		return( NULL );
	}

	dn = ch_strdup( dn );

#ifdef DNS_DN
	/*
	 * no =, assume it is a dns name, like blah@some.domain.name
	 * if the blah@ part is there, return some.domain.name.  if
	 * it's just some.domain.name, return domain.name.
	 */
	if ( strchr( dn, '=' ) == NULL ) {
		if ( (s = strchr( dn, '@' )) == NULL ) {
			if ( (s = strchr( dn, '.' )) == NULL ) {
				return( dn );
			}
		}
		*s = '\0';
		return( dn );
	}
#endif

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
			} else if ( DNSEPARATOR( *s ) ) {
				*s = '\0';
				return( dn );
			}
		}
	}

	return( dn );
}


/*
 * return a charray of all subtrees to which the DN resides in
 */
char **dn_subtree(
	Backend	*be,
    const char	*dn )
{
	char *child, *parent;
	char **subtree = NULL;
	
	child = ch_strdup( dn );

	do {
		charray_add( &subtree, child );

		parent = dn_parent( be, child );

		free( child );

		child = parent;
	} while ( child != NULL );

	return subtree;
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

	return( strcmp( dn + dnlen - suffixlen, suffix ) == 0 );
}

#ifdef DNS_DN
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
#endif

char *
str2upper( char *str )
{
	char    *s;

	/* normalize case */
	for ( s = str; *s; s++ ) {
		*s = TOUPPER( (unsigned char) *s );
	}

	return( str );
}

char *
str2lower( char *str )
{
	char    *s;

	/* normalize case */
	for ( s = str; *s; s++ ) {
		*s = TOLOWER( (unsigned char) *s );
	}

	return( str );
}


/*
 * get_next_substring(), rdn_attr_type(), rdn_attr_value(), and
 * build_new_dn().
 * 
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

/* get_next_substring:
 *
 * Gets next substring in s, using d (or the end of the string '\0') as a 
 * string delimiter, and places it in a duplicated memory space. Leading 
 * spaces are ignored. String s **must** be null-terminated.
 */ 

static char * 
get_next_substring( char * s, char d )
{

	char	*str, *r;

	r = str = ch_malloc( strlen(s) + 1 );

	/* Skip leading spaces */
	
	while ( *s && SPACE(*s) ) {
	    
		s++;
	    
	}
	
	/* Copy word */

	while ( *s && (*s != d) ) {

		/* Don't stop when you see trailing spaces may be a multi-word
		* string, i.e. name=John Doe!
		*/

		*str++ = *s++;
	    
	}
	
	*str = '\0';
	
	return r;
	
}


/* rdn_attr_type:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns the type of an attribute, that is the 
 * string "attribute_type" which is placed in newly allocated 
 * memory. The returned string will be null-terminated.
 */

char * rdn_attr_type( char * s )
{

	return get_next_substring( s, '=' );

}


/* rdn_attr_value:
 *
 * Given a string (i.e. an rdn) of the form:
 *	 "attribute_type = attribute_value"
 * this function returns "attribute_type" which is placed in newly allocated 
 * memory. The returned string will be null-terminated and may contain 
 * spaces (i.e. "John Doe\0").
 */

char * 
rdn_attr_value( char * rdn )
{

	char	*str;

	if ( (str = strchr( rdn, '=' )) != NULL ) {

		return get_next_substring(++str, '\0');

	}

	return NULL;

}


int rdn_validate( const char * rdn )
{
	/* just a simple check for now */
	return strchr( rdn, '=' ) != NULL;
}


/* build_new_dn:
 *
 * Used by ldbm/bdb2_back_modrdn to create the new dn of entries being
 * renamed.
 *
 * new_dn = parent (p_dn)  + separator(s) + rdn (newrdn) + null.
 */

void
build_new_dn( char ** new_dn,
	const char *e_dn,
	const char * p_dn,
	const char * newrdn )
{

    if ( p_dn == NULL ) {

	*new_dn = ch_strdup( newrdn );
	return;

    }
    
    *new_dn = (char *) ch_malloc( strlen( p_dn ) + strlen( newrdn ) + 3 );

#ifdef DNS_DN
    if ( dn_type( e_dn ) == DN_X500 ) {
#endif

	strcpy( *new_dn, newrdn );
	strcat( *new_dn, "," );
	strcat( *new_dn, p_dn );

#ifdef DNS_DN
    } else {

	char	*s;
	char	sep[2];

	strcpy( *new_dn, newrdn );
	s = strchr( newrdn, '\0' );
	s--;

	if ( (*s != '.') && (*s != '@') ) {

	    if ( (s = strpbrk( e_dn, ".@" )) != NULL ) {

		sep[0] = *s;
		sep[1] = '\0';
		strcat( *new_dn, sep );

	    }

	}

	strcat( *new_dn, p_dn );

    }
#endif
    
}
