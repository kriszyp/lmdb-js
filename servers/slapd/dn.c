/* dn.c - routines for dealing with distinguished names */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_pvt.h"

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

#define UTF8DN 1

/*
 * dn_validate - validate and compress dn.  the dn is
 * compressed in place are returned if valid.
 */

char *
dn_validate( char *dn_in )
{
	char	*d, *s;
	int	state, gotesc;
	char	*dn = dn_in;

	gotesc = 0;
	state = B4LEADTYPE;
	for ( d = s = dn; *s; s++ ) {
		switch ( state ) {
		case B4LEADTYPE:
		case B4TYPE:
			if ( OID_LEADCHAR(*s) ) {
				state = INOIDTYPE;
				*d++ = *s;
			} else if ( ATTR_LEADCHAR(*s) ) {
				state = INKEYTYPE;
				*d++ = *s;
			} else if ( ! ASCII_SPACE( *s ) ) {
				dn = NULL;
				state = INKEYTYPE;
				*d++ = *s;
			}
			break;

		case INOIDTYPE:
			if ( OID_CHAR(*s) ) {
				*d++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( ASCII_SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				dn = NULL;
				*d++ = *s;
			}
			break;

		case INKEYTYPE:
			if ( ATTR_CHAR(*s) ) {
				*d++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( ASCII_SPACE( *s ) ) {
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
			} else if ( ! ASCII_SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*d++ = *s;
				dn = NULL;
			}
			break;

		case B4VALUE:
			if ( *s == '"' ) {
				state = INQUOTEDVALUE;
				*d++ = *s;
			} else if ( ! ASCII_SPACE( *s ) ) { 
				state = INVALUE;
				*d++ = *s;
			}
			break;

		case INVALUE:
			if ( !gotesc && RDN_SEPARATOR( *s ) ) {
				while ( ASCII_SPACE( *(d - 1) ) )
					d--;
				state = B4TYPE;
				if ( *s == '+' ) {
					*d++ = *s;
				} else {
					*d++ = ',';
				}
			} else if ( gotesc && !RDN_NEEDSESCAPE( *s ) &&
			    !RDN_SEPARATOR( *s ) ) {
				*--d = *s;
				d++;
			} else if( !ASCII_SPACE( *s ) || !ASCII_SPACE( *(d - 1) ) ) {
				*d++ = *s;
			}
			break;

		case INQUOTEDVALUE:
			if ( !gotesc && *s == '"' ) {
				state = B4SEPARATOR;
				*d++ = *s;
			} else if ( gotesc && !RDN_NEEDSESCAPE( *s ) ) {
				*--d = *s;
				d++;
			} else if( !ASCII_SPACE( *s ) || !ASCII_SPACE( *(d - 1) ) ) {
				*d++ = *s;
			}
			break;

		case B4SEPARATOR:
			if ( RDN_SEPARATOR( *s ) ) {
				state = B4TYPE;
				*d++ = *s;
			} else if ( !ASCII_SPACE( *s ) ) {
				dn = NULL;
			}
			break;

		default:
			dn = NULL;
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
				   "dn_validate: unknown state %d for dn \"%s\".\n",
				   state, dn_in ));
#else
			Debug( LDAP_DEBUG_ANY,
			    "dn_validate - unknown state %d\n", state, 0, 0 );
#endif
			break;
		}

		if ( *s == '\\' ) {
			gotesc = 1;
		} else {
			gotesc = 0;
		}
	}

	/* trim trailing spaces */
	while( d > dn_in && ASCII_SPACE( *(d-1) ) ) {
		--d;
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
 * dn_normalize - put dn into a canonical form suitable for storing
 * in a hash database.	this involves normalizing the case as well as
 * the format.	the dn is normalized in place as well as returned if valid.
 */

char *
dn_normalize( char *dn )
{
	char *out;
	/* upper case it */
#ifndef UTF8DN
	ldap_pvt_str2upper( dn );
	/* validate and compress dn */
	out = dn_validate( dn );
#else
	/* enabling this might require reindexing */
	struct berval *bvdn, *nbvdn;

	out = NULL;
	bvdn = ber_bvstr( dn );
	
	if ( dnNormalize( NULL, bvdn, &nbvdn ) == LDAP_SUCCESS ) {
		if ( nbvdn->bv_len <= bvdn->bv_len ) {
			out = dn;
			strcpy( out, nbvdn->bv_val );
		}
		ber_bvfree( nbvdn );
	}
	bvdn->bv_val = NULL; /* prevent bvfree from freeing dn */
	ber_bvfree( bvdn );
#endif

	return( out );
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

	while(*dn != '\0' && ASCII_SPACE(*dn)) {
		dn++;
	}

	if( *dn == '\0' ) {
		return NULL;
	}

	if ( be != NULL && be_issuffix( be, dn ) ) {
		return NULL;
	}

	/*
	 * assume it is an X.500-style name, which looks like
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
			} else if ( DN_SEPARATOR( *s ) ) {
				return ch_strdup( &s[1] );
			}
		}
	}

	return ch_strdup( "" );
}

char * dn_rdn( 
    Backend	*be,
    const char	*dn_in )
{
	char	*dn, *s;
	int	inquote;

	if( dn_in == NULL ) {
		return NULL;
	}

	while(*dn_in && ASCII_SPACE(*dn_in)) {
		dn_in++;
	}

	if( *dn_in == '\0' ) {
		return( NULL );
	}

	if ( be != NULL && be_issuffix( be, dn_in ) ) {
		return( NULL );
	}

	dn = ch_strdup( dn_in );

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
			} else if ( DN_SEPARATOR( *s ) ) {
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
    const char	*dn,
    const char	*suffix
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
get_next_substring( const char * s, char d )
{

	char	*str, *r;

	r = str = ch_malloc( strlen(s) + 1 );

	/* Skip leading spaces */
	
	while ( *s && ASCII_SPACE(*s) ) {
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

char * rdn_attr_type( const char * s )
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
rdn_attr_value( const char * rdn )
{

	const char	*str;

	if ( (str = strchr( rdn, '=' )) != NULL ) {
		return get_next_substring(++str, '\0');
	}

	return NULL;

}


/* rdn_attrs:
 *
 * Given a string (i.e. an rdn) of the form:
 *       "attribute_type=attribute_value[+attribute_type=attribute_value[...]]"
 * this function stores the types of the attributes in ptypes, that is the 
 * array of strings "attribute_type" which is placed in newly allocated 
 * memory, and the values of the attributes in pvalues, that is the
 * array of strings "attribute_value" which is placed in newly allocated
 * memory. Returns 1 on success, 0 on failure.
 *
 * note: got part of the code from dn_validate
 */
int
rdn_attrs( const char * rdn_in, char ***ptypes, char ***pvalues)
{
	char	*start, *end, *s;
	int	state, gotesc, t = 0, v = 0;
	char	*dn = ch_strdup( rdn_in );

	*ptypes = NULL;
	*pvalues = NULL;

	gotesc = 0;
	state = B4LEADTYPE;
	for ( start = end = s = dn; *s; s++ ) {
		switch ( state ) {
		case B4LEADTYPE:
		case B4TYPE:
			if ( OID_LEADCHAR(*s) ) {
				state = INOIDTYPE;
				start = end;
				*end++ = *s;
			} else if ( ATTR_LEADCHAR(*s) ) {
				state = INKEYTYPE;
				start = end;
				*end++ = *s;
			} else if ( ! ASCII_SPACE( *s ) ) {
				goto failure;
				state = INKEYTYPE;
				*end++ = *s;
			}
			break;

		case INOIDTYPE:
			if ( OID_CHAR(*s) ) {
				*end++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				charray_add_n( ptypes, start, ( end - start ) );
				t++;
				*end++ = *s;
			} else if ( ASCII_SPACE( *s ) ) {
				state = B4EQUAL;
				charray_add_n( ptypes, start, ( end - start ) );
				t++;
			} else {
				*end++ = *s;
				goto failure;
			}
			break;

		case INKEYTYPE:
			if ( ATTR_CHAR(*s) ) {
				*end++ = *s;
			} else if ( *s == '=' ) {
				state = B4VALUE;
				charray_add_n( ptypes, start, ( end - start ) );
				t++;
				*end++ = *s;
			} else if ( ASCII_SPACE( *s ) ) {
				state = B4EQUAL;
				charray_add_n( ptypes, start, ( end - start ) );
				t++;
			} else {
				*end++ = *s;
				goto failure;
			}
			break;

		case B4EQUAL:
			if ( *s == '=' ) {
				state = B4VALUE;
				*end++ = *s;
			} else if ( ! ASCII_SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*end++ = *s;
				goto failure;
			}
			break;

		case B4VALUE:
			if ( *s == '"' ) {
				state = INQUOTEDVALUE;
				start = end;
				*end++ = *s;
			} else if ( ! ASCII_SPACE( *s ) ) { 
				state = INVALUE;
				start = end;
				*end++ = *s;
			}
			break;

		case INVALUE:
			if ( !gotesc && RDN_SEPARATOR( *s ) ) {
				while ( ASCII_SPACE( *(end - 1) ) )
					end--;
				state = B4TYPE;
				if ( RDN_ATTRTYPEANDVALUE_SEPARATOR( *s ) ) {
					if ( ++v != t ) {
						goto failure;
					}
					charray_add_n( pvalues, start, ( end - start ) );
					*end++ = *s;
				} else {
					/* not a rdn! */
					goto failure;
				}
			} else if ( gotesc && !RDN_NEEDSESCAPE( *s ) &&
			    !RDN_SEPARATOR( *s ) ) {
				*--end = *s;
				end++;
			} else if( !ASCII_SPACE( *s ) || !ASCII_SPACE( *(end - 1) ) ) {
				*end++ = *s;
			}
			break;

		case INQUOTEDVALUE:
			if ( !gotesc && *s == '"' ) {
				state = B4SEPARATOR;
				*end++ = *s;
			} else if ( gotesc && !RDN_NEEDSESCAPE( *s ) ) {
				*--end = *s;
				end++;
			} else if( !ASCII_SPACE( *s ) || !ASCII_SPACE( *(end - 1) ) ) {
				*end++ = *s;
			}
			break;

		case B4SEPARATOR:
			if ( RDN_SEPARATOR( *s ) ) {
				state = B4TYPE;
				if ( RDN_ATTRTYPEANDVALUE_SEPARATOR( *s ) ) {
					if ( ++v != t ) {
						goto failure;
					}
					charray_add_n( pvalues, start, ( end - start ) );
					*end++ = *s;
				} else {
					/* not a rdn! */
					goto failure;
				}
			} else if ( !ASCII_SPACE( *s ) ) {
				goto failure;
			}
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
				   "rdn_attrs: unknown state %d for rdn \"%s\".\n",
				   state, dn_in ));
#else
			Debug( LDAP_DEBUG_ANY,
			    "rdn_attrs - unknown state %d\n", state, 0, 0 );
#endif
			goto failure;
		}

		if ( *s == '\\' ) {
			gotesc = 1;
		} else {
			gotesc = 0;
		}
	}

	if( gotesc ) {
		/* shouldn't be left in escape */
		goto failure;
	}

	/* check end state */
	switch( state ) {
	case B4LEADTYPE:	/* looking for first type */
	case B4SEPARATOR:	/* looking for separator */
	case INVALUE:		/* inside value */
		if ( ++v != t ) {
			goto failure;
		}
		charray_add_n( pvalues, start, ( end - start ) );
		break;
	default:
		goto failure;
	}
	ch_free( dn );
	
	return( 1 );

failure:
	ch_free( dn );
	charray_free( *ptypes );
	*ptypes = NULL;
	charray_free( *pvalues );
	*pvalues = NULL;

	return( 0 );
}


/* rdn_validate:
 * 
 * 1 if rdn is a legal rdn; 
 * 0 otherwise (including a sequence of rdns)
 *
 * note: got it from dn_rdn; it should be rewritten 
 * according to dn_validate
 */
int
rdn_validate( const char * rdn )
{
	int	inquote;

	if ( rdn == NULL ) {
		return( 0 );
	}

	if ( strchr( rdn, '=' ) == NULL ) {
		return( 0 );
	}

	while ( *rdn && ASCII_SPACE( *rdn ) ) {
		rdn++;
	}

	if( *rdn == '\0' ) {
		return( 0 );
	}

	inquote = 0;

	for ( ; *rdn; rdn++ ) {
		if ( *rdn == '\\' ) {
			if ( *(rdn + 1) ) {
				rdn++;
			}
			continue;
		}
		if ( inquote ) {
			if ( *rdn == '"' ) {
				inquote = 0;
			}
		} else {
			if ( *rdn == '"' ) {
				inquote = 1;
			} else if ( DN_SEPARATOR( *rdn ) ) {
				return( 0 );
			}
		}
	}

	return( 1 );
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

	strcpy( *new_dn, newrdn );
	strcat( *new_dn, "," );
	strcat( *new_dn, p_dn );
}
