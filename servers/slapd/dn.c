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

/*
 * dn_pretty - "pretty" the DN
 */
char *dn_pretty( const char *dn_in )
{
	/*
	 * dn_validate based implementation (for now)
	 *	likely better just to zap this, dn_validate, dn_normalize
	 */
	char *dn, *dn_out;

	dn = ch_strdup( dn_in );
	dn_out = dn_validate( dn );
	if( dn_out == NULL ) free( dn );
	return dn_out;
}

/*
 * dn_validate - validate and compress dn.  the dn is
 * compressed in place are returned if valid.
 */

char *
dn_validate( char *dn_in )
{
#ifdef USE_LDAP_DN_PARSING
	struct berval	val, *normalized;
	int		rc;

	if ( dn_in == NULL || dn_in[ 0 ] == '\0' ) {
		return( dn_in );
	}

	val.bv_val = dn_in;
	val.bv_len = strlen( dn_in );

	rc = dnPretty( NULL, &val, &normalized );
	if ( rc != LDAP_SUCCESS ) {
		return( NULL );
	}

	if ( val.bv_len < normalized->bv_len ) {
		ber_bvfree( normalized );
		return( NULL );
	}

	AC_MEMCPY( dn_in, normalized->bv_val, normalized->bv_len + 1 );
	ber_bvfree( normalized );

	return( dn_in );
	
#else /* !USE_LDAP_DN_PARSING */
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
				!RDN_SEPARATOR( *s ) )
			{
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
#endif /* !USE_LDAP_DN_PARSING */
}

/*
 * dn_normalize - put dn into a canonical form suitable for storing
 * in a hash database.	this involves normalizing the case as well as
 * the format.	the dn is normalized in place as well as returned if valid.
 */

char *
dn_normalize( char *dn )
{
#ifdef USE_LDAP_DN_PARSING
	struct berval	val, *normalized;
	int		rc;

	if ( dn == NULL || dn[ 0 ] == '\0' ) {
		return( dn );
	}

	val.bv_val = dn;
	val.bv_len = strlen( dn );

	rc = dnNormalize( NULL, &val, &normalized );
	if ( rc != LDAP_SUCCESS ) {
		return( NULL );
	}

	if ( val.bv_len < normalized->bv_len ) {
		ber_bvfree( normalized );
		return( NULL );
	}

	AC_MEMCPY( dn, normalized->bv_val, normalized->bv_len + 1 );
	ber_bvfree( normalized );

	return( dn );
	
#else /* !USE_LDAP_DN_PARSING */
	char *out;
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

	return( out );
#endif /* !USE_LDAP_DN_PARSING */
}

int
dn_match( const char *val, const char *asserted )
{
	struct berval	bval, basserted;

	if ( val == NULL || asserted == NULL ) {
		return 0;
	}

	bval.bv_val = ( char * )val;
	bval.bv_len = strlen( val );

	basserted.bv_val = ( char * )asserted;
	basserted.bv_len = strlen( asserted);

	return dnMatch( NULL, 0, NULL, NULL, &bval, &basserted);
}

/*
 * dn_parent - return the dn's parent, in-place
 */

char *
dn_parent(
	Backend	*be,
	const char	*dn )
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
				return (char *)s + 1;
			}
		}
	}

	return "";
}

int dn_rdnlen(
	Backend	*be,
	const char	*dn_in )
{
	char	*dn, *s;
	int	inquote;

	if( dn_in == NULL ) {
		return 0;
	}

	while(*dn_in && ASCII_SPACE(*dn_in)) {
		dn_in++;
	}

	if( *dn_in == '\0' ) {
		return( 0 );
	}

	if ( be != NULL && be_issuffix( be, dn_in ) ) {
		return( 0 );
	}

	dn = dn_in;

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
				break;
			}
		}
	}

	return( s - dn );
}

char * dn_rdn(
	Backend	*be,
	const char	*dn_in )
{
	char *rdn;
	int i = dn_rdnlen( be, dn_in );

	rdn = ch_malloc( i + 1 );
	strncpy(rdn, dn_in, i);
	rdn[i] = '\0';
	return rdn;
}

/*
 * return a charray of all subtrees to which the DN resides in
 */
char **dn_subtree(
	Backend	*be,
	const char	*dn )
{
	char **subtree = NULL;
	
	do {
		charray_add( &subtree, dn );

		dn = dn_parent( be, dn );

	} while ( dn != NULL );

	return subtree;
}


/*
 * dn_issuffix - tells whether suffix is a suffix of dn. Both dn
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
 *   "attribute_type=attribute_value[+attribute_type=attribute_value[...]]"
 * this function stores the types of the attributes in ptypes, that is the
 * array of strings "attribute_type" which is placed in newly allocated
 * memory, and the values of the attributes in pvalues, that is the
 * array of strings "attribute_value" which is placed in newly allocated
 * memory. Returns 0 on success, -1 on failure.
 *
 * note: got part of the code from dn_validate
 */

int
rdn_attrs( const char * rdn_in, char ***ptypes, char ***pvalues)
{
	char **parts, **p;

	*ptypes = NULL;
	*pvalues = NULL;

	/*
	 * explode the rdn in parts
	 */
	parts = ldap_explode_rdn( rdn_in, 0 );

	if ( parts == NULL ) {
		return( -1 );
	}

	for ( p = parts; p[0]; p++ ) {
		char *s, *e, *d;
		
		/* split each rdn part in type value */
		s = strchr( p[0], '=' );
		if ( s == NULL ) {
			charray_free( *ptypes );
			charray_free( *pvalues );
			charray_free( parts );
			return( -1 );
		}
		
		/* type should be fine */
		charray_add_n( ptypes, p[0], ( s-p[0] ) );

		/* value needs to be unescaped
		 * (maybe this should be moved to ldap_explode_rdn?) */
		for ( e = d = s + 1; e[0]; e++ ) {
			if ( *e != '\\' ) {
				*d++ = *e;
			}
		}
		d[0] = '\0';
		charray_add( pvalues, s + 1 );
	}

	/* free array */
	charray_free( parts );

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
 * Used by ldbm/bdb2 back_modrdn to create the new dn of entries being
 * renamed.
 *
 * new_dn = parent (p_dn) + separator(s) + rdn (newrdn) + null.
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
