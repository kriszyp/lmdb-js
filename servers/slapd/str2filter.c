/* str2filter.c - parse an rfc 1588 string filter */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "slap.h"
#include <ldap_pvt.h>

static char	*find_matching_paren(char *s);
static Filter	*str2list(char *str, long unsigned int ftype);
static Filter	*str2simple(char *str);
static int	str2subvals(char *val, Filter *f);

Filter *
str2filter( char *str )
{
	Filter	*f = NULL;
	char	*end, *freeme;

	Debug( LDAP_DEBUG_FILTER, "str2filter \"%s\"\n", str, 0, 0 );

	if ( str == NULL || *str == '\0' ) {
		return( NULL );
	}

	str = freeme = ch_strdup( str );

	switch ( *str ) {
	case '(':
		if ( (end = find_matching_paren( str )) == NULL ) {
			filter_free( f );
			free( freeme );
			return( NULL );
		}
		*end = '\0';

		str++;
		switch ( *str ) {
		case '&':
			Debug( LDAP_DEBUG_FILTER, "str2filter: AND\n",
			    0, 0, 0 );

			str++;
			f = str2list( str, LDAP_FILTER_AND );
			break;

		case '|':
			Debug( LDAP_DEBUG_FILTER, "put_filter: OR\n",
			    0, 0, 0 );

			str++;
			f = str2list( str, LDAP_FILTER_OR );
			break;

		case '!':
			Debug( LDAP_DEBUG_FILTER, "put_filter: NOT\n",
			    0, 0, 0 );

			str++;
			f = str2list( str, LDAP_FILTER_NOT );
			break;

		default:
			Debug( LDAP_DEBUG_FILTER, "str2filter: simple\n",
			    0, 0, 0 );

			f = str2simple( str );
			break;
		}
		*end = ')';
		break;

	default:	/* assume it's a simple type=value filter */
		Debug( LDAP_DEBUG_FILTER, "str2filter: default\n", 0, 0,
		    0 );

		f = str2simple( str );
		break;
	}

	free( freeme );
	return( f );
}

/*
 * Put a list of filters like this "(filter1)(filter2)..."
 */

static Filter *
str2list( char *str, unsigned long ftype )
{
	Filter	*f;
	Filter	**fp;
	char	*next;
	char	save;

	Debug( LDAP_DEBUG_FILTER, "str2list \"%s\"\n", str, 0, 0 );

	f = (Filter *) ch_calloc( 1, sizeof(Filter) );
	f->f_choice = ftype;
	fp = &f->f_list;

	while ( *str ) {
		while ( *str && isspace( (unsigned char) *str ) )
			str++;
		if ( *str == '\0' )
			break;

		if ( (next = find_matching_paren( str )) == NULL ) {
			filter_free( f );
			return( NULL );
		}
		save = *++next;
		*next = '\0';

		/* now we have "(filter)" with str pointing to it */
		if ( (*fp = str2filter( str )) == NULL ) {
			filter_free( f );
			*next = save;
			return( NULL );
		}
		*next = save;

		str = next;
		fp = &(*fp)->f_next;
	}
	*fp = NULL;

	return( f );
}

static Filter *
str2simple( char *str )
{
	Filter		*f;
	char		*s;
	char		*value, savechar;

	Debug( LDAP_DEBUG_FILTER, "str2simple \"%s\"\n", str, 0, 0 );

	if ( (s = strchr( str, '=' )) == NULL ) {
		return( NULL );
	}
	value = s + 1;
	*s-- = '\0';
	savechar = *s;

	f = (Filter *) ch_calloc( 1, sizeof(Filter) );

	switch ( *s ) {
	case '<':
		f->f_choice = LDAP_FILTER_LE;
		*s = '\0';
		break;
	case '>':
		f->f_choice = LDAP_FILTER_GE;
		*s = '\0';
		break;
	case '~':
		f->f_choice = LDAP_FILTER_APPROX;
		*s = '\0';
		break;
	default:
		if ( ldap_pvt_find_wildcard( value ) == NULL ) {
			f->f_choice = LDAP_FILTER_EQUALITY;
		} else if ( strcmp( value, "*" ) == 0 ) {
			f->f_choice = LDAP_FILTER_PRESENT;
		} else {
			f->f_choice = LDAP_FILTER_SUBSTRINGS;
			f->f_sub_type = ch_strdup( str );
			if ( str2subvals( value, f ) != 0 ) {
				filter_free( f );
				*(value-1) = '=';
				return( NULL );
			}
			*(value-1) = '=';
			return( f );
		}
		break;
	}

	if ( f->f_choice == LDAP_FILTER_PRESENT ) {
		f->f_type = ch_strdup( str );
	} else {
		f->f_avtype = ch_strdup( str );
		f->f_avvalue.bv_val = ch_strdup( value );
		ldap_pvt_filter_value_unescape( f->f_avvalue.bv_val );
		f->f_avvalue.bv_len = strlen( value );
	}

	*s = savechar;
	*(value-1) = '=';
	return( f );
}

static int
str2subvals( char *val, Filter *f )
{
	char	*nextstar, *freeme;
	int	gotstar;

	Debug( LDAP_DEBUG_FILTER, "str2subvals \"%s\"\n", val, 0, 0 );

	val = freeme = ch_strdup( val );
	gotstar = 0;
	while ( val != NULL && *val ) {
		if ( (nextstar = ldap_pvt_find_wildcard( val )) != NULL )
			*nextstar++ = '\0';

		ldap_pvt_filter_value_unescape( val );
		if ( gotstar == 0 ) {
			f->f_sub_initial = ch_strdup( val );
		} else if ( nextstar == NULL ) {
			f->f_sub_final = ch_strdup( val );
		} else {
			charray_add( &f->f_sub_any, val );
		}

		gotstar = 1;
		val = nextstar;
	}

	free( freeme );
	return( 0 );
}

/*
 * find_matching_paren - return a pointer to the right paren in s matching
 * the left paren to which *s currently points
 */

static char *
find_matching_paren( char *s )
{
	int	balance, escape;

	balance = 0;
	escape = 0;
	for ( ; *s; s++ ) {
		if ( escape == 0 ) {
			if ( *s == '(' )
				balance++;
			else if ( *s == ')' )
				balance--;
		}
		if ( balance == 0 ) {
			return( s );
		}
		if ( *s == '\\' && ! escape )
			escape = 1;
		else
			escape = 0;
	}

	return( NULL );
}
