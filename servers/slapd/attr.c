/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* attr.c - routines for dealing with attributes */

#include "portable.h"

#include <stdio.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_pvt.h"
#include "slap.h"

#ifdef LDAP_DEBUG
static void at_index_print( void );
#endif

void
attr_free( Attribute *a )
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	ad_free( a->a_desc, 1 );
#else
	free( a->a_type );
#endif
	ber_bvecfree( a->a_vals );
	free( a );
}

void
attrs_free( Attribute *a )
{
	Attribute *next;

	for( ; a != NULL ; a = next ) {
		next = a->a_next;
		attr_free( a );
	}
}

Attribute *attr_dup( Attribute *a )
{
	Attribute *tmp;

	if( a == NULL) return NULL;

	tmp = ch_malloc( sizeof(Attribute) );

	if( a->a_vals != NULL ) {
		int i;

		for( i=0; a->a_vals[i] != NULL; i++ ) {
			/* EMPTY */ ;
		}

		tmp->a_vals = ch_malloc((i+1) * sizeof(struct berval*));

		for( i=0; a->a_vals[i] != NULL; i++ ) {
			tmp->a_vals[i] = ber_bvdup( a->a_vals[i] );

			if( tmp->a_vals[i] == NULL ) break;
		}

		tmp->a_vals[i] = NULL;

	} else {
		tmp->a_vals = NULL;
	}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	tmp->a_desc = ad_dup( a->a_desc );
#else
	tmp->a_type = ch_strdup( a->a_type );
	tmp->a_syntax = a->a_syntax;
#endif
	tmp->a_next = NULL;

	return tmp;
}

Attribute *attrs_dup( Attribute *a )
{
	Attribute *tmp, **next;

	if( a == NULL ) return NULL;

	tmp = NULL;
	next = &tmp;

	for( ; a != NULL ; a = a->a_next ) {
		*next = attr_dup( a );
		next = &((*next)->a_next);
	}
	*next = NULL;

	return tmp;
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
/*
 * attr_normalize - normalize an attribute name (make it all lowercase)
 */

char *
attr_normalize( char *s )
{
	assert( s != NULL );

	return( ldap_pvt_str2lower( s ) );
}
#endif

#ifndef SLAPD_SCHEMA_NOT_COMPAT
/*
 * attr_merge_fast - merge the given type and value with the list of
 * attributes in attrs. called from str2entry(), where we can make some
 * assumptions to make things faster.
 * returns	0	everything went ok
 *		-1	trouble
 */

int
attr_merge_fast(
    Entry		*e,
    const char		*type,
    struct berval	**vals,
    int			nvals,
    int			naddvals,
    int			*maxvals,
    Attribute		***a
)
{
	if ( *a == NULL ) {
		for ( *a = &e->e_attrs; **a != NULL; *a = &(**a)->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			/* not yet implemented */
#else
			if ( strcasecmp( (**a)->a_type, type ) == 0 ) {
				break;
			}
#endif
		}
	}

	if ( **a == NULL ) {
		**a = (Attribute *) ch_malloc( sizeof(Attribute) );
		(**a)->a_vals = NULL;
#ifndef SLAPD_SCHEMA_NOT_COMPAT
		(**a)->a_type = attr_normalize( ch_strdup( type ) );
		(**a)->a_syntax = attr_syntax( type );
#endif
		(**a)->a_next = NULL;
	}

	return( value_add_fast( &(**a)->a_vals, vals, nvals, naddvals,
	    maxvals ) );
}
#endif

/*
 * attr_merge - merge the given type and value with the list of
 * attributes in attrs.
 * returns	0	everything went ok
 *		-1	trouble
 */

int
attr_merge(
    Entry		*e,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc,
#else
    const char		*type,
#endif
    struct berval	**vals )
{
	Attribute	**a;

	for ( a = &e->e_attrs; *a != NULL; a = &(*a)->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* not yet implemented */
#else
		if ( strcasecmp( (*a)->a_type, type ) == 0 ) {
			break;
		}
#endif
	}

	if ( *a == NULL ) {
		*a = (Attribute *) ch_malloc( sizeof(Attribute) );
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* not yet implemented */
#else
		(*a)->a_type = attr_normalize( ch_strdup( type ) );
		(*a)->a_syntax = attr_syntax( type );
#endif
		(*a)->a_vals = NULL;
		(*a)->a_next = NULL;
	}

	return( value_add( &(*a)->a_vals, vals ) );
}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
/*
 * attrs_find - find attribute(s) by AttributeDescription
 * returns next attribute which is subtype of provided description.
 */

Attribute *
attrs_find(
    Attribute	*a,
	AttributeDescription *desc
)
{
	for ( ; a != NULL; a = a->a_next ) {
		if ( is_ad_subtype( a->a_desc, desc ) == 0 ) {
			return( a );
		}
	}

	return( NULL );
}
#endif

/*
 * attr_find - find attribute by type
 */

Attribute *
attr_find(
    Attribute	*a,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc
#else
	const char	*type
#endif
)
{
	for ( ; a != NULL; a = a->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		if ( ad_cmp( a->a_desc, desc ) == 0 )
#else
		if ( strcasecmp( a->a_type, type ) == 0 )
#endif
		{
			return( a );
		}
	}

	return( NULL );
}

/*
 * attr_delete - delete the attribute type in list pointed to by attrs
 * return	0	deleted ok
 * 		1	not found in list a
 * 		-1	something bad happened
 */

int
attr_delete(
    Attribute	**attrs,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc
#else
    const char	*type
#endif
)
{
	Attribute	**a;
	Attribute	*save;

	for ( a = attrs; *a != NULL; a = &(*a)->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* not yet implemented */
#else
		if ( strcasecmp( (*a)->a_type, type ) == 0 ) {
			break;
		}
#endif
	}

	if ( *a == NULL ) {
		return( 1 );
	}

	save = *a;
	*a = (*a)->a_next;
	attr_free( save );

	return( 0 );
}

