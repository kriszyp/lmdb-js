/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
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
static void at_index_print( void ) 
{
}
#endif

void
attr_free( Attribute *a )
{
	ber_bvarray_free( a->a_vals );
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

		for( i=0; a->a_vals[i].bv_val != NULL; i++ ) {
			/* EMPTY */ ;
		}

		tmp->a_vals = ch_malloc((i+1) * sizeof(struct berval));

		for( i=0; a->a_vals[i].bv_val != NULL; i++ ) {
			ber_dupbv( &tmp->a_vals[i], &a->a_vals[i] );
			if( tmp->a_vals[i].bv_val == NULL ) break;
		}

		tmp->a_vals[i].bv_val = NULL;

	} else {
		tmp->a_vals = NULL;
	}

	tmp->a_desc = a->a_desc;
	tmp->a_next = NULL;
	tmp->a_flags = 0;

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



/*
 * attr_merge - merge the given type and value with the list of
 * attributes in attrs.
 * returns	0	everything went ok
 *		-1	trouble
 */

int
attr_merge(
	Entry		*e,
	AttributeDescription *desc,
	BerVarray	vals )
{
	Attribute	**a;

	for ( a = &e->e_attrs; *a != NULL; a = &(*a)->a_next ) {
		if ( ad_cmp( (*a)->a_desc, desc ) == 0 ) {
			break;
		}
	}

	if ( *a == NULL ) {
		*a = (Attribute *) ch_malloc( sizeof(Attribute) );
		(*a)->a_desc = desc;
		(*a)->a_vals = NULL;
		(*a)->a_next = NULL;
		(*a)->a_flags = 0;
	}

	return( value_add( &(*a)->a_vals, vals ) );
}

int
attr_merge_one(
	Entry		*e,
	AttributeDescription *desc,
	struct berval	*val )
{
	Attribute	**a;

	for ( a = &e->e_attrs; *a != NULL; a = &(*a)->a_next ) {
		if ( ad_cmp( (*a)->a_desc, desc ) == 0 ) {
			break;
		}
	}

	if ( *a == NULL ) {
		*a = (Attribute *) ch_malloc( sizeof(Attribute) );
		(*a)->a_desc = desc;
		(*a)->a_vals = NULL;
		(*a)->a_next = NULL;
		(*a)->a_flags = 0;
	}

	return( value_add_one( &(*a)->a_vals, val ) );
}

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
		if ( is_ad_subtype( a->a_desc, desc ) ) {
			return( a );
		}
	}

	return( NULL );
}

/*
 * attr_find - find attribute by type
 */

Attribute *
attr_find(
    Attribute	*a,
	AttributeDescription *desc
)
{
	for ( ; a != NULL; a = a->a_next ) {
		if ( ad_cmp( a->a_desc, desc ) == 0 ) {
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
	AttributeDescription *desc
)
{
	Attribute	**a;

	for ( a = attrs; *a != NULL; a = &(*a)->a_next ) {
		if ( ad_cmp( (*a)->a_desc, desc ) == 0 ) {
			Attribute	*save = *a;
			*a = (*a)->a_next;
			attr_free( save );

			return LDAP_SUCCESS;
		}
	}

	return LDAP_NO_SUCH_ATTRIBUTE;
}

