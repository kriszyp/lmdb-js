/* attr.c - routines for dealing with attributes */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

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

#include "slap.h"

Attribute *
attr_alloc( AttributeDescription *ad )
{
	Attribute *a = ch_malloc( sizeof(Attribute) );

	a->a_desc = ad;
	a->a_next = NULL;
	a->a_flags = 0;
	a->a_vals = NULL;
	a->a_nvals = NULL;
#ifdef LDAP_COMP_MATCH
	a->a_comp_data = NULL;
#endif

	return a;
}

void
attr_free( Attribute *a )
{
	if ( a->a_nvals && a->a_nvals != a->a_vals ) {
		ber_bvarray_free( a->a_nvals );
	}
	/* a_vals may be equal to slap_dummy_bv, a static empty berval;
	 * this is used as a placeholder for attributes that do not carry
	 * values, e.g. when proxying search entries with the "attrsonly"
	 * bit set. */
	if ( a->a_vals != &slap_dummy_bv ) {
		ber_bvarray_free( a->a_vals );
	}
	free( a );
}

#ifdef LDAP_COMP_MATCH
void
comp_tree_free( Attribute *a )
{
	Attribute *next;

	for( ; a != NULL ; a = next ) {
		next = a->a_next;
		if ( component_destructor && a->a_comp_data ) {
			if ( a->a_comp_data->cd_mem_op )
				component_destructor( a->a_comp_data->cd_mem_op );
			free ( a->a_comp_data );
		}
	}
}
#endif

void
attrs_free( Attribute *a )
{
	Attribute *next;

	for( ; a != NULL ; a = next ) {
		next = a->a_next;
		attr_free( a );
	}
}

Attribute *
attr_dup( Attribute *a )
{
	Attribute *tmp;

	if ( a == NULL) return NULL;

	tmp = attr_alloc( a->a_desc );

	if ( a->a_vals != NULL ) {
		int	i;

		for ( i = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) {
			/* EMPTY */ ;
		}

		tmp->a_vals = ch_malloc( (i + 1) * sizeof(struct berval) );
		for ( i = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) {
			ber_dupbv( &tmp->a_vals[i], &a->a_vals[i] );
			if ( BER_BVISNULL( &tmp->a_vals[i] ) ) break;
			/* FIXME: error? */
		}
		BER_BVZERO( &tmp->a_vals[i] );

		/* a_nvals must be non null; it may be equal to a_vals */
		assert( a->a_nvals != NULL );

		if ( a->a_nvals != a->a_vals ) {
			int	j;

			tmp->a_nvals = ch_malloc( (i + 1) * sizeof(struct berval) );
			for ( j = 0; !BER_BVISNULL( &a->a_nvals[j] ); j++ ) {
				assert( j < i );
				ber_dupbv( &tmp->a_nvals[j], &a->a_nvals[j] );
				if ( BER_BVISNULL( &tmp->a_nvals[j] ) ) break;
				/* FIXME: error? */
			}
			assert( j == i );
			BER_BVZERO( &tmp->a_nvals[j] );

		} else {
			tmp->a_nvals = tmp->a_vals;
		}

	} else {
		tmp->a_vals = NULL;
		tmp->a_nvals = NULL;
	}
	return tmp;
}

Attribute *
attrs_dup( Attribute *a )
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
 *
 * nvals must be NULL if the attribute has no normalizer.
 * In this case, a->a_nvals will be set equal to a->a_vals.
 *
 * returns	0	everything went ok
 *		-1	trouble
 */

int
attr_merge(
	Entry		*e,
	AttributeDescription *desc,
	BerVarray	vals,
	BerVarray	nvals )
{
	int rc;

	Attribute	**a;

	for ( a = &e->e_attrs; *a != NULL; a = &(*a)->a_next ) {
		if (  (*a)->a_desc == desc ) {
			break;
		}
	}

	if ( *a == NULL ) {
		*a = attr_alloc( desc );
	} else {
		/*
		 * FIXME: if the attribute already exists, the presence
		 * of nvals and the value of (*a)->a_nvals must be consistent
		 */
		assert( ( nvals == NULL && (*a)->a_nvals == (*a)->a_vals )
				|| ( nvals != NULL && (
					( (*a)->a_vals == NULL && (*a)->a_nvals == NULL )
					|| ( (*a)->a_nvals != (*a)->a_vals ) ) ) );
	}

	rc = value_add( &(*a)->a_vals, vals );

	if ( rc == LDAP_SUCCESS ) {
		if ( nvals ) {
			rc = value_add( &(*a)->a_nvals, nvals );
			/* FIXME: what if rc != LDAP_SUCCESS ? */
		} else {
			(*a)->a_nvals = (*a)->a_vals;
		}
	}

	return rc;
}

int
attr_merge_normalize(
	Entry		*e,
	AttributeDescription *desc,
	BerVarray	vals,
	void	 *memctx )
{
	BerVarray	nvals = NULL;
	int		rc;

	if ( desc->ad_type->sat_equality &&
		desc->ad_type->sat_equality->smr_normalize )
	{
		int	i;
		
		for ( i = 0; !BER_BVISNULL( &vals[i] ); i++ );

		nvals = slap_sl_calloc( sizeof(struct berval), i + 1, memctx );
		for ( i = 0; !BER_BVISNULL( &vals[i] ); i++ ) {
			rc = (*desc->ad_type->sat_equality->smr_normalize)(
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					desc->ad_type->sat_syntax,
					desc->ad_type->sat_equality,
					&vals[i], &nvals[i], memctx );

			if ( rc != LDAP_SUCCESS ) {
				BER_BVZERO( &nvals[i + 1] );
				goto error_return;
			}
		}
		BER_BVZERO( &nvals[i] );
	}

	rc = attr_merge( e, desc, vals, nvals );

error_return:;
	if ( nvals != NULL ) {
		ber_bvarray_free_x( nvals, memctx );
	}
	return rc;
}

int
attr_merge_one(
	Entry		*e,
	AttributeDescription *desc,
	struct berval	*val,
	struct berval	*nval )
{
	int rc;
	Attribute	**a;

	for ( a = &e->e_attrs; *a != NULL; a = &(*a)->a_next ) {
		if ( (*a)->a_desc == desc ) {
			break;
		}
	}

	if ( *a == NULL ) {
		*a = attr_alloc( desc );
	}

	rc = value_add_one( &(*a)->a_vals, val );

	if ( rc == LDAP_SUCCESS ) {
		if ( nval ) {
			rc = value_add_one( &(*a)->a_nvals, nval );
			/* FIXME: what if rc != LDAP_SUCCESS ? */
		} else {
			(*a)->a_nvals = (*a)->a_vals;
		}
	}
	return rc;
}

int
attr_merge_normalize_one(
	Entry		*e,
	AttributeDescription *desc,
	struct berval	*val,
	void		*memctx )
{
	struct berval	nval;
	struct berval	*nvalp = NULL;
	int		rc;

	if ( desc->ad_type->sat_equality &&
		desc->ad_type->sat_equality->smr_normalize )
	{
		rc = (*desc->ad_type->sat_equality->smr_normalize)(
				SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
				desc->ad_type->sat_syntax,
				desc->ad_type->sat_equality,
				val, &nval, memctx );

		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}
		nvalp = &nval;
	}

	rc = attr_merge_one( e, desc, val, nvalp );
	if ( nvalp != NULL ) {
		slap_sl_free( nval.bv_val, memctx );
	}
	return rc;
}

/*
 * attrs_find - find attribute(s) by AttributeDescription
 * returns next attribute which is subtype of provided description.
 */

Attribute *
attrs_find(
    Attribute	*a,
	AttributeDescription *desc )
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
	AttributeDescription *desc )
{
	for ( ; a != NULL; a = a->a_next ) {
		if ( a->a_desc == desc ) {
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
	AttributeDescription *desc )
{
	Attribute	**a;

	for ( a = attrs; *a != NULL; a = &(*a)->a_next ) {
		if ( (*a)->a_desc == desc ) {
			Attribute	*save = *a;
			*a = (*a)->a_next;
			attr_free( save );

			return LDAP_SUCCESS;
		}
	}

	return LDAP_NO_SUCH_ATTRIBUTE;
}

