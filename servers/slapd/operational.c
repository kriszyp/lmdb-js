/* operational.c - routines to deal with on-the-fly operational attrs */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
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

#include "portable.h"

#include "slap.h"

/*
 * helpers for on-the-fly operational attribute generation
 */

Attribute *
slap_operational_subschemaSubentry( Backend *be )
{
	Attribute	*a;

	/* The backend wants to take care of it */
	if ( be && be->be_schemadn.bv_val ) return NULL;

	a = ch_malloc( sizeof( Attribute ) );
	a->a_desc = slap_schema.si_ad_subschemaSubentry;

	a->a_vals = ch_malloc( 2 * sizeof( struct berval ) );
	ber_dupbv( a->a_vals, &global_schemadn );
	a->a_vals[1].bv_len = 0;
	a->a_vals[1].bv_val = NULL;

	a->a_nvals = ch_malloc( 2 * sizeof( struct berval ) );
	ber_dupbv( a->a_nvals, &global_schemandn );
	a->a_nvals[1].bv_len = 0;
	a->a_nvals[1].bv_val = NULL;

	a->a_next = NULL;
	a->a_flags = 0;

	return a;
}

Attribute *
slap_operational_hasSubordinate( int hs )
{
	Attribute	*a;
	struct berval	val;

	if ( hs ) {
		val = slap_true_bv;

	} else {
		val = slap_false_bv;
	}

	a = ch_malloc( sizeof( Attribute ) );
	a->a_desc = slap_schema.si_ad_hasSubordinates;
	a->a_vals = ch_malloc( 2 * sizeof( struct berval ) );

	ber_dupbv( &a->a_vals[0], &val );
	a->a_vals[1].bv_val = NULL;

	a->a_nvals = a->a_vals;

	a->a_next = NULL;
	a->a_flags = 0;

	return a;
}

