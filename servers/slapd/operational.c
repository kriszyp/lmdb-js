/* operational.c - routines to deal with on-the-fly operational attrs */
/*
 * Copyright 2001-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include "slap.h"

/*
 * helpers for on-the-fly operational attribute generation
 */

#ifdef SLAPD_SCHEMA_DN
Attribute *
slap_operational_subschemaSubentry( void )
{
	Attribute	*a;

	a = ch_malloc( sizeof( Attribute ) );
	a->a_desc = slap_schema.si_ad_subschemaSubentry;

	/* Should be backend specific */
	a->a_vals = ch_malloc( 2 * sizeof( struct berval ) );
	ber_str2bv( SLAPD_SCHEMA_DN, sizeof(SLAPD_SCHEMA_DN)-1, 1, a->a_vals );
	a->a_vals[1].bv_val = NULL;

	a->a_next = NULL;
	a->a_flags = 0;

	return a;
}
#endif /* SLAPD_SCHEMA_DN */

Attribute *
slap_operational_hasSubordinate( int hs )
{
	Attribute	*a;
	
	a = ch_malloc( sizeof( Attribute ) );
	a->a_desc = slap_schema.si_ad_hasSubordinates;

	a->a_vals = ch_malloc( 2 * sizeof( struct berval ) );
	ber_str2bv( hs ? "TRUE" : "FALSE",
		hs ? sizeof("TRUE")-1 : sizeof("FALSE")-1,
		1, a->a_vals );
	a->a_vals[1].bv_val = NULL;

	a->a_next = NULL;
	a->a_flags = 0;

	return a;
}

