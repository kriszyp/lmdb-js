/* operational.c - routines to deal with on-the-fly operational attrs */
/*
 * Copyright 2001 The OpenLDAP Foundation, All Rights Reserved.
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
	a->a_vals = ch_malloc( 2 * sizeof( struct berval * ) );
	a->a_vals[0] = ber_bvstrdup( SLAPD_SCHEMA_DN );
	a->a_vals[1] = NULL;

	a->a_next = NULL;

	return a;
}
#endif /* SLAPD_SCHEMA_DN */

Attribute *
slap_operational_hasSubordinate( int hs )
{
	Attribute	*a;
	
	a = ch_malloc( sizeof( Attribute ) );
	a->a_desc = slap_schema.si_ad_hasSubordinates;

	a->a_vals = ch_malloc( 2 * sizeof( struct berval * ) );
	a->a_vals[0] = ber_bvstrdup( hs ? "TRUE" : "FALSE" );
	a->a_vals[1] = NULL;

	a->a_next = NULL;

	return a;
}

