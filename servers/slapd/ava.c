/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ava.c - routines for dealing with attribute value assertions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#ifdef SLAPD_SCHEMA_NOT_COMPAT

void
ava_free(
    AttributeAssertion *ava,
    int	freeit
)
{
	ad_free( ava->aa_desc, 1 );
	ber_bvfree( ava->aa_value );
	if ( freeit ) {
		ch_free( (char *) ava );
	}
}

#else

void
ava_free(
    Ava	*ava,
    int	freeit
)
{
	ch_free( (char *) ava->ava_type );
	ch_free( (char *) ava->ava_value.bv_val );
	if ( freeit ) {
		ch_free( (char *) ava );
	}
}

int
get_ava(
    BerElement	*ber,
    Ava		*ava
)
{
	if ( ber_scanf( ber, "{ao}", &ava->ava_type, &ava->ava_value )
	    == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "  get_ava ber_scanf\n", 0, 0, 0 );
		return SLAPD_DISCONNECT;
	}

	attr_normalize( ava->ava_type );
	value_normalize( ava->ava_value.bv_val, attr_syntax( ava->ava_type ) );

	return LDAP_SUCCESS;
}

#endif
