/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ava.c - routines for dealing with attribute value assertions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

int
get_ava(
    BerElement	*ber,
    Ava		*ava
)
{
	if ( ber_scanf( ber, "{ao}", &ava->ava_type, &ava->ava_value )
	    == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "  get_ava ber_scanf\n", 0, 0, 0 );
		return( -1 );
	}

	attr_normalize( ava->ava_type );

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	value_normalize( ava->ava_value.bv_val, attr_syntax( ava->ava_type ) );
#endif

	return( LDAP_SUCCESS );
}

void
ava_free(
    Ava	*ava,
    int	freeit
)
{
	free( (char *) ava->ava_type );
	free( (char *) ava->ava_value.bv_val );
	if ( freeit ) {
		free( (char *) ava );
	}
}

