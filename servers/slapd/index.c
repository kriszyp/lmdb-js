/* index.c - index utilities */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"

int slap_str2index( const char *str, slap_mask_t *idx )
{
	if ( strcasecmp( str, "pres" ) == 0 ) {
		*idx = SLAP_INDEX_PRESENT;
	} else if ( strcasecmp( str, "eq" ) == 0 ) {
		*idx = SLAP_INDEX_EQUALITY;
	} else if ( strcasecmp( str, "approx" ) == 0 ) {
		*idx = SLAP_INDEX_APPROX;
	} else if ( strcasecmp( str, "subinitial" ) == 0 ) {
		*idx = SLAP_INDEX_SUBSTR_INITIAL;
	} else if ( strcasecmp( str, "subany" ) == 0 ) {
		*idx = SLAP_INDEX_SUBSTR_ANY;
	} else if ( strcasecmp( str, "subfinal" ) == 0 ) {
		*idx = SLAP_INDEX_SUBSTR_FINAL;
	} else if ( strcasecmp( str, "substr" ) == 0 ||
		strcasecmp( str, "sub" ) == 0 )
	{
		*idx = SLAP_INDEX_SUBSTR_DEFAULT;
	} else if ( strcasecmp( str, "nolang" ) == 0 ||	/* backwards compat */
	            strcasecmp( str, "notags" ) == 0 ) {
		*idx = SLAP_INDEX_NOTAGS;
	} else if ( strcasecmp( str, "nosubtypes" ) == 0 ) {
		*idx = SLAP_INDEX_NOSUBTYPES;
	} else {
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}
