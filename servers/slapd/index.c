/* index.c - index utilities */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"

int
slap_index2prefix( int indextype )
{
	int	prefix;

	switch ( indextype ) {
	case SLAP_INDEX_EQUALITY:
		prefix = SLAP_INDEX_EQUALITY_PREFIX;
		break;
	case SLAP_INDEX_APPROX:
		prefix = SLAP_INDEX_APPROX_PREFIX;
		break;
	case SLAP_INDEX_SUBSTR:
		prefix = SLAP_INDEX_SUBSTR_PREFIX;
		break;
	default:
		prefix = SLAP_INDEX_UNKNOWN_PREFIX;
		break;
	}

	return( prefix );
}

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
	} else if ( strcasecmp( str, "lang" ) == 0 ) {
		*idx = SLAP_INDEX_LANG;
	} else if ( strcasecmp( str, "autolang" ) == 0 ) {
		*idx = SLAP_INDEX_AUTO_LANG;
	} else if ( strcasecmp( str, "subtypes" ) == 0 ) {
		*idx = SLAP_INDEX_SUBTYPES;
	} else if ( strcasecmp( str, "autosubtypes" ) == 0 ) {
		*idx = SLAP_INDEX_AUTO_SUBTYPES;
	} else {
		return LDAP_OTHER;
	}

	return LDAP_SUCCESS;
}
