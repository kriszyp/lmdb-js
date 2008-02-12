/* operational.c - ldbm backend operational attributes function */
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

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

/*
 * sets *hasSubordinates to LDAP_COMPARE_TRUE/LDAP_COMPARE_FALSE
 * if the entry has children or not.
 */
int
ldbm_back_hasSubordinates(
	Operation	*op,
	Entry		*e,
	int		*hasSubordinates )
{
	if ( has_children( op->o_bd, e ) ) {
		*hasSubordinates = LDAP_COMPARE_TRUE;

	} else {
		*hasSubordinates = LDAP_COMPARE_FALSE;
	}

	return 0;
}

/*
 * sets the supported operational attributes (if required)
 */
int
ldbm_back_operational(
	Operation	*op,
	SlapReply	*rs )
{
	Attribute	**ap;

	assert( rs->sr_entry != NULL );

	for ( ap = &rs->sr_operational_attrs; *ap; ap = &(*ap)->a_next )
		/* just count */ ;

	if ( SLAP_OPATTRS( rs->sr_attr_flags ) ||
			ad_inlist( slap_schema.si_ad_hasSubordinates, rs->sr_attrs ) )
	{
		int	hs;

		hs = has_children( op->o_bd, rs->sr_entry );
		*ap = slap_operational_hasSubordinate( hs );
		assert( *ap != NULL );

		ap = &(*ap)->a_next;
	}

	return 0;
}

