/* operational.c - monitor backend operational attributes function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-monitor.h"
#include "proto-back-monitor.h"

/*
 * sets the supported operational attributes (if required)
 */

int
monitor_back_operational(
	Operation	*op,
	SlapReply	*rs,
	int		opattrs,
	Attribute	**a )
{
	Attribute	**aa = a;

	assert( rs->sr_entry );

	if ( opattrs || ad_inlist( slap_schema.si_ad_hasSubordinates,
				rs->sr_attrs ) ) {
		int			hs;
		struct monitorentrypriv	*mp;

		mp = ( struct monitorentrypriv * )rs->sr_entry->e_private;

		assert( mp );

		hs = MONITOR_HAS_CHILDREN( mp );
		*aa = slap_operational_hasSubordinate( hs );
		if ( *aa != NULL ) {
			aa = &(*aa)->a_next;
		}
	}
	
	return 0;
}

