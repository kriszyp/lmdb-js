/* operational.c - monitor backend operational attributes function */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
	BackendDB	*be,
	Connection	*conn, 
	Operation	*op,
	Entry		*e,
	AttributeName	*attrs,
	int		opattrs,
	Attribute	**a )
{
	Attribute	**aa = a;

	assert( e );

	if ( opattrs || ad_inlist( slap_schema.si_ad_hasSubordinates, attrs ) ) {
		int			hs;
		struct monitorentrypriv	*mp;

		mp = ( struct monitorentrypriv * )e->e_private;

		assert( mp );

		hs = MONITOR_HAS_CHILDREN( mp );
		*aa = slap_operational_hasSubordinate( hs );
		if ( *aa != NULL ) {
			aa = &(*aa)->a_next;
		}
	}
	
	return 0;
}

