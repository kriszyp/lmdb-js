/* operational.c - monitor backend operational attributes function */
/*
 * Copyright 1998-2001 The OpenLDAP Foundation, All Rights Reserved.
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
	char		**attrs,
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

		*aa = ch_malloc( sizeof( Attribute ) );
		(*aa)->a_desc = slap_schema.si_ad_hasSubordinates;

		(*aa)->a_vals = ch_malloc( 2 * sizeof( struct berval * ) );
		(*aa)->a_vals[0] = ber_bvstrdup( hs ? "TRUE" : "FALSE" );
		(*aa)->a_vals[1] = NULL;

		(*aa)->a_next = NULL;
		aa = &(*aa)->a_next;
	}
	
	return 0;
}

