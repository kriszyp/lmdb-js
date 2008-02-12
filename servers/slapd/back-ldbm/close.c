/* close.c - close ldbm backend */
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

#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

int
ldbm_back_db_close( Backend *be )
{
	struct ldbminfo *li = be->be_private;

	Debug( LDAP_DEBUG_TRACE, "ldbm backend syncing\n", 0, 0, 0 );

	ldbm_cache_flush_all( be );
	Debug( LDAP_DEBUG_TRACE, "ldbm backend done syncing\n", 0, 0, 0 );

	cache_release_all( &li->li_cache );
	if ( alock_close( &li->li_alock_info )) {
		Debug( LDAP_DEBUG_ANY,
			"ldbm_back_db_close: alock_close failed\n", 0, 0, 0 );
	}

	return 0;
}
