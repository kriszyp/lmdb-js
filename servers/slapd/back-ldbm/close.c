/* close.c - close ldbm backend */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

int
ldbm_back_db_close( Backend *be )
{
#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_CRIT,
		   "ldbm_back_db_close: ldbm backend syncing\n" ));
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm backend syncing\n", 0, 0, 0 );
#endif

	ldbm_cache_flush_all( be );
#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_CRIT,
		   "ldbm_back_db_close: ldbm backend synch'ed\n" ));
#else
	Debug( LDAP_DEBUG_TRACE, "ldbm backend done syncing\n", 0, 0, 0 );
#endif


	cache_release_all( &((struct ldbminfo *) be->be_private)->li_cache );

	return 0;
}
