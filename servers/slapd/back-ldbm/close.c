/* close.c - close ldbm backend */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

int
ldbm_back_db_close( Backend *be )
{
	Debug( LDAP_DEBUG_TRACE, "ldbm backend saving nextid\n", 0, 0, 0 );
	if ( next_id_save( be ) < 0 ) {
		Debug( LDAP_DEBUG_ANY, "ldbm backend nextid save failed!\n", 0, 0, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "ldbm backend syncing\n", 0, 0, 0 );
	ldbm_cache_flush_all( be );
	Debug( LDAP_DEBUG_TRACE, "ldbm backend done syncing\n", 0, 0, 0 );

#ifdef SLAP_CLEANUP
	cache_release_all( &((struct ldbminfo *) be->be_private)->li_cache );
#endif

	return 0;
}
