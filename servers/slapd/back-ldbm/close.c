/* close.c - close ldbm backend */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

ldbm_back_close( Backend *be )
{
	Debug( LDAP_DEBUG_TRACE, "ldbm backend syncing\n", 0, 0, 0 );
	ldbm_cache_flush_all( be );
	Debug( LDAP_DEBUG_TRACE, "ldbm backend done syncing\n", 0, 0, 0 );
}
