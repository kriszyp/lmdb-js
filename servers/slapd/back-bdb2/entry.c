/* entry.c - ldbm backend entry_release routine */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"


int
bdb2_back_entry_release_rw(
	BackendDB *be,
	Entry   *e,
	int     rw
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	/* free entry and reader or writer lock */
	bdb2i_cache_return_entry_rw( &li->li_cache, e, rw ); 
	bdb2i_release_add_lock();

	return 0;
}
