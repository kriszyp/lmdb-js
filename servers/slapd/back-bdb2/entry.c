/* entry.c - ldbm backend entry_release routine */

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
#if 0
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	/* free entry and reader or writer lock */
	bdb2i_cache_return_entry_rw( &li->li_cache, e, rw ); 
#endif

	return 0;
}
