/* entry.c - ldbm backend entry_release routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


int
ldbm_back_entry_release_rw(
	BackendDB *be,
	Entry   *e,
	int     rw
)
{
	return 0;
}
