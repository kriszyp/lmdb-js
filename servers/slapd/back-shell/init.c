/* init.c - initialize shell backend */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "shell.h"

shell_back_init(
    Backend	*be
)
{
	struct shellinfo	*si;

	si = (struct shellinfo *) ch_calloc( 1, sizeof(struct shellinfo) );

	be->be_private = si;
}
