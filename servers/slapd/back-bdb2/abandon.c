/* abandon.c - ldbm backend abandon routine */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "slap.h"
#include "back-bdb2.h"


/*ARGSUSED*/
static int
bdb2i_back_abandon_internal(
	BackendDB    *be,
	Connection *c,
	Operation  *o,
	int        msgid )
{
	return 0;
}


int
bdb2_back_abandon(
	BackendDB    *be,
	Connection *conn,
	Operation  *op,
	int        msgid )
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	ret = bdb2i_back_abandon_internal( be, conn, op, msgid );

	bdb2i_stop_timing( be->bd_info, time1, "ABND", conn, op );

	return( ret );
}


