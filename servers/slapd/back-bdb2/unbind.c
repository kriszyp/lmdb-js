/* unbind.c - handle an ldap unbind operation */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

static int
bdb2i_back_unbind_internal(
	BackendDB     *be,
	Connection  *conn,
	Operation   *op
)
{
	return( 0 );
}


int
bdb2_back_unbind(
	BackendDB     *be,
	Connection  *conn,
	Operation   *op
)
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	ret = bdb2i_back_unbind_internal( be, conn, op );
	bdb2i_stop_timing( be->bd_info, time1, "UNBIND", conn, op );

	return( ret );
}
