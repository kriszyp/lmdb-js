/* unbind.c - handle an ldap unbind operation */

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
	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	ret = bdb2i_back_unbind_internal( be, conn, op );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "conn=%d op=%d UNBIND elapsed=%s\n",
				conn->c_connid, op->o_opid, elapsed_time );
		free( elapsed_time );

	}

	return( ret );
}
