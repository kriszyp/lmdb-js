/* abandon.c - ldbm backend abandon routine */

#include "portable.h"

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include <ac/string.h>

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
	Connection *c,
	Operation  *o,
	int        msgid )
{
	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	ret = bdb2i_back_abandon_internal( be, c, o, msgid );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "ABND elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}

	return( ret );
}


