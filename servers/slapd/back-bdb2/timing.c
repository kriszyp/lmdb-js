/* timing.c - timing bdb2 backend */

#include "portable.h"

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"


char *
bdb2i_elapsed( struct timeval firsttime,  struct timeval secondtime )
{
    long int elapsedmicrosec, elapsedsec;
    char elapsed_string[BUFSIZ];
    
    elapsedsec = secondtime.tv_sec - firsttime.tv_sec;
    elapsedmicrosec = secondtime.tv_usec - firsttime.tv_usec;
    if(elapsedmicrosec < 0) {
        elapsedmicrosec += 1000000;
        elapsedsec -= 1;
    }

    sprintf( elapsed_string, "%ld.%.6ld", elapsedsec, elapsedmicrosec );
    return( strdup( elapsed_string ));
}


void
bdb2i_start_timing(
	BackendInfo     *bi,
	struct timeval  *time1
)
{
	if ( with_timing( bi )) gettimeofday( time1, NULL );
}


void
bdb2i_stop_timing(
	BackendInfo     *bi,
	struct timeval  time1,
	char            *func,
	Connection      *conn,
	Operation       *op
)
{
	if ( with_timing( bi )) {
		struct timeval  time2;
		char            *elapsed_time;
		char            buf[BUFSIZ];

		*buf = '\0';

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );

		if ( conn != NULL ) sprintf( buf, "conn=%d ", conn->c_connid );
		if ( op != NULL )   sprintf( buf, "%sop=%d ", buf, op->o_opid );

		Debug( LDAP_DEBUG_ANY, "%s%s elapsed=%s\n", buf, func, elapsed_time );

		free( elapsed_time );

	}
}


