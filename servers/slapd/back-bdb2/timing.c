/* timing.c - timing bdb2 backend */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "slap.h"
#include "back-bdb2.h"


static char *
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
    return( ch_strdup( elapsed_string ));
}


void
bdb2i_uncond_start_timing(
	struct timeval  *time1
)
{
	gettimeofday( time1, NULL );
}


void
bdb2i_uncond_stop_timing(
	struct timeval  time1,
	char            *func,
	Connection      *conn,
	Operation       *op,
	int             level
)
{
	struct timeval  time2;
	char            *elapsed_time;
	char            buf[BUFSIZ];

	*buf = '\0';

	gettimeofday( &time2, NULL);
	elapsed_time = bdb2i_elapsed( time1, time2 );

	if ( conn != NULL ) sprintf( buf, "conn=%d ", conn->c_connid );
	if ( op != NULL )   sprintf( buf, "%sop=%d ", buf, op->o_opid );

	Debug( level, "%s%s elapsed=%s\n", buf, func, elapsed_time );

	free( elapsed_time );

}


