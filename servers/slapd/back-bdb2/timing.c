/* timing.c - timing bdb2 backend */

#include "portable.h"

#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"


int  bdb2i_do_timing = 0;


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


