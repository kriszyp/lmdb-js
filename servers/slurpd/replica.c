/*
 * Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */


/*
 * replica.c - code to start up replica threads.
 */


#include <stdio.h>

#include "slurp.h"
#include "globals.h"


/*
 * Just invoke the Ri's process() member function, and log the start and
 * finish.
 */
void
replicate(
    Ri	*ri
)
{
    int i;
    unsigned long seq;

    Debug( LDAP_DEBUG_ARGS, "begin replication thread for %s:%d\n",
	    ri->ri_hostname, ri->ri_port, 0 );

    ri->ri_process( ri );

    Debug( LDAP_DEBUG_ARGS, "end replication thread for %s:%d\n",
	    ri->ri_hostname, ri->ri_port, 0 );
    return;
}



/*
 * Start a detached thread for the given replica.
 */
int
start_replica_thread(
    Ri	*ri
)
{
    pthread_attr_t	attr;

    pthread_attr_init( &attr );
#ifdef NOTDEF
	/* if main wants to join with us, we shouldn't detach */
    pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );
#endif

#ifndef THREAD_MIT_PTHREADS
    /* POSIX_THREADS or compatible
     * This is a draft 10 or standard pthreads implementation
     */
    if ( pthread_create( &(ri->ri_tid), &attr, (void *) replicate,
	    (void *) ri ) != 0 ) {
	Debug( LDAP_DEBUG_ANY, "replica \"%s:%d\" pthread_create failed\n",
		ri->ri_hostname, ri->ri_port, 0 );
	pthread_attr_destroy( &attr );
	return -1;
    }
#else	/* !THREAD_MIT_PTHREADS */
    /*
     * This is a draft 4 or earlier pthreads implementation
     */
    if ( pthread_create( &(ri->ri_tid), attr, (void *) replicate,
	    (void *) ri ) != 0 ) {
	Debug( LDAP_DEBUG_ANY, "replica \"%s:%d\" pthread_create failed\n",
		ri->ri_hostname, ri->ri_port, 0 );
	pthread_attr_destroy( &attr );
	return -1;
    }
#endif	/* !THREAD_MIT_PTHREADS */
    pthread_attr_destroy( &attr );
    return 0;
}
