/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
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

#include "portable.h"

#include <stdio.h>

#include "slurp.h"
#include "globals.h"


/*
 * Just invoke the Ri's process() member function, and log the start and
 * finish.
 */
static void *
replicate(
    void	*ri_arg
)
{
    Ri		*ri = (Ri *) ri_arg;

    Debug( LDAP_DEBUG_ARGS, "begin replication thread for %s:%d\n",
	    ((Ri *)ri)->ri_hostname, ((Ri *)ri)->ri_port, 0 );

    ri->ri_process( ri );

    Debug( LDAP_DEBUG_ARGS, "end replication thread for %s:%d\n",
	    ri->ri_hostname, ri->ri_port, 0 );
    return NULL;
}



/*
 * Start a detached thread for the given replica.
 */
int
start_replica_thread(
    Ri	*ri
)
{
    /* POSIX_THREADS or compatible */
    if ( ldap_pvt_thread_create( &(ri->ri_tid), 0, replicate,
	    (void *) ri ) != 0 ) {
	Debug( LDAP_DEBUG_ANY, "replica \"%s:%d\" ldap_pvt_thread_create failed\n",
		ri->ri_hostname, ri->ri_port, 0 );
	return -1;
    }

    return 0;
}
