/* $OpenLDAP$ */
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
 * ldap_pvt_thread_sleep.c - allow a thread to sleep without putting
 * the whole process (e.g. pod under lwp) to sleep.
 *
 * Contains platform-specific code to allow this:
 *
 * Under non-preemptive threads packages like SunOS lwp, tsleep() adds
 * the thread to a list of sleepers.  The lwp_scheduler process takes
 * care of resuming suspended threads.
 *
 * Under a fully-preemptive threads package, like Solaris threads,
 * tsleep just calls sleep(), and there is no scheduler thread.  Life
 * is so much simpler...
 */

#include "portable.h"

#if !defined( HAVE_LWP )

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/unistd.h>			/* get sleep() */

#include "ldap_pvt_thread.h"


/*
 * Here we assume we have fully preemptive threads and that sleep()
 * does the right thing.
 */
unsigned int
ldap_pvt_thread_sleep(
	unsigned int interval
)
{
	sleep( interval );
	return 0;
}

#else

/* LWP implementation of sleep can be found in thr_lwp.c */

#endif /* HAVE_LWP */
