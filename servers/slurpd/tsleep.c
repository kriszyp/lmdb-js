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
 * tsleep.c - allow a thread to sleep without putting the whole process
 * (e.g. pod under lwp) to sleep.  Contains platform-specific code to
 * allow this:
 *
 * Under non-preemptive threads packages like SunOS lwp, tsleep() adds
 * the thread to a list of sleepers.  The lwp_scheduler process takes
 * care of resuming suspended threads.
 *
 * Under a fully-preemptive threads package, like Solaris threads,
 * tsleep just calls sleep(), and there is no scheduler thread.  Life
 * is so much simpler...
 */

#include <stdio.h>

#include "slurp.h"
#include "globals.h"


#if defined( THREAD_SUNOS4_LWP )

extern stkalign_t *get_stack( int * );
extern void free_stack( int );

int
tsleep(
    int	interval
)
{
    thread_t	mylwp;
    tl_t	*t, *nt;
    time_t	now;


    if ( lwp_self( &mylwp ) < 0 ) {
	return -1;
    }
    time( &now );

    mon_enter( &sglob->tsl_mon );
    if ( sglob->tsl_list != NULL ) {
	for ( t = sglob->tsl_list; t != NULL; t = t->tl_next ) {
	    if ( SAMETHREAD( t->tl_tid, mylwp )) {
		/* We're already sleeping? */
		t->tl_wake = now + (time_t) interval;
		mon_exit( &sglob->tsl_mon );
		lwp_suspend( mylwp );
		return 0;
	    }
	}
    }
    nt = (tl_t *) malloc( sizeof( tl_t ));

    nt->tl_next = sglob->tsl_list;
    nt->tl_wake = now + (time_t) interval;
    nt->tl_tid = mylwp;
    sglob->tsl_list = nt;
    mon_exit( &sglob->tsl_mon );
    lwp_suspend( mylwp );
    return 0;
}

/*
 * The lwp_scheduler thread periodically checks to see if any threads
 * are due to be resumed.  If there are, it resumes them.  Otherwise,
 * it computes the lesser of ( 1 second ) or ( the minimum time until
 * a thread need to be resumed ) and puts itself to sleep for that amount
 * of time.
 */
void
lwp_scheduler(
    int	stackno
)
{
    time_t		now, min;
    struct timeval	interval;
    tl_t		*t;

    while ( !sglob->slurpd_shutdown ) {
	mon_enter( &sglob->tsl_mon );
	time( &now );
	min = 0L;
	if ( sglob->tsl_list != NULL ) {
	    for ( t = sglob->tsl_list; t != NULL; t = t->tl_next ) {
		if (( t->tl_wake  > 0L ) && ( t->tl_wake < now )) {
		    lwp_resume( t->tl_tid );
		    t->tl_wake = 0L;
		}
		if (( t->tl_wake > now ) && ( t->tl_wake < min )) {
		    min =  t->tl_wake;
		}
	    }
	}
	mon_exit( &sglob->tsl_mon );
	interval.tv_usec = 0L;
	if ( min == 0L ) {
	    interval.tv_sec = 1L;
	} else {
	    interval.tv_sec = min;
	}
	lwp_sleep( &interval );
    }
    mon_enter( &sglob->tsl_mon );
    for ( t = sglob->tsl_list; t != NULL; t = t->tl_next ) {
	lwp_resume( t->tl_tid );
    }
    mon_exit( &sglob->tsl_mon );
    free_stack( stackno );
}


/*
 * Create the lwp_scheduler thread.
 */
void
start_lwp_scheduler()
{
    thread_t	tid;
    stkalign_t	*stack;
    int		stackno;

    if (( stack = get_stack( &stackno )) == NULL ) {
	return;
    }
    lwp_create( &tid, lwp_scheduler, MINPRIO, 0, stack, 1, stackno );
    return;
}


#else /* THREAD_SUNOS4_LWP */

/*
 * Here we assume we have fully preemptive threads, and that sleep()
 * does the right thing.
 */
void
tsleep(
    time_t	interval
)
{
    sleep( interval );
}
#endif /* THREAD_SUNOS4_LWP */



