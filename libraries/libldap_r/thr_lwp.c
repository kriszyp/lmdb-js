/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/* thr_lwp.c - wrappers around SunOS LWP threads */

/* BUGS:
 * - slurpd calls the get_stack/free_stack functions. Should be fixed, so
 *   they can become static.
 */

#include "portable.h"
#include "ldap_pvt_thread.h"

#if defined( HAVE_LWP )

/*************
 *           *
 * SunOS LWP *
 *           *
 *************/
#include <stdio.h>

#include <ac/time.h>
#include <ac/socket.h>

#include "lber.h"
#include "ldap.h"
#include "ldap_log.h"

#include <lwp/lwp.h>
#include <lwp/stackdep.h>

#define MAX_STACK	51200
#define MAX_THREADS	20

/*
 * Initialize LWP by spinning of a schedular
 */
int
ldap_pvt_thread_initialize( void )
{
	thread_t		tid;
	stkalign_t		*stack;
	int			stackno;

	if (( stack = get_stack( &stackno )) == NULL ) {
		return -1;
	}

	lwp_create( &tid, lwp_scheduler, MINPRIO, 0, stack, 1, stackno );
	return 0;
}

struct stackinfo {
	int		stk_inuse;
	stkalign_t	*stk_stack;
};

static struct stackinfo	*stacks;

stkalign_t * ldap_pvt_thread_get_stack( int *stacknop )
{
	int	i;

	if ( stacks == NULL ) {
		stacks = (struct stackinfo *) ch_calloc( 1, MAX_THREADS *
		    sizeof(struct stackinfo) );
	}

	for ( i = 0; i < MAX_THREADS; i++ ) {
		if ( stacks[i].stk_inuse == 0 ) {
			break;
		}
	}

	if ( i == MAX_THREADS ) {
		Debug( LDAP_DEBUG_ANY,
		    "no more stacks (max %d) - increase MAX_THREADS for more",
		    MAX_THREADS, 0, 0 );
		return( NULL );
	}

	if ( stacks[i].stk_stack == NULL ) {
		stacks[i].stk_stack = (stkalign_t *) malloc(
		    (MAX_STACK / sizeof(stkalign_t) + 1 )
		    * sizeof(stkalign_t) );
	}

	*stacknop = i;
	stacks[i].stk_inuse = 1;
	return( stacks[i].stk_stack + MAX_STACK / sizeof(stkalign_t) );
}

void
ldap_pvt_thread_free_stack( int	stackno )
{
	if ( stackno < 0 || stackno > MAX_THREADS ) {
		Debug( LDAP_DEBUG_ANY, "free_stack of bogus stack %d",
		    stackno, 0, 0 );
	}

	stacks[stackno].stk_inuse = 0;
}

static void
lwp_create_stack( void *(*func)(), void *arg, int stackno )
{
	(*func)( arg );

	ldap_pvt_thread_free_stack( stackno );
}

int 
ldap_pvt_thread_create( ldap_pvt_thread_t * thread, 
	int detach,
	void *(*start_routine)( void *),
	void *arg)
{
	stkalign_t	*stack;
	int		stackno;

	if ( (stack = ldap_pvt_thread_get_stack( &stackno )) == NULL ) {
		return( -1 );
	}
	return( lwp_create( thread, lwp_create_stack, MINPRIO, 0, 
			   stack, 3, start_routine, arg, stackno ) );
}

void 
ldap_pvt_thread_exit( void *retval )
{
	lwp_destroy( SELF );
}

int 
ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
	lwp_join( thread );
	return 0;
}

int 
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
	return 0;
}

int 
ldap_pvt_thread_yield( void )
{
	lwp_yield( SELF );
	return 0;
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond )
{
	/*
	 * lwp cv_create requires the monitor id be passed in
	 * when the cv is created, pthreads passes it when the
	 * condition is waited for.  so, we fake the creation
	 * here and actually do it when the cv is waited for
	 * later.
	 */

	cond->lcv_created = 0;

	return( 0 );
}

int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	return( cond->lcv_created ? cv_notify( cv->lcv_cv ) : 0 );
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
		      ldap_pvt_thread_mutex_t *mutex )
{
	if ( ! cond->lcv_created ) {
		cv_create( &cond->lcv_cv, *mutex );
		cond->lcv_created = 1;
	}

	return( cv_wait( cond->lcv_cv ) );	
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex )
{
	return( mon_create( mutex ) );
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	return( mon_destroy( *mutex ) );
}

int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	return( mon_enter( *mutex ) );
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	return( mon_exit( *mutex ) );
}

int
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mp )
{
	return( mon_cond_enter( *mp ) );
}

int
ldap_pvt_thread_cond_destroy( ldap_pvt_thread_cond_t *cv )
{
	return( cv->lcv_created ? cv_destroy( cv->lcv_cv ) : 0 );
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cv )
{
	return( cv->lcv_created ? cv_broadcast( cv->lcv_cv ) : 0 );
}

#endif /* HAVE_LWP */
