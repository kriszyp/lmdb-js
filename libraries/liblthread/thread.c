/* thread.c - glue routines to provide a consistent thread interface */

#include "portable.h"

#include <lthread.h>

#if defined( HAVE_PTHREADS )

#ifndef HAVE_PTHREAD_KILL
/***********************************************************************
 *                                                                     *
 * pthreads package with DCE - no mapping to do (except to create a    *
 * pthread_kill() routine)                                             *
 *                                                                     *
 ***********************************************************************/

/* ARGSUSED */
void
pthread_kill( pthread_t tid, int sig )
{
	kill( getpid(), sig );
}
#endif /* HAVE_PTHREAD_KILL */

#elif defined( HAVE_MACH_CTHREADS )

/***********************************************************************
 *                                                                     *
 * under NEXTSTEP or OPENSTEP use CThreads                             *
 * lukeh@xedoc.com.au                                                  *
 *                                                                     *
 ***********************************************************************/

int
pthread_attr_init( pthread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int
pthread_attr_destroy( pthread_attr_t *attr )
{
	return( 0 );
}

int
pthread_attr_getdetachstate( pthread_attr_t *attr, int *detachstate )
{
	*detachstate = *attr;
	return( 0 );
}

int
pthread_attr_setdetachstate( pthread_attr_t *attr, int detachstate )
{
	*attr = detachstate;
	return( 0 );
}

/* ARGSUSED */
int
pthread_create(
    pthread_t		*tid,
    pthread_attr_t	*attr,
    VFP			func,
    void		*arg
)
{
	*tid = cthread_fork(func, arg);
	 return ( *tid == NULL ? -1 : 0 );
}

void
pthread_yield( void )
{
	cthread_yield();
}

void
pthread_exit( any_t a )
{
	cthread_exit( a );
}

void
pthread_join( pthread_t tid, int *pStatus )
{
	int status;
	status = (int) cthread_join ( tid );
	if (pStatus != NULL)
		{
		*pStatus = status;
		}
}

/* ARGSUSED */
void
pthread_kill( pthread_t tid, int sig )
{
	return;
}

/* ARGSUSED */
int
pthread_mutex_init( pthread_mutex_t *mp, pthread_mutexattr_t *attr )
{
	mutex_init( mp );
	mp->name = NULL;
	return ( 0 );
}

int
pthread_mutex_destroy( pthread_mutex_t *mp )
{
	mutex_clear( mp );
	return ( 0 );
}

int
pthread_mutex_lock( pthread_mutex_t *mp )
{
	mutex_lock( mp );
	return ( 0 );
}

int
pthread_mutex_unlock( pthread_mutex_t *mp )
{
	mutex_unlock( mp );
	return ( 0 );
}

int
pthread_mutex_trylock( pthread_mutex_t *mp )
{
	return mutex_try_lock( mp );
}

int
pthread_cond_init( pthread_cond_t *cv, pthread_condattr_t *attr )
{
	condition_init( cv );
	return( 0 );
}

int
pthread_cond_destroy( pthread_cond_t *cv )
{
	condition_clear( cv );
	return( 0 );
}

int
pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mp )
{
	condition_wait( cv, mp );
	return( 0 );
}

int
pthread_cond_signal( pthread_cond_t *cv )
{
	condition_signal( cv );
	return( 0 );
}

int
pthread_cond_broadcast( pthread_cond_t *cv )
{
	condition_broadcast( cv );
	return( 0 );
}

#elif defined( HAVE_THR )

/*******************
 *                 *
 * Solaris Threads *
 *                 *
 *******************/

int
pthread_attr_init( pthread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int
pthread_attr_destroy( pthread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int
pthread_attr_getdetachstate( pthread_attr_t *attr, int *detachstate )
{
	*detachstate = *attr;
	return( 0 );
}

int
pthread_attr_setdetachstate( pthread_attr_t *attr, int detachstate )
{
	*attr = detachstate;
	return( 0 );
}

/* ARGSUSED */
int
pthread_create(
    pthread_t		*tid,
    pthread_attr_t	*attr,
    VFP			func,
    void		*arg
)
{
	return( thr_create( NULL, 0, func, arg, *attr, tid ) );
}

void
pthread_yield( void )
{
	thr_yield();
}

void
pthread_exit()
{
	thr_exit( NULL );
}

void
pthread_join( pthread_t tid, int *status )
{
	thr_join( tid, NULL, (void **) status );
}

void
pthread_kill( pthread_t tid, int sig )
{
	thr_kill( tid, sig );
}

/* ARGSUSED */
int
pthread_mutex_init( pthread_mutex_t *mp, pthread_mutexattr_t *attr )
{
	return( mutex_init( mp, attr ? *attr : USYNC_THREAD, NULL ) );
}

int
pthread_mutex_destroy( pthread_mutex_t *mp )
{
	return( mutex_destroy( mp ) );
}

int
pthread_mutex_lock( pthread_mutex_t *mp )
{
	return( mutex_lock( mp ) );
}

int
pthread_mutex_unlock( pthread_mutex_t *mp )
{
	return( mutex_unlock( mp ) );
}

int
pthread_mutex_trylock( pthread_mutex_t *mp )
{
	return( mutex_trylock( mp ) );
}

int
pthread_cond_init( pthread_cond_t *cv, pthread_condattr_t *attr )
{
	return( cond_init( cv, attr ? *attr : USYNC_THREAD, NULL ) );
}

int
pthread_cond_destroy( pthread_cond_t *cv )
{
	return( cond_destroy( cv ) );
}

int
pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mp )
{
	return( cond_wait( cv, mp ) );
}

int
pthread_cond_signal( pthread_cond_t *cv )
{
	return( cond_signal( cv ) );
}

int
pthread_cond_broadcast( pthread_cond_t *cv )
{
	return( cond_broadcast( cv ) );
}

#elif defined( HAVE_LWP )

/*************
 *           *
 * SunOS LWP *
 *           *
 *************/

int
pthread_attr_init( pthread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int
pthread_attr_destroy( pthread_attr_t *attr )
{
	return( 0 );
}

int
pthread_attr_getdetachstate( pthread_attr_t *attr, int *detachstate )
{
	*detachstate = *attr;
	return( 0 );
}

int
pthread_attr_setdetachstate( pthread_attr_t *attr, int detachstate )
{
	*attr = detachstate;
	return( 0 );
}

static void
lwp_create_stack( VFP func, void *arg, int stackno )
{
	(*func)( arg );

	free_stack( stackno );
}

/* ARGSUSED */
int
pthread_create(
    pthread_t		*tid,
    pthread_attr_t	*attr,
    VFP			func,
    void		*arg
)
{
	stkalign_t	*stack;
	int		stackno;

	if ( (stack = get_stack( &stackno )) == NULL ) {
		return( -1 );
	}
	return( lwp_create( tid, lwp_create_stack, MINPRIO, 0, stack, 3, func,
	    arg, stackno ) );
}

void
pthread_yield( void )
{
	lwp_yield( SELF );
}

void
pthread_exit()
{
	lwp_destroy( SELF );
}

void
pthread_join( pthread_t tid, int *status )
{
	lwp_join( tid );
}

/* ARGSUSED */
void
pthread_kill( pthread_t tid, int sig )
{
	return;
}

/* ARGSUSED */
int
pthread_mutex_init( pthread_mutex_t *mp, pthread_mutexattr_t *attr )
{
	return( mon_create( mp ) );
}

int
pthread_mutex_destroy( pthread_mutex_t *mp )
{
	return( mon_destroy( *mp ) );
}

int
pthread_mutex_lock( pthread_mutex_t *mp )
{
	return( mon_enter( *mp ) );
}

int
pthread_mutex_unlock( pthread_mutex_t *mp )
{
	return( mon_exit( *mp ) );
}

int
pthread_mutex_trylock( pthread_mutex_t *mp )
{
	return( mon_cond_enter( *mp ) );
}

int
pthread_cond_init( pthread_cond_t *cv, pthread_condattr_t *attr )
{
	/*
	 * lwp cv_create requires the monitor id be passed in
	 * when the cv is created, pthreads passes it when the
	 * condition is waited for.  so, we fake the creation
	 * here and actually do it when the cv is waited for
	 * later.
	 */

	cv->lcv_created = 0;

	return( 0 );
}

int
pthread_cond_destroy( pthread_cond_t *cv )
{
	return( cv->lcv_created ? cv_destroy( cv->lcv_cv ) : 0 );
}

int
pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mp )
{
	if ( ! cv->lcv_created ) {
		cv_create( &cv->lcv_cv, *mp );
		cv->lcv_created = 1;
	}

	return( cv_wait( cv->lcv_cv ) );
}

int
pthread_cond_signal( pthread_cond_t *cv )
{
	return( cv->lcv_created ? cv_notify( cv->lcv_cv ) : 0 );
}

int
pthread_cond_broadcast( pthread_cond_t *cv )
{
	return( cv->lcv_created ? cv_broadcast( cv->lcv_cv ) : 0 );
}


#elif defined( HAVE_NT_MULTITHREADS )

#include <process.h>
#include <winsock2.h>

int
pthread_attr_init( pthread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int
pthread_attr_destroy( pthread_attr_t *attr )
{
	return( 0 );
}

int
pthread_attr_getdetachstate( pthread_attr_t *attr, int *detachstate )
{
	*detachstate = *attr;
	return( 0 );
}

int
pthread_attr_setdetachstate( pthread_attr_t *attr, int detachstate )
{
	*attr = detachstate;
	return( 0 );
}

int
pthread_create(
    pthread_t		*tid,
    pthread_attr_t	*attr,
    VFP			func,
    void		*arg
)
{
	*tid = (pthread_t)_beginthread( (void *) func, 0, arg );
	 return ( (unsigned long)*tid == -1 ? -1 : 0 );
}

void
pthread_yield()
{

}

void
pthread_exit( void )
{
	_endthread( );
}

void
pthread_join( pthread_t tid, int *pStatus )
{
	DWORD status;
	status = WaitForSingleObject( tid, INFINITE );
	if ( pStatus != NULL)
	{
		if ( status != WAIT_FAILED )
			*pStatus = 0;
		else
			*pStatus = WAIT_ABANDONED;
	}
}


void
pthread_kill( pthread_t tid, int sig )
{
	return;
}


int
pthread_mutex_init( pthread_mutex_t *mp, pthread_mutexattr_t *attr )
{
	*mp = CreateMutex( NULL, 0, NULL );
	return ( 0 );
}

int
pthread_mutex_destroy( pthread_mutex_t *mp )
{
	CloseHandle( *mp );
	return ( 0 );
}

int
pthread_mutex_lock( pthread_mutex_t *mp )
{
	WaitForSingleObject( *mp, INFINITE );
	return ( 0 );
}

int
pthread_mutex_unlock( pthread_mutex_t *mp )
{
	ReleaseMutex( *mp );
	return ( 0 );
}

int
pthread_mutex_trylock( pthread_mutex_t *mp )
{
	DWORD status;

	status = WaitForSingleObject( *mp, 0 );
	if ( (status == WAIT_FAILED) || (status == WAIT_TIMEOUT) )
		return 0;
	else
		return 1;
}

int
pthread_cond_init( pthread_cond_t *cv, pthread_condattr_t *attr )
{
	*cv = CreateEvent( NULL, FALSE, FALSE, NULL );
	return( 0 );
}

int
pthread_cond_destroy( pthread_cond_t *cv )
{
	CloseHandle( *cv );
	return( 0 );
}

int
pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mp )
{
	ReleaseMutex( *mp );
	WaitForSingleObject( *cv, INFINITE );
	WaitForSingleObject( *mp, INFINITE );
	return( 0 );
}

int
pthread_cond_signal( pthread_cond_t *cv )
{
	SetEvent( *cv );
	return( 0 );
}

int
pthread_cond_broadcast( pthread_cond_t *cv )
{
	SetEvent( *cv );
	return( 0 );
}

#else

/***********************************************************************
 *                                                                     *
 * no threads package defined for this system - fake ok returns from   *
 * all threads routines (making it single-threaded).                   *
 *                                                                     *
 ***********************************************************************/

/* ARGSUSED */
int
pthread_attr_init( pthread_attr_t *attr )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_attr_destroy( pthread_attr_t *attr )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_attr_getdetachstate( pthread_attr_t *attr, int *detachstate )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_attr_setdetachstate( pthread_attr_t *attr, int detachstate )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_create(
    pthread_t		*tid,
    pthread_attr_t	*attr,
    VFP			func,
    void		*arg
)
{
	(*func)( arg );

	return( 0 );
}

void
pthread_yield( void )
{
	return;
}

void
pthread_exit()
{
	return;
}

/* ARGSUSED */
void
pthread_kill( pthread_t tid, int sig )
{
	return;
}

void
pthread_join( pthread_t tid, int *status )
{
	return;
}

/* ARGSUSED */
int
pthread_mutex_init( pthread_mutex_t *mp, pthread_mutexattr_t *attr )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_mutex_destroy( pthread_mutex_t *mp )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_mutex_lock( pthread_mutex_t *mp )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_mutex_unlock( pthread_mutex_t *mp )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_mutex_trylock( pthread_mutex_t *mp )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_cond_init( pthread_cond_t *cv, pthread_condattr_t *attr )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_cond_destroy( pthread_cond_t *cv )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_cond_wait( pthread_cond_t *cv, pthread_mutex_t *mp )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_cond_signal( pthread_cond_t *cv )
{
	return( 0 );
}

/* ARGSUSED */
int
pthread_cond_broadcast( pthread_cond_t *cv )
{
	return( 0 );
}

#endif /* no threads package */
