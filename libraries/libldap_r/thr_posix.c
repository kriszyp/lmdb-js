/* thr_posix.c - wrapper around posix and posixish thread implementations.  */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#if defined( HAVE_PTHREADS )

#include <ac/errno.h>

#include "ldap_pvt_thread.h"


#if HAVE_PTHREADS < 6
#  define LDAP_INT_THREAD_ATTR_DEFAULT		pthread_attr_default
#  define LDAP_INT_THREAD_CONDATTR_DEFAULT	pthread_condattr_default
#  define LDAP_INT_THREAD_MUTEXATTR_DEFAULT	pthread_mutexattr_default
#else
#  define LDAP_INT_THREAD_ATTR_DEFAULT		NULL
#  define LDAP_INT_THREAD_CONDATTR_DEFAULT	NULL
#  define LDAP_INT_THREAD_MUTEXATTR_DEFAULT	NULL
#endif


int
ldap_int_thread_initialize( void )
{
	return 0;
}

int
ldap_int_thread_destroy( void )
{
#ifdef HAVE_PTHREAD_KILL_OTHER_THREADS_NP
	/* LinuxThreads: kill clones */
	pthread_kill_other_threads_np();
#endif
	return 0;
}

#ifdef LDAP_THREAD_HAVE_SETCONCURRENCY
int
ldap_pvt_thread_set_concurrency(int n)
{
#ifdef HAVE_PTHREAD_SETCONCURRENCY
	return pthread_setconcurrency( n );
#elif HAVE_THR_SETCONCURRENCY
	return thr_setconcurrency( n );
#else
	return 0;
#endif
}
#endif

#ifdef LDAP_THREAD_HAVE_GETCONCURRENCY
int
ldap_pvt_thread_get_concurrency(void)
{
#ifdef HAVE_PTHREAD_GETCONCURRENCY
	return pthread_getconcurrency();
#elif HAVE_THR_GETCONCURRENCY
	return thr_getconcurrency();
#else
	return 0;
#endif
}
#endif

/* detachstate appeared in Draft 6, but without manifest constants.
 * in Draft 7 they were called PTHREAD_CREATE_UNDETACHED and ...DETACHED.
 * in Draft 8 on, ...UNDETACHED became ...JOINABLE.
 */
#ifndef PTHREAD_CREATE_JOINABLE
#ifdef PTHREAD_CREATE_UNDETACHED
#define	PTHREAD_CREATE_JOINABLE	PTHREAD_CREATE_UNDETACHED
#else
#define	PTHREAD_CREATE_JOINABLE	0
#endif
#endif

#ifndef PTHREAD_CREATE_DETACHED
#define	PTHREAD_CREATE_DETACHED	1
#endif

int 
ldap_pvt_thread_create( ldap_pvt_thread_t * thread,
	int detach,
	void *(*start_routine)( void * ),
	void *arg)
{
	int rtn;
	pthread_attr_t attr;

/* Always create the thread attrs, so we can set stacksize if we need to */
#if HAVE_PTHREADS > 5
	pthread_attr_init(&attr);
#else
	pthread_attr_create(&attr);
#endif

#if defined(LDAP_PVT_THREAD_STACK_SIZE) && LDAP_PVT_THREAD_STACK_SIZE > 0
	/* this should be tunable */
	pthread_attr_setstacksize( &attr, LDAP_PVT_THREAD_STACK_SIZE );
#endif

#if HAVE_PTHREADS > 5
	detach = detach ? PTHREAD_CREATE_DETACHED : PTHREAD_CREATE_JOINABLE;
#if HAVE_PTHREADS == 6
	pthread_attr_setdetachstate(&attr, &detach);
#else
	pthread_attr_setdetachstate(&attr, detach);
#endif
#endif

#if HAVE_PTHREADS < 5
	rtn = pthread_create( thread, attr, start_routine, arg );
#else
	rtn = pthread_create( thread, &attr, start_routine, arg );
#endif
#if HAVE_PTHREADS > 5
	pthread_attr_destroy(&attr);
#else
	pthread_attr_delete(&attr);
	if( detach ) {
		pthread_detach( thread );
	}
#endif

#if HAVE_PTHREADS < 7
	if ( rtn < 0 ) rtn = errno;
#endif
	return rtn;
}

void 
ldap_pvt_thread_exit( void *retval )
{
	pthread_exit( retval );
}

int 
ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
#if HAVE_PTHREADS < 7
	void *dummy;

	if (thread_return==NULL)
	  thread_return=&dummy;

	if ( pthread_join( thread, thread_return ) < 0 ) return errno;
	return 0;
#else
	return pthread_join( thread, thread_return );
#endif
}

int 
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
#if ( HAVE_PTHREAD_KILL && HAVE_PTHREADS > 6 )
	/* MacOS 10.1 is detected as v10 but has no pthread_kill() */
	return pthread_kill( thread, signo );
#elif ( HAVE_PTHREAD_KILL && HAVE_PTHREADS > 4 )
	if ( pthread_kill( thread, signo ) < 0 ) return errno;
	return 0;
#else
	/* pthread package with DCE */
	if (kill( getpid(), signo )<0)
		return errno;
	return 0;
#endif
}

int 
ldap_pvt_thread_yield( void )
{
#if HAVE_THR_YIELD
	return thr_yield();

#elif HAVE_PTHREADS == 10
	return sched_yield();

#elif defined(_POSIX_THREAD_IS_GNU_PTH)
	sched_yield();
	return 0;

#elif HAVE_PTHREADS == 6
	pthread_yield(NULL);
	return 0;
#else
	pthread_yield();
	return 0;
#endif
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond )
{
#if HAVE_PTHREADS < 7
	if ( pthread_cond_init( cond, LDAP_INT_THREAD_CONDATTR_DEFAULT ) < 0 )
		return errno;
	return 0;
#else
	return pthread_cond_init( cond, LDAP_INT_THREAD_CONDATTR_DEFAULT );
#endif
}

int 
ldap_pvt_thread_cond_destroy( ldap_pvt_thread_cond_t *cond )
{
#if HAVE_PTHREADS < 7
	if ( pthread_cond_destroy( cond ) < 0 ) return errno;
	return 0;
#else
	return pthread_cond_destroy( cond );
#endif
}
	
int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
#if HAVE_PTHREADS < 7
	if ( pthread_cond_signal( cond ) < 0 ) return errno;
	return 0;
#else
	return pthread_cond_signal( cond );
#endif
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cond )
{
#if HAVE_PTHREADS < 7
	if ( pthread_cond_broadcast( cond ) < 0 ) return errno;
	return 0;
#else
	return pthread_cond_broadcast( cond );
#endif
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
		      ldap_pvt_thread_mutex_t *mutex )
{
#if HAVE_PTHREADS < 7
	if ( pthread_cond_wait( cond, mutex ) < 0 ) return errno;
	return 0;
#else
	return pthread_cond_wait( cond, mutex );
#endif
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex )
{
#if HAVE_PTHREADS < 7
	if ( pthread_mutex_init( mutex, LDAP_INT_THREAD_MUTEXATTR_DEFAULT )<0)
		return errno;
	return 0;
#else
	return pthread_mutex_init( mutex, LDAP_INT_THREAD_MUTEXATTR_DEFAULT );
#endif
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
#if HAVE_PTHREADS < 7
	if ( pthread_mutex_destroy( mutex ) < 0 ) return errno;
	return 0;
#else
	return pthread_mutex_destroy( mutex );
#endif
}

int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
#if HAVE_PTHREADS < 7
	if ( pthread_mutex_lock( mutex ) < 0 ) return errno;
	return 0;
#else
	return pthread_mutex_lock( mutex );
#endif
}

int 
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mutex )
{
#if HAVE_PTHREADS < 7
	if ( pthread_mutex_trylock( mutex ) < 0 ) return errno;
	return 0;
#else
	return pthread_mutex_trylock( mutex );
#endif
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
#if HAVE_PTHREADS < 7
	if ( pthread_mutex_unlock( mutex ) < 0 ) return errno;
	return 0;
#else
	return pthread_mutex_unlock( mutex );
#endif
}

ldap_pvt_thread_t ldap_pvt_thread_self( void )
{
	return pthread_self();
}

#ifdef LDAP_THREAD_HAVE_RDWR
#ifdef HAVE_PTHREAD_RWLOCK_DESTROY
int 
ldap_pvt_thread_rdwr_init( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_init( rw, NULL ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_init( rw, NULL );
#endif
}

int 
ldap_pvt_thread_rdwr_destroy( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_destroy( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_destroy( rw );
#endif
}

int ldap_pvt_thread_rdwr_rlock( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_rdlock( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_rdlock( rw );
#endif
}

int ldap_pvt_thread_rdwr_rtrylock( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_tryrdlock( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_tryrdlock( rw );
#endif
}

int ldap_pvt_thread_rdwr_runlock( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_unlock( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_unlock( rw );
#endif
}

int ldap_pvt_thread_rdwr_wlock( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_wrlock( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_wrlock( rw );
#endif
}

int ldap_pvt_thread_rdwr_wtrylock( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_trywrlock( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_trywrlock( rw );
#endif
}

int ldap_pvt_thread_rdwr_wunlock( ldap_pvt_thread_rdwr_t *rw )
{
#if HAVE_PTHREADS < 7
	if ( pthread_rwlock_unlock( rw ) < 0 ) return errno;
	return 0;
#else
	return pthread_rwlock_unlock( rw );
#endif
}

#endif /* HAVE_PTHREAD_RDLOCK_DESTROY */
#endif /* LDAP_THREAD_HAVE_RDWR */
#endif /* HAVE_PTHREADS */

