/* thrsolaris.c - wrappers around solaris threads */

#include "portable.h"
#include "ldap_pvt_thread.h"

#if defined( HAVE_THR )

/*******************
 *                 *
 * Solaris Threads *
 *                 *
 *******************/

int 
ldap_pvt_thread_create( ldap_pvt_thread_t * thread, 
		       ldap_pvt_thread_attr_t *attr,
		       void *(*start_routine)( void *), void *arg)
{
	return( thr_create( NULL, 0, start_routine, arg, *attr, thread ) );
}

void 
ldap_pvt_thread_exit( void *retval )
{
	thr_exit( NULL );
}

int ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
	thr_join( thread, NULL, thread_return );
	return 0;
}

int 
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
	thr_kill( thread, signo );
	return 0;
}
	
int 
ldap_pvt_thread_yield( void )
{
	thr_yield();
	return 0;
}

int 
ldap_pvt_thread_attr_init( ldap_pvt_thread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int 
ldap_pvt_thread_attr_destroy( ldap_pvt_thread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int 
ldap_pvt_thread_attr_setdetachstate( ldap_pvt_thread_attr_t *attr, int dstate )
{
	*attr = detachstate;
	return( 0 );
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond, 
			  ldap_pvt_thread_condattr_t *attr )
{
	return( cond_init( cond, attr ? *attr : USYNC_THREAD, NULL ) );
}

int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	return( cond_signal( cond ) );
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cv )
{
	return( cond_broadcast( cv ) );
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
			  ldap_pvt_thread_mutex_t *mutex )
{
	return( cond_wait( cond, mutex ) );
}

int
ldap_pvt_thread_cond_destroy( ldap_pvt_thread_cond_t *cv )
{
	return( cond_destroy( cv ) );
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex,
			   ldap_pvt_thread_mutexattr_t *attr )
{
	return( mutex_init( mutex, attr ? *attr : USYNC_THREAD, NULL ) );
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	return( mutex_destroy( mutex ) );
}

int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	return( mutex_lock( mutex ) );
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	return( mutex_unlock( mutex ) );
}

int
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mp )
{
	return( mutex_trylock( mp ) );
}

#endif /* HAVE_THR */
