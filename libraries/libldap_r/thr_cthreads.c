/* thrmach.c - wrapper for mach cthreads */

#include "portable.h"
#include "ldap_pvt_thread.h"

#if defined( HAVE_MACH_CTHREADS )

/***********************************************************************
 *                                                                     *
 * under NEXTSTEP or OPENSTEP use CThreads                             *
 * lukeh@xedoc.com.au                                                  *
 *                                                                     *
 ***********************************************************************/

int 
ldap_pvt_thread_create( ldap_pvt_thread_t * thread, 
		       ldap_pvt_thread_attr_t *attr,
		       void *(*start_routine)( void *), void *arg)
{
	*thread = cthread_fork( (cthread_fn_t) start_routine, arg);
	return ( *thread == NULL ? -1 : 0 );	
}

void 
ldap_pvt_thread_exit( void *retval )
{
	cthread_exit( (any_t) retval );
}

int 
ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
	void *status;
	status = (void *) cthread_join ( tid );
	if (thread_return != NULL)
		{
		*thread_return = status;
		}
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
	cthread_yield();
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
	return( 0 );
}

int 
ldap_pvt_thread_attr_setdetachstate( ldap_pvt_thread_attr_t *attr, int dstate )
{
	*attr = dstate;
	return( 0 );
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond, 
			  ldap_pvt_thread_condattr_t *attr )
{
	condition_init( cond );
	return( 0 );
}

int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	condition_signal( cond );
	return( 0 );
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cv )
{
	condition_broadcast( cv );
	return( 0 );
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
			  ldap_pvt_thread_mutex_t *mutex )
{
	condition_wait( cond, mutex );
	return( 0 );	
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex,
			   ldap_pvt_thread_mutexattr_t *attr )
{
	mutex_init( mutex );
	mutex->name = NULL;
	return ( 0 );
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	mutex_clear( mutex );
	return ( 0 );	
}
	
int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	mutex_lock( mutex );
	return ( 0 );
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	mutex_unlock( mutex );
	return ( 0 );
}

int
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mutex )
{
	return mutex_try_lock( mutex );
}

#endif /* HAVE_MACH_CTHREADS */
