/* thrposix.c - wrapper around posix and posixish thread implementations.
 */

#include "portable.h"
#include "ldap_pvt_thread.h"

#if defined( HAVE_PTHREADS )

int 
ldap_pvt_thread_create( ldap_pvt_thread_t * thread, 
		        ldap_pvt_thread_attr_t *attr,
		       void *(*start_routine)( void *), void *arg)
{
#if !defined( HAVE_PTHREADS_D4 )
	/* This is a standard pthreads implementation. */
	return pthread_create( thread, attr, start_routine, arg );
#else
	/* This is a draft 4 or earlier implementation. */
	return pthread_create( thread, *attr, start_routine, arg );
#endif	
}

void 
ldap_pvt_thread_exit( void *retval )
{
	pthread_exit( retval );
}

int 
ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
#if !defined( HAVE_PTHREADS_FINAL )
	void *dummy;
	if (thread_return==NULL)
	  thread_return=&dummy;
#endif	
	return pthread_join( thread, thread_return );
}

int 
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
#ifdef HAVE_PTHREAD_KILL
	return pthread_kill( thread, signo );
#else
	/* pthread package with DCE */
	if (kill( getpid(), sig )<0)
		return errno;
	return 0;
#endif
}

int 
ldap_pvt_thread_yield( void )
{
#ifdef HAVE_SCHED_YIELD
	return sched_yield();
#else
	return pthread_yield();
#endif   
}

int 
ldap_pvt_thread_attr_init( ldap_pvt_thread_attr_t *attr )
{
#if defined( HAVE_PTHREAD_ATTR_INIT )
	return pthread_attr_init( attr );
#elif defined( HAVE_PTHREAD_ATTR_CREATE )
	return pthread_attr_create( attr );
#else
	No way to init attr, so cause an error.
#endif
}
	
int 
ldap_pvt_thread_attr_destroy( ldap_pvt_thread_attr_t *attr )
{
#if defined( HAVE_PTHREAD_ATTR_DESTROY )
	return pthread_attr_destroy( attr );
#elif defined( HAVE_PTHREAD_ATTR_DELETE )
	return pthread_attr_delete( attr );
#else
	No way to destroy attr, so cause an error.
#endif
}

int 
ldap_pvt_thread_attr_setdetachstate( ldap_pvt_thread_attr_t *attr, int dstate )
{
#if defined( HAVE_PTHREAD_ATTR_SETDETACHSTATE )
	return pthread_attr_setdetachstate( attr, dstate );
#elif defined( HAVE_PTHREAD_ATTR_SETDETACH_NP )
	return pthread_attr_setdetach_np( attr, dstate );
#else
	No way to set state, so cause an error.
#endif
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond, 
			  ldap_pvt_thread_condattr_t *attr )
{
#if defined( HAVE_PTHREADS_D4 )
	return pthread_cond_init( cond, 
				 attr ? attr : pthread_condattr_default );
#else	
	return pthread_cond_init( cond, attr );
#endif	
}
	
int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	return pthread_cond_signal( cond );
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cond )
{
	return pthread_cond_broadcast( cond );
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
		      ldap_pvt_thread_mutex_t *mutex )
{
	return pthread_cond_wait( cond, mutex );
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex,
			   ldap_pvt_thread_mutexattr_t *attr )
{
#if defined( HAVE_PTHREADS_D4 )
	return pthread_mutex_init( mutex,
				  attr ? attr : pthread_mutexattr_default );
#else	    
	return pthread_mutex_init( mutex, attr );
#endif	    
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	return pthread_mutex_destroy( mutex );
}

int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	return pthread_mutex_lock( mutex );
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	return pthread_mutex_unlock( mutex );
}

#endif /* HAVE_PTHREADS */

