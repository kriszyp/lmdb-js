/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/* thr_thr.c - wrappers around solaris threads */

#include "portable.h"

#if defined( HAVE_GNU_PTH )

#include "ldap_pvt_thread.h"

/*******************
 *                 *
 * GNU Pth Threads *
 *                 *
 *******************/

static pth_attr_t detach_attr;

int
ldap_int_thread_initialize( void )
{
	if( !pth_init() ) {
		return -1;
	}
	detach_attr = pth_attr_new();
	return pth_attr_set( detach_attr, PTH_ATTR_JOINABLE, FALSE );
}

int
ldap_int_thread_destroy( void )
{
	pth_attr_destroy(detach_attr);
	pth_kill();
	return 0;
}

int 
ldap_pvt_thread_create( ldap_pvt_thread_t * thread, 
	int detach,
	void *(*start_routine)( void *),
	void *arg)
{
	*thread = pth_spawn( detach ? detach_attr : PTH_ATTR_DEFAULT,
		start_routine, arg );

	return *thread == NULL;
}

void 
ldap_pvt_thread_exit( void *retval )
{
	pth_exit( retval );
}

int ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
	pth_join( thread, thread_return );
	return 0;
}

int 
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
	pth_raise( thread, signo );
	return 0;
}
	
int 
ldap_pvt_thread_yield( void )
{
	pth_yield(NULL);
	return 0;
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond )
{
	return( pth_cond_init( cond ) );
}

int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	return( pth_cond_notify( cond, 0 ) );
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cond )
{
	return( pth_cond_notify( cond, 1 ) );
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
	ldap_pvt_thread_mutex_t *mutex )
{
	return( pth_cond_await( cond, mutex, NULL ) );
}

int
ldap_pvt_thread_cond_destroy( ldap_pvt_thread_cond_t *cv )
{
	return 0;
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex )
{
	return( pth_mutex_init( mutex ) );
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	return 0;
}

int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	return( pth_mutex_acquire( mutex, 0, NULL ) );
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	return( pth_mutex_release( mutex ) );
}

int
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mutex )
{
	return( pth_mutex_acquire( mutex, 1, NULL ) );
}

#ifdef LDAP_THREAD_HAVE_RDWR
int 
ldap_pvt_thread_rdwr_init( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_init( rw );
}

int 
ldap_pvt_thread_rdwr_destroy( ldap_pvt_thread_rdwr_t *rw )
{
	return 0;
}

int ldap_pvt_thread_rdwr_rlock( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_acquire( rw, PTH_RWLOCK_RD, 0, NULL );
}

int ldap_pvt_thread_rdwr_rtrylock( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_acquire( rw, PTH_RWLOCK_RD, 1, NULL );
}

int ldap_pvt_thread_rdwr_runlock( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_release( rw );
}

int ldap_pvt_thread_rdwr_wlock( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_acquire( rw, PTH_RWLOCK_RW, 0, NULL );
}

int ldap_pvt_thread_rdwr_wtrylock( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_acquire( rw, PTH_RWLOCK_RW, 1, NULL );
}

int ldap_pvt_thread_rdwr_wunlock( ldap_pvt_thread_rdwr_t *rw )
{
	return pth_rwlock_release( rw );
}

#endif /* LDAP_THREAD_HAVE_RDWR */
#endif /* HAVE_GNU_PTH */
