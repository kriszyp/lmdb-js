/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/* thr_nt.c - wrapper around NT threads */

#include "portable.h"
#include "ldap_pvt_thread.h"

#if defined( HAVE_NT_THREADS )

int 
openldap_thread_create( openldap_thread_t * thread, 
		       openldap_thread_attr_t *attr,
		       void *(*start_routine)( void *), void *arg)
{
	*thread = (openldap_thread_t)_beginthread( (void *) start_routine, 
						0, arg );
	 return ( (unsigned long)*thread == -1 ? -1 : 0 );
}
	
void 
openldap_thread_exit( void *retval )
{
	_endthread( );
}

int 
openldap_thread_join( openldap_thread_t thread, void **thread_return )
{
	DWORD status;
	status = WaitForSingleObject( thread, INFINITE );
	if (status == WAIT_FAILED) {
		return -1;
	}
	return 0;
}

int 
openldap_thread_kill( openldap_thread_t thread, int signo )
{
	return 0;
}

int 
openldap_thread_yield( void )
{
	return 0;
}

int 
openldap_thread_attr_init( openldap_thread_attr_t *attr )
{
	*attr = 0;
	return( 0 );
}

int 
openldap_thread_attr_destroy( openldap_thread_attr_t *attr )
{
	return( 0 );
}

int 
openldap_thread_attr_setdetachstate( openldap_thread_attr_t *attr, int dstate )
{
	*attr = dstate;
	return( 0 );
}

int
openldap_thread_attr_getdetachstate( openldap_thread_attr_t *attr, 
				     int *detachstate )
{
	*detachstate = *attr;
	return( 0 );
}

int 
openldap_thread_cond_init( openldap_thread_cond_t *cond, 
			  openldap_thread_condattr_t *attr )
{
	*cond = CreateEvent( NULL, FALSE, FALSE, NULL );
	return( 0 );
}

int
openldap_thread_cond_destroy( openldap_thread_cond_t *cv )
{
	CloseHandle( *cv );
	return( 0 );
}

int 
openldap_thread_cond_signal( openldap_thread_cond_t *cond )
{
	SetEvent( *cond );
	return( 0 );
}

int 
openldap_thread_cond_wait( openldap_thread_cond_t *cond, 
			  openldap_thread_mutex_t *mutex )
{
	ReleaseMutex( *mutex );
	WaitForSingleObject( *cond, INFINITE );
	WaitForSingleObject( *mutex, INFINITE );
	return( 0 );
}

int
openldap_thread_cond_broadcast( openldap_thread_cond_t *cv )
{
	SetEvent( *cv );
	return( 0 );
}

int 
openldap_thread_mutex_init( openldap_thread_mutex_t *mutex,
			   openldap_thread_mutexattr_t *attr )
{
	*mutex = CreateMutex( NULL, 0, NULL );
	return ( 0 );
}

int 
openldap_thread_mutex_destroy( openldap_thread_mutex_t *mutex )
{
	CloseHandle( *mutex );
	return ( 0 );	
}

int 
openldap_thread_mutex_lock( openldap_thread_mutex_t *mutex )
{
	WaitForSingleObject( *mutex, INFINITE );
	return ( 0 );
}

int 
openldap_thread_mutex_unlock( openldap_thread_mutex_t *mutex )
{
	ReleaseMutex( *mutex );
	return ( 0 );
}

int
openldap_thread_mutex_trylock( openldap_thread_mutex_t *mp )
{
	DWORD status;

	status = WaitForSingleObject( *mp, 0 );
	if ( (status == WAIT_FAILED) || (status == WAIT_TIMEOUT) )
		return 0;
	else
		return 1;
}

#endif
