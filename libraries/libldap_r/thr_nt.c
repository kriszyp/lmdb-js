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

/* thr_nt.c - wrapper around NT threads */

#include "portable.h"

#if defined( HAVE_NT_THREADS )

#include "ldap_int_thread.h"

int
ldap_int_thread_initialize( void )
{
	return 0;
}

int
ldap_int_thread_destroy( void )
{
	return 0;
}

int 
ldap_int_thread_create( ldap_int_thread_t * thread, 
	int detach,
	void *(*start_routine)( void *),
	void *arg)
{
	*thread = (ldap_int_thread_t)_beginthread( (void *) start_routine, 
						0, arg );
	 return ( (unsigned long)*thread == -1 ? -1 : 0 );
}
	
void 
ldap_int_thread_exit( void *retval )
{
	_endthread( );
}

int 
ldap_int_thread_join( ldap_int_thread_t thread, void **thread_return )
{
	DWORD status;
	status = WaitForSingleObject( (HANDLE) thread, INFINITE );
	if (status == WAIT_FAILED) {
		return -1;
	}
	return 0;
}

int 
ldap_int_thread_kill( ldap_int_thread_t thread, int signo )
{
	return 0;
}

int 
ldap_int_thread_yield( void )
{
	Sleep( 0 );
	return 0;
}

int 
ldap_int_thread_cond_init( ldap_int_thread_cond_t *cond )
{
	*cond = CreateEvent( NULL, FALSE, FALSE, NULL );
	return( 0 );
}

int
ldap_int_thread_cond_destroy( ldap_int_thread_cond_t *cv )
{
	CloseHandle( *cv );
	return( 0 );
}

int 
ldap_int_thread_cond_signal( ldap_int_thread_cond_t *cond )
{
	SetEvent( *cond );
	return( 0 );
}

int 
ldap_int_thread_cond_wait( ldap_int_thread_cond_t *cond, 
			  ldap_int_thread_mutex_t *mutex )
{
	ReleaseMutex( *mutex );
	SignalObjectAndWait( *mutex, *cond, INFINITE, FALSE );
	WaitForSingleObject( *mutex, INFINITE );
	return( 0 );
}

int
ldap_int_thread_cond_broadcast( ldap_int_thread_cond_t *cond )
{
	SetEvent( *cond );
	return( 0 );
}

int 
ldap_int_thread_mutex_init( ldap_int_thread_mutex_t *mutex )
{
	*mutex = CreateMutex( NULL, 0, NULL );
	return ( 0 );
}

int 
ldap_int_thread_mutex_destroy( ldap_int_thread_mutex_t *mutex )
{
	CloseHandle( *mutex );
	return ( 0 );	
}

int 
ldap_int_thread_mutex_lock( ldap_int_thread_mutex_t *mutex )
{
	WaitForSingleObject( *mutex, INFINITE );
	return ( 0 );
}

int 
ldap_int_thread_mutex_unlock( ldap_int_thread_mutex_t *mutex )
{
	ReleaseMutex( *mutex );
	return ( 0 );
}

int
ldap_int_thread_mutex_trylock( ldap_int_thread_mutex_t *mp )
{
	DWORD status;

	status = WaitForSingleObject( *mp, 0 );
	if ( (status == WAIT_FAILED) || (status == WAIT_TIMEOUT) )
		return 0;
	else
		return 1;
}

#endif
