/* thr_nt.c - wrapper around NT threads */
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

#if defined( HAVE_NT_THREADS )

#include "ldap_pvt_thread.h"

/* mingw compiler very sensitive about getting prototypes right */
typedef unsigned __stdcall thrfunc_t(void *);

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
ldap_pvt_thread_create( ldap_pvt_thread_t * thread, 
	int detach,
	void *(*start_routine)( void *),
	void *arg)
{
	unsigned tid;
	HANDLE thd;

	thd = (HANDLE) _beginthreadex(NULL, LDAP_PVT_THREAD_STACK_SIZE, (thrfunc_t *) start_routine,
				      arg, 0, &tid);

	*thread = (ldap_pvt_thread_t) thd;

	return thd == NULL ? -1 : 0;
}
	
void 
ldap_pvt_thread_exit( void *retval )
{
	_endthread( );
}

int 
ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
	DWORD status;
	status = WaitForSingleObject( (HANDLE) thread, INFINITE );
	return status == WAIT_FAILED ? -1 : 0;
}

int 
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
	return 0;
}

int 
ldap_pvt_thread_yield( void )
{
	Sleep( 0 );
	return 0;
}

int 
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond )
{
	*cond = CreateEvent( NULL, FALSE, FALSE, NULL );
	return( 0 );
}

int
ldap_pvt_thread_cond_destroy( ldap_pvt_thread_cond_t *cv )
{
	CloseHandle( *cv );
	return( 0 );
}

int 
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	SetEvent( *cond );
	return( 0 );
}

int 
ldap_pvt_thread_cond_wait( ldap_pvt_thread_cond_t *cond, 
	ldap_pvt_thread_mutex_t *mutex )
{
	SignalObjectAndWait( *mutex, *cond, INFINITE, FALSE );
	WaitForSingleObject( *mutex, INFINITE );
	return( 0 );
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cond )
{
	while ( WaitForSingleObject( *cond, 0 ) == WAIT_TIMEOUT )
		SetEvent( *cond );
	return( 0 );
}

int 
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex )
{
	*mutex = CreateMutex( NULL, 0, NULL );
	return ( 0 );
}

int 
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	CloseHandle( *mutex );
	return ( 0 );	
}

int 
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	DWORD status;
	status = WaitForSingleObject( *mutex, INFINITE );
	return status == WAIT_FAILED ? -1 : 0;
}

int 
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	ReleaseMutex( *mutex );
	return ( 0 );
}

int
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mp )
{
	DWORD status;
	status = WaitForSingleObject( *mp, 0 );
	return status == WAIT_FAILED || status == WAIT_TIMEOUT
		? -1 : 0;
}

ldap_pvt_thread_t
ldap_pvt_thread_self( void )
{
	return GetCurrentThread();
}

#endif
