/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/* thr_stub.c - stubs for the threads */

#include "portable.h"
#include "ldap_pvt_thread.h"

#if defined( NO_THREADS )

/***********************************************************************
 *                                                                     *
 * no threads package defined for this system - fake ok returns from   *
 * all threads routines (making it single-threaded).                   *
 *                                                                     *
 ***********************************************************************/

int 
openldap_thread_create( openldap_thread_t * thread, 
		       openldap_thread_attr_t *attr,
		       void *(*start_routine)( void *), void *arg)
{
	start_routine( arg );
	return 0;
}

void 
openldap_thread_exit( void *retval )
{
	return;
}

int 
openldap_thread_join( openldap_thread_t thread, void **thread_return )
{
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
	return 0;
}

int 
openldap_thread_attr_destroy( openldap_thread_attr_t *attr )
{
	return 0;
}

int 
openldap_thread_attr_setdetachstate( openldap_thread_attr_t *attr, int dstate )
{
	return 0;
}

int 
openldap_thread_cond_init( openldap_thread_cond_t *cond, 
			  openldap_thread_condattr_t *attr )
{
	return 0;
}

int 
openldap_thread_cond_signal( openldap_thread_cond_t *cond )
{
	return 0;
}

int 
openldap_thread_cond_wait( openldap_thread_cond_t *cond,
			  openldap_thread_mutex_t *mutex )
{
	return 0;
}

int 
openldap_thread_mutex_init( openldap_thread_mutex_t *mutex,
			   openldap_thread_mutexattr_t *attr )
{
	return 0;
}

int 
openldap_thread_mutex_destroy( openldap_thread_mutex_t *mutex )
{
	return 0;
}

int 
openldap_thread_mutex_lock( openldap_thread_mutex_t *mutex )
{
	return 0;
}

int 
openldap_thread_mutex_unlock( openldap_thread_mutex_t *mutex )
{
	return 0;
}

#endif /* NO_THREADS */
