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

#include "portable.h"

#include "ldap_int_thread.h"
#include "ldap_pvt_thread.h"

LIBLDAP_F( int )
ldap_pvt_thread_initialize ( void )
{
	return ldap_int_thread_initialize();
}

LIBLDAP_F( int )
ldap_pvt_thread_destroy ( void )
{
	return ldap_int_thread_destroy();
}

LIBLDAP_F( int )
ldap_pvt_thread_get_concurrency ( void )
{
#ifdef HAVE_GETCONCURRENCY
	return ldap_int_thread_get_concurrency();
#else
	return 1;
#endif
}

LIBLDAP_F( int )
ldap_pvt_thread_set_concurrency ( int concurrency )
{
#ifdef HAVE_SETCONCURRENCY
	return ldap_int_thread_set_concurrency(concurrency);
#else
	return 1;
#endif
}

LIBLDAP_F( int ) 
ldap_pvt_thread_create (
	ldap_pvt_thread_t * thread, 
	int	detach,
	void *(*start_routine)( void * ), 
	void *arg)
{
	return ldap_int_thread_create(thread, detach, start_routine, arg);
}

LIBLDAP_F( void ) 
ldap_pvt_thread_exit ( void *retval )
{
	ldap_int_thread_exit(retval);
}

LIBLDAP_F( int )
ldap_pvt_thread_join ( ldap_pvt_thread_t thread, void **status )
{
	return ldap_int_thread_join(thread, status);
}

LIBLDAP_F( int )
ldap_pvt_thread_kill ( ldap_pvt_thread_t thread, int signo )
{
	return ldap_int_thread_kill(thread, signo);
}

LIBLDAP_F( int )
ldap_pvt_thread_yield ( void )
{
	return ldap_int_thread_yield();
}

LIBLDAP_F( int )
ldap_pvt_thread_cond_init ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_init(cond);
}

LIBLDAP_F( int )
ldap_pvt_thread_cond_destroy ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_destroy(cond);
}

LIBLDAP_F( int )
ldap_pvt_thread_cond_signal ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_signal(cond);
}

LIBLDAP_F( int )
ldap_pvt_thread_cond_broadcast ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_broadcast(cond);
}

LIBLDAP_F( int )
ldap_pvt_thread_cond_wait (
	ldap_pvt_thread_cond_t *cond, 
	ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_cond_wait(cond, mutex);
}

LIBLDAP_F( int )
ldap_pvt_thread_mutex_init ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_init(mutex);
}

LIBLDAP_F( int )
ldap_pvt_thread_mutex_destroy ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_destroy(mutex);
}

LIBLDAP_F( int )
ldap_pvt_thread_mutex_lock ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_lock(mutex);
}

LIBLDAP_F( int )
ldap_pvt_thread_mutex_trylock ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_trylock(mutex);
}

LIBLDAP_F( int )
ldap_pvt_thread_mutex_unlock ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_unlock(mutex);
}
