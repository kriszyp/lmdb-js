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
/* ldap_int_thread.h - ldap internal thread wrappers header file */

#ifndef _LDAP_INT_THREAD_H
#define _LDAP_INT_THREAD_H

#include "ldap_cdefs.h"

#if defined( HAVE_PTHREADS )
/**********************************
 *                                *
 * definitions for POSIX Threads  *
 *                                *
 **********************************/

#include <pthread.h>
#ifdef HAVE_SCHED_H
#include <sched.h>
#endif

LDAP_BEGIN_DECL

typedef pthread_t		ldap_int_thread_t;
typedef pthread_mutex_t		ldap_int_thread_mutex_t;
typedef pthread_cond_t		ldap_int_thread_cond_t;

#if defined( _POSIX_REENTRANT_FUNCTIONS ) || \
	defined( _POSIX_THREAD_SAFE_FUNCTIONS ) || \
	defined( _POSIX_THREADSAFE_FUNCTIONS )
#define HAVE_REENTRANT_FUNCTIONS 1
#endif

#if defined( HAVE_PTHREAD_GETCONCURRENCY ) || \
	defined( HAVE_THR_GETCONCURRENCY )
#define HAVE_GETCONCURRENCY 1
#endif

#if defined( HAVE_PTHREAD_SETCONCURRENCY ) || \
	defined( HAVE_THR_SETCONCURRENCY )
#define HAVE_SETCONCURRENCY 1
#endif

#if defined( HAVE_PTHREAD_RWLOCK_DESTROY )
#define LDAP_THREAD_HAVE_RDWR 1
typedef pthread_rwlock_t ldap_pvt_thread_rdwr_t;
#endif

LDAP_END_DECL

#elif defined ( HAVE_MACH_CTHREADS )
/**********************************
 *                                *
 * definitions for Mach CThreads  *
 *                                *
 **********************************/

#include <mach/cthreads.h>

LDAP_BEGIN_DECL

typedef cthread_t		ldap_int_thread_t;
typedef struct mutex		ldap_int_thread_mutex_t;
typedef struct condition	ldap_int_thread_cond_t;

LDAP_END_DECL

#elif defined( HAVE_GNU_PTH )
/***********************************
 *                                 *
 * thread definitions for GNU Pth  *
 *                                 *
 ***********************************/

#define PTH_SYSCALL_SOFT 1
#include <pth.h>

LDAP_BEGIN_DECL

typedef pth_t		ldap_int_thread_t;
typedef pth_mutex_t	ldap_int_thread_mutex_t;
typedef pth_cond_t	ldap_int_thread_cond_t;

#define LDAP_THREAD_HAVE_RDWR 1
typedef pth_rwlock_t ldap_pvt_thread_rdwr_t;

LDAP_END_DECL


#elif defined( HAVE_THR )
/********************************************
 *                                          *
 * thread definitions for Solaris LWP (THR) *
 *                                          *
 ********************************************/

#include <thread.h>
#include <synch.h>

LDAP_BEGIN_DECL

typedef thread_t		ldap_int_thread_t;
typedef mutex_t			ldap_int_thread_mutex_t;
typedef cond_t			ldap_int_thread_cond_t;

#define HAVE_REENTRANT_FUNCTIONS 1

#ifdef HAVE_THR_GETCONCURRENCY
#define HAVE_GETCONCURRENCY 1
#endif
#ifdef HAVE_THR_SETCONCURRENCY
#define HAVE_SETCONCURRENCY 1
#endif

LDAP_END_DECL

#elif defined( HAVE_LWP )
/*************************************
 *                                   *
 * thread definitions for SunOS LWP  *
 *                                   *
 *************************************/

#include <lwp/lwp.h>
#include <lwp/stackdep.h>

LDAP_BEGIN_DECL

typedef thread_t		ldap_int_thread_t;
typedef mon_t			ldap_int_thread_mutex_t;
struct ldap_int_thread_lwp_cv {
	int		lcv_created;
	cv_t		lcv_cv;
};
typedef struct ldap_int_thread_lwp_cv ldap_int_thread_cond_t;

#define HAVE_REENTRANT_FUNCTIONS 1

LDAP_END_DECL

#elif defined(HAVE_NT_THREADS)

LDAP_BEGIN_DECL

#include <process.h>
#include <windows.h>

typedef unsigned long	ldap_int_thread_t;
typedef HANDLE	ldap_int_thread_mutex_t;
typedef HANDLE	ldap_int_thread_cond_t;

LDAP_END_DECL

#else

/***********************************
 *                                 *
 * thread definitions for no       *
 * underlying library support      *
 *                                 *
 ***********************************/

LDAP_BEGIN_DECL

#ifndef NO_THREADS
#define NO_THREADS 1
#endif

typedef int			ldap_int_thread_t;
typedef int			ldap_int_thread_mutex_t;
typedef int			ldap_int_thread_cond_t;

LDAP_END_DECL

#endif /* no threads support */

LDAP_BEGIN_DECL

LIBLDAP_F( int )
ldap_int_thread_initialize LDAP_P(( void ));

LIBLDAP_F( int )
ldap_int_thread_destroy LDAP_P(( void ));

LIBLDAP_F( unsigned int )
ldap_int_thread_sleep LDAP_P(( unsigned int s ));

#ifdef HAVE_GETCONCURRENCY
LIBLDAP_F( int )
ldap_int_thread_get_concurrency LDAP_P(( void ));
#endif

#ifdef HAVE_SETCONCURRENCY
#	ifndef LDAP_THREAD_CONCURRENCY
	/* three concurrent threads should be enough */
#	define LDAP_THREAD_CONCURRENCY	3
#	endif
LIBLDAP_F( int )
ldap_int_thread_set_concurrency LDAP_P(( int ));
#endif

LIBLDAP_F( int ) 
ldap_int_thread_create LDAP_P((
	ldap_int_thread_t * thread, 
	int	detach,
	void *(*start_routine)( void * ), 
	void *arg));

LIBLDAP_F( void ) 
ldap_int_thread_exit LDAP_P(( void *retval ));

LIBLDAP_F( int )
ldap_int_thread_join LDAP_P(( ldap_int_thread_t thread, void **status ));

LIBLDAP_F( int )
ldap_int_thread_kill LDAP_P(( ldap_int_thread_t thread, int signo ));

LIBLDAP_F( int )
ldap_int_thread_yield LDAP_P(( void ));

LIBLDAP_F( int )
ldap_int_thread_cond_init LDAP_P(( ldap_int_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_int_thread_cond_destroy LDAP_P(( ldap_int_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_int_thread_cond_signal LDAP_P(( ldap_int_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_int_thread_cond_broadcast LDAP_P(( ldap_int_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_int_thread_cond_wait LDAP_P((
	ldap_int_thread_cond_t *cond, 
	ldap_int_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_int_thread_mutex_init LDAP_P(( ldap_int_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_int_thread_mutex_destroy LDAP_P(( ldap_int_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_int_thread_mutex_lock LDAP_P(( ldap_int_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_int_thread_mutex_trylock LDAP_P(( ldap_int_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_int_thread_mutex_unlock LDAP_P(( ldap_int_thread_mutex_t *mutex ));

LDAP_END_DECL

#endif /* _LDAP_INT_THREAD_H */
