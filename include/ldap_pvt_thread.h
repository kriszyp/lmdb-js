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
/* ldap_pvt_thread.h - ldap threads header file NG */

#ifndef _LDAP_PVT_THREAD_H
#define _LDAP_PVT_THREAD_H

#include "ldap_cdefs.h"
#include "ldap_int_thread.h"

LDAP_BEGIN_DECL

typedef ldap_int_thread_t ldap_pvt_thread_t;
typedef ldap_int_thread_mutex_t ldap_pvt_thread_mutex_t;
typedef ldap_int_thread_cond_t ldap_pvt_thread_cond_t;


LIBLDAP_F( int )
ldap_pvt_thread_initialize LDAP_P(( void ));

LIBLDAP_F( int )
ldap_pvt_thread_destroy LDAP_P(( void ));

LIBLDAP_F( unsigned int )
ldap_pvt_thread_sleep LDAP_P(( unsigned int s ));

LIBLDAP_F( int )
ldap_pvt_thread_get_concurrency LDAP_P(( void ));

#ifndef LDAP_THREAD_CONCURRENCY
	/* three concurrent threads should be enough */
#define LDAP_THREAD_CONCURRENCY	3
#endif
LIBLDAP_F( int )
ldap_pvt_thread_set_concurrency LDAP_P(( int ));

#define LDAP_PVT_THREAD_CREATE_JOINABLE 0
#define LDAP_PVT_THREAD_CREATE_DETACHED 1

LIBLDAP_F( int ) 
ldap_pvt_thread_create LDAP_P((
	ldap_pvt_thread_t * thread, 
	int	detach,
	void *(*start_routine)( void * ), 
	void *arg));

LIBLDAP_F( void ) 
ldap_pvt_thread_exit LDAP_P(( void *retval ));

LIBLDAP_F( int )
ldap_pvt_thread_join LDAP_P(( ldap_pvt_thread_t thread, void **status ));

LIBLDAP_F( int )
ldap_pvt_thread_kill LDAP_P(( ldap_pvt_thread_t thread, int signo ));

LIBLDAP_F( int )
ldap_pvt_thread_yield LDAP_P(( void ));

LIBLDAP_F( int )
ldap_pvt_thread_cond_init LDAP_P(( ldap_pvt_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_pvt_thread_cond_destroy LDAP_P(( ldap_pvt_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_pvt_thread_cond_signal LDAP_P(( ldap_pvt_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_pvt_thread_cond_broadcast LDAP_P(( ldap_pvt_thread_cond_t *cond ));

LIBLDAP_F( int )
ldap_pvt_thread_cond_wait LDAP_P((
	ldap_pvt_thread_cond_t *cond, 
	ldap_pvt_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_pvt_thread_mutex_init LDAP_P(( ldap_pvt_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_pvt_thread_mutex_destroy LDAP_P(( ldap_pvt_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_pvt_thread_mutex_lock LDAP_P(( ldap_pvt_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_pvt_thread_mutex_trylock LDAP_P(( ldap_pvt_thread_mutex_t *mutex ));

LIBLDAP_F( int )
ldap_pvt_thread_mutex_unlock LDAP_P(( ldap_pvt_thread_mutex_t *mutex ));

#ifndef LDAP_THREAD_HAVE_RDWR
typedef struct ldap_pvt_thread_rdwr_var {
	ldap_pvt_thread_mutex_t ltrw_mutex;	
	ldap_pvt_thread_cond_t ltrw_read;	/* wait for read */
	ldap_pvt_thread_cond_t ltrw_write;	/* wait for write */
	int ltrw_valid;
#define LDAP_PVT_THREAD_RDWR_VALID 0x0bad
	int ltrw_r_active;
	int ltrw_w_active;
	int ltrw_r_wait;
	int ltrw_w_wait;
} ldap_pvt_thread_rdwr_t;
#endif

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_init LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_destroy LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_rlock LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_rtrylock LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_runlock LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_wlock LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_wtrylock LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_wunlock LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

#ifdef LDAP_DEBUG
LIBLDAP_F( int )
ldap_pvt_thread_rdwr_readers LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_writers LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));

LIBLDAP_F( int )
ldap_pvt_thread_rdwr_active LDAP_P((ldap_pvt_thread_rdwr_t *rdwrp));
#endif /* LDAP_DEBUG */

#define LDAP_PVT_THREAD_EINVAL EINVAL
#define LDAP_PVT_THREAD_EBUSY EINVAL

LDAP_END_DECL

#endif /* _LDAP_THREAD_H */
