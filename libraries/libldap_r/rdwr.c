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

/*
** This is an improved implementation of Reader/Writer locks does
** not protect writers from starvation.  That is, if a writer is
** currently waiting on a reader, any new reader will get
** the lock before the writer.
**
** Does not support cancellation nor does any status checking.
*/
/* Adapted from publically available examples for:
 *	"Programming with Posix Threads"
 *		by David R Butenhof, Addison-Wesley 
 *		http://cseng.aw.com/bookpage.taf?ISBN=0-201-63392-2
 */

#include "portable.h"

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_pvt_thread.h"

/*
 * implementations that provide their own compatible 
 * reader/writer locks define LDAP_THREAD_HAVE_RDWR
 * in ldap_pvt_thread.h
 */
#ifndef LDAP_THREAD_HAVE_RDWR

struct ldap_int_thread_rdwr_s {
	ldap_pvt_thread_mutex_t ltrw_mutex;
	ldap_pvt_thread_cond_t ltrw_read;       /* wait for read */
	ldap_pvt_thread_cond_t ltrw_write;      /* wait for write */
	int ltrw_valid;
#define LDAP_PVT_THREAD_RDWR_VALID 0x0bad
	int ltrw_r_active;
	int ltrw_w_active;
	int ltrw_r_wait;
	int ltrw_w_wait;
};

int 
ldap_pvt_thread_rdwr_init( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );

	rw = (struct ldap_int_thread_rdwr_s *) LDAP_CALLOC( 1,
		sizeof( struct ldap_int_thread_rdwr_s ) );

	/* we should check return results */
	ldap_pvt_thread_mutex_init( &rw->ltrw_mutex );
	ldap_pvt_thread_cond_init( &rw->ltrw_read );
	ldap_pvt_thread_cond_init( &rw->ltrw_write );

	rw->ltrw_valid = LDAP_PVT_THREAD_RDWR_VALID;

	*rwlock = rw;
	return 0;
}

int 
ldap_pvt_thread_rdwr_destroy( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	/* active threads? */
	if( rw->ltrw_r_active > 0 || rw->ltrw_w_active > 0) {
		ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );
		return LDAP_PVT_THREAD_EBUSY;
	}

	/* waiting threads? */
	if( rw->ltrw_r_wait > 0 || rw->ltrw_w_wait > 0) {
		ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );
		return LDAP_PVT_THREAD_EBUSY;
	}

	rw->ltrw_valid = 0;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	ldap_pvt_thread_mutex_destroy( &rw->ltrw_mutex );
	ldap_pvt_thread_cond_destroy( &rw->ltrw_read );
	ldap_pvt_thread_cond_destroy( &rw->ltrw_write );

	LDAP_FREE(rw);
	*rwlock = NULL;
	return 0;
}

int ldap_pvt_thread_rdwr_rlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	if( rw->ltrw_w_active > 0 ) {
		/* writer is active */

		rw->ltrw_r_wait++;

		do {
			ldap_pvt_thread_cond_wait(
				&rw->ltrw_read, &rw->ltrw_mutex );
		} while( rw->ltrw_w_active > 0 );

		rw->ltrw_r_wait--;
		assert( rw->ltrw_r_wait >= 0 ); 
	}

	rw->ltrw_r_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_rtrylock( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	if( rw->ltrw_w_active > 0) {
		ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );
		return LDAP_PVT_THREAD_EBUSY;
	}

	rw->ltrw_r_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_runlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	rw->ltrw_r_active--;

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	if (rw->ltrw_r_active == 0 && rw->ltrw_w_wait > 0 ) {
		ldap_pvt_thread_cond_signal( &rw->ltrw_write );
	}

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_wlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	if ( rw->ltrw_w_active > 0 || rw->ltrw_r_active > 0 ) {
		rw->ltrw_w_wait++;

		do {
			ldap_pvt_thread_cond_wait(
				&rw->ltrw_write, &rw->ltrw_mutex );
		} while ( rw->ltrw_w_active > 0 || rw->ltrw_r_active > 0 );

		rw->ltrw_w_wait--;
		assert( rw->ltrw_w_wait >= 0 ); 
	}

	rw->ltrw_w_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_wtrylock( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	if ( rw->ltrw_w_active > 0 || rw->ltrw_r_active > 0 ) {
		ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );
		return LDAP_PVT_THREAD_EBUSY;
	}

	rw->ltrw_w_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_wunlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	rw->ltrw_w_active--;

	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	if (rw->ltrw_r_wait > 0) {
		ldap_pvt_thread_cond_broadcast( &rw->ltrw_read );

	} else if (rw->ltrw_w_wait > 0) {
		ldap_pvt_thread_cond_signal( &rw->ltrw_write );
	}

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

#ifdef LDAP_RDWR_DEBUG

/* just for testing, 
 * return 0 if false, suitable for assert(ldap_pvt_thread_rdwr_Xchk(rdwr))
 * 
 * Currently they don't check if the calling thread is the one 
 * that has the lock, just that there is a reader or writer.
 *
 * Basically sufficent for testing that places that should have
 * a lock are caught.
 */

int ldap_pvt_thread_rdwr_readers(ldap_pvt_thread_rdwr_t *rwlock)
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );
	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	return( rw->ltrw_r_active );
}

int ldap_pvt_thread_rdwr_writers(ldap_pvt_thread_rdwr_t *rwlock)
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );
	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	return( rw->ltrw_w_active );
}

int ldap_pvt_thread_rdwr_active(ldap_pvt_thread_rdwr_t *rwlock)
{
	struct ldap_int_thread_rdwr_s *rw;

	assert( rwlock != NULL );
	rw = *rwlock;

	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );
	assert( rw->ltrw_w_active >= 0 ); 
	assert( rw->ltrw_w_wait >= 0 ); 
	assert( rw->ltrw_r_active >= 0 ); 
	assert( rw->ltrw_r_wait >= 0 ); 

	return(ldap_pvt_thread_rdwr_readers(rw) +
	       ldap_pvt_thread_rdwr_writers(rw));
}

#endif /* LDAP_DEBUG */

#endif /* LDAP_THREAD_HAVE_RDWR */
