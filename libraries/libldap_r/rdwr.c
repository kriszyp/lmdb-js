/* $OpenLDAP$ */
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

#include "ldap_pvt_thread.h"

/*
 * implementations that provide their own compatible 
 * reader/writer locks define LDAP_THREAD_HAVE_RDWR
 * in ldap_pvt_thread.h
 */
#ifndef LDAP_THREAD_HAVE_RDWR

int 
ldap_pvt_thread_rdwr_init( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );

	memset( rw, 0, sizeof(ldap_pvt_thread_rdwr_t) );

	/* we should check return results */
	ldap_pvt_thread_mutex_init( &rw->ltrw_mutex );
	ldap_pvt_thread_cond_init( &rw->ltrw_read );
	ldap_pvt_thread_cond_init( &rw->ltrw_write );

	rw->ltrw_valid = LDAP_PVT_THREAD_RDWR_VALID;
	return 0;
}

int 
ldap_pvt_thread_rdwr_destroy( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

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

	return 0;
}

int ldap_pvt_thread_rdwr_rlock( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	if( rw->ltrw_w_active > 0 ) {
		/* writer is active */

		rw->ltrw_r_wait++;

		do {
			ldap_pvt_thread_cond_wait(
				&rw->ltrw_read, &rw->ltrw_mutex );
		} while( rw->ltrw_w_active > 0 );

		rw->ltrw_r_wait--;
	}

	rw->ltrw_r_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_rtrylock( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	if( rw->ltrw_w_active > 0) {
		ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );
		return LDAP_PVT_THREAD_EBUSY;
	}

	rw->ltrw_r_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_runlock( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	rw->ltrw_r_active--;

	if (rw->ltrw_r_active == 0 && rw->ltrw_w_wait > 0 ) {
		ldap_pvt_thread_cond_signal( &rw->ltrw_write );
	}

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_wlock( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	if ( rw->ltrw_w_active > 0 || rw->ltrw_r_active > 0 ) {
		rw->ltrw_w_wait++;

		do {
			ldap_pvt_thread_cond_wait(
				&rw->ltrw_write, &rw->ltrw_mutex );
		} while ( rw->ltrw_w_active > 0 || rw->ltrw_r_active > 0 );

		rw->ltrw_w_wait--;
	}

	rw->ltrw_w_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_wtrylock( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	if ( rw->ltrw_w_active > 0 || rw->ltrw_r_active > 0 ) {
		ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );
		return LDAP_PVT_THREAD_EBUSY;
	}

	rw->ltrw_w_active++;

	ldap_pvt_thread_mutex_unlock( &rw->ltrw_mutex );

	return 0;
}

int ldap_pvt_thread_rdwr_wunlock( ldap_pvt_thread_rdwr_t *rw )
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	if( rw->ltrw_valid != LDAP_PVT_THREAD_RDWR_VALID )
		return LDAP_PVT_THREAD_EINVAL;

	ldap_pvt_thread_mutex_lock( &rw->ltrw_mutex );

	rw->ltrw_w_active--;

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

int ldap_pvt_thread_rdwr_readers(ldap_pvt_thread_rdwr_t *rw)
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	return( rw->ltrw_r_active );
}

int ldap_pvt_thread_rdwr_writers(ldap_pvt_thread_rdwr_t *rw)
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	return( rw->ltrw_w_active );
}

int ldap_pvt_thread_rdwr_active(ldap_pvt_thread_rdwr_t *rw)
{
	assert( rw != NULL );
	assert( rw->ltrw_valid == LDAP_PVT_THREAD_RDWR_VALID );

	return(ldap_pvt_thread_rdwr_readers(rw) +
	       ldap_pvt_thread_rdwr_writers(rw));
}

#endif /* LDAP_DEBUG */

#endif /* LDAP_THREAD_HAVE_RDWR */
