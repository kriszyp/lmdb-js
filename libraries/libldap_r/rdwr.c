/*
** This basic implementation of Reader/Writer locks does not
** protect writers from starvation.  That is, if a writer is
** currently waiting on a reader, any new reader will get
** the lock before the writer.
*/

/********************************************************
 * An example source module to accompany...
 *
 * "Using POSIX Threads: Programming with Pthreads"
 *		 by Brad nichols, Dick Buttlar, Jackie Farrell
 *		 O'Reilly & Associates, Inc.
 *
 ********************************************************
 * rdwr.c --
 * 
 * Library of functions implementing reader/writer locks
 */

#include "portable.h"

#include <stdlib.h>

#include "ldap_pvt_thread.h"

int 
ldap_pvt_thread_rdwr_init(ldap_pvt_thread_rdwr_t *rdwrp, 
			  ldap_pvt_thread_rdwrattr_t *attrp)
{
	rdwrp->readers_reading = 0;
	rdwrp->writer_writing = 0;
	ldap_pvt_thread_mutex_init(&(rdwrp->mutex), NULL );
	ldap_pvt_thread_cond_init(&(rdwrp->lock_free), NULL );
	return 0;
}

int ldap_pvt_thread_rdwr_rlock(ldap_pvt_thread_rdwr_t *rdwrp){
	ldap_pvt_thread_mutex_lock(&(rdwrp->mutex));
	while(rdwrp->writer_writing) {
		ldap_pvt_thread_cond_wait(&(rdwrp->lock_free), 
					  &(rdwrp->mutex));
	}
	rdwrp->readers_reading++;
	ldap_pvt_thread_mutex_unlock(&(rdwrp->mutex));
	return 0;
}

int ldap_pvt_thread_rdwr_runlock(ldap_pvt_thread_rdwr_t *rdwrp)
{
	ldap_pvt_thread_mutex_lock(&(rdwrp->mutex));
	if (rdwrp->readers_reading == 0) {
		ldap_pvt_thread_mutex_unlock(&(rdwrp->mutex));
		return -1;
	}
	else {
		rdwrp->readers_reading--;
		if (rdwrp->readers_reading == 0) {
			ldap_pvt_thread_cond_signal(&(rdwrp->lock_free));
		}
		ldap_pvt_thread_mutex_unlock(&(rdwrp->mutex));
		return 0;
	}
}

int ldap_pvt_thread_rdwr_wlock(ldap_pvt_thread_rdwr_t *rdwrp)
{
	ldap_pvt_thread_mutex_lock(&(rdwrp->mutex));
	while(rdwrp->writer_writing || rdwrp->readers_reading) {
		ldap_pvt_thread_cond_wait(&(rdwrp->lock_free), 
					  &(rdwrp->mutex));
	}
	rdwrp->writer_writing++;
	ldap_pvt_thread_mutex_unlock(&(rdwrp->mutex));
	return 0;
}

int ldap_pvt_thread_rdwr_wunlock(ldap_pvt_thread_rdwr_t *rdwrp)
{
	ldap_pvt_thread_mutex_lock(&(rdwrp->mutex));
	if (rdwrp->writer_writing == 0) {
		ldap_pvt_thread_mutex_unlock(&(rdwrp->mutex));
		return -1;
	}
	else {
		rdwrp->writer_writing = 0;
		ldap_pvt_thread_cond_broadcast(&(rdwrp->lock_free));
		ldap_pvt_thread_mutex_unlock(&(rdwrp->mutex));
		return 0;
	}
}

#ifdef LDAP_DEBUG

/* just for testing, 
 * return 0 if false, suitable for assert(ldap_pvt_thread_rdwr_Xchk(rdwr))
 * 
 * Currently they don't check if the calling thread is the one 
 * that has the lock, just that there is a reader or writer.
 *
 * Basically sufficent for testing that places that should have
 * a lock are caught.
 */

int ldap_pvt_thread_rdwr_rchk(ldap_pvt_thread_rdwr_t *rdwrp)
{
	return(rdwrp->readers_reading!=0);
}

int ldap_pvt_thread_rdwr_wchk(ldap_pvt_thread_rdwr_t *rdwrp)
{
	return(rdwrp->writer_writing!=0);
}
int ldap_pvt_thread_rdwr_rwchk(ldap_pvt_thread_rdwr_t *rdwrp)
{
	return(ldap_pvt_thread_rdwr_rchk_np(rdwrp) || 
	       ldap_pvt_thread_rdwr_wchk_np(rdwrp));
}

#endif /* LDAP_DEBUG */
