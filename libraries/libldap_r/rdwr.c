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
ldap_pvt_thread_rdwr_init(ldap_pvt_thread_rdwr_t *rdwrp )
{
	rdwrp->lt_readers_reading = 0;
	rdwrp->lt_writer_writing = 0;
	ldap_pvt_thread_mutex_init(&(rdwrp->lt_mutex) );
	ldap_pvt_thread_cond_init(&(rdwrp->lt_lock_free) );
	return 0;
}

int ldap_pvt_thread_rdwr_rlock(ldap_pvt_thread_rdwr_t *rdwrp){
	ldap_pvt_thread_mutex_lock(&(rdwrp->lt_mutex));
	while(rdwrp->lt_writer_writing) {
		ldap_pvt_thread_cond_wait(&(rdwrp->lt_lock_free), 
					  &(rdwrp->lt_mutex));
	}
	rdwrp->lt_readers_reading++;
	ldap_pvt_thread_mutex_unlock(&(rdwrp->lt_mutex));
	return 0;
}

int ldap_pvt_thread_rdwr_runlock(ldap_pvt_thread_rdwr_t *rdwrp)
{
	ldap_pvt_thread_mutex_lock(&(rdwrp->lt_mutex));
	if (rdwrp->lt_readers_reading == 0) {
		ldap_pvt_thread_mutex_unlock(&(rdwrp->lt_mutex));
		return -1;
	}
	else {
		rdwrp->lt_readers_reading--;
		if (rdwrp->lt_readers_reading == 0) {
			ldap_pvt_thread_cond_signal(&(rdwrp->lt_lock_free));
		}
		ldap_pvt_thread_mutex_unlock(&(rdwrp->lt_mutex));
		return 0;
	}
}

int ldap_pvt_thread_rdwr_wlock(ldap_pvt_thread_rdwr_t *rdwrp)
{
	ldap_pvt_thread_mutex_lock(&(rdwrp->lt_mutex));
	while(rdwrp->lt_writer_writing || rdwrp->lt_readers_reading) {
		ldap_pvt_thread_cond_wait(&(rdwrp->lt_lock_free), 
					  &(rdwrp->lt_mutex));
	}
	rdwrp->lt_writer_writing++;
	ldap_pvt_thread_mutex_unlock(&(rdwrp->lt_mutex));
	return 0;
}

int ldap_pvt_thread_rdwr_wunlock(ldap_pvt_thread_rdwr_t *rdwrp)
{
	ldap_pvt_thread_mutex_lock(&(rdwrp->lt_mutex));
	if (rdwrp->lt_writer_writing == 0) {
		ldap_pvt_thread_mutex_unlock(&(rdwrp->lt_mutex));
		return -1;
	}
	else {
		rdwrp->lt_writer_writing = 0;
		ldap_pvt_thread_cond_broadcast(&(rdwrp->lt_lock_free));
		ldap_pvt_thread_mutex_unlock(&(rdwrp->lt_mutex));
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
	return(rdwrp->lt_readers_reading!=0);
}

int ldap_pvt_thread_rdwr_wchk(ldap_pvt_thread_rdwr_t *rdwrp)
{
	return(rdwrp->lt_writer_writing!=0);
}
int ldap_pvt_thread_rdwr_rwchk(ldap_pvt_thread_rdwr_t *rdwrp)
{
	return(ldap_pvt_thread_rdwr_rchk(rdwrp) || 
	       ldap_pvt_thread_rdwr_wchk(rdwrp));
}

#endif /* LDAP_DEBUG */
