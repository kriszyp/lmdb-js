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
#include <stdlib.h>
#include <lthread.h>
#include <lthread_rdwr.h>

int pthread_rdwr_init_np(pthread_rdwr_t *rdwrp, pthread_rdwrattr_t *attrp)
{
	rdwrp->readers_reading = 0;
	rdwrp->writer_writing = 0;
	pthread_mutex_init(&(rdwrp->mutex), NULL);
	pthread_cond_init(&(rdwrp->lock_free), NULL);
	return 0;
}

int pthread_rdwr_rlock_np(pthread_rdwr_t *rdwrp){
	pthread_mutex_lock(&(rdwrp->mutex));
	while(rdwrp->writer_writing) {
		pthread_cond_wait(&(rdwrp->lock_free), &(rdwrp->mutex));
	}
	rdwrp->readers_reading++;
	pthread_mutex_unlock(&(rdwrp->mutex));
	return 0;
}

int pthread_rdwr_runlock_np(pthread_rdwr_t *rdwrp)
{
	pthread_mutex_lock(&(rdwrp->mutex));
	if (rdwrp->readers_reading == 0) {
		pthread_mutex_unlock(&(rdwrp->mutex));
		return -1;
	}
	else {
		rdwrp->readers_reading--;
		if (rdwrp->readers_reading == 0) {
			pthread_cond_signal(&(rdwrp->lock_free));
		}
		pthread_mutex_unlock(&(rdwrp->mutex));
		return 0;
	}
}

int pthread_rdwr_wlock_np(pthread_rdwr_t *rdwrp)
{
	pthread_mutex_lock(&(rdwrp->mutex));
	while(rdwrp->writer_writing || rdwrp->readers_reading) {
		pthread_cond_wait(&(rdwrp->lock_free), &(rdwrp->mutex));
	}
	rdwrp->writer_writing++;
	pthread_mutex_unlock(&(rdwrp->mutex));
	return 0;
}

int pthread_rdwr_wunlock_np(pthread_rdwr_t *rdwrp)
{
	pthread_mutex_lock(&(rdwrp->mutex));
	if (rdwrp->writer_writing == 0) {
		pthread_mutex_unlock(&(rdwrp->mutex));
		return -1;
	}
	else {
		rdwrp->writer_writing = 0;
		pthread_cond_broadcast(&(rdwrp->lock_free));
		pthread_mutex_unlock(&(rdwrp->mutex));
		return 0;
	}
}

#ifdef LDAP_DEBUG

/* just for testing, 
 * return 0 if false, suitable for assert(pthread_rdwr_Xchk(rdwr))
 * 
 * Currently they don't check if the calling thread is the one 
 * that has the lock, just that there is a reader or writer.
 *
 * Basically sufficent for testing that places that should have
 * a lock are caught.
 */

int pthread_rdwr_rchk_np(pthread_rdwr_t *rdwrp)
{
	return(rdwrp->readers_reading!=0);
}

int pthread_rdwr_wchk_np(pthread_rdwr_t *rdwrp)
{
	return(rdwrp->writer_writing!=0);
}
int pthread_rdwr_rwchk_np(pthread_rdwr_t *rdwrp)
{
	return(pthread_rdwr_rchk_np(rdwrp) || pthread_rdwr_wchk_np(rdwrp));
}

#endif LDAP_DEBUG
