/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2007 The OpenLDAP Foundation.
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

#include <stdio.h>

#include <ac/stdarg.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/errno.h>

#include "ldap-int.h"
#include "ldap_pvt_thread.h" /* Get the thread interface */
#include "ldap_queue.h"
#define LDAP_THREAD_POOL_IMPLEMENTATION
#include "ldap_thr_debug.h"  /* May rename symbols defined below */

#ifndef LDAP_THREAD_HAVE_TPOOL

typedef enum ldap_int_thread_pool_state_e {
	LDAP_INT_THREAD_POOL_RUNNING,
	LDAP_INT_THREAD_POOL_FINISHING,
	LDAP_INT_THREAD_POOL_STOPPING
} ldap_int_thread_pool_state_t;

typedef struct ldap_int_thread_key_s {
	void *ltk_key;
	void *ltk_data;
	ldap_pvt_thread_pool_keyfree_t *ltk_free;
} ldap_int_thread_key_t;

/* Max number of thread-specific keys we store per thread.
 * We don't expect to use many...
 */
#define	MAXKEYS	32
#define	LDAP_MAXTHR	1024	/* must be a power of 2 */

typedef struct ldap_int_thread_userctx_s {
	ldap_pvt_thread_t ltu_id;
	ldap_int_thread_key_t ltu_key[MAXKEYS];
} ldap_int_thread_userctx_t;

static ldap_pvt_thread_t tid_zero;

/* Thread ID -> context mapping (poor open-addressed hash table).
 * Protected by ldap_pvt_thread_pool_mutex except during pauses,
 * when it is reserved for ldap_pvt_thread_pool_purgekey().
 */
static struct {
	ldap_pvt_thread_t id;
	ldap_int_thread_userctx_t *ctx;		/* set when id != tid_zero */
#	define DELETED_THREAD_CTX (&ldap_int_main_thrctx + 1) /* dummy addr */
} thread_keys[LDAP_MAXTHR];

#define	TID_HASH(tid, hash) do { \
	unsigned const char *ptr_ = (unsigned const char *)&(tid); \
	unsigned i_; \
	for (i_ = 0, (hash) = ptr_[0]; ++i_ < sizeof(tid);) \
		(hash) += ((hash) << 5) ^ ptr_[i_]; \
} while(0)


typedef struct ldap_int_thread_ctx_s {
	union {
	LDAP_STAILQ_ENTRY(ldap_int_thread_ctx_s) q;
	LDAP_SLIST_ENTRY(ldap_int_thread_ctx_s) l;
	LDAP_SLIST_ENTRY(ldap_int_thread_ctx_s) al;
	} ltc_next;
	ldap_pvt_thread_start_t *ltc_start_routine;
	void *ltc_arg;
} ldap_int_thread_ctx_t;

struct ldap_int_thread_pool_s {
	LDAP_STAILQ_ENTRY(ldap_int_thread_pool_s) ltp_next;
	ldap_pvt_thread_mutex_t ltp_mutex;
	ldap_pvt_thread_cond_t ltp_cond;
	ldap_pvt_thread_cond_t ltp_pcond;
	LDAP_STAILQ_HEAD(tcq, ldap_int_thread_ctx_s) ltp_pending_list;
	LDAP_SLIST_HEAD(tcl, ldap_int_thread_ctx_s) ltp_free_list;
	LDAP_SLIST_HEAD(tclq, ldap_int_thread_ctx_s) ltp_active_list;
	ldap_int_thread_pool_state_t ltp_state;
	int ltp_pause;
	long ltp_max_count;
	long ltp_max_pending;
	long ltp_pending_count;
	long ltp_active_count;
	long ltp_open_count;
	long ltp_starting;
};

static LDAP_STAILQ_HEAD(tpq, ldap_int_thread_pool_s)
	ldap_int_thread_pool_list =
	LDAP_STAILQ_HEAD_INITIALIZER(ldap_int_thread_pool_list);

static ldap_pvt_thread_mutex_t ldap_pvt_thread_pool_mutex;

static void *ldap_int_thread_pool_wrapper( void *pool );

static ldap_pvt_thread_t ldap_int_main_tid;

static ldap_int_thread_userctx_t ldap_int_main_thrctx;

int
ldap_int_thread_pool_startup ( void )
{
	ldap_int_main_tid = ldap_pvt_thread_self();
	ldap_int_main_thrctx.ltu_id = ldap_int_main_tid;

	return ldap_pvt_thread_mutex_init(&ldap_pvt_thread_pool_mutex);
}

int
ldap_int_thread_pool_shutdown ( void )
{
	struct ldap_int_thread_pool_s *pool;

	while ((pool = LDAP_STAILQ_FIRST(&ldap_int_thread_pool_list)) != NULL) {
		(ldap_pvt_thread_pool_destroy)(&pool, 0); /* ignore thr_debug macro */
	}
	ldap_pvt_thread_mutex_destroy(&ldap_pvt_thread_pool_mutex);
	return(0);
}

typedef struct ldap_lazy_sem_t {
	ldap_pvt_thread_mutex_t ls_mutex;
	ldap_pvt_thread_cond_t	ls_cond;
	int ls_sem_value;
	/*
	 * when more than ls_lazy_count number of resources
	 * becmoes available, the thread wating for the resources will
	 * be waken up in order to prevent frequent blocking/waking-up
	 */
	unsigned int ls_lazy_count;
	/*
	 * only one thread(listener) will wait on this semaphore
	 * using a flag instead of a list
	 */
	int ls_wait;
} ldap_lazy_sem_t;

ldap_lazy_sem_t* thread_pool_sem = NULL;

int
ldap_lazy_sem_init( unsigned int value, unsigned int lazyness )
{
	thread_pool_sem = (ldap_lazy_sem_t*) LDAP_CALLOC(1,
		sizeof( ldap_lazy_sem_t ));

	if( thread_pool_sem == NULL ) return -1;

	ldap_pvt_thread_mutex_init( &thread_pool_sem->ls_mutex );
	ldap_pvt_thread_cond_init( &thread_pool_sem->ls_cond );
	thread_pool_sem->ls_sem_value = value;
	thread_pool_sem->ls_lazy_count = lazyness;
	thread_pool_sem->ls_wait = 0;

	return 0;
}

/* FIXME: move to some approprite header */
int ldap_lazy_sem_dec( ldap_lazy_sem_t* ls );
int ldap_lazy_sem_wait ( ldap_lazy_sem_t* ls );

/*
 * ldap_lazy_sem_wait is used if a caller is blockable(listener).
 * Otherwise use ldap_lazy_sem_dec (worker)
 */
int
ldap_lazy_sem_op_submit( ldap_lazy_sem_t* ls )
{
	if ( ls == NULL ) return -1;

	/* only worker thread has its thread ctx */
	if ( ldap_pvt_thread_pool_context() ) {
		/* worker thread */
		return ldap_lazy_sem_dec( ls );
	} else {
		/* listener */
		return ldap_lazy_sem_wait( ls );
	}
}

/*
 * test if given semaphore's count is zero.
 * If 0, the caller is blocked 
 * If not, the count is decremented.
 */
int
ldap_lazy_sem_wait ( ldap_lazy_sem_t* ls )
{
	ldap_pvt_thread_mutex_lock( &ls->ls_mutex );

lazy_sem_retry:
	if ( ls->ls_sem_value <= 0 ) {
		/* no more avaliable resources */
		ls->ls_wait = 1;
		ldap_pvt_thread_cond_wait( &ls->ls_cond, &ls->ls_mutex );
		goto lazy_sem_retry;
	} else {
		/* avaliable resources */
		ls->ls_sem_value--;
	}

	ldap_pvt_thread_mutex_unlock( &ls->ls_mutex );

	return 0;
}

/*
 * decrement the count without blocking
 * even when the count becomes less than or equal to 0
 */
int
ldap_lazy_sem_dec( ldap_lazy_sem_t* ls )
{
	ldap_pvt_thread_mutex_lock( &ls->ls_mutex );

	ls->ls_sem_value--;

	ldap_pvt_thread_mutex_unlock( &ls->ls_mutex );

	return 0;
}

/*
 * Increment the count by one and test if it is greater or
 * equal to lazyness. If it is, wake up a blocked thread.
 */
int
ldap_lazy_sem_post( ldap_lazy_sem_t* ls )
{
	if( ls == NULL ) return (-1);

	ldap_pvt_thread_mutex_lock( &ls->ls_mutex );

	ls->ls_sem_value++;
	if ( ls->ls_wait ) {
		if ( ls->ls_sem_value >= ls->ls_lazy_count ) {
			ls->ls_wait = 0;
			ldap_pvt_thread_cond_signal( &ls->ls_cond );
		}
	}

	ldap_pvt_thread_mutex_unlock( &ls->ls_mutex );

	return 0;
}

int
ldap_pvt_thread_pool_init (
	ldap_pvt_thread_pool_t *tpool,
	int max_threads,
	int max_pending )
{
	ldap_pvt_thread_pool_t pool;
	int rc;

	*tpool = NULL;
	pool = (ldap_pvt_thread_pool_t) LDAP_CALLOC(1,
		sizeof(struct ldap_int_thread_pool_s));

	if (pool == NULL) return(-1);

	rc = ldap_pvt_thread_mutex_init(&pool->ltp_mutex);
	if (rc != 0)
		return(rc);
	rc = ldap_pvt_thread_cond_init(&pool->ltp_cond);
	if (rc != 0)
		return(rc);
	rc = ldap_pvt_thread_cond_init(&pool->ltp_pcond);
	if (rc != 0)
		return(rc);
	pool->ltp_state = LDAP_INT_THREAD_POOL_RUNNING;
	pool->ltp_max_count = max_threads;
	pool->ltp_max_pending = max_pending;
	LDAP_STAILQ_INIT(&pool->ltp_pending_list);
	LDAP_SLIST_INIT(&pool->ltp_free_list);
	LDAP_SLIST_INIT(&pool->ltp_active_list);
	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	LDAP_STAILQ_INSERT_TAIL(&ldap_int_thread_pool_list, pool, ltp_next);
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

#if 0
	/* THIS WILL NOT WORK on some systems.  If the process
	 * forks after starting a thread, there is no guarantee
	 * that the thread will survive the fork.  For example,
	 * slapd forks in order to daemonize, and does so after
	 * calling ldap_pvt_thread_pool_init.  On some systems,
	 * this initial thread does not run in the child process,
	 * but ltp_open_count == 1, so two things happen: 
	 * 1) the first client connection fails, and 2) when
	 * slapd is kill'ed, it never terminates since it waits
	 * for all worker threads to exit. */

	/* start up one thread, just so there is one. no need to
	 * lock the mutex right now, since no threads are running.
	 */
	pool->ltp_open_count++;

	ldap_pvt_thread_t thr;
	rc = ldap_pvt_thread_create( &thr, 1, ldap_int_thread_pool_wrapper, pool );

	if( rc != 0) {
		/* couldn't start one?  then don't start any */
		ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
		LDAP_STAILQ_REMOVE(ldap_int_thread_pool_list, pool, 
			ldap_int_thread_pool_s, ltp_next);
		ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);
		ldap_pvt_thread_cond_destroy(&pool->ltp_pcond);
		ldap_pvt_thread_cond_destroy(&pool->ltp_cond);
		ldap_pvt_thread_mutex_destroy(&pool->ltp_mutex);
		LDAP_FREE(pool);
		return(-1);
	}
#endif

	*tpool = pool;
	return(0);
}


int
ldap_pvt_thread_pool_submit (
	ldap_pvt_thread_pool_t *tpool,
	ldap_pvt_thread_start_t *start_routine, void *arg )
{
	struct ldap_int_thread_pool_s *pool;
	ldap_int_thread_ctx_t *ctx;
	int need_thread = 0;
	ldap_pvt_thread_t thr;

	if (tpool == NULL)
		return(-1);

	pool = *tpool;

	if (pool == NULL)
		return(-1);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	if (pool->ltp_state != LDAP_INT_THREAD_POOL_RUNNING
		|| (pool->ltp_max_pending > 0
			&& pool->ltp_pending_count >= pool->ltp_max_pending))
	{
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
		return(-1);
	}

	ctx = LDAP_SLIST_FIRST(&pool->ltp_free_list);
	if (ctx) {
		LDAP_SLIST_REMOVE_HEAD(&pool->ltp_free_list, ltc_next.l);
	} else {
		ctx = (ldap_int_thread_ctx_t *) LDAP_MALLOC(
			sizeof(ldap_int_thread_ctx_t));
		if (ctx == NULL) {
			ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
			return(-1);
		}
	}

	ctx->ltc_start_routine = start_routine;
	ctx->ltc_arg = arg;

	pool->ltp_pending_count++;
	LDAP_STAILQ_INSERT_TAIL(&pool->ltp_pending_list, ctx, ltc_next.q);
	if (pool->ltp_pause) {
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
		return(0);
	}
	ldap_pvt_thread_cond_signal(&pool->ltp_cond);
	if (pool->ltp_open_count < pool->ltp_active_count + pool->ltp_pending_count
		&& (pool->ltp_open_count < pool->ltp_max_count ||
			pool->ltp_max_count <= 0 ))
	{
		pool->ltp_open_count++;
		pool->ltp_starting++;
		need_thread = 1;
	}
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

#ifdef LDAP_PVT_THREAD_POOL_SEM_LOAD_CONTROL
	ldap_lazy_sem_op_submit( thread_pool_sem );
#endif

	if (need_thread) {
		int rc;

		ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);

		rc = ldap_pvt_thread_create( &thr, 1,
			ldap_int_thread_pool_wrapper, pool );
		pool->ltp_starting--;
		if (rc != 0) {
			/* couldn't create thread.  back out of
			 * ltp_open_count and check for even worse things.
			 */
			pool->ltp_open_count--;
			if (pool->ltp_open_count == 0) {
				/* no open threads at all?!?
				 */
				ldap_int_thread_ctx_t *ptr;

				/* let pool_destroy know there are no more threads */
				ldap_pvt_thread_cond_signal(&pool->ltp_cond);

				LDAP_STAILQ_FOREACH(ptr, &pool->ltp_pending_list, ltc_next.q)
					if (ptr == ctx) break;
				if (ptr == ctx) {
					/* no open threads, context not handled, so
					 * back out of ltp_pending_count, free the context,
					 * report the error.
					 */
					LDAP_STAILQ_REMOVE(&pool->ltp_pending_list, ctx, 
						ldap_int_thread_ctx_s, ltc_next.q);
					pool->ltp_pending_count--;
					ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
					LDAP_FREE(ctx);
					return(-1);
				}
			}
			/* there is another open thread, so this
			 * context will be handled eventually.
			 * continue on and signal that the context
			 * is waiting.
			 */
		}
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	}

	return(0);
}

int
ldap_pvt_thread_pool_maxthreads ( ldap_pvt_thread_pool_t *tpool, int max_threads )
{
	struct ldap_int_thread_pool_s *pool;

	if (tpool == NULL)
		return(-1);

	pool = *tpool;

	if (pool == NULL)
		return(-1);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	pool->ltp_max_count = max_threads;
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	return(0);
}

int
ldap_pvt_thread_pool_query ( ldap_pvt_thread_pool_t *tpool, ldap_pvt_thread_pool_param_t param, void *value )
{
	struct ldap_int_thread_pool_s	*pool;
	int				count = -1;

	if ( tpool == NULL || value == NULL ) {
		return -1;
	}

	pool = *tpool;

	if ( pool == NULL ) {
		return 0;
	}

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	switch ( param ) {
	case LDAP_PVT_THREAD_POOL_PARAM_MAX:
		count = pool->ltp_max_count;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_MAX_PENDING:
		count = pool->ltp_max_pending;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_OPEN:
		count = pool->ltp_open_count;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_STARTING:
		count = pool->ltp_starting;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_ACTIVE:
		count = pool->ltp_active_count;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_PENDING:
		count = pool->ltp_pending_count;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_BACKLOAD:
		count = pool->ltp_pending_count + pool->ltp_active_count;
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_ACTIVE_MAX:
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_PENDING_MAX:
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_BACKLOAD_MAX:
		break;

	case LDAP_PVT_THREAD_POOL_PARAM_STATE: {
		static struct {
			char				*name;
			ldap_int_thread_pool_state_t	state;
		}		str2state[] = {
			{ "running",	LDAP_INT_THREAD_POOL_RUNNING },
			{ "finishing",	LDAP_INT_THREAD_POOL_FINISHING },
			{ "stopping",	LDAP_INT_THREAD_POOL_STOPPING },
			{ NULL }
		};
		int		i;

		if ( pool->ltp_pause ) {
			*((char **)value) = "pausing";
		} else {
			for ( i = 0; str2state[ i ].name != NULL; i++ ) {
				if ( str2state[ i ].state == pool->ltp_state ) {
					break;
				}
			}
			*((char **)value) = str2state[ i ].name;
		}
		if ( *((char **)value) != NULL ) {
			count = -2;
		}
		} break;
	}
	ldap_pvt_thread_mutex_unlock( &pool->ltp_mutex );

	if ( count > -1 ) {
		*((int *)value) = count;
	}

	return ( count == -1 ? -1 : 0 );
}

/*
 * wrapper for ldap_pvt_thread_pool_query(), left around
 * for backwards compatibility
 */
int
ldap_pvt_thread_pool_backload ( ldap_pvt_thread_pool_t *tpool )
{
	int	rc, count;

	rc = ldap_pvt_thread_pool_query( tpool,
		LDAP_PVT_THREAD_POOL_PARAM_BACKLOAD, (void *)&count );

	if ( rc == 0 ) {
		return count;
	}

	return rc;
}

int
ldap_pvt_thread_pool_destroy ( ldap_pvt_thread_pool_t *tpool, int run_pending )
{
	struct ldap_int_thread_pool_s *pool, *pptr;
	ldap_int_thread_ctx_t *ctx;

	if (tpool == NULL)
		return(-1);

	pool = *tpool;

	if (pool == NULL) return(-1);

	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	LDAP_STAILQ_FOREACH(pptr, &ldap_int_thread_pool_list, ltp_next)
		if (pptr == pool) break;
	if (pptr == pool)
		LDAP_STAILQ_REMOVE(&ldap_int_thread_pool_list, pool,
			ldap_int_thread_pool_s, ltp_next);
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	if (pool != pptr) return(-1);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	pool->ltp_state = run_pending
		? LDAP_INT_THREAD_POOL_FINISHING
		: LDAP_INT_THREAD_POOL_STOPPING;

	while (pool->ltp_open_count) {
		if (!pool->ltp_pause)
			ldap_pvt_thread_cond_broadcast(&pool->ltp_cond);
		ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);
	}
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

	while ((ctx = LDAP_STAILQ_FIRST(&pool->ltp_pending_list)) != NULL)
	{
		LDAP_STAILQ_REMOVE_HEAD(&pool->ltp_pending_list, ltc_next.q);
		LDAP_FREE(ctx);
	}

	while ((ctx = LDAP_SLIST_FIRST(&pool->ltp_free_list)) != NULL)
	{
		LDAP_SLIST_REMOVE_HEAD(&pool->ltp_free_list, ltc_next.l);
		LDAP_FREE(ctx);
	}

	ldap_pvt_thread_cond_destroy(&pool->ltp_pcond);
	ldap_pvt_thread_cond_destroy(&pool->ltp_cond);
	ldap_pvt_thread_mutex_destroy(&pool->ltp_mutex);
	LDAP_FREE(pool);
#ifdef LDAP_PVT_THREAD_POOL_SEM_LOAD_CONTROL
	if ( thread_pool_sem ) {
		LDAP_FREE( thread_pool_sem );
	}
#endif
	return(0);
}

static void *
ldap_int_thread_pool_wrapper ( 
	void *xpool )
{
	struct ldap_int_thread_pool_s *pool = xpool;
	ldap_int_thread_ctx_t *ctx;
	ldap_int_thread_userctx_t uctx;
	unsigned i, keyslot, hash;

	if (pool == NULL)
		return NULL;

	for ( i=0; i<MAXKEYS; i++ ) {
		uctx.ltu_key[i].ltk_key = NULL;
	}

	uctx.ltu_id = ldap_pvt_thread_self();
	TID_HASH(uctx.ltu_id, hash);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);

	/* when paused, thread_keys[] is reserved for pool_purgekey() */
	while (pool->ltp_pause)
		ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

	/* find a key slot to give this thread ID and store a
	 * pointer to our keys there; start at the thread ID
	 * itself (mod LDAP_MAXTHR) and look for an empty slot.
	 */
	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	for (keyslot = hash & (LDAP_MAXTHR-1);
		!ldap_pvt_thread_equal(thread_keys[keyslot].id, tid_zero);
		keyslot = (keyslot+1) & (LDAP_MAXTHR-1));
	thread_keys[keyslot].id = uctx.ltu_id;
	thread_keys[keyslot].ctx = &uctx;
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	for (;;) {
		while (pool->ltp_pause)
			ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

		if (pool->ltp_state == LDAP_INT_THREAD_POOL_STOPPING)
			break;

		ctx = LDAP_STAILQ_FIRST(&pool->ltp_pending_list);
		if (ctx == NULL) {
			if (pool->ltp_state == LDAP_INT_THREAD_POOL_FINISHING)
				break;

			if (pool->ltp_max_count > 0
				&& pool->ltp_open_count > pool->ltp_max_count)
			{
				/* too many threads running (can happen if the
				 * maximum threads value is set during ongoing
				 * operation using ldap_pvt_thread_pool_maxthreads)
				 * so let this thread die.
				 */
				break;
			}

			/* we could check an idle timer here, and let the
			 * thread die if it has been inactive for a while.
			 * only die if there are other open threads (i.e.,
			 * always have at least one thread open).  the check
			 * should be like this:
			 *   if (pool->ltp_open_count > 1 && pool->ltp_starting == 0)
			 *       check timer, wait if ltp_pause, leave thread (break;)
			 *
			 * Just use pthread_cond_timedwait if we want to
			 * check idle time.
			 */

			assert(pool->ltp_state == LDAP_INT_THREAD_POOL_RUNNING);
			ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);
			continue;
		}

		LDAP_STAILQ_REMOVE_HEAD(&pool->ltp_pending_list, ltc_next.q);
		pool->ltp_pending_count--;

		LDAP_SLIST_INSERT_HEAD(&pool->ltp_active_list, ctx, ltc_next.al);
		pool->ltp_active_count++;
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

		ctx->ltc_start_routine(&uctx, ctx->ltc_arg);

#ifdef LDAP_PVT_THREAD_POOL_SEM_LOAD_CONTROL
		ldap_lazy_sem_post( thread_pool_sem );
#endif
		ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
		LDAP_SLIST_REMOVE(&pool->ltp_active_list, ctx,
			ldap_int_thread_ctx_s, ltc_next.al);
		LDAP_SLIST_INSERT_HEAD(&pool->ltp_free_list, ctx, ltc_next.l);
		pool->ltp_active_count--;

		/* let pool_pause know when it is the sole active thread */
		if (pool->ltp_active_count < 2)
			ldap_pvt_thread_cond_signal(&pool->ltp_pcond);
	}

	ldap_pvt_thread_pool_context_reset(&uctx);

	/* Needed if context_reset can let another thread request a pause */
	while (pool->ltp_pause)
		ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	thread_keys[keyslot].ctx = DELETED_THREAD_CTX;
	thread_keys[keyslot].id = tid_zero;
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	pool->ltp_open_count--;

	/* let pool_destroy know we're all done */
	if (pool->ltp_open_count < 1)
		ldap_pvt_thread_cond_signal(&pool->ltp_cond);

	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

	ldap_pvt_thread_exit(NULL);
	return(NULL);
}

int
ldap_pvt_thread_pool_pause ( 
	ldap_pvt_thread_pool_t *tpool )
{
	struct ldap_int_thread_pool_s *pool;

	if (tpool == NULL)
		return(-1);

	pool = *tpool;

	if (pool == NULL)
		return(0);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);

	/* If someone else has already requested a pause, we have to wait */
	while (pool->ltp_pause) {
		pool->ltp_pending_count++;
		pool->ltp_active_count--;
		/* let the other pool_pause() know when it can proceed */
		if (pool->ltp_active_count < 2)
			ldap_pvt_thread_cond_signal(&pool->ltp_pcond);
		ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);
		pool->ltp_pending_count--;
		pool->ltp_active_count++;
	}

	/* Wait for everyone else to pause or finish */
	pool->ltp_pause = 1;
	while (pool->ltp_active_count > 1) {
		ldap_pvt_thread_cond_wait(&pool->ltp_pcond, &pool->ltp_mutex);
	}

	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	return(0);
}

int
ldap_pvt_thread_pool_resume ( 
	ldap_pvt_thread_pool_t *tpool )
{
	struct ldap_int_thread_pool_s *pool;

	if (tpool == NULL)
		return(-1);

	pool = *tpool;

	if (pool == NULL)
		return(0);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	pool->ltp_pause = 0;
	ldap_pvt_thread_cond_broadcast(&pool->ltp_cond);
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	return(0);
}

int ldap_pvt_thread_pool_getkey(
	void *xctx,
	void *key,
	void **data,
	ldap_pvt_thread_pool_keyfree_t **kfree )
{
	ldap_int_thread_userctx_t *ctx = xctx;
	int i;

	if ( !ctx || !key || !data ) return EINVAL;

	for ( i=0; i<MAXKEYS && ctx->ltu_key[i].ltk_key; i++ ) {
		if ( ctx->ltu_key[i].ltk_key == key ) {
			*data = ctx->ltu_key[i].ltk_data;
			if ( kfree ) *kfree = ctx->ltu_key[i].ltk_free;
			return 0;
		}
	}
	return ENOENT;
}

static void
clear_key_idx( ldap_int_thread_userctx_t *ctx, int i )
{
	int j = i;
	while ( ++j < MAXKEYS && ctx->ltu_key[j].ltk_key );
	if ( --j != i ) {
		ctx->ltu_key[i] = ctx->ltu_key[j];
		i = j;
	}
	ctx->ltu_key[i].ltk_key = NULL;
}

int ldap_pvt_thread_pool_setkey(
	void *xctx,
	void *key,
	void *data,
	ldap_pvt_thread_pool_keyfree_t *kfree )
{
	ldap_int_thread_userctx_t *ctx = xctx;
	int i, found;

	if ( !ctx || !key ) return EINVAL;

	for ( i=found=0; i<MAXKEYS; i++ ) {
		if ( ctx->ltu_key[i].ltk_key == key ) {
			found = 1;
			break;
		} else if ( !ctx->ltu_key[i].ltk_key ) {
			break;
		}
	}

	if ( data || kfree ) {
		if ( i>=MAXKEYS )
			return ENOMEM;
		ctx->ltu_key[i].ltk_key = key;
		ctx->ltu_key[i].ltk_data = data;
		ctx->ltu_key[i].ltk_free = kfree;
	} else if ( found ) {
		clear_key_idx( ctx, i );
	}

	return 0;
}

/* Free all elements with this key, no matter which thread they're in.
 * May only be called while the pool is paused.
 */
void ldap_pvt_thread_pool_purgekey( void *key )
{
	int i, j;
	ldap_int_thread_userctx_t *ctx;

	assert ( key != NULL );

	for ( i=0; i<LDAP_MAXTHR; i++ ) {
		ctx = thread_keys[i].ctx;
		if ( ctx && ctx != DELETED_THREAD_CTX ) {
			for ( j=0; j<MAXKEYS && ctx->ltu_key[j].ltk_key; j++ ) {
				if ( ctx->ltu_key[j].ltk_key == key ) {
					if (ctx->ltu_key[j].ltk_free)
						ctx->ltu_key[j].ltk_free( ctx->ltu_key[j].ltk_key,
						ctx->ltu_key[j].ltk_data );
					clear_key_idx( ctx, j );
					break;
				}
			}
		}
	}
}

/*
 * This is necessary if the caller does not have access to the
 * thread context handle (for example, a slapd plugin calling
 * slapi_search_internal()). No doubt it is more efficient
 * for the application to keep track of the thread context
 * handles itself.
 */
void *ldap_pvt_thread_pool_context( )
{
	ldap_pvt_thread_t tid;
	unsigned i, hash;
	ldap_int_thread_userctx_t *ctx;

	tid = ldap_pvt_thread_self();
	if ( ldap_pvt_thread_equal( tid, ldap_int_main_tid ))
		return &ldap_int_main_thrctx;

	TID_HASH( tid, hash );
	i = hash &= (LDAP_MAXTHR-1);
	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	do {
		ctx = thread_keys[i].ctx;
		if ( ctx != DELETED_THREAD_CTX )
			if ( ldap_pvt_thread_equal(thread_keys[i].id, tid) || !ctx )
				goto done;
	} while ( (i = (i+1) & (LDAP_MAXTHR-1)) != hash );
	ctx = NULL;
 done:
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	return ctx;
}

void ldap_pvt_thread_pool_context_reset( void *vctx )
{
	ldap_int_thread_userctx_t *ctx = vctx;
	int i;

	for ( i=MAXKEYS-1; i>=0; i--) {
		if ( !ctx->ltu_key[i].ltk_key )
			continue;
		if ( ctx->ltu_key[i].ltk_free )
			ctx->ltu_key[i].ltk_free( ctx->ltu_key[i].ltk_key,
			ctx->ltu_key[i].ltk_data );
		ctx->ltu_key[i].ltk_key = NULL;
	}
}

ldap_pvt_thread_t ldap_pvt_thread_pool_tid( void *vctx )
{
	ldap_int_thread_userctx_t *ctx = vctx;

	return ctx->ltu_id;
}
#endif /* LDAP_THREAD_HAVE_TPOOL */
