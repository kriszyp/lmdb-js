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

/* Thread-specific key with data and optional free function */
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

/* Context: thread ID and thread-specific key/data pairs */
typedef struct ldap_int_thread_userctx_s {
	ldap_pvt_thread_t ltu_id;
	ldap_int_thread_key_t ltu_key[MAXKEYS];
} ldap_int_thread_userctx_t;


/* Simple {thread ID -> context} hash table; key=ctx->ltu_id.
 * Protected by ldap_pvt_thread_pool_mutex except during pauses,
 * when it is read-only (used by pool_purgekey and pool_context).
 */
static struct {
	ldap_int_thread_userctx_t *ctx;
	/* ctx is valid when not NULL or DELETED_THREAD_CTX */
#	define DELETED_THREAD_CTX (&ldap_int_main_thrctx + 1) /* dummy addr */
} thread_keys[LDAP_MAXTHR];

#define	TID_HASH(tid, hash) do { \
	unsigned const char *ptr_ = (unsigned const char *)&(tid); \
	unsigned i_; \
	for (i_ = 0, (hash) = ptr_[0]; ++i_ < sizeof(tid);) \
		(hash) += ((hash) << 5) ^ ptr_[i_]; \
} while(0)


/* Task for a thread to perform */
typedef struct ldap_int_thread_task_s {
	union {
		LDAP_STAILQ_ENTRY(ldap_int_thread_task_s) q;
		LDAP_SLIST_ENTRY(ldap_int_thread_task_s) l;
	} ltt_next;
	ldap_pvt_thread_start_t *ltt_start_routine;
	void *ltt_arg;
} ldap_int_thread_task_t;

struct ldap_int_thread_pool_s {
	LDAP_STAILQ_ENTRY(ldap_int_thread_pool_s) ltp_next;

	/* protect members below */
	ldap_pvt_thread_mutex_t ltp_mutex;

	/* not paused and something to do for pool_<wrapper/pause/destroy>() */
	ldap_pvt_thread_cond_t ltp_cond;

	/* ltp_active_count <= 1 && ltp_pause */
	ldap_pvt_thread_cond_t ltp_pcond;

	/* pending tasks, and unused task objects */
	LDAP_STAILQ_HEAD(tcq, ldap_int_thread_task_s) ltp_pending_list;
	LDAP_SLIST_HEAD(tcl, ldap_int_thread_task_s) ltp_free_list;

	ldap_int_thread_pool_state_t ltp_state;

	/* some active request needs to be the sole active request */
	int ltp_pause;

	long ltp_max_count;			/* max number of threads in pool */
	long ltp_max_pending;		/* max pending or paused requests */
	long ltp_pending_count;		/* pending or paused requests */
	long ltp_active_count;		/* active, not paused requests */
	long ltp_open_count;		/* number of threads */
	long ltp_starting;			/* currenlty starting threads */
};

static int ldap_int_has_thread_pool = 0;
static LDAP_STAILQ_HEAD(tpq, ldap_int_thread_pool_s)
	ldap_int_thread_pool_list =
	LDAP_STAILQ_HEAD_INITIALIZER(ldap_int_thread_pool_list);

static ldap_pvt_thread_mutex_t ldap_pvt_thread_pool_mutex;

static void *ldap_int_thread_pool_wrapper( void *pool );

/* Context of the main thread */
static ldap_int_thread_userctx_t ldap_int_main_thrctx;

int
ldap_int_thread_pool_startup ( void )
{
	ldap_int_main_thrctx.ltu_id = ldap_pvt_thread_self();
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


/* Create a thread pool */
int
ldap_pvt_thread_pool_init (
	ldap_pvt_thread_pool_t *tpool,
	int max_threads,
	int max_pending )
{
	ldap_pvt_thread_pool_t pool;
	int rc;

	/* multiple pools are currently not supported (ITS#4943) */
	assert(!ldap_int_has_thread_pool);

	if (! (0 <= max_threads && max_threads <= LDAP_MAXTHR))
		max_threads = 0;

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

	ldap_int_has_thread_pool = 1;
	pool->ltp_state = LDAP_INT_THREAD_POOL_RUNNING;
	pool->ltp_max_count = max_threads;
	pool->ltp_max_pending = max_pending;
	LDAP_STAILQ_INIT(&pool->ltp_pending_list);
	LDAP_SLIST_INIT(&pool->ltp_free_list);
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
		ldap_int_has_thread_pool = 0;
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


/* Submit a task to be performed by the thread pool */
int
ldap_pvt_thread_pool_submit (
	ldap_pvt_thread_pool_t *tpool,
	ldap_pvt_thread_start_t *start_routine, void *arg )
{
	struct ldap_int_thread_pool_s *pool;
	ldap_int_thread_task_t *task;
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

	task = LDAP_SLIST_FIRST(&pool->ltp_free_list);
	if (task) {
		LDAP_SLIST_REMOVE_HEAD(&pool->ltp_free_list, ltt_next.l);
	} else {
		task = (ldap_int_thread_task_t *) LDAP_MALLOC(sizeof(*task));
		if (task == NULL) {
			ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
			return(-1);
		}
	}

	task->ltt_start_routine = start_routine;
	task->ltt_arg = arg;

	pool->ltp_pending_count++;
	LDAP_STAILQ_INSERT_TAIL(&pool->ltp_pending_list, task, ltt_next.q);
	if (pool->ltp_pause) {
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
		return(0);
	}
	ldap_pvt_thread_cond_signal(&pool->ltp_cond);
	if (pool->ltp_open_count < pool->ltp_active_count + pool->ltp_pending_count
		&& (pool->ltp_open_count <
			(pool->ltp_max_count ? pool->ltp_max_count : LDAP_MAXTHR)))
	{
		pool->ltp_open_count++;
		pool->ltp_starting++;
		if (0 != ldap_pvt_thread_create(
			&thr, 1, ldap_int_thread_pool_wrapper, pool))
		{
			/* couldn't create thread.  back out of
			 * ltp_open_count and check for even worse things.
			 */
			pool->ltp_starting--;
			pool->ltp_open_count--;
			if (pool->ltp_open_count == 0) {
				/* no open threads at all?!?
				 */
				ldap_int_thread_task_t *ptr;

				/* let pool_destroy know there are no more threads */
				ldap_pvt_thread_cond_signal(&pool->ltp_cond);

				LDAP_STAILQ_FOREACH(ptr, &pool->ltp_pending_list, ltt_next.q)
					if (ptr == task) break;
				if (ptr == task) {
					/* no open threads, task not handled, so
					 * back out of ltp_pending_count, free the task,
					 * report the error.
					 */
					LDAP_STAILQ_REMOVE(&pool->ltp_pending_list, task,
						ldap_int_thread_task_s, ltt_next.q);
					pool->ltp_pending_count--;
					ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
					LDAP_FREE(task);
					return(-1);
				}
			}
			/* there is another open thread, so this
			 * task will be handled eventually.
			 * continue on, we have signalled that
			 * the task is waiting.
			 */
		}
	}

	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	return(0);
}

/* Set max #threads.  value <= 0 means max supported #threads (LDAP_MAXTHR) */
int
ldap_pvt_thread_pool_maxthreads ( ldap_pvt_thread_pool_t *tpool, int max_threads )
{
	struct ldap_int_thread_pool_s *pool;

	if (! (0 <= max_threads && max_threads <= LDAP_MAXTHR))
		max_threads = 0;

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

/* Inspect the pool */
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

	case LDAP_PVT_THREAD_POOL_PARAM_UNKNOWN:
		break;
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

/* Destroy the pool after making its threads finish */
int
ldap_pvt_thread_pool_destroy ( ldap_pvt_thread_pool_t *tpool, int run_pending )
{
	struct ldap_int_thread_pool_s *pool, *pptr;
	ldap_int_thread_task_t *task;

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

	while ((task = LDAP_STAILQ_FIRST(&pool->ltp_pending_list)) != NULL)
	{
		LDAP_STAILQ_REMOVE_HEAD(&pool->ltp_pending_list, ltt_next.q);
		LDAP_FREE(task);
	}

	while ((task = LDAP_SLIST_FIRST(&pool->ltp_free_list)) != NULL)
	{
		LDAP_SLIST_REMOVE_HEAD(&pool->ltp_free_list, ltt_next.l);
		LDAP_FREE(task);
	}

	ldap_pvt_thread_cond_destroy(&pool->ltp_pcond);
	ldap_pvt_thread_cond_destroy(&pool->ltp_cond);
	ldap_pvt_thread_mutex_destroy(&pool->ltp_mutex);
	LDAP_FREE(pool);
	ldap_int_has_thread_pool = 0;
	return(0);
}

/* Thread loop.  Accept and handle submitted tasks. */
static void *
ldap_int_thread_pool_wrapper ( 
	void *xpool )
{
	struct ldap_int_thread_pool_s *pool = xpool;
	ldap_int_thread_task_t *task;
	ldap_int_thread_userctx_t ctx, *kctx;
	unsigned i, keyslot, hash;

	assert(pool != NULL);

	for ( i=0; i<MAXKEYS; i++ ) {
		ctx.ltu_key[i].ltk_key = NULL;
	}

	ctx.ltu_id = ldap_pvt_thread_self();
	TID_HASH(ctx.ltu_id, hash);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);

	/* thread_keys[] is read-only when paused */
	while (pool->ltp_pause)
		ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

	/* find a key slot to give this thread ID and store a
	 * pointer to our keys there; start at the thread ID
	 * itself (mod LDAP_MAXTHR) and look for an empty slot.
	 */
	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	for (keyslot = hash & (LDAP_MAXTHR-1);
		(kctx = thread_keys[keyslot].ctx) && kctx != DELETED_THREAD_CTX;
		keyslot = (keyslot+1) & (LDAP_MAXTHR-1));
	thread_keys[keyslot].ctx = &ctx;
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	pool->ltp_starting--;

	for (;;) {
		while (pool->ltp_pause)
			ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

		if (pool->ltp_state == LDAP_INT_THREAD_POOL_STOPPING)
			break;

		task = LDAP_STAILQ_FIRST(&pool->ltp_pending_list);
		if (task == NULL) {
			if (pool->ltp_state == LDAP_INT_THREAD_POOL_FINISHING)
				break;

			if (pool->ltp_open_count >
				(pool->ltp_max_count ? pool->ltp_max_count : LDAP_MAXTHR))
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

		LDAP_STAILQ_REMOVE_HEAD(&pool->ltp_pending_list, ltt_next.q);
		pool->ltp_pending_count--;
		pool->ltp_active_count++;
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

		task->ltt_start_routine(&ctx, task->ltt_arg);

		ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
		LDAP_SLIST_INSERT_HEAD(&pool->ltp_free_list, task, ltt_next.l);
		pool->ltp_active_count--;
		/* let pool_pause know when it is the sole active thread */
		if (pool->ltp_active_count < 2)
			ldap_pvt_thread_cond_signal(&pool->ltp_pcond);
	}

	ldap_pvt_thread_pool_context_reset(&ctx);

	/* Needed if context_reset can let another thread request a pause */
	while (pool->ltp_pause)
		ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	thread_keys[keyslot].ctx = DELETED_THREAD_CTX;
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	pool->ltp_open_count--;

	/* let pool_destroy know we're all done */
	if (pool->ltp_open_count < 1)
		ldap_pvt_thread_cond_signal(&pool->ltp_cond);

	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

	ldap_pvt_thread_exit(NULL);
	return(NULL);
}

/* Pause the pool.  Return when all other threads are paused. */
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
	if (pool->ltp_pause) {
		pool->ltp_pending_count++;
		pool->ltp_active_count--;
		/* let the other pool_pause() know when it can proceed */
		if (pool->ltp_active_count < 2)
			ldap_pvt_thread_cond_signal(&pool->ltp_pcond);
		do {
			ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);
		} while (pool->ltp_pause);
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

/* End a pause */
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

/*
 * Get the key's data and optionally free function in the given context.
 * Must not be called when the pool is paused.
 */
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
	for ( ; i < MAXKEYS-1 && ctx->ltu_key[i+1].ltk_key; i++ )
		ctx->ltu_key[i] = ctx->ltu_key[i+1];
	ctx->ltu_key[i].ltk_key = NULL;
}

/*
 * Set or remove data for the key in the given context.
 * Must not be called when the pool is paused.
 * key can be any unique pointer.
 * kfree() is an optional function to free the data (but not the key):
 * pool_context_reset() and pool_purgekey() call kfree(key, data),
 * but pool_setkey() does not.  For pool_setkey() it is the caller's
 * responsibility to free any existing data with the same key.
 */
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
 * Find the context of the current thread.
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
	if ( ldap_pvt_thread_equal( tid, ldap_int_main_thrctx.ltu_id ))
		return &ldap_int_main_thrctx;

	TID_HASH( tid, hash );
	i = hash &= (LDAP_MAXTHR-1);
	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	do {
		ctx = thread_keys[i].ctx;
		if ( ctx == DELETED_THREAD_CTX )
			continue;
		if ( !ctx || ldap_pvt_thread_equal(thread_keys[i].ctx->ltu_id, tid) )
			goto done;
	} while ( (i = (i+1) & (LDAP_MAXTHR-1)) != hash );
	ctx = NULL;
 done:
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	return ctx;
}

/* Free the context's keys.  Must not be called when the pool is paused. */
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
