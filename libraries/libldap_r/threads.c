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

#include <stdio.h>
#include <stdarg.h>

#include <ac/stdlib.h>
#include <ac/string.h>

#include "ldap_int_thread.h"
#include "ldap_pvt_thread.h"

enum {
	LDAP_PVT_THREAD_POOL_RUNNING,
	LDAP_PVT_THREAD_POOL_FINISHING,
	LDAP_PVT_THREAD_POOL_STOPPING
};

typedef struct t_ldap_pvt_thread_listelement {
	struct t_ldap_pvt_thread_listelement *next;
} ldap_pvt_thread_listelement, *ldap_pvt_thread_list;

struct t_ldap_pvt_thread_pool {
	struct t_ldap_pvt_thread_pool *ltp_next;
	ldap_pvt_thread_mutex_t ltp_mutex;
	ldap_pvt_thread_cond_t ltp_cond;
	ldap_pvt_thread_list ltp_pending_list;
	long ltp_state;
	long ltp_max_count;
	long ltp_max_pending;
	long ltp_pending_count;
	long ltp_active_count;
	long ltp_open_count;
};

typedef struct t_ldap_pvt_thread_ctx {
	struct t_ldap_pvt_thread_ctx *ltc_next;
	void *(*ltc_start_routine)( void *);
	void *ltc_arg;
} ldap_pvt_thread_ctx;

ldap_pvt_thread_list ldap_pvt_thread_pool_list = NULL;
ldap_pvt_thread_mutex_t ldap_pvt_thread_pool_mutex;

void *ldap_pvt_thread_pool_wrapper( ldap_pvt_thread_pool_t pool );
void *ldap_pvt_thread_enlist( ldap_pvt_thread_list *list, void *elem );
void *ldap_pvt_thread_delist( ldap_pvt_thread_list *list, void *elem );
void *ldap_pvt_thread_onlist( ldap_pvt_thread_list *list, void *elem );


int
ldap_pvt_thread_initialize ( void )
{
	int rc;

	rc = ldap_int_thread_initialize();
	if (rc == 0) {
		/* init the mutex that protext the list of pools
		 */
		ldap_pvt_thread_mutex_init(&ldap_pvt_thread_pool_mutex);
	}
	return rc;
}

int
ldap_pvt_thread_destroy ( void )
{
	while (ldap_pvt_thread_pool_list != NULL) {
		ldap_pvt_thread_pool_destroy((ldap_pvt_thread_pool_t)ldap_pvt_thread_pool_list, 0);
	}
	ldap_pvt_thread_mutex_destroy(&ldap_pvt_thread_pool_mutex);

	return ldap_int_thread_destroy();
}

int
ldap_pvt_thread_get_concurrency ( void )
{
#ifdef HAVE_GETCONCURRENCY
	return ldap_int_thread_get_concurrency();
#else
	return 1;
#endif
}

int
ldap_pvt_thread_set_concurrency ( int concurrency )
{
#ifdef HAVE_SETCONCURRENCY
	return ldap_int_thread_set_concurrency(concurrency);
#else
	return 1;
#endif
}

int 
ldap_pvt_thread_create (
	ldap_pvt_thread_t * thread, 
	int	detach,
	void *(*start_routine)( void * ), 
	void *arg)
{
	return ldap_int_thread_create(thread, detach, start_routine, arg);
}

void
ldap_pvt_thread_exit ( void *retval )
{
	ldap_int_thread_exit(retval);
}

int
ldap_pvt_thread_join ( ldap_pvt_thread_t thread, void **status )
{
	return ldap_int_thread_join(thread, status);
}

int
ldap_pvt_thread_kill ( ldap_pvt_thread_t thread, int signo )
{
	return ldap_int_thread_kill(thread, signo);
}

int
ldap_pvt_thread_yield ( void )
{
	return ldap_int_thread_yield();
}

int
ldap_pvt_thread_cond_init ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_init(cond);
}

int
ldap_pvt_thread_cond_destroy ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_destroy(cond);
}

int
ldap_pvt_thread_cond_signal ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_signal(cond);
}

int
ldap_pvt_thread_cond_broadcast ( ldap_pvt_thread_cond_t *cond )
{
	return ldap_int_thread_cond_broadcast(cond);
}

int
ldap_pvt_thread_cond_wait (
	ldap_pvt_thread_cond_t *cond, 
	ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_cond_wait(cond, mutex);
}

int
ldap_pvt_thread_mutex_init ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_init(mutex);
}

int
ldap_pvt_thread_mutex_destroy ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_destroy(mutex);
}

int
ldap_pvt_thread_mutex_lock ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_lock(mutex);
}

int
ldap_pvt_thread_mutex_trylock ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_trylock(mutex);
}

int
ldap_pvt_thread_mutex_unlock ( ldap_pvt_thread_mutex_t *mutex )
{
	return ldap_int_thread_mutex_unlock(mutex);
}

#ifdef NO_THREADS

/* There must be a separate implementation when NO_THREADS is on.
 * Since ldap_pvt_thread_pool_wrapper loops, there's no way to
 * simply let the underlying (stub) thread implementation take
 * care of things (unless there was an #ifdef that removed the
 * "while" in ldap_pvt_thread_pool_wrapper, but why do all the
 * extra work of init/submit/destroy when all that's needed
 * are these stubs?)
 */
int
ldap_pvt_thread_pool_startup ( void )
{
	return(0);
}

int
ldap_pvt_thread_pool_shutdown ( void )
{
	return(0);
}

int
ldap_pvt_thread_pool_initialize ( ldap_pvt_thread_pool_t *pool_out, int max_concurrency, int max_pending )
{
	*pool_out = NULL;
	return(0);
}

int
ldap_pvt_thread_pool_submit ( ldap_pvt_thread_pool_t pool, void *(*start_routine)( void * ), void *arg )
{
	(start_routine)(arg);
	return(0);
}

int
ldap_pvt_thread_pool_backload ( ldap_pvt_thread_pool_t pool )
{
	return(0);
}

int
ldap_pvt_thread_pool_destroy ( ldap_pvt_thread_pool_t pool, int run_pending )
{
	return(0);
}

#else

int
ldap_pvt_thread_pool_startup ( void )
{
	return ldap_pvt_thread_mutex_init(&ldap_pvt_thread_pool_mutex);
}

int
ldap_pvt_thread_pool_shutdown ( void )
{
	while (ldap_pvt_thread_pool_list != NULL) {
		ldap_pvt_thread_pool_destroy((ldap_pvt_thread_pool_t)ldap_pvt_thread_pool_list, 0);
	}
	ldap_pvt_thread_mutex_destroy(&ldap_pvt_thread_pool_mutex);
	return(0);
}

int
ldap_pvt_thread_pool_initialize ( ldap_pvt_thread_pool_t *pool_out, int max_concurrency, int max_pending )
{
	ldap_pvt_thread_pool_t pool;
	ldap_pvt_thread_t thr;

	*pool_out = NULL;
	pool = (ldap_pvt_thread_pool_t)calloc(1, sizeof(struct t_ldap_pvt_thread_pool));
	if (pool == NULL)
		return(-1);

	ldap_pvt_thread_mutex_init(&pool->ltp_mutex);
	ldap_pvt_thread_cond_init(&pool->ltp_cond);
	pool->ltp_state = LDAP_PVT_THREAD_POOL_RUNNING;
	pool->ltp_max_count = max_concurrency;
	pool->ltp_max_pending = max_pending;
	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	ldap_pvt_thread_enlist(&ldap_pvt_thread_pool_list, pool);
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	/* start up one thread, just so there is one */
	pool->ltp_open_count++;
	if (ldap_pvt_thread_create( &thr, 1, (void *)ldap_pvt_thread_pool_wrapper, pool ) != 0) {
		/* couldn't start one?  then don't start any */
		ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
		ldap_pvt_thread_delist(&ldap_pvt_thread_pool_list, pool);
		ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);
		ldap_pvt_thread_cond_destroy(&pool->ltp_cond);
		ldap_pvt_thread_mutex_destroy(&pool->ltp_mutex);
		free(pool);
		return(-1);
	}

	*pool_out = pool;
	return(0);
}

int
ldap_pvt_thread_pool_submit ( ldap_pvt_thread_pool_t pool, void *(*start_routine)( void * ), void *arg )
{
	ldap_pvt_thread_ctx *ctx;
	int need_thread = 0;
	ldap_pvt_thread_t thr;

	if (pool == NULL)
		return(-1);

	ctx = (ldap_pvt_thread_ctx *)calloc(1, sizeof(ldap_pvt_thread_ctx));
	if (ctx == NULL)
		return(-1);

	ctx->ltc_start_routine = start_routine;
	ctx->ltc_arg = arg;

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	if (pool->ltp_state != LDAP_PVT_THREAD_POOL_RUNNING
		|| (pool->ltp_max_pending > 0 && pool->ltp_pending_count >= pool->ltp_max_pending))
	{
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
		free(ctx);
		return(-1);
	}
	pool->ltp_pending_count++;
	ldap_pvt_thread_enlist(&pool->ltp_pending_list, ctx);
	ldap_pvt_thread_cond_signal(&pool->ltp_cond);
	if ((pool->ltp_open_count <= 0
			|| pool->ltp_pending_count > 1
			|| pool->ltp_open_count == pool->ltp_active_count)
		&& (pool->ltp_max_count <= 0
			|| pool->ltp_open_count < pool->ltp_max_count))
	{
		pool->ltp_open_count++;
		need_thread = 1;
	}
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

	if (need_thread) {
		if (ldap_pvt_thread_create( &thr, 1, (void *)ldap_pvt_thread_pool_wrapper, pool ) != 0) {
			/* couldn't create thread.  back out of
			 * ltp_open_count and check for even worse things.
			 */
			ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
			pool->ltp_open_count--;
			if (pool->ltp_open_count == 0) {
				/* no open threads at all?!?  this will never happen
				 * because we always leave at least one thread open.
				 */
				if (ldap_pvt_thread_delist(&pool->ltp_pending_list, ctx)) {
					/* no open threads, context not handled, so
					 * back out of ltp_pending_count, free the context,
					 * report the error.
					 */
					pool->ltp_pending_count++;
					ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
					free(ctx);
					return(-1);
				}
			}
			ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
			/* there is another open thread, so this
			 * context will be handled eventually.
			 * continue on and signal that the context
			 * is waiting.
			 */
		}
	}

	return(0);
}

int
ldap_pvt_thread_pool_backload ( ldap_pvt_thread_pool_t pool )
{
	int count;

	if (pool == NULL)
		return(0);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	count = pool->ltp_pending_count + pool->ltp_active_count;
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	return(count);
}

int
ldap_pvt_thread_pool_destroy ( ldap_pvt_thread_pool_t pool, int run_pending )
{
	long waiting;
	ldap_pvt_thread_ctx *ctx;

	if (pool == NULL)
		return(-1);

	ldap_pvt_thread_mutex_lock(&ldap_pvt_thread_pool_mutex);
	pool = ldap_pvt_thread_delist(&ldap_pvt_thread_pool_list, pool);
	ldap_pvt_thread_mutex_unlock(&ldap_pvt_thread_pool_mutex);

	if (pool == NULL)
		return(-1);

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
	if (run_pending)
		pool->ltp_state = LDAP_PVT_THREAD_POOL_FINISHING;
	else
		pool->ltp_state = LDAP_PVT_THREAD_POOL_STOPPING;
	waiting = pool->ltp_open_count;
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

	/* broadcast could be used here, but only after
	 * it is fixed in the NT thread implementation
	 */
	while (--waiting >= 0)
		ldap_pvt_thread_cond_signal(&pool->ltp_cond);
	do {
		ldap_pvt_thread_yield();
		ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
		waiting = pool->ltp_open_count;
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
	} while (waiting > 0);

	while (ctx = (ldap_pvt_thread_ctx *)ldap_pvt_thread_delist(&pool->ltp_pending_list, NULL))
		free(ctx);

	ldap_pvt_thread_cond_destroy(&pool->ltp_cond);
	ldap_pvt_thread_mutex_destroy(&pool->ltp_mutex);
	free(pool);
	return(0);
}

void *
ldap_pvt_thread_pool_wrapper ( ldap_pvt_thread_pool_t pool )
{
	ldap_pvt_thread_ctx *ctx;

	ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);

	while (pool->ltp_state != LDAP_PVT_THREAD_POOL_STOPPING) {

		ctx = ldap_pvt_thread_delist(&pool->ltp_pending_list, NULL);
		if (ctx == NULL) {
			if (pool->ltp_state == LDAP_PVT_THREAD_POOL_FINISHING)
				break;
			/* we could check an idle timer here, and let the
			 * thread die if it has been inactive for a while.
			 * only die if there are other open threads (i.e.,
			 * always have at least one thread open).
			 */
			ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);
			ldap_pvt_thread_yield();
			ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);

			if (pool->ltp_state == LDAP_PVT_THREAD_POOL_RUNNING)
				ldap_pvt_thread_cond_wait(&pool->ltp_cond, &pool->ltp_mutex);

			continue;
		}

		pool->ltp_pending_count--;
		pool->ltp_active_count++;
		ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

		(ctx->ltc_start_routine)(ctx->ltc_arg);
		free(ctx);
		ldap_pvt_thread_yield();

		/* if we use an idle timer, here's
		 * a good place to update it
		 */

		ldap_pvt_thread_mutex_lock(&pool->ltp_mutex);
		pool->ltp_active_count--;
	}

	pool->ltp_open_count--;
	ldap_pvt_thread_mutex_unlock(&pool->ltp_mutex);

	ldap_pvt_thread_exit(NULL);
	return(NULL);
}

void *
ldap_pvt_thread_enlist( ldap_pvt_thread_list *list, void *elem )
{
	ldap_pvt_thread_listelement *prev;

	if (elem == NULL)
		return(NULL);

	((ldap_pvt_thread_listelement *)elem)->next = NULL;
	if (*list == NULL) {
		*list = elem;
		return(elem);
	}

	for (prev = *list ; prev->next != NULL; prev = prev->next) ;
	prev->next = elem;
	return(elem);
}

void *
ldap_pvt_thread_delist( ldap_pvt_thread_list *list, void *elem )
{
	ldap_pvt_thread_listelement *prev;

	if (*list == NULL)
		return(NULL);

	if (elem == NULL)
		elem = *list;

	if (*list == elem) {
		*list = ((ldap_pvt_thread_listelement *)elem)->next;
		return(elem);
	}

	for (prev = *list ; prev->next != NULL; prev = prev->next) {
		if (prev->next == elem) {
			prev->next = ((ldap_pvt_thread_listelement *)elem)->next;
			return(elem);
		}
	}
	return(NULL);
}

void *
ldap_pvt_thread_onlist( ldap_pvt_thread_list *list, void *elem )
{
	ldap_pvt_thread_listelement *prev;

	if (elem == NULL || *list == NULL)
		return(NULL);

	for (prev = *list ; prev != NULL; prev = prev->next) {
		if (prev == elem)
			return(elem);
	}

	return(NULL);
}

#endif	/* NO_THREADS */
