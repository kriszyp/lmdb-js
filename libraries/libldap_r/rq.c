/* $OpenLDAP$ */
/* 
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdarg.h>
#include <ac/stdlib.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_pvt_thread.h"
#include "ldap_queue.h"
#include "ldap_rq.h"

void
ldap_pvt_runqueue_insert(
	struct runqueue_s* rq,
	time_t interval,
	ldap_pvt_thread_start_t *routine,
	void *arg
)
{
	struct re_s* entry;

	entry = (struct re_s *) LDAP_CALLOC( 1, sizeof( struct re_s ));
	entry->interval.tv_sec = interval;
	entry->interval.tv_usec = 0;
	entry->next_sched.tv_sec = time( NULL );
	entry->next_sched.tv_usec = 0;
	entry->routine = routine;
	entry->arg = arg;
	LDAP_STAILQ_INSERT_HEAD( &rq->task_list, entry, tnext );
}

void
ldap_pvt_runqueue_remove(
	struct runqueue_s* rq,
	struct re_s* entry
)
{
	struct re_s* e;

	LDAP_STAILQ_FOREACH( e, &rq->task_list, tnext ) {
		if ( e == entry)
			break;
	}

	assert ( e == entry );

	LDAP_STAILQ_REMOVE( &rq->task_list, entry, re_s, tnext );

	LDAP_FREE( entry );

}

struct re_s*
ldap_pvt_runqueue_next_sched(
	struct runqueue_s* rq,
	struct timeval** next_run
)
{
	struct re_s* entry;

	entry = LDAP_STAILQ_FIRST( &rq->task_list );
	if ( entry == NULL ) {
		*next_run = NULL;
		return NULL;
	} else if ( entry->next_sched.tv_sec == 0 ) {
		*next_run = NULL;
		return NULL;
	} else {
		*next_run = &entry->next_sched;
		return entry;
	}
}

void
ldap_pvt_runqueue_runtask(
	struct runqueue_s* rq,
	struct re_s* entry
)
{
	LDAP_STAILQ_INSERT_HEAD( &rq->run_list, entry, rnext );
}

void
ldap_pvt_runqueue_stoptask(
	struct runqueue_s* rq,
	struct re_s* entry
)
{
	LDAP_STAILQ_REMOVE( &rq->run_list, entry, re_s, rnext );
}

int
ldap_pvt_runqueue_isrunning(
	struct runqueue_s* rq,
	struct re_s* entry
)
{
	struct re_s* e;

	LDAP_STAILQ_FOREACH( e, &rq->run_list, rnext ) {
		if ( e == entry ) {
			return 1;
		}
	}
	return 0;
}

void 
ldap_pvt_runqueue_resched(
	struct runqueue_s* rq,
	struct re_s* entry,
	int defer
)
{
	struct re_s* prev;
	struct re_s* e;

	LDAP_STAILQ_FOREACH( e, &rq->task_list, tnext ) {
		if ( e == entry )
			break;
	}

	assert ( e == entry );

	LDAP_STAILQ_REMOVE( &rq->task_list, entry, re_s, tnext );

	if ( entry->interval.tv_sec && !defer ) {
		entry->next_sched.tv_sec = time( NULL ) + entry->interval.tv_sec;
	} else {
		entry->next_sched.tv_sec = 0;
	}

	if ( LDAP_STAILQ_EMPTY( &rq->task_list )) {
		LDAP_STAILQ_INSERT_HEAD( &rq->task_list, entry, tnext );
	} else if ( entry->next_sched.tv_sec == 0 ) {
		LDAP_STAILQ_INSERT_TAIL( &rq->task_list, entry, tnext );
	} else {
		prev = NULL;
		LDAP_STAILQ_FOREACH( e, &rq->task_list, tnext ) {
			if ( e->next_sched.tv_sec == 0 ) {
				if ( prev == NULL ) {
					LDAP_STAILQ_INSERT_HEAD( &rq->task_list, entry, tnext );
				} else {
					LDAP_STAILQ_INSERT_AFTER( &rq->task_list, prev, entry, tnext );
				}
				break;
			} else if ( e->next_sched.tv_sec > entry->next_sched.tv_sec ) {
				if ( prev == NULL ) {
					LDAP_STAILQ_INSERT_HEAD( &rq->task_list, entry, tnext );
				} else {
					LDAP_STAILQ_INSERT_AFTER( &rq->task_list, prev, entry, tnext );
				}
				break;
			}
			prev = e;
		}
	}
}

int
ldap_pvt_runqueue_persistent_backload(
	struct runqueue_s* rq
)
{
	struct re_s* e;
	int count = 0;

	ldap_pvt_thread_mutex_lock( &rq->rq_mutex );
	if ( !LDAP_STAILQ_EMPTY( &rq->task_list )) {
		LDAP_STAILQ_FOREACH( e, &rq->task_list, tnext ) {
			if ( e->next_sched.tv_sec == 0 )
				count++;
		}
	}
	ldap_pvt_thread_mutex_unlock( &rq->rq_mutex );
	return count;
}

