/* $OpenLDAP$ */
#include "portable.h"

#include <stdio.h>

#include <ac/stdarg.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/errno.h>

#include "ldap-int.h"
#include "ldap_pvt_thread.h"
#include "ldap_queue.h"
#include "ldap_rq.h"

void
ldap_pvt_runqueue_insert(
	struct runqueue_s* rq,
	time_t interval,
	void *private
)
{
	struct re_s* entry;
	entry = (struct re_s *) ch_calloc( 1, sizeof( struct re_s ));
	entry->interval.tv_sec = interval;
	entry->interval.tv_usec = 0;
	entry->next_sched.tv_sec = time( NULL );
	entry->next_sched.tv_usec = 0;
	entry->private = private;
	LDAP_STAILQ_INSERT_HEAD( &rq->run_list, entry, next );
}

void
ldap_pvt_runqueue_next_sched(
	struct runqueue_s* rq,
	struct timeval** next_run,
	void **private
)
{
	struct re_s* entry;
	entry = LDAP_STAILQ_FIRST( &rq->run_list );
	if ( entry == NULL ) {
		*next_run = NULL;
		*private = NULL;
	} else {
		*next_run = &entry->next_sched;
		*private = entry->private;
	}
}

void 
ldap_pvt_runqueue_resched(
	struct runqueue_s* rq
)
{
	struct re_s* entry;
	struct re_s* prev;
	struct re_s* e;

	entry = LDAP_STAILQ_FIRST( &rq->run_list );
	if ( entry == NULL ) {
		return;
	} else {
		entry->next_sched.tv_sec = time( NULL ) + entry->interval.tv_sec;
		LDAP_STAILQ_REMOVE_HEAD( &rq->run_list, next );
		if ( LDAP_STAILQ_EMPTY( &rq->run_list )) {
			LDAP_STAILQ_INSERT_HEAD( &rq->run_list, entry, next );
		} else {
			prev = entry;
			LDAP_STAILQ_FOREACH( e, &rq->run_list, next ) {
				if ( e->next_sched.tv_sec > entry->next_sched.tv_sec ) {
					if ( prev == entry ) {
						LDAP_STAILQ_INSERT_HEAD( &rq->run_list, entry, next );
					} else {
						LDAP_STAILQ_INSERT_AFTER( &rq->run_list, prev, entry, next );
					}
				}
				prev = e;
			}
		}
	}
}
