/* $OpenLDAP$ */

#ifdef LDAP_SYNCREPL

typedef struct re_s {
	struct timeval next_sched;
	struct timeval interval;
	LDAP_STAILQ_ENTRY(re_s) tnext; /* it includes running */
	LDAP_STAILQ_ENTRY(re_s) rnext;
	void *private;
} re_t;

typedef struct runqueue_s {
	LDAP_STAILQ_HEAD(l, re_s) task_list;
	LDAP_STAILQ_HEAD(rl, re_s) run_list;
	ldap_pvt_thread_mutex_t	rq_mutex;
} runqueue_t;

LDAP_F( void )
ldap_pvt_runqueue_insert(
	struct runqueue_s* rq,
	time_t interval,
	void *private
);

LDAP_F( void )
ldap_pvt_runqueue_remove(
	struct runqueue_s* rq,
	struct re_s* entry
);

LDAP_F( struct re_s* )
ldap_pvt_runqueue_next_sched(
	struct runqueue_s* rq,
	struct timeval** next_run
);

LDAP_F( void )
ldap_pvt_runqueue_runtask(
	struct runqueue_s* rq,
	struct re_s* entry
);

LDAP_F( void )
ldap_pvt_runqueue_stoptask(
	struct runqueue_s* rq,
	struct re_s* entry
);

LDAP_F( int )
ldap_pvt_runqueue_isrunning(
	struct runqueue_s* rq,
	struct re_s* entry
);

LDAP_F( void )
ldap_pvt_runqueue_resched(
	struct runqueue_s* rq,
	struct re_s* entry
);

#endif
