/* $OpenLDAP$ */

typedef struct re_s {
	struct timeval next_sched;
	struct timeval interval;
	LDAP_STAILQ_ENTRY(re_s) next;
	void *private;
} re_t;

typedef struct runqueue_s {
	LDAP_STAILQ_HEAD(rl, re_s) run_list;
} runqueue_t;
