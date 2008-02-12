/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2008 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#ifndef _PROTO_BACK_MONITOR
#define _PROTO_BACK_MONITOR

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/*
 * backends
 */
int
monitor_subsys_backend_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * cache
 */
extern int
monitor_cache_cmp LDAP_P((
	const void		*c1,
	const void		*c2 ));
extern int
monitor_cache_dup LDAP_P((
	void			*c1,
	void			*c2 ));
extern int
monitor_cache_add LDAP_P((
	monitor_info_t		*mi,
	Entry			*e ));
extern int
monitor_cache_get LDAP_P((
	monitor_info_t		*mi,
	struct berval		*ndn,
	Entry			**ep ));
extern int
monitor_cache_dn2entry LDAP_P((
	Operation		*op,
	SlapReply		*rs,
	struct berval		*ndn,
	Entry			**ep,
	Entry			**matched ));
extern int
monitor_cache_lock LDAP_P((
	Entry			*e ));
extern int
monitor_cache_release LDAP_P((
	monitor_info_t		*mi,
	Entry			*e ));

extern int
monitor_cache_destroy LDAP_P((
	monitor_info_t		*mi ));

/*
 * connections
 */
extern int
monitor_subsys_conn_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * databases 
 */
extern int
monitor_subsys_database_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * entry
 */
extern int
monitor_entry_update LDAP_P((
	Operation		*op,
	SlapReply		*rs,
	Entry			*e ));
extern int
monitor_entry_create LDAP_P((
	Operation		*op,
	SlapReply		*rs,
	struct berval		*ndn,
	Entry			*e_parent,
	Entry			**ep ));
extern int
monitor_entry_modify LDAP_P((
	Operation		*op,
	SlapReply		*rs,
	Entry			*e ));
extern int
monitor_entry_test_flags LDAP_P((
	monitor_entry_t		*mp,
	int			cond ));
extern monitor_entry_t *
monitor_entrypriv_create LDAP_P((
	void ));

/*
 * init
 */
extern int
monitor_back_register_subsys LDAP_P((
	monitor_subsys_t	*ms ));
extern monitor_subsys_t *
monitor_back_get_subsys LDAP_P((
	const char		*name ));
extern monitor_subsys_t *
monitor_back_get_subsys_by_dn LDAP_P((
	struct berval		*ndn,
	int			sub ));
extern int
monitor_back_is_configured LDAP_P(( void ));
extern int
monitor_back_register_entry LDAP_P((
	Entry			*e,
	monitor_callback_t	*cb ));
extern int
monitor_back_register_entry_parent LDAP_P((
	Entry			*e,
	monitor_callback_t	*cb,
	struct berval		*base,
	int			scope,
	struct berval		*filter ));
extern int
monitor_filter2ndn LDAP_P((
	struct berval		*base,
	int			scope,
	struct berval		*filter,
	struct berval		*ndn ));
extern int
monitor_back_register_entry_attrs LDAP_P((
	struct berval		*ndn,
	Attribute		*a,
	monitor_callback_t	*cb,
	struct berval		*base,
	int			scope,
	struct berval		*filter ));
extern int
monitor_back_register_entry_callback LDAP_P((
	struct berval		*ndn,
	monitor_callback_t	*cb,
	struct berval		*base,
	int			scope,
	struct berval		*filter ));

/*
 * listener
 */
extern int
monitor_subsys_listener_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * log
 */
extern int
monitor_subsys_log_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * operations
 */
extern int
monitor_subsys_ops_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * overlay
 */
extern int
monitor_subsys_overlay_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * sent
 */
extern int
monitor_subsys_sent_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * threads
 */
extern int
monitor_subsys_thread_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * time
 */
extern int monitor_subsys_time_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * waiters
 */
extern int
monitor_subsys_rww_init LDAP_P((
	BackendDB		*be,
	monitor_subsys_t	*ms ));

/*
 * former external.h
 */

extern BI_init			monitor_back_initialize;

extern BI_db_init		monitor_back_db_init;
extern BI_db_open		monitor_back_db_open;
extern BI_config		monitor_back_config;
extern BI_db_destroy		monitor_back_db_destroy;
extern BI_db_config		monitor_back_db_config;

extern BI_op_search		monitor_back_search;
extern BI_op_compare		monitor_back_compare;
extern BI_op_modify		monitor_back_modify;
extern BI_op_bind		monitor_back_bind;
extern BI_operational		monitor_back_operational;

LDAP_END_DECL

#endif /* _PROTO_BACK_MONITOR */

