/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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
/* This is an altered version */
/*
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This work has beed deveolped for the OpenLDAP Foundation 
 * in the hope that it may be useful to the Open Source community, 
 * but WITHOUT ANY WARRANTY.
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from
 *    flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 * 
 * 4. This notice may not be removed or altered.
 */

#ifndef _PROTO_BACK_MONITOR
#define _PROTO_BACK_MONITOR

#include <ldap_cdefs.h>

#include "external.h"

LDAP_BEGIN_DECL

/*
 * entry
 */
int monitor_entry_test_flags LDAP_P(( struct monitorentrypriv *mp, int cond ));

/*
 * backends
 */
int monitor_subsys_backend_init LDAP_P(( BackendDB *be ));

/*
 * databases 
 */
int monitor_subsys_database_init LDAP_P(( BackendDB *be ));

/*
 * threads
 */
int monitor_subsys_thread_init LDAP_P(( BackendDB *be ));
int monitor_subsys_thread_update LDAP_P(( Operation *op, Entry *e ));

/*
 * connections
 */
int monitor_subsys_conn_init LDAP_P(( BackendDB *be ));
int monitor_subsys_conn_update LDAP_P(( Operation *op, Entry *e ));
int monitor_subsys_conn_create LDAP_P(( Operation *op, struct berval *ndn,
			Entry *e_parent, Entry **ep ));

/*
 * waiters
 */
int monitor_subsys_rww_init LDAP_P(( BackendDB *be ));
int monitor_subsys_rww_update LDAP_P(( Operation *op, Entry *e ));

/*
 * log
 */
int monitor_subsys_log_init LDAP_P(( BackendDB *be ));
int monitor_subsys_log_modify LDAP_P(( Operation *op, Entry *e ));

/*
 * operations
 */
int monitor_subsys_ops_init LDAP_P(( BackendDB *be ));
int monitor_subsys_ops_update LDAP_P(( Operation *op, Entry *e ));

/*
 * sent
 */
int monitor_subsys_sent_init LDAP_P(( BackendDB *be ));
int monitor_subsys_sent_update LDAP_P(( Operation *op, Entry *e ));

/*
 * listener
 */
int monitor_subsys_listener_init LDAP_P(( BackendDB *be ));

/*
 * time
 */
int monitor_subsys_time_init LDAP_P(( BackendDB *be ));
int monitor_subsys_time_update LDAP_P(( Operation *op, Entry *e ));

LDAP_END_DECL

#endif /* _PROTO_BACK_MONITOR */

