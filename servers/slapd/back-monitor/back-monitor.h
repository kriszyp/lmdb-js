/* back-monitor.h - ldap monitor back-end header file */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
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

#ifndef _BACK_MONITOR_H_
#define _BACK_MONITOR_H_

#include <ldap_pvt.h>
#include <ldap_pvt_thread.h>
#include <avl.h>
#include <slap.h>

LDAP_BEGIN_DECL

/*
 * The cache maps DNs to Entries.
 * Each entry, on turn, holds the list of its children in the e_private field.
 * This is used by search operation to perform onelevel and subtree candidate
 * selection.
 */
struct monitorcache {
	struct berval		mc_ndn;
	Entry   		*mc_e;
};

struct monitorentrypriv {
	ldap_pvt_thread_mutex_t	mp_mutex;	/* entry mutex */
	Entry			*mp_next;	/* pointer to next sibling */
	Entry			*mp_children;	/* pointer to first child */
	struct monitorsubsys	*mp_info;	/* subsystem info */
#define mp_type		mp_info->mss_type
	int			mp_flags;	/* flags */

#define	MONITOR_F_NONE		0x00
#define MONITOR_F_SUB		0x01		/* subentry of subsystem */
#define MONITOR_F_PERSISTENT	0x10		/* persistent entry */
#define MONITOR_F_PERSISTENT_CH	0x20		/* subsystem generates 
						   persistent entries */
#define MONITOR_F_VOLATILE	0x40		/* volatile entry */
#define MONITOR_F_VOLATILE_CH	0x80		/* subsystem generates 
						   volatile entries */
};

struct monitorinfo {
	Avlnode			*mi_cache;
	ldap_pvt_thread_mutex_t	mi_cache_mutex;
};

/*
 * DNs
 */
#define	SLAPD_MONITOR_LISTENER		0
#define SLAPD_MONITOR_LISTENER_NAME	"Listeners"
#define SLAPD_MONITOR_LISTENER_RDN	\
	"cn=" SLAPD_MONITOR_LISTENER_NAME
#define SLAPD_MONITOR_LISTENER_DN	\
	SLAPD_MONITOR_LISTENER_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_DATABASE		1
#define SLAPD_MONITOR_DATABASE_NAME	"Databases"
#define SLAPD_MONITOR_DATABASE_RDN	\
	"cn=" SLAPD_MONITOR_DATABASE_NAME
#define SLAPD_MONITOR_DATABASE_DN	\
	SLAPD_MONITOR_DATABASE_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_BACKEND		2
#define SLAPD_MONITOR_BACKEND_NAME	"Backends"
#define SLAPD_MONITOR_BACKEND_RDN	\
	"cn=" SLAPD_MONITOR_BACKEND_NAME
#define SLAPD_MONITOR_BACKEND_DN	\
	SLAPD_MONITOR_BACKEND_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_THREAD		3
#define SLAPD_MONITOR_THREAD_NAME	"Threads"
#define SLAPD_MONITOR_THREAD_RDN	\
	"cn=" SLAPD_MONITOR_THREAD_NAME
#define SLAPD_MONITOR_THREAD_DN	\
	SLAPD_MONITOR_THREAD_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_SASL		4
#define SLAPD_MONITOR_SASL_NAME		"SASL"
#define SLAPD_MONITOR_SASL_RDN	\
	"cn=" SLAPD_MONITOR_SASL_NAME
#define SLAPD_MONITOR_SASL_DN	\
	SLAPD_MONITOR_SASL_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_TLS		5
#define SLAPD_MONITOR_TLS_NAME		"TLS"
#define SLAPD_MONITOR_TLS_RDN	\
	"cn=" SLAPD_MONITOR_TLS_NAME
#define SLAPD_MONITOR_TLS_DN	\
	SLAPD_MONITOR_TLS_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_CONN		6
#define SLAPD_MONITOR_CONN_NAME		"Connections"
#define SLAPD_MONITOR_CONN_RDN	\
	"cn=" SLAPD_MONITOR_CONN_NAME
#define SLAPD_MONITOR_CONN_DN	\
	SLAPD_MONITOR_CONN_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_READW		7
#define SLAPD_MONITOR_READW_NAME	"Read Waiters"
#define SLAPD_MONITOR_READW_RDN	\
	"cn=" SLAPD_MONITOR_READW_NAME
#define SLAPD_MONITOR_READW_DN	\
	SLAPD_MONITOR_READW_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_WRITEW		8
#define SLAPD_MONITOR_WRITEW_NAME	"Write Waiters"
#define SLAPD_MONITOR_WRITEW_RDN	\
	"cn=" SLAPD_MONITOR_WRITEW_NAME
#define SLAPD_MONITOR_WRITEW_DN	\
	SLAPD_MONITOR_WRITEW_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_LOG		9
#define SLAPD_MONITOR_LOG_NAME		"Log"
#define SLAPD_MONITOR_LOG_RDN	\
	"cn=" SLAPD_MONITOR_LOG_NAME
#define SLAPD_MONITOR_LOG_DN	\
	SLAPD_MONITOR_LOG_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_OPS		10
#define SLAPD_MONITOR_OPS_NAME		"Operations"
#define SLAPD_MONITOR_OPS_RDN	\
	"cn=" SLAPD_MONITOR_OPS_NAME
#define SLAPD_MONITOR_OPS_DN	\
	SLAPD_MONITOR_OPS_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_SENT		11
#define SLAPD_MONITOR_SENT_NAME		"Statistics"
#define SLAPD_MONITOR_SENT_RDN	\
	"cn=" SLAPD_MONITOR_SENT_NAME
#define SLAPD_MONITOR_SENT_DN	\
	SLAPD_MONITOR_SENT_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_TIME		12
#define SLAPD_MONITOR_TIME_NAME		"Time"
#define SLAPD_MONITOR_TIME_RDN  \
	"cn=" SLAPD_MONITOR_TIME_NAME
#define SLAPD_MONITOR_TIME_DN   \
	SLAPD_MONITOR_TIME_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_OBJECTCLASSES \
	"objectClass: top\n" \
	"objectClass: monitor\n" \
	"objectClass: extensibleObject\n" \
	"structuralObjectClass: monitor\n"

struct monitorsubsys {
	int		mss_type;
	char		*mss_name;
	struct berval	mss_rdn;
	struct berval	mss_dn;
	struct berval	mss_ndn;
	int		mss_flags;

#define MONITOR_HAS_VOLATILE_CH( mp ) \
	( ( mp )->mp_flags & MONITOR_F_VOLATILE_CH )
#define MONITOR_HAS_CHILDREN( mp ) \
	( ( mp )->mp_children || MONITOR_HAS_VOLATILE_CH( mp ) )

	/* initialize entry and subentries */
	int		( *mss_init )( BackendDB * );
	/* update existing dynamic entry and subentries */
	int		( *mss_update )( struct monitorinfo *, Entry * );
	/* create new dynamic subentries */
	int		( *mss_create )( struct monitorinfo *, 
				struct berval *ndn, Entry *, Entry ** );
	/* modify entry and subentries */
	int		( *mss_modify )( struct monitorinfo *, Entry *, 
				Modifications *modlist );
};

extern struct monitorsubsys monitor_subsys[];

extern AttributeDescription *monitor_ad_desc;
extern BackendDB *be_monitor;

/*
 * cache
 */

extern int monitor_cache_cmp LDAP_P(( const void *c1, const void *c2 ));
extern int monitor_cache_dup LDAP_P(( void *c1, void *c2 ));
extern int monitor_cache_add LDAP_P(( struct monitorinfo *mi, Entry *e ));
extern int monitor_cache_get LDAP_P(( struct monitorinfo *mi, struct berval *ndn, Entry **ep ));
extern int monitor_cache_dn2entry LDAP_P(( struct monitorinfo *mi, struct berval *ndn, Entry **ep, Entry **matched ));
extern int monitor_cache_lock LDAP_P(( Entry *e ));
extern int monitor_cache_release LDAP_P(( struct monitorinfo *mi, Entry *e ));

/*
 * update
 */

extern int monitor_entry_update LDAP_P(( struct monitorinfo *mi, Entry *e ));
extern int monitor_entry_create LDAP_P(( struct monitorinfo *mi, struct berval *ndn, Entry *e_parent, Entry **ep ));
extern int monitor_entry_modify LDAP_P(( struct monitorinfo *mi, Entry *e, Modifications *modlist ));

LDAP_END_DECL

#include "proto-back-monitor.h"

#endif /* _back_monitor_h_ */

