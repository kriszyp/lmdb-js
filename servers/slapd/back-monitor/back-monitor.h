/* back-monitor.h - ldap monitor back-end header file */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
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

	/*
	 * Internal data
	 */
	Avlnode			*mi_cache;
	ldap_pvt_thread_mutex_t	mi_cache_mutex;

	/*
	 * Config parameters
	 */
	struct berval		mi_l;
	struct berval		mi_startTime;	/* don't free it */

	/*
	 * Specific schema entities
	 */
	ObjectClass *mi_oc_monitor;
	ObjectClass *mi_oc_monitorServer;
	ObjectClass *mi_oc_monitorContainer;
	ObjectClass *mi_oc_monitorCounterObject;
	ObjectClass *mi_oc_monitorOperation;
	ObjectClass *mi_oc_monitorConnection;
	ObjectClass *mi_oc_managedObject;
	ObjectClass *mi_oc_monitoredObject;

	AttributeDescription *mi_ad_monitoredInfo;
	AttributeDescription *mi_ad_managedInfo;
	AttributeDescription *mi_ad_monitorCounter;
	AttributeDescription *mi_ad_monitorOpCompleted;
	AttributeDescription *mi_ad_monitorOpInitiated;
	AttributeDescription *mi_ad_monitorConnectionNumber;
	AttributeDescription *mi_ad_monitorConnectionAuthzDN;
	AttributeDescription *mi_ad_monitorConnectionLocalAddress;
	AttributeDescription *mi_ad_monitorConnectionPeerAddress;
	AttributeDescription *mi_ad_monitorTimestamp;
	AttributeDescription *mi_ad_monitorOverlay;

	/*
	 * Generic description attribute
	 */
	AttributeDescription *mi_ad_description;
	AttributeDescription *mi_ad_seeAlso;
	AttributeDescription *mi_ad_l;
};

/*
 * DNs
 */

#define SLAPD_MONITOR_AT		"cn"

#define	SLAPD_MONITOR_LISTENER		0
#define SLAPD_MONITOR_LISTENER_NAME	"Listeners"
#define SLAPD_MONITOR_LISTENER_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_LISTENER_NAME
#define SLAPD_MONITOR_LISTENER_DN	\
	SLAPD_MONITOR_LISTENER_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_DATABASE		1
#define SLAPD_MONITOR_DATABASE_NAME	"Databases"
#define SLAPD_MONITOR_DATABASE_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_DATABASE_NAME
#define SLAPD_MONITOR_DATABASE_DN	\
	SLAPD_MONITOR_DATABASE_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_BACKEND		2
#define SLAPD_MONITOR_BACKEND_NAME	"Backends"
#define SLAPD_MONITOR_BACKEND_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_BACKEND_NAME
#define SLAPD_MONITOR_BACKEND_DN	\
	SLAPD_MONITOR_BACKEND_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_THREAD		3
#define SLAPD_MONITOR_THREAD_NAME	"Threads"
#define SLAPD_MONITOR_THREAD_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_THREAD_NAME
#define SLAPD_MONITOR_THREAD_DN	\
	SLAPD_MONITOR_THREAD_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_SASL		4
#define SLAPD_MONITOR_SASL_NAME		"SASL"
#define SLAPD_MONITOR_SASL_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_SASL_NAME
#define SLAPD_MONITOR_SASL_DN	\
	SLAPD_MONITOR_SASL_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_TLS		5
#define SLAPD_MONITOR_TLS_NAME		"TLS"
#define SLAPD_MONITOR_TLS_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_TLS_NAME
#define SLAPD_MONITOR_TLS_DN	\
	SLAPD_MONITOR_TLS_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_CONN		6
#define SLAPD_MONITOR_CONN_NAME		"Connections"
#define SLAPD_MONITOR_CONN_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_CONN_NAME
#define SLAPD_MONITOR_CONN_DN	\
	SLAPD_MONITOR_CONN_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_RWW		7
#define SLAPD_MONITOR_RWW_NAME	"Waiters"
#define SLAPD_MONITOR_RWW_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_RWW_NAME
#define SLAPD_MONITOR_RWW_DN	\
	SLAPD_MONITOR_RWW_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_LOG		8
#define SLAPD_MONITOR_LOG_NAME		"Log"
#define SLAPD_MONITOR_LOG_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_LOG_NAME
#define SLAPD_MONITOR_LOG_DN	\
	SLAPD_MONITOR_LOG_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_OPS		9
#define SLAPD_MONITOR_OPS_NAME		"Operations"
#define SLAPD_MONITOR_OPS_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_OPS_NAME
#define SLAPD_MONITOR_OPS_DN	\
	SLAPD_MONITOR_OPS_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_SENT		10
#define SLAPD_MONITOR_SENT_NAME		"Statistics"
#define SLAPD_MONITOR_SENT_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_SENT_NAME
#define SLAPD_MONITOR_SENT_DN	\
	SLAPD_MONITOR_SENT_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_TIME		11
#define SLAPD_MONITOR_TIME_NAME		"Time"
#define SLAPD_MONITOR_TIME_RDN  \
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_TIME_NAME
#define SLAPD_MONITOR_TIME_DN   \
	SLAPD_MONITOR_TIME_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_OVERLAY		12
#define SLAPD_MONITOR_OVERLAY_NAME		"Overlay"
#define SLAPD_MONITOR_OVERLAY_RDN  \
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_OVERLAY_NAME
#define SLAPD_MONITOR_OVERLAY_DN   \
	SLAPD_MONITOR_OVERLAY_RDN "," SLAPD_MONITOR_DN

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
	int		( *mss_update )( Operation *, Entry * );
	/* create new dynamic subentries */
	int		( *mss_create )( Operation *,
				struct berval *ndn, Entry *, Entry ** );
	/* modify entry and subentries */
	int		( *mss_modify )( Operation *, Entry * );
};

extern struct monitorsubsys monitor_subsys[];

extern BackendDB *be_monitor;

/* increase this bufsize if entries in string form get too big */
#define BACKMONITOR_BUFSIZE	1024

/*
 * cache
 */

extern int monitor_cache_cmp LDAP_P(( const void *c1, const void *c2 ));
extern int monitor_cache_dup LDAP_P(( void *c1, void *c2 ));
extern int monitor_cache_add LDAP_P(( struct monitorinfo *mi, Entry *e ));
extern int monitor_cache_get LDAP_P(( struct monitorinfo *mi, struct berval *ndn, Entry **ep ));
extern int monitor_cache_dn2entry LDAP_P(( Operation *op, struct berval *ndn, Entry **ep, Entry **matched ));
extern int monitor_cache_lock LDAP_P(( Entry *e ));
extern int monitor_cache_release LDAP_P(( struct monitorinfo *mi, Entry *e ));

/*
 * update
 */

extern int monitor_entry_update LDAP_P(( Operation *op, Entry *e ));
extern int monitor_entry_create LDAP_P(( Operation *op, struct berval *ndn,
		Entry *e_parent, Entry **ep ));
extern int monitor_entry_modify LDAP_P(( Operation *op, Entry *e ));

LDAP_END_DECL

#include "proto-back-monitor.h"

#endif /* _back_monitor_h_ */

