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
	unsigned long		mp_flags;	/* flags */

#define	MONITOR_F_NONE		0x00U
#define MONITOR_F_SUB		0x01U		/* subentry of subsystem */
#define MONITOR_F_PERSISTENT	0x10U		/* persistent entry */
#define MONITOR_F_PERSISTENT_CH	0x20U		/* subsystem generates 
						   persistent entries */
#define MONITOR_F_VOLATILE	0x40U		/* volatile entry */
#define MONITOR_F_VOLATILE_CH	0x80U		/* subsystem generates 
						   volatile entries */
/* NOTE: flags with 0xF0000000U mask are reserved for subsystem internals */

	int			(*mp_update)( Operation *op, Entry *e );
						/* update callback
						   for user-defined entries */
	void			*mp_private;	/* opaque pointer to
						   private data */
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
	struct berval		mi_startTime;		/* don't free it! */
	struct berval		mi_creatorsName;	/* don't free it! */

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
	AttributeDescription *mi_ad_labeledURI;
	AttributeDescription *mi_ad_readOnly;
	AttributeDescription *mi_ad_restrictedOperation;
};

/*
 * DNs
 */

enum {
	SLAPD_MONITOR_BACKEND = 0,
	SLAPD_MONITOR_CONN,
	SLAPD_MONITOR_DATABASE,
	SLAPD_MONITOR_LISTENER,
	SLAPD_MONITOR_LOG,
	SLAPD_MONITOR_OPS,
	SLAPD_MONITOR_OVERLAY,
	SLAPD_MONITOR_SASL,
	SLAPD_MONITOR_SENT,
	SLAPD_MONITOR_THREAD,
	SLAPD_MONITOR_TIME,
	SLAPD_MONITOR_TLS,
	SLAPD_MONITOR_RWW,

	SLAPD_MONITOR_LAST
};

#define SLAPD_MONITOR_AT		"cn"

#define SLAPD_MONITOR_BACKEND_NAME	"Backends"
#define SLAPD_MONITOR_BACKEND_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_BACKEND_NAME
#define SLAPD_MONITOR_BACKEND_DN	\
	SLAPD_MONITOR_BACKEND_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_CONN_NAME		"Connections"
#define SLAPD_MONITOR_CONN_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_CONN_NAME
#define SLAPD_MONITOR_CONN_DN	\
	SLAPD_MONITOR_CONN_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_DATABASE_NAME	"Databases"
#define SLAPD_MONITOR_DATABASE_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_DATABASE_NAME
#define SLAPD_MONITOR_DATABASE_DN	\
	SLAPD_MONITOR_DATABASE_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_LISTENER_NAME	"Listeners"
#define SLAPD_MONITOR_LISTENER_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_LISTENER_NAME
#define SLAPD_MONITOR_LISTENER_DN	\
	SLAPD_MONITOR_LISTENER_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_LOG_NAME		"Log"
#define SLAPD_MONITOR_LOG_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_LOG_NAME
#define SLAPD_MONITOR_LOG_DN	\
	SLAPD_MONITOR_LOG_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_OPS_NAME		"Operations"
#define SLAPD_MONITOR_OPS_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_OPS_NAME
#define SLAPD_MONITOR_OPS_DN	\
	SLAPD_MONITOR_OPS_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_OVERLAY_NAME	"Overlay"
#define SLAPD_MONITOR_OVERLAY_RDN  \
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_OVERLAY_NAME
#define SLAPD_MONITOR_OVERLAY_DN   \
	SLAPD_MONITOR_OVERLAY_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_SASL_NAME		"SASL"
#define SLAPD_MONITOR_SASL_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_SASL_NAME
#define SLAPD_MONITOR_SASL_DN	\
	SLAPD_MONITOR_SASL_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_SENT_NAME		"Statistics"
#define SLAPD_MONITOR_SENT_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_SENT_NAME
#define SLAPD_MONITOR_SENT_DN	\
	SLAPD_MONITOR_SENT_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_THREAD_NAME	"Threads"
#define SLAPD_MONITOR_THREAD_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_THREAD_NAME
#define SLAPD_MONITOR_THREAD_DN	\
	SLAPD_MONITOR_THREAD_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_TIME_NAME		"Time"
#define SLAPD_MONITOR_TIME_RDN  \
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_TIME_NAME
#define SLAPD_MONITOR_TIME_DN   \
	SLAPD_MONITOR_TIME_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_TLS_NAME		"TLS"
#define SLAPD_MONITOR_TLS_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_TLS_NAME
#define SLAPD_MONITOR_TLS_DN	\
	SLAPD_MONITOR_TLS_RDN "," SLAPD_MONITOR_DN

#define SLAPD_MONITOR_RWW_NAME		"Waiters"
#define SLAPD_MONITOR_RWW_RDN	\
	SLAPD_MONITOR_AT "=" SLAPD_MONITOR_RWW_NAME
#define SLAPD_MONITOR_RWW_DN	\
	SLAPD_MONITOR_RWW_RDN "," SLAPD_MONITOR_DN

typedef struct monitorsubsys {
	char		*mss_name;
	struct berval	mss_rdn;
	struct berval	mss_dn;
	struct berval	mss_ndn;
	int		mss_flags;
#define MONITOR_F_OPENED	0x10000000U

#define MONITOR_HAS_VOLATILE_CH( mp ) \
	( ( mp )->mp_flags & MONITOR_F_VOLATILE_CH )
#define MONITOR_HAS_CHILDREN( mp ) \
	( ( mp )->mp_children || MONITOR_HAS_VOLATILE_CH( mp ) )

	/* initialize entry and subentries */
	int		( *mss_open )( BackendDB *, struct monitorsubsys *ms );
	/* update existing dynamic entry and subentries */
	int		( *mss_update )( Operation *, Entry * );
	/* create new dynamic subentries */
	int		( *mss_create )( Operation *,
				struct berval *ndn, Entry *, Entry ** );
	/* modify entry and subentries */
	int		( *mss_modify )( Operation *, Entry * );
} monitorsubsys;

extern BackendDB *be_monitor;

/* increase this bufsize if entries in string form get too big */
#define BACKMONITOR_BUFSIZE	1024

LDAP_END_DECL

#include "proto-back-monitor.h"

#endif /* _back_monitor_h_ */

