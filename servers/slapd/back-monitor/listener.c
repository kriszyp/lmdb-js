/* listener.c - deals with listener subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2003 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "back-monitor.h"

int
monitor_subsys_listener_init(
	BackendDB	*be
)
{
	struct monitorinfo	*mi;
	Entry			*e, *e_listener, *e_tmp;
	int			i;
	struct monitorentrypriv	*mp;
	Listener		**l;

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
				&monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn, 
				&e_listener ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_listener_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_listener_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	if ( ( l = slapd_get_listeners() ) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_listener_init: "
			"unable to get listeners\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_listener_init: "
			"unable to get listeners\n", 0, 0, 0 );
#endif
		return( -1 );
	}

	e_tmp = NULL;
	for ( i = 0; l[i]; i++ );
	for ( ; i--; ) {
		char 		buf[ BACKMONITOR_BUFSIZE ];

		snprintf( buf, sizeof( buf ),
				"dn: cn=Listener %d,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: Listener %d\n"
				"%s: %s\n"
				"labeledURI: %s\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				i,
				monitor_subsys[SLAPD_MONITOR_LISTENER].mss_dn.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				i,
				mi->mi_ad_monitorConnectionLocalAddress->ad_cname.bv_val,
				l[i]->sl_name.bv_val,
				l[i]->sl_url.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_listener_init: "
				"unable to create entry 'cn=Listener, %d,%s'\n",
				i, monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_listener_init: "
				"unable to create entry 'cn=Listener %d,%s'\n%s",
				i,
				monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val,
				"" );
#endif
			return( -1 );
		}

#ifdef HAVE_TLS
		if ( l[i]->sl_is_tls ) {
			struct berval bv;

			bv.bv_val = "TLS";
			bv.bv_len = sizeof("TLS")-1;

			attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
					&bv, NULL );
		}
#endif /* HAVE_TLS */
#ifdef LDAP_CONNECTIONLESS
		if ( l[i]->sl_is_udp ) {
			struct berval bv;

			bv.bv_val = "UDP";
			bv.bv_len = sizeof("UDP")-1;

			attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
					&bv, NULL );
		}
#endif /* HAVE_TLS */

		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = e_tmp;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_LISTENER];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_LISTENER].mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_listener_init: "
				"unable to add entry 'cn=Listener %d,%s'\n",
				i, monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_listener_init: "
				"unable to add entry 'cn=Listener %d,%s'\n",
				i,
				monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val,
				0 );
#endif
			return( -1 );
		}

		e_tmp = e;
	}
	
	mp = ( struct monitorentrypriv * )e_listener->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_listener );

	return( 0 );
}

