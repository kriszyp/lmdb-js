/* listener.c - deals with listener subsystem */
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
	Entry			*e_listener, **ep;
	int			i;
	struct monitorentrypriv	*mp;
	Listener		**l;

	assert( be != NULL );

	if ( ( l = slapd_get_listeners() ) == NULL ) {
		if ( slapMode & SLAP_TOOL_MODE ) {
			return 0;
		}

		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_listener_init: "
			"unable to get listeners\n", 0, 0, 0 );
		return( -1 );
	}

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
				&monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn, 
				&e_listener ) )
	{
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_listener_init: "
			"unable to get entry \"%s\"\n",
			monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	mp = ( struct monitorentrypriv * )e_listener->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	for ( i = 0; l[i]; i++ ) {
		char 		buf[ BACKMONITOR_BUFSIZE ];
		Entry		*e;

		snprintf( buf, sizeof( buf ),
				"dn: cn=Listener %d,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: Listener %d\n"
				"%s: %s\n"
				"labeledURI: %s\n"
				"creatorsName: %s\n"
				"modifiersName: %s\n"
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
				mi->mi_creatorsName.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_listener_init: "
				"unable to create entry \"cn=Listener %d,%s\"\n",
				i, monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 0 );
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

			BER_BVSTR( &bv, "UDP" );
			attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
					&bv, NULL );
		}
#endif /* HAVE_TLS */

		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = NULL;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_LISTENER];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_LISTENER].mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_listener_init: "
				"unable to add entry \"cn=Listener %d,%s\"\n",
				i, monitor_subsys[SLAPD_MONITOR_LISTENER].mss_ndn.bv_val, 0 );
			return( -1 );
		}

		*ep = e;
		ep = &mp->mp_next;
	}
	
	monitor_cache_release( mi, e_listener );

	return( 0 );
}

