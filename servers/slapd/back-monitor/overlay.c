/* overlay.c - deals with overlay subsystem */
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
#include <ac/string.h>

#include "slap.h"
#include "back-monitor.h"

/*
 * initializes overlay subentries
 */
int
monitor_subsys_overlay_init(
	BackendDB	*be
)
{
	struct monitorinfo	*mi;
	Entry			*e, *e_overlay, *e_tmp;
	int			i;
	struct monitorentrypriv	*mp;
	slap_overinst		*on;

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
				&monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn, 
				&e_overlay ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_overlay_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_overlay_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;
	for ( on = overlay_next( NULL ), i = 0; on ; on = overlay_next( on ), i++ ) {
		char 		buf[ BACKMONITOR_BUFSIZE ];
		struct berval 	bv;
		int		j;

		snprintf( buf, sizeof( buf ),
				"dn: cn=Overlay %d,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: Overlay %d\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				i,
				monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_dn.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				i,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_overlay_init: "
				"unable to create entry 'cn=Overlay %d,%s'\n",
				i, monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_overlay_init: "
				"unable to create entry 'cn=Overlay %d,%s'\n%s",
				i, 
				monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn.bv_val,
				"" );
#endif
			return( -1 );
		}
		
		bv.bv_val = on->on_bi.bi_type;
		bv.bv_len = strlen( bv.bv_val );

		attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
				&bv, NULL );
		attr_merge_normalize_one( e_overlay, mi->mi_ad_monitoredInfo,
				&bv, NULL );

		for ( j = 0; j < nBackendDB; j++ ) {
			BackendDB	*be = &backendDB[j];
			char		buf[ SLAP_LDAPDN_MAXLEN ];
			struct berval	dn;
			slap_overinst	*on2;

			if ( strcmp( be->bd_info->bi_type, "over" ) != 0 ) {
				continue;
			}

			on2 = ((slap_overinfo *)be->bd_info->bi_private)->oi_list;
			for ( ; on2; on2 = on2->on_next ) {
				if ( on2->on_bi.bi_type == on->on_bi.bi_type ) {
					break;
				}
			}

			if ( on2 == NULL ) {
				continue;
			}

			snprintf( buf, sizeof( buf ), "cn=Database %d,%s",
					j, monitor_subsys[SLAPD_MONITOR_DATABASE].mss_dn.bv_val );
			dn.bv_val = buf;
			dn.bv_len = strlen( buf );

			attr_merge_normalize_one( e, mi->mi_ad_seeAlso,
					&dn, NULL );
		}
		
		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = e_tmp;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_OVERLAY];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_overlay_init: "
				"unable to add entry 'cn=Overlay %d,%s'\n",
				i, monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_overlay_init: "
				"unable to add entry 'cn=Overlay %d,%s'\n%s",
				i,
			       	monitor_subsys[SLAPD_MONITOR_OVERLAY].mss_ndn.bv_val,
			    	"" );
#endif
			return( -1 );
		}

		e_tmp = e;
	}
	
	mp = ( struct monitorentrypriv * )e_overlay->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_overlay );

	return( 0 );
}

