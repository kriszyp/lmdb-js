/* backend.c - deals with backend subsystem */
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
#include <ac/string.h>

#include "slap.h"
#include "back-monitor.h"

/*
 * initializes backend subentries
 */
int
monitor_subsys_backend_init(
	BackendDB	*be
)
{
	struct monitorinfo	*mi;
	Entry			*e, *e_backend, *e_tmp;
	int			i;
	struct monitorentrypriv	*mp;

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
				&monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn, 
				&e_backend ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_backend_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_backend_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;
	for ( i = nBackendInfo; i--; ) {
		char 		buf[ BACKMONITOR_BUFSIZE ];
		BackendInfo 	*bi;
		struct berval 	bv;
		int		j;

		bi = &backendInfo[i];

		snprintf( buf, sizeof( buf ),
				"dn: cn=Backend %d,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: Backend %d\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				i,
				monitor_subsys[SLAPD_MONITOR_BACKEND].mss_dn.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				mi->mi_oc_monitoredObject->soc_cname.bv_val,
				i,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );
		
		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_backend_init: "
				"unable to create entry 'cn=Backend %d,%s'\n",
				i, monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_backend_init: "
				"unable to create entry 'cn=Backend %d,%s'\n%s",
				i, 
				monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn.bv_val,
				"" );
#endif
			return( -1 );
		}
		
		bv.bv_val = bi->bi_type;
		bv.bv_len = strlen( bv.bv_val );

		attr_merge_normalize_one( e, mi->mi_ad_monitoredInfo,
				&bv, NULL );
		attr_merge_normalize_one( e_backend, mi->mi_ad_monitoredInfo,
				&bv, NULL );

		if ( bi->bi_controls ) {
			int j;

			for ( j = 0; bi->bi_controls[ j ]; j++ ) {
				bv.bv_val = bi->bi_controls[ j ];
				bv.bv_len = strlen( bv.bv_val );
				attr_merge_one( e, slap_schema.si_ad_supportedControl, &bv, NULL );
			}
		}

		for ( j = 0; j < nBackendDB; j++ ) {
			BackendDB	*be = &backendDB[j];
			char		buf[ SLAP_LDAPDN_MAXLEN ];
			struct berval	dn;
			
			if ( be->bd_info != bi ) {
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
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_BACKEND];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_BACKEND].mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_backend_init: "
				"unable to add entry 'cn=Backend %d,%s'\n",
				i, monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_backend_init: "
				"unable to add entry 'cn=Backend %d,%s'\n%s",
				i,
			       	monitor_subsys[SLAPD_MONITOR_BACKEND].mss_ndn.bv_val,
			    	"" );
#endif
			return( -1 );
		}

		e_tmp = e;
	}
	
	mp = ( struct monitorentrypriv * )e_backend->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_backend );

	return( 0 );
}

