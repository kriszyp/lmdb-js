/* database.c - deals with database subsystem */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 * 
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

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "back-monitor.h"

int
monitor_subsys_database_init(
	BackendDB	*be
)
{
	struct monitorinfo	*mi;
	Entry			*e, *e_database, *e_tmp;
	int			i;
	struct monitorentrypriv	*mp;
	AttributeDescription 	*ad_nc = slap_schema.si_ad_namingContexts;
	struct berval 		val, *bv[2] = { &val, NULL };

	assert( be != NULL );
	assert( monitor_ad_desc != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, 
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn, 
				&e_database ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_database_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn->bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_database_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn->bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;
	for ( i = nBackendDB; i--; ) {
		char buf[1024];
		int j;

		be = &backendDB[i];

		snprintf( buf, sizeof( buf ),
				"dn: cn=%d,%s\n"
				"objectClass: top\n"
				"objectClass: LDAPsubEntry\n"
#ifdef SLAPD_MONITORSUBENTRY
				"objectClass: monitorSubEntry\n"
#else /* !SLAPD_MONITORSUBENTRY */
				"objectClass: extensibleObject\n"
#endif /* !SLAPD_MONITORSUBENTRY */
				"cn: %d\n",
				i,
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_dn->bv_val,
				i );
		
		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"monitor_subsys_database_init: "
				"unable to create entry 'cn=%d,%s'\n",
				i, 
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn->bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_database_init: "
				"unable to create entry 'cn=%d,%s'\n%s",
				i, 
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn->bv_val,
				"" );
#endif
			return( -1 );
		}
		
		val.bv_val = be->bd_info->bi_type;
		val.bv_len = strlen( val.bv_val );
		attr_merge( e, monitor_ad_desc, bv );
		
		for ( j = 0; be->be_suffix[j]; j++ ) {
			val = *be->be_suffix[j];

			attr_merge( e, ad_nc, bv );
			attr_merge( e_database, ad_nc, bv );
		}
				
		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = e_tmp;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_DATABASE];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_DATABASE].mss_flags
			| MONITOR_F_SUB;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
				"monitor_subsys_database_init: "
				"unable to add entry 'cn=%d,%s'\n",
				i, 
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn->bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_database_init: "
				"unable to add entry 'cn=%d,%s'\n",
				i, 
				monitor_subsys[SLAPD_MONITOR_DATABASE].mss_ndn->bv_val,
				0 );
#endif
			return( -1 );
		}

		e_tmp = e;
	}
	
	mp = ( struct monitorentrypriv * )e_database->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_database );

	return( 0 );
}

