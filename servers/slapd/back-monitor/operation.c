/* operation.c - deal with operation subsystem */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "back-monitor.h"

int
monitor_subsys_ops_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_op;
	struct monitorentrypriv	*mp;
	char			buf[1024];
	struct berval		bv[2];

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn, &e_op ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_ops_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;

	/*
	 * Initiated ops
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Initiated,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Initiated\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=Initiated,%s'\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=Initiated,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	bv[1].bv_val = NULL;
	bv[0].bv_val = "0";
	bv[0].bv_len = 1;
	attr_merge( e, monitor_ad_desc, bv );
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = e_tmp;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_OPS];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_OPS].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=Initiated,%s'\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=Initiated,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	/*
	 * Completed ops
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Completed,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Completed\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=Completed,%s'\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=Completed,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}

	bv[0].bv_val = "0";
	bv[0].bv_len = 1;
	attr_merge( e, monitor_ad_desc, bv );
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = e_tmp;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_OPS];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_OPS].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=Completed,%s'\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=Completed,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	mp = ( struct monitorentrypriv * )e_op->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_op );

	return( 0 );
}

int
monitor_subsys_ops_update(
	struct monitorinfo      *mi,
	Entry                   *e
)
{
	long 		n = -1;

	assert( mi );
	assert( e );
	
	if ( strncasecmp( e->e_ndn, "CN=INITIATED", 
				sizeof("CN=INITIATED")-1 ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_ops_mutex);
		n = num_ops_initiated;
		ldap_pvt_thread_mutex_unlock(&num_ops_mutex);

	} else if ( strncasecmp( e->e_ndn, "CN=COMPLETED", 
				sizeof("CN=COMPLETED")-1 ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_ops_mutex);
		n = num_ops_completed;
		ldap_pvt_thread_mutex_unlock(&num_ops_mutex);
	}

	if ( n != -1 ) {
		Attribute	*a;
		char		buf[16];

		a = attr_find( e->e_attrs, monitor_ad_desc );
		if ( a == NULL ) {
			return( -1 );
		}

		snprintf( buf, sizeof( buf ), "%ld", n );
		free( a->a_vals[ 0 ].bv_val );
		ber_str2bv( buf, 0, 1, a->a_vals );
	}

	return( 0 );
}

