/* operation.c - deal with operation subsystem */
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

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "back-monitor.h"
#include "lber_pvt.h"

static struct berval 
	bv_initiated = BER_BVC( "Initiated" ),
	bv_completed = BER_BVC( "Completed" ),
	bv_op[] = {
		BER_BVC( "Bind" ),
		BER_BVC( "Unbind" ),
		BER_BVC( "Add" ),
		BER_BVC( "Delete" ),
		BER_BVC( "Modrdn" ),
		BER_BVC( "Modify" ),
		BER_BVC( "Compare" ),
		BER_BVC( "Search" ),
		BER_BVC( "Abandon" ),
		BER_BVC( "Extended" )
	};

int
monitor_subsys_ops_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_op, *e_children;
	struct monitorentrypriv	*mp;
	char			buf[1024];
	struct berval		bv[2];
	int 			i;

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn, &e_op ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_ops_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0, 0 );
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
			"dn: cn=%s,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: %s\n",
			bv_initiated.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val,
			bv_initiated.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=%s,%s'\n",
			bv_initiated.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=%s,%s'\n%s",
			bv_initiated.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"" );
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
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=%s,%s'\n",
			bv_initiated.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=%s,%s'\n%s",
			bv_initiated.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"" );
#endif
		return( -1 );
	}
	
	e_tmp = e;
	e_children = NULL;

	for ( i = SLAP_OP_LAST; i-- > 0; ) {

		/*
		 * Initiated ops
		 */
		snprintf( buf, sizeof( buf ),
				"dn: cn=%s,cn=%s,%s\n"
				SLAPD_MONITOR_OBJECTCLASSES
				"cn: %s\n",
				bv_op[ i ].bv_val,
				bv_initiated.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val,
				bv_op[ i ].bv_val );

		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_ops_init: "
				"unable to create entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_initiated.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to create entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_initiated.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#endif
			return( -1 );
		}
	
		bv[1].bv_val = NULL;
		bv[0].bv_val = "0";
		bv[0].bv_len = 1;
		attr_merge( e, monitor_ad_desc, bv );
	
		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = e_children;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_OPS];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_OPS].mss_flags \
			| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_ops_init: "
				"unable to add entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_initiated.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to add entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_initiated.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#endif
			return( -1 );
		}
	
		e_children = e;
	}

	mp = ( struct monitorentrypriv * )e_tmp->e_private;
	mp->mp_children = e_children;

	/*
	 * Completed ops
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=%s,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: %s\n",
			bv_completed.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val,
			bv_completed.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=%s,%s'\n",
			bv_completed.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to create entry 'cn=%s,%s'\n%s",
			bv_completed.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"" );
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
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=%s,%s'\n",
			bv_completed.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to add entry 'cn=%s,%s'\n%s",
			bv_completed.bv_val,
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val,
			"" );
#endif
		return( -1 );
	}
	
	e_tmp = e;
	e_children = NULL;

	for ( i = SLAP_OP_LAST; i-- > 0; ) {

		/*
		 * Completed ops
		 */
		snprintf( buf, sizeof( buf ),
				"dn: cn=%s,cn=%s,%s\n"
				SLAPD_MONITOR_OBJECTCLASSES
				"cn: %s\n",
				bv_op[ i ].bv_val,
				bv_completed.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val,
		       		bv_op[ i ].bv_val );
	
		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_ops_init: "
				"unable to create entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_completed.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to create entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_completed.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#endif
			return( -1 );
		}

		bv[0].bv_val = "0";
		bv[0].bv_len = 1;
		attr_merge( e, monitor_ad_desc, bv );
	
		mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
		e->e_private = ( void * )mp;
		mp->mp_next = e_children;
		mp->mp_children = NULL;
		mp->mp_info = &monitor_subsys[SLAPD_MONITOR_OPS];
		mp->mp_flags = monitor_subsys[SLAPD_MONITOR_OPS].mss_flags \
			| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

		if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_ops_init: "
				"unable to add entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_completed.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to add entry 'cn=%s,cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				bv_completed.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val );
#endif
			return( -1 );
		}
	
		e_children = e;
	}

	mp = ( struct monitorentrypriv * )e_tmp->e_private;
	mp->mp_children = e_children;

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
	char 		*dn;

	assert( mi );
	assert( e );

	dn = e->e_dn + 3;

	if ( strncmp( dn, bv_initiated.bv_val, 
				bv_initiated.bv_len ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_ops_mutex);
		n = num_ops_initiated;
		ldap_pvt_thread_mutex_unlock(&num_ops_mutex);

	} else if ( strncmp( dn, bv_completed.bv_val,
				bv_completed.bv_len ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_ops_mutex);
		n = num_ops_completed;
		ldap_pvt_thread_mutex_unlock(&num_ops_mutex);

	} else {
		int 		i;
		ber_len_t 	len;
		
		for (i = 0; i < SLAP_OP_LAST; i++ ) {
			len = bv_op[ i ].bv_len;

			if ( strncmp( dn, bv_op[ i ].bv_val, len ) == 0 ) {
				break;
			}
		}

		if ( i == SLAP_OP_LAST ) {
			return( 0 );
		}

		dn += len + 3 + 1;

		if ( strncmp( dn, bv_initiated.bv_val,
					bv_initiated.bv_len ) == 0 ) {
			ldap_pvt_thread_mutex_lock(&num_ops_mutex);
			n = num_ops_initiated_[ i ];
			ldap_pvt_thread_mutex_unlock(&num_ops_mutex);

		} else if ( strncmp( dn, bv_completed.bv_val,
					bv_completed.bv_len ) == 0 ) {
			ldap_pvt_thread_mutex_lock(&num_ops_mutex);
			n = num_ops_completed_[ i ];
			ldap_pvt_thread_mutex_unlock(&num_ops_mutex);

		} else {
			assert( 0 );
		}
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

