/* sent.c - deal with data sent subsystem */
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

int
monitor_subsys_sent_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_sent;
	struct monitorentrypriv	*mp;
	char			buf[1024];
	struct berval		bv[2];

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn, &e_sent ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;

	/*
	 * Entries
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Entries,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Entries\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=Entries,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=Entries,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
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
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_SENT];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_SENT].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=Entries,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=Entries,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	/*
	 * Referrals
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Referrals,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Referrals\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=Referrals,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=Referrals,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
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
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_SENT];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_SENT].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=Referrals,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=Referrals,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	/*
	 * PDU
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=PDU,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: PDU\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=PDU,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=PDU,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
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
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_SENT];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_SENT].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=PDU,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=PDU,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	/*
	 * Bytes
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Bytes,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Bytes\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=Bytes,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to create entry 'cn=Bytes,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
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
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_SENT];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_SENT].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=Bytes,%s'\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to add entry 'cn=Bytes,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	mp = ( struct monitorentrypriv * )e_sent->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_sent );

	return( 0 );
}

int
monitor_subsys_sent_update(
	struct monitorinfo      *mi,
	Entry                   *e
)
{
	long 		n = -1;

	assert( mi );
	assert( e );
	
	if ( strncasecmp( e->e_ndn, "cn=entries", 
				sizeof("cn=entries")-1 ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_sent_mutex);
		n = num_entries_sent;
		ldap_pvt_thread_mutex_unlock(&num_sent_mutex);

	} else if ( strncasecmp( e->e_ndn, "cn=referrals", 
				sizeof("cn=referrals")-1 ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_sent_mutex);
		n = num_refs_sent;
		ldap_pvt_thread_mutex_unlock(&num_sent_mutex);

	} else if ( strncasecmp( e->e_ndn, "cn=pdu", 
				sizeof("cn=pdu")-1 ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_sent_mutex);
		n = num_pdu_sent;
		ldap_pvt_thread_mutex_unlock(&num_sent_mutex);

	} else if ( strncasecmp( e->e_ndn, "cn=bytes", 
				sizeof("cn=bytes")-1 ) == 0 ) {
		ldap_pvt_thread_mutex_lock(&num_sent_mutex);
		n = num_bytes_sent;
		ldap_pvt_thread_mutex_unlock(&num_sent_mutex);
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

