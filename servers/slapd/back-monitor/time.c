/* time.c - deal with time subsystem */
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
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "proto-slap.h"
#include "back-monitor.h"

static int
local_time( const struct tm *ztm, long delta, char *buf, size_t len );

int
monitor_subsys_time_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_time;
	struct monitorentrypriv	*mp;
	char			buf[1024], ztmbuf[20], ltmbuf[20];
	struct tm		*ztm, *ltm;

	/*
	 * Note: ltmbuf, ltm are used only if HACK_LOCAL_TIME is defined
	 */

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn, &e_time ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_time_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;

	/*
	 * Start
	 */
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
	ztm = gmtime( &starttime );
	strftime( ztmbuf, sizeof(ztmbuf), "%Y%m%d%H%M%SZ", ztm );
#ifdef HACK_LOCAL_TIME
	ltm = localtime( &starttime );
	local_time( ltm, -timezone, ltmbuf, sizeof( ltmbuf ) );
#endif /* HACK_LOCAL_TIME */
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
	snprintf( buf, sizeof( buf ),
			"dn: cn=Start,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Start\n"
			"description: %s\n"
#ifdef HACK_LOCAL_TIME
			"description;lang-x-local: %s"
#endif /* HACK_LOCAL_TIME */
			, monitor_subsys[SLAPD_MONITOR_TIME].mss_dn.bv_val,
			ztmbuf
#ifdef HACK_LOCAL_TIME
			, ltmbuf 
#endif /* HACK_LOCAL_TIME */
			);

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_time_init: "
			"unable to create entry 'cn=Start,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to create entry 'cn=Start,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = e_tmp;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_TIME];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_TIME].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_time_init: "
			"unable to add entry 'cn=Start,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to add entry 'cn=Start,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	/*
	 * Current
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Current,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Current\n"
			"description: %s\n"
#ifdef HACK_LOCAL_TIME 
			"description;lang-x-local: %s"
#endif /* HACK_LOCAL_TIME */
			, monitor_subsys[SLAPD_MONITOR_TIME].mss_dn.bv_val,
			ztmbuf
#ifdef HACK_LOCAL_TIME
			, ltmbuf
#endif /* HACK_LOCAL_TIME */
			);

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_time_init: "
			"unable to create entry 'cn=Current,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to create entry 'cn=Current,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = e_tmp;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_TIME];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_TIME].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "operation", LDAP_LEVEL_CRIT,
			"monitor_subsys_time_init: "
			"unable to add entry 'cn=Current,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val ));
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to add entry 'cn=Current,%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val,
			"", "" );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	mp = ( struct monitorentrypriv * )e_time->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_time );

	return( 0 );
}

int
monitor_subsys_time_update(
	struct monitorinfo      *mi,
	Entry                   *e
)
{
	char		ztmbuf[20], ltmbuf[20];
	struct tm	*ztm, *ltm;
	time_t		currenttime;
	Attribute	*a;
	static AttributeDescription	*ad_local = NULL;
	const char	*text = NULL;
	ber_len_t	len;

	static int	init_start = 0;

	/*
	 * Note: ltmbuf, ltm, ad_local, text are used only if HACK_LOCAL_TIME
	 * 	 is defined
	 */

	assert( mi );
	assert( e );
	
	if ( init_start == 0 && strncmp( e->e_nname.bv_val, "cn=START",
				sizeof("cn=START")-1 ) == 0 ) {
		currenttime = starttime;
		init_start = 1;

	} else if ( strncmp( e->e_nname.bv_val, "cn=CURRENT",
				sizeof("cn=CURRENT")-1 ) == 0 ) {
		currenttime = slap_get_time();

	} else {
		return( 0 );
	}

	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
	ztm = gmtime( &currenttime );
	strftime( ztmbuf, sizeof( ztmbuf ), "%Y%m%d%H%M%SZ", ztm );
#ifdef HACK_LOCAL_TIME
	ltm = localtime( &currenttime );
	local_time( ltm, -timezone, ltmbuf, sizeof( ltmbuf ) );
#endif /* HACK_LOCAL_TIME */
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

	a = attr_find( e->e_attrs, monitor_ad_desc );
	if ( a == NULL ) {
		return( -1 );
	}

	len = strlen( ztmbuf );
	assert( len == a->a_vals[0].bv_len );
	AC_MEMCPY( a->a_vals[0].bv_val, ztmbuf, len );

#ifdef HACK_LOCAL_TIME
	if ( ad_local == NULL ) {
		if ( slap_str2ad( "description;lang-x-local", 
					&ad_local, &text ) != LDAP_SUCCESS ) {
			return( -1 );
		}
	}
	a = attr_find( e->e_attrs, ad_local );
	if ( a == NULL ) {
		return( -1 );
	}

	len = strlen( ltmbuf );
	assert( len == a->a_vals[0].bv_len );
	AC_MEMCPY( a->a_vals[0].bv_val, ltmbuf, len );
#endif /* HACK_LOCAL_TIME */

	return( 0 );
}

/*
 * assumes gmtime_mutex is locked
 */
static int
local_time( const struct tm *ltm, long delta, char *buf, size_t len )
{
	char *p;

	if ( len < 20 ) {
		return -1;
	}
	strftime( buf, len, "%Y%m%d%H%M%S", ltm );

	p = buf + 14;

	if ( delta < 0 ) {
		p[ 0 ] = '-';
		delta = -delta;
	} else {
		p[ 0 ] = '+';
	}
	p++;

	snprintf( p, len - 15, "%02ld%02ld", delta / 3600, delta % 3600 );
	
	return 0;
}

