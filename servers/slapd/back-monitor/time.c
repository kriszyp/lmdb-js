/* time.c - deal with time subsystem */
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
#include <ac/string.h>
#include <ac/time.h>


#include "slap.h"
#include <lutil.h>
#include "proto-slap.h"
#include "back-monitor.h"

#ifdef HACK_LOCAL_TIME
static int
local_time( const struct tm *ztm, long delta, char *buf, size_t len );
#endif /* HACK_LOCAL_TIME */

int
monitor_subsys_time_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_time;
	struct monitorentrypriv	*mp;
	char			buf[1024];
	struct tm		*tms;
	char			tmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];

	/*
	 * Note: ltmbuf, ltm are used only if HACK_LOCAL_TIME is defined
	 */

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn, &e_time ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_time_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val, 0, 0 );
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
#ifdef HACK_LOCAL_TIME
	tms = localtime( &starttime );
	local_time( tms, -timezone, tmbuf, sizeof( tmbuf ) );
#else /* !HACK_LOCAL_TIME */
	tms = gmtime( &starttime );
	lutil_gentime( tmbuf, sizeof(tmbuf), tms );
#endif /* !HACK_LOCAL_TIME */
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
	snprintf( buf, sizeof( buf ),
			"dn: cn=Start,%s\n"
			SLAPD_MONITOR_OBJECTCLASSES
			"cn: Start\n"
			"createTimestamp: %s", 
			monitor_subsys[SLAPD_MONITOR_TIME].mss_dn.bv_val,
			tmbuf );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_time_init: "
			"unable to create entry 'cn=Start,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val, 0, 0 );
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
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_time_init: "
			"unable to add entry 'cn=Start,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val, 0, 0 );
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
			"createTimestamp: %s\n"
			"modifyTimestamp: %s",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_dn.bv_val,
			tmbuf, tmbuf );

	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_time_init: "
			"unable to create entry 'cn=Current,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val, 0, 0 );
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
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_time_init: "
			"unable to add entry 'cn=Current,%s'\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_ndn.bv_val, 0, 0 );
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
	char		stmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ],
			ctmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
	struct tm	*stm, *ctm;
	Attribute	*a;
	ber_len_t	len;

	static int	init_start = 0, init_current = 0;
#define ENTRY_TIME	0
#define ENTRY_START	1
#define ENTRY_CURRENT	2
	int		entry = ENTRY_TIME;

	assert( mi );
	assert( e );
	
	if ( strncmp( e->e_nname.bv_val, "cn=start", 
				sizeof("cn=start")-1 ) == 0 ) {
		entry = ENTRY_START;
		if ( init_start == 1 ) {
			return( 0 );
		}

	} else if ( strncmp( e->e_nname.bv_val, "cn=current",
				sizeof("cn=current")-1 ) == 0 ) {
		entry = ENTRY_CURRENT;
	}
	
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
	if ( init_start == 0 ) {
#ifdef HACK_LOCAL_TIME
		stm = localtime( &starttime );
		local_time( stm, -timezone, stmbuf, sizeof( stmbuf ) );
#else /* !HACK_LOCAL_TIME */
		stm = gmtime( &starttime );
		lutil_gentime( stmbuf, sizeof( stmbuf ), stm );
#endif /* !HACK_LOCAL_TIME */
	}

	if ( entry == ENTRY_CURRENT ) {
		time_t currentTime = slap_get_time();
#ifdef HACK_LOCAL_TIME
		ctm = localtime( &currentTime );
		local_time( ctm, -timezone, ctmbuf, sizeof( ctmbuf ) );
#else /* !HACK_LOCAL_TIME */
		ctm = gmtime( &currentTime );
		lutil_gentime( ctmbuf, sizeof( ctmbuf ), ctm );
#endif /* !HACK_LOCAL_TIME */
	}
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

	if ( ( entry == ENTRY_START && init_start == 0 ) 
			|| ( entry == ENTRY_CURRENT && init_current == 0 ) ) {
		a = attr_find( e->e_attrs, slap_schema.si_ad_createTimestamp );
		if ( a == NULL ) {
			return( -1 );
		}

		len = strlen( stmbuf );
		assert( len == a->a_vals[0].bv_len );
		AC_MEMCPY( a->a_vals[0].bv_val, stmbuf, len );

		if ( entry == ENTRY_START ) {
			init_start = 1;
		} else if ( entry == ENTRY_CURRENT ) {
			init_current = 1;
		}
	}

	if ( entry == ENTRY_CURRENT ) {
		a = attr_find( e->e_attrs, slap_schema.si_ad_modifyTimestamp );
		if ( a == NULL ) {
			return( -1 );
		}

		len = strlen( ctmbuf );
		assert( len == a->a_vals[0].bv_len );
		AC_MEMCPY( a->a_vals[0].bv_val, ctmbuf, len );
	}

	return( 0 );
}

#ifdef HACK_LOCAL_TIME
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
#endif /* HACK_LOCAL_TIME */

