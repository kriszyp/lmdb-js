/* time.c - deal with time subsystem */
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
#include <ac/string.h>
#include <ac/time.h>


#include "slap.h"
#include <lutil.h>
#include "proto-slap.h"
#include "back-monitor.h"

int
monitor_subsys_time_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_time;
	struct monitorentrypriv	*mp;
	char			buf[ BACKMONITOR_BUFSIZE ];

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

	snprintf( buf, sizeof( buf ),
			"dn: cn=Start,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Start\n"
			"%s: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n", 
			monitor_subsys[SLAPD_MONITOR_TIME].mss_dn.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_ad_monitorTimestamp->ad_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

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
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Current\n"
			"%s: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			monitor_subsys[SLAPD_MONITOR_TIME].mss_dn.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_ad_monitorTimestamp->ad_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

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
	Operation		*op,
	Entry                   *e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;

	assert( mi );
	assert( e );
	
	if ( strncmp( e->e_nname.bv_val, "cn=current",
				sizeof("cn=current") - 1 ) == 0 ) {
		struct tm	*tm;
#ifdef HAVE_GMTIME_R
		struct tm	tm_buf;
#endif
		char		tmbuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
		Attribute	*a;
		ber_len_t	len;
		time_t		currtime;

		currtime = slap_get_time();

#ifndef HAVE_GMTIME_R
		ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#endif
#ifdef HACK_LOCAL_TIME
# ifdef HAVE_LOCALTIME_R
		tm = localtime_r( &currtime, &tm_buf );
# else
		tm = localtime( &currtime );
# endif /* HAVE_LOCALTIME_R */
		lutil_localtime( tmbuf, sizeof( tmbuf ), tm, -timezone );
#else /* !HACK_LOCAL_TIME */
# ifdef HAVE_GMTIME_R
		tm = gmtime_r( &currtime, &tm_buf );
# else
		tm = gmtime( &currtime );
# endif /* HAVE_GMTIME_R */
		lutil_gentime( tmbuf, sizeof( tmbuf ), tm );
#endif /* !HACK_LOCAL_TIME */
#ifndef HAVE_GMTIME_R
		ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
#endif

		len = strlen( tmbuf );

		a = attr_find( e->e_attrs, mi->mi_ad_monitorTimestamp );
		if ( a == NULL ) {
			return( -1 );
		}

		assert( len == a->a_vals[0].bv_len );
		AC_MEMCPY( a->a_vals[0].bv_val, tmbuf, len );
	}

	return( 0 );
}

