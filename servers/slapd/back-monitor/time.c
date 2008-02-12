/* time.c - deal with time subsystem */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2008 The OpenLDAP Foundation.
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

static int
monitor_subsys_time_update(
	Operation		*op,
	SlapReply		*rs,
	Entry                   *e );

int
monitor_subsys_time_init(
	BackendDB		*be,
	monitor_subsys_t	*ms )
{
	monitor_info_t	*mi;
	
	Entry		*e, **ep, *e_time;
	monitor_entry_t	*mp;
	char		buf[ BACKMONITOR_BUFSIZE ];

	assert( be != NULL );

	ms->mss_update = monitor_subsys_time_update;

	mi = ( monitor_info_t * )be->be_private;

	if ( monitor_cache_get( mi,
			&ms->mss_ndn, &e_time ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to get entry \"%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	mp = ( monitor_entry_t * )e_time->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	snprintf( buf, sizeof( buf ),
			"dn: cn=Start,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Start\n"
			"%s: %s\n"
			"creatorsName: %s\n"
			"modifiersName: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n", 
			ms->mss_dn.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_ad_monitorTimestamp->ad_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to create entry \"cn=Start,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	mp = monitor_entrypriv_create();
	if ( mp == NULL ) {
		return -1;
	}
	e->e_private = ( void * )mp;
	mp->mp_info = ms;
	mp->mp_flags = ms->mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to add entry \"cn=Start,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	/*
	 * Current
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Current,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Current\n"
			"%s: %s\n"
			"creatorsName: %s\n"
			"modifiersName: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			ms->mss_dn.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_ad_monitorTimestamp->ad_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to create entry \"cn=Current,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	mp = monitor_entrypriv_create();
	if ( mp == NULL ) {
		return -1;
	}
	e->e_private = ( void * )mp;
	mp->mp_info = ms;
	mp->mp_flags = ms->mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_time_init: "
			"unable to add entry \"cn=Current,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	monitor_cache_release( mi, e_time );

	return( 0 );
}

static int
monitor_subsys_time_update(
	Operation		*op,
	SlapReply		*rs,
	Entry                   *e )
{
	monitor_info_t		*mi = ( monitor_info_t * )op->o_bd->be_private;
	static struct berval	bv_current = BER_BVC( "cn=current" );
	struct berval		rdn;

	assert( mi != NULL );
	assert( e != NULL );

	dnRdn( &e->e_nname, &rdn );
	
	if ( dn_match( &rdn, &bv_current ) ) {
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
			return rs->sr_err = LDAP_OTHER;
		}

		assert( len == a->a_vals[ 0 ].bv_len );
		AC_MEMCPY( a->a_vals[ 0 ].bv_val, tmbuf, len );

		/* FIXME: touch modifyTimestamp? */
	}

	return SLAP_CB_CONTINUE;
}

