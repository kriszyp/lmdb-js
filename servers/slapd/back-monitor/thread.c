/* thread.c - deal with thread subsystem */
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
*  * initializes log subentry
*   */
int
monitor_subsys_thread_init(
	BackendDB       *be,
	monitorsubsys	*ms
)
{
	struct monitorinfo      *mi;
	struct monitorentrypriv	*mp;
	Entry                   *e, **ep, *e_thread;
	static char		buf[ BACKMONITOR_BUFSIZE ];

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi, &ms->mss_ndn, &e_thread ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_thread_init: unable to get entry \"%s\"\n",
			ms->mss_ndn.bv_val, 
			0, 0 );
		return( -1 );
	}

	mp = ( struct monitorentrypriv * )e_thread->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	/*
	 * Max
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Max,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Max\n"
			"%s: %d\n"
			"creatorsName: %s\n"
			"modifiersName: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n", 
			ms->mss_dn.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_ad_monitoredInfo->ad_cname.bv_val,
			connection_pool_max,
			mi->mi_creatorsName.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_thread_init: "
			"unable to create entry \"cn=Max,%s\"\n",
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
			"monitor_subsys_thread_init: "
			"unable to add entry \"cn=Max,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	/*
	 * Backload
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Backload,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Backload\n"
			"%s: 0\n"
			"creatorsName: %s\n"
			"modifiersName: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			ms->mss_dn.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_oc_monitoredObject->soc_cname.bv_val,
			mi->mi_ad_monitoredInfo->ad_cname.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_thread_init: "
			"unable to create entry \"cn=Backload,%s\"\n",
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
			"monitor_subsys_thread_init: "
			"unable to add entry \"cn=Backload,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	monitor_cache_release( mi, e_thread );

	return( 0 );
}

int 
monitor_subsys_thread_update( 
	Operation		*op,
	Entry 			*e
)
{
	struct monitorinfo	*mi =
		(struct monitorinfo *)op->o_bd->be_private;
	Attribute		*a;
	char 			buf[ BACKMONITOR_BUFSIZE ];
	static struct berval	backload_bv = BER_BVC( "cn=backload" );
	struct berval		rdn;
	ber_len_t		len;

	assert( mi != NULL );

	dnRdn( &e->e_nname, &rdn );
	if ( !dn_match( &rdn, &backload_bv ) ) {
		return 0;
	}

	a = attr_find( e->e_attrs, mi->mi_ad_monitoredInfo );
	if ( a == NULL ) {
		return -1;
	}

	snprintf( buf, sizeof( buf ), "%d", 
			ldap_pvt_thread_pool_backload( &connection_pool ) );
	len = strlen( buf );
	if ( len > a->a_vals[ 0 ].bv_len ) {
		a->a_vals[ 0 ].bv_val = ber_memrealloc( a->a_vals[ 0 ].bv_val, len + 1 );
	}
	a->a_vals[ 0 ].bv_len = len;
	AC_MEMCPY( a->a_vals[ 0 ].bv_val, buf, len + 1 );

	return( 0 );
}

