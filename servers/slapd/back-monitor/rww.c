/* readw.c - deal with read waiters subsystem */
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
#include "lutil.h"
#include "back-monitor.h"

int
monitor_subsys_rww_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, **ep, *e_conn;
	struct monitorentrypriv	*mp;
	char			buf[ BACKMONITOR_BUFSIZE ];
	struct berval		bv;

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn, &e_conn ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to get entry \"%s\"\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}

	mp = ( struct monitorentrypriv * )e_conn->e_private;
	mp->mp_children = NULL;
	ep = &mp->mp_children;

	/*
	 * Total conns
	 */
	snprintf( buf, sizeof( buf ),
		"dn: cn=Read,%s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Read\n"
		"creatorsName: %s\n"
		"modifiersName: %s\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		monitor_subsys[SLAPD_MONITOR_RWW].mss_dn.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_creatorsName.bv_val,
		mi->mi_startTime.bv_val,
		mi->mi_startTime.bv_val );
	
	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to create entry \"cn=Read,%s\"\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = NULL;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_RWW];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_RWW].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to add entry \"cn=Read,%s\"\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	/*
	 * Current conns
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Write,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Write\n"
			"creatorsName: %s\n"
			"modifiersName: %s\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_dn.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_creatorsName.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );
	
	e = str2entry( buf );
	if ( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to create entry \"cn=Write,%s\"\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = NULL;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_RWW];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_RWW].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to add entry \"cn=Write,%s\"\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	monitor_cache_release( mi, e_conn );

	return( 0 );
}

int
monitor_subsys_rww_update(
	Operation		*op,
	Entry                   *e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	Connection              *c;
	int                     connindex;
	long			nconns, nwritewaiters, nreadwaiters;

#define RWW_NONE	0
#define RWW_READ	1
#define RWW_WRITE	2
	int			type = RWW_NONE;
	
	Attribute		*a;
	char 			buf[] = "+9223372036854775807L";
	long			num = 0;

	assert( mi != NULL );
	assert( e != NULL );
	
	if ( strncasecmp( e->e_ndn, "cn=read", 
				sizeof("cn=read")-1 ) == 0 ) {
		type = RWW_READ;

	} else if ( strncasecmp( e->e_ndn, "cn=write", 
				sizeof("cn=write")-1 ) == 0 ) {
		type = RWW_WRITE;

	} else {
		return( 0 );
	}

	nconns = nwritewaiters = nreadwaiters = 0;
	for ( c = connection_first( &connindex );
			c != NULL;
			c = connection_next( c, &connindex ), nconns++ ) {
		if ( c->c_writewaiter ) {
			nwritewaiters++;
		}
		if ( c->c_currentber != NULL ) {
			nreadwaiters++;
		}
	}
	connection_done(c);

	switch ( type ) {
	case RWW_READ:
		num = nreadwaiters;
		break;

	case RWW_WRITE:
		num = nwritewaiters;
		break;

	default:
		assert( 0 );
	}

	snprintf( buf, sizeof( buf ), "%ld", num );

	a = attr_find( e->e_attrs, mi->mi_ad_monitorCounter );
	assert( a );
	free( a->a_vals[0].bv_val );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );

	return( 0 );
}

