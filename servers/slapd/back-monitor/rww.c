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
	
	Entry			*e, *e_tmp, *e_conn;
	struct monitorentrypriv	*mp;
	char			buf[ BACKMONITOR_BUFSIZE ];
	struct berval		bv;

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn, &e_conn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_rww_init: "
			"unable to get entry '%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to get entry '%s'\n%s%s",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 
			"", "" );
#endif
		return( -1 );
	}

	e_tmp = NULL;

	/*
	 * Total conns
	 */
	snprintf( buf, sizeof( buf ),
		"dn: cn=Read,%s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Read\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		monitor_subsys[SLAPD_MONITOR_RWW].mss_dn.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_startTime.bv_val,
		mi->mi_startTime.bv_val );
	
	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_rww_init: "
			"unable to create entry 'cn=Read,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to create entry 'cn=Read,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#endif
		return( -1 );
	}
	
	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = e_tmp;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_RWW];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_RWW].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_rww_init: "
			"unable to add entry 'cn=Read,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to add entry 'cn=Read,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	/*
	 * Current conns
	 */
	snprintf( buf, sizeof( buf ),
		"dn: cn=Write,%s\n"
		"objectClass: %s\n"
		"structuralObjectClass: %s\n"
		"cn: Write\n"
		"createTimestamp: %s\n"
		"modifyTimestamp: %s\n",
		monitor_subsys[SLAPD_MONITOR_RWW].mss_dn.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
		mi->mi_startTime.bv_val,
		mi->mi_startTime.bv_val );
	
	e = str2entry( buf );
	if ( e == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_rww_init: "
			"unable to create entry 'cn=Write,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to create entry 'cn=Write,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#endif
		return( -1 );
	}
	
	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );
	e->e_private = ( void * )mp;
	mp->mp_next = e_tmp;
	mp->mp_children = NULL;
	mp->mp_info = &monitor_subsys[SLAPD_MONITOR_RWW];
	mp->mp_flags = monitor_subsys[SLAPD_MONITOR_RWW].mss_flags \
		| MONITOR_F_SUB | MONITOR_F_PERSISTENT;

	if ( monitor_cache_add( mi, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT,
			"monitor_subsys_rww_init: "
			"unable to add entry 'cn=Write,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_rww_init: "
			"unable to add entry 'cn=Write,%s'\n",
			monitor_subsys[SLAPD_MONITOR_RWW].mss_ndn.bv_val, 0, 0 );
#endif
		return( -1 );
	}
	
	e_tmp = e;

	mp = ( struct monitorentrypriv * )e_conn->e_private;
	mp->mp_children = e_tmp;

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

