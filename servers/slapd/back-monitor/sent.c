/* sent.c - deal with data sent subsystem */
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
	char			buf[ BACKMONITOR_BUFSIZE ];
	struct berval		bv;

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
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Entries\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

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
	
	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
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
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Referrals\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

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

	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
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
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: PDU\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

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

	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
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
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Bytes\n"
			"createTimestamp: %s\n"
			"modifyTimestamp: %s\n",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
			mi->mi_startTime.bv_val,
			mi->mi_startTime.bv_val );

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

	bv.bv_val = "0";
	bv.bv_len = 1;
	attr_merge_one( e, mi->mi_ad_monitorCounter, &bv, NULL );
	
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
	Operation		*op,
	Entry                   *e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
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
		char		buf[] = "+9223372036854775807L";

		a = attr_find( e->e_attrs, mi->mi_ad_monitorCounter);
		if ( a == NULL ) {
			return( -1 );
		}

		snprintf( buf, sizeof( buf ), "%ld", n );
		free( a->a_vals[ 0 ].bv_val );
		ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );
	}

	return( 0 );
}

