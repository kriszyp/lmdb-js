/* operation.c - deal with operation subsystem */
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
#include "lber_pvt.h"

static struct berval 
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
		BER_BVC( "Extended" ),
		{ 0, NULL }
	};

int
monitor_subsys_ops_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e, *e_tmp, *e_op;
	struct monitorentrypriv	*mp;
	char			buf[ BACKMONITOR_BUFSIZE ];
	int 			i;
	struct berval		bv_zero = BER_BVC("0");

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

	attr_merge_one( e_op, mi->mi_ad_monitorOpInitiated, &bv_zero, NULL );
	attr_merge_one( e_op, mi->mi_ad_monitorOpCompleted, &bv_zero, NULL );

	e_tmp = NULL;

	for ( i = SLAP_OP_LAST; i-- > 0; ) {

		/*
		 * Initiated ops
		 */
		snprintf( buf, sizeof( buf ),
				"dn: cn=%s,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: %s\n"
				"%s: 0\n"
				"%s: 0\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				bv_op[ i ].bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val,
				mi->mi_oc_monitorOperation->soc_cname.bv_val,
				mi->mi_oc_monitorOperation->soc_cname.bv_val,
				bv_op[ i ].bv_val,
				mi->mi_ad_monitorOpInitiated->ad_cname.bv_val,
				mi->mi_ad_monitorOpCompleted->ad_cname.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );

		e = str2entry( buf );
		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, CRIT,
				"monitor_subsys_ops_init: "
				"unable to create entry 'cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to create entry 'cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#endif
			return( -1 );
		}
	
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
				bv_op[ i ].bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to add entry 'cn=%s,%s'\n",
				bv_op[ i ].bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
#endif
			return( -1 );
		}
	
		e_tmp = e;
	}

	mp = ( struct monitorentrypriv * )e_op->e_private;
	mp->mp_children = e_tmp;

	monitor_cache_release( mi, e_op );

	return( 0 );
}

int
monitor_subsys_ops_update(
	Operation		*op,
	Entry                   *e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	long 		nInitiated = 0, nCompleted = 0;
	char 		*rdnvalue;
	int 		i;
	Attribute	*a;
	char		buf[] = "+9223372036854775807L";

	assert( mi );
	assert( e );

	rdnvalue = e->e_dn + ( sizeof( "cn=" ) - 1 );

	if ( strncmp( rdnvalue, SLAPD_MONITOR_OPS_NAME,
				sizeof( SLAPD_MONITOR_OPS_NAME ) - 1 ) == 0 )
	{
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
			nInitiated += num_ops_initiated_[ i ];
			nCompleted += num_ops_completed_[ i ];
		}
		
	} else {
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
			if ( strncmp( rdnvalue, bv_op[ i ].bv_val, 
						bv_op[ i ].bv_len ) == 0 )
			{
				nInitiated = num_ops_initiated_[ i ];
				nCompleted = num_ops_completed_[ i ];
				break;
			}
		}

		if ( i == SLAP_OP_LAST ) {
			/* not found ... */
			return( 0 );
		}
	}

	a = attr_find( e->e_attrs, mi->mi_ad_monitorOpInitiated );
	assert ( a != NULL );
	snprintf( buf, sizeof( buf ), "%ld", nInitiated );
	free( a->a_vals[ 0 ].bv_val );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );

	a = attr_find( e->e_attrs, mi->mi_ad_monitorOpCompleted );
	assert ( a != NULL );
	snprintf( buf, sizeof( buf ), "%ld", nCompleted );
	free( a->a_vals[ 0 ].bv_val );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );

	return( 0 );
}

