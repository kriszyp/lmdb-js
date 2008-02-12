/* thread.c - deal with thread subsystem */
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

#include "slap.h"
#include "back-monitor.h"

#include <ldap_rq.h>

static int 
monitor_subsys_thread_update( 
	Operation		*op,
	SlapReply		*rs,
	Entry 			*e );

/*
 * initializes log subentry
 */
int
monitor_subsys_thread_init(
	BackendDB       	*be,
	monitor_subsys_t	*ms
)
{
	monitor_info_t	*mi;
	monitor_entry_t	*mp;
	Entry		*e, **ep, *e_thread;
	static char	buf[ BACKMONITOR_BUFSIZE ];

	ms->mss_update = monitor_subsys_thread_update;

	mi = ( monitor_info_t * )be->be_private;

	if ( monitor_cache_get( mi, &ms->mss_ndn, &e_thread ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_thread_init: unable to get entry \"%s\"\n",
			ms->mss_ndn.bv_val, 
			0, 0 );
		return( -1 );
	}

	mp = ( monitor_entry_t * )e_thread->e_private;
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

	/*
	 * Runqueue runners
	 */
	snprintf( buf, sizeof( buf ),
			"dn: cn=Runqueue,%s\n"
			"objectClass: %s\n"
			"structuralObjectClass: %s\n"
			"cn: Runqueue\n"
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
			"unable to create entry \"cn=Runqueue,%s\"\n",
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
			"unable to add entry \"cn=Runqueue,%s\"\n",
			ms->mss_ndn.bv_val, 0, 0 );
		return( -1 );
	}
	
	*ep = e;
	ep = &mp->mp_next;

	monitor_cache_release( mi, e_thread );

	return( 0 );
}

static int 
monitor_subsys_thread_update( 
	Operation		*op,
	SlapReply		*rs,
	Entry 			*e )
{
	monitor_info_t	*mi = ( monitor_info_t * )op->o_bd->be_private;
	Attribute		*a;
	char 			buf[ BACKMONITOR_BUFSIZE ];
	static struct berval	backload_bv = BER_BVC( "cn=backload" );
	static struct berval	runqueue_bv = BER_BVC( "cn=runqueue" );
	struct berval		rdn, bv;
	ber_len_t		len;
	int which = 0, i;
	struct re_s *re;

	assert( mi != NULL );

	dnRdn( &e->e_nname, &rdn );
	if ( dn_match( &rdn, &backload_bv ) ) {
		which = 1;

	} else if ( dn_match( &rdn, &runqueue_bv ) ) {
		which = 2;

	} else {
		return SLAP_CB_CONTINUE;
	}

	a = attr_find( e->e_attrs, mi->mi_ad_monitoredInfo );
	if ( a == NULL ) {
		return rs->sr_err = LDAP_OTHER;
	}

	switch ( which ) {
	case 1:
		snprintf( buf, sizeof( buf ), "%d", 
			ldap_pvt_thread_pool_backload( &connection_pool ) );
		len = strlen( buf );
		if ( len > a->a_vals[ 0 ].bv_len ) {
			a->a_vals[ 0 ].bv_val = ber_memrealloc( a->a_vals[ 0 ].bv_val, len + 1 );
		}
		a->a_vals[ 0 ].bv_len = len;
		AC_MEMCPY( a->a_vals[ 0 ].bv_val, buf, len + 1 );
		break;

	case 2:
		for ( i = 0; !BER_BVISNULL( &a->a_vals[ i ] ); i++ ) {
			ch_free( a->a_vals[i].bv_val );
			BER_BVZERO( &a->a_vals[ i ] );
		}
		bv.bv_val = buf;
		ldap_pvt_thread_mutex_lock( &slapd_rq.rq_mutex );
		LDAP_STAILQ_FOREACH( re, &slapd_rq.run_list, rnext ) {
			bv.bv_len = snprintf( buf, sizeof( buf ), "%s(%s)",
				re->tname, re->tspec );
			value_add_one( &a->a_vals, &bv );
		}
		ldap_pvt_thread_mutex_unlock( &slapd_rq.rq_mutex );

		/* don't leave 'round attributes with no values */
		if ( BER_BVISNULL( &a->a_vals[ 0 ] ) ) {
			BER_BVSTR( &bv, "()" );
			value_add_one( &a->a_vals, &bv );
		}
		break;
	}

	/* FIXME: touch modifyTimestamp? */

	return SLAP_CB_CONTINUE;
}

