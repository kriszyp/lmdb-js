/* sent.c - deal with data sent subsystem */
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

enum {
	MONITOR_SENT_ENTRIES = 0,
	MONITOR_SENT_REFERRALS,
	MONITOR_SENT_PDU,
	MONITOR_SENT_BYTES,

	MONITOR_SENT_LAST
};

struct monitor_sent_t {
	struct berval	rdn;
	struct berval	nrdn;
} monitor_sent[] = {
	{ BER_BVC("cn=Entries"),	BER_BVC("cn=entries")		},
	{ BER_BVC("cn=Referrals"),	BER_BVC("cn=referrals")		},
	{ BER_BVC("cn=PDU"),		BER_BVC("cn=pdu")		},
	{ BER_BVC("cn=Bytes"),		BER_BVC("cn=bytes")		},
	{ BER_BVNULL,			BER_BVNULL			}
};

int
monitor_subsys_sent_init(
	BackendDB		*be
)
{
	struct monitorinfo	*mi;
	
	Entry			*e_tmp, *e_sent;
	struct monitorentrypriv	*mp;
	int			i;

	assert( be != NULL );

	mi = ( struct monitorinfo * )be->be_private;

	if ( monitor_cache_get( mi,
			&monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn, &e_sent ) ) {
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_sent_init: "
			"unable to get entry \"%s\"\n%s%s",
			monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 
			"", "" );
		return( -1 );
	}

	e_tmp = NULL;

	for ( i = MONITOR_SENT_LAST; --i >= 0; ) {
		char			buf[ BACKMONITOR_BUFSIZE ];
		struct berval		bv;
		Entry			*e;

		snprintf( buf, sizeof( buf ),
				"dn: %s,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: %s\n"
				"creatorsName: %s\n"
				"modifiersName: %s\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				monitor_sent[i].rdn.bv_val,
				monitor_subsys[SLAPD_MONITOR_SENT].mss_dn.bv_val,
				mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
				mi->mi_oc_monitorCounterObject->soc_cname.bv_val,
				&monitor_sent[i].rdn.bv_val[STRLENOF( "cn=" )],
				mi->mi_creatorsName.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );

		e = str2entry( buf );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_sent_init: "
				"unable to create entry \"%s,%s\"\n",
				monitor_sent[i].rdn.bv_val,
				monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0 );
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
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_sent_init: "
				"unable to add entry \"%s,%s\"\n%s%s",
				monitor_sent[i].rdn.bv_val,
				monitor_subsys[SLAPD_MONITOR_SENT].mss_ndn.bv_val, 0 );
			return( -1 );
		}
	
		e_tmp = e;
	}

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
	struct monitorinfo	*mi = 
		(struct monitorinfo *)op->o_bd->be_private;
	
	struct berval		rdn;
	unsigned long 		n;
	Attribute		*a;
	char			buf[] = "+9223372036854775807L";
	int			i;

	assert( mi );
	assert( e );

	dnRdn( &e->e_nname, &rdn );

	for ( i = 0; i < MONITOR_SENT_LAST; i++ ) {
		if ( dn_match( &rdn, &monitor_sent[i].nrdn ) ) {
			break;
		}
	}

	if ( i == MONITOR_SENT_LAST ) {
		return 0;
	}

	ldap_pvt_thread_mutex_lock(&num_sent_mutex);
	switch ( i ) {
	case MONITOR_SENT_ENTRIES:
		n = num_entries_sent;
		break;

	case MONITOR_SENT_REFERRALS:
		n = num_refs_sent;
		break;

	case MONITOR_SENT_PDU:
		n = num_pdu_sent;
		break;

	case MONITOR_SENT_BYTES:
		n = num_bytes_sent;
		break;

	default:
		assert(0);
	}
	ldap_pvt_thread_mutex_unlock(&num_sent_mutex);
	
	a = attr_find( e->e_attrs, mi->mi_ad_monitorCounter );
	if ( a == NULL ) {
		return -1;
	}

	snprintf( buf, sizeof( buf ), "%lu", n );
	free( a->a_vals[ 0 ].bv_val );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );

	return 0;
}

