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
	MONITOR_SENT_BYTES = 0,
	MONITOR_SENT_PDU,
	MONITOR_SENT_ENTRIES,
	MONITOR_SENT_REFERRALS,

	MONITOR_SENT_LAST
};

struct monitor_sent_t {
	struct berval	rdn;
	struct berval	nrdn;
} monitor_sent[] = {
	{ BER_BVC("cn=Bytes"),		BER_BVNULL },
	{ BER_BVC("cn=PDU"),		BER_BVNULL },
	{ BER_BVC("cn=Entries"),	BER_BVNULL },
	{ BER_BVC("cn=Referrals"),	BER_BVNULL },
	{ BER_BVNULL,			BER_BVNULL }
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
		struct berval		rdn, bv;
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

		/* steal normalized RDN */
		dnRdn( &e->e_nname, &rdn );
		ber_dupbv( &monitor_sent[i].nrdn, &rdn );
	
		BER_BVSTR( &bv, "0" );
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
#ifdef HAVE_GMP
	mpz_t			n;
#else /* ! HAVE_GMP */
	unsigned long 		n;
#endif /* ! HAVE_GMP */
	Attribute		*a;
#ifndef HAVE_GMP
	char			buf[] = "+9223372036854775807L";
#endif /* ! HAVE_GMP */
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

	ldap_pvt_thread_mutex_lock(&slap_counters.sc_sent_mutex);
	switch ( i ) {
	case MONITOR_SENT_ENTRIES:
#ifdef HAVE_GMP
		mpz_init_set( n, slap_counters.sc_entries );
#else /* ! HAVE_GMP */
		n = slap_counters.sc_entries;
#endif /* ! HAVE_GMP */
		break;

	case MONITOR_SENT_REFERRALS:
#ifdef HAVE_GMP
		mpz_init_set( n, slap_counters.sc_refs );
#else /* ! HAVE_GMP */
		n = slap_counters.sc_refs;
#endif /* ! HAVE_GMP */
		break;

	case MONITOR_SENT_PDU:
#ifdef HAVE_GMP
		mpz_init_set( n, slap_counters.sc_pdu );
#else /* ! HAVE_GMP */
		n = slap_counters.sc_pdu;
#endif /* ! HAVE_GMP */
		break;

	case MONITOR_SENT_BYTES:
#ifdef HAVE_GMP
		mpz_init_set( n, slap_counters.sc_bytes );
#else /* ! HAVE_GMP */
		n = slap_counters.sc_bytes;
#endif /* ! HAVE_GMP */
		break;

	default:
		assert(0);
	}
	ldap_pvt_thread_mutex_unlock(&slap_counters.sc_sent_mutex);
	
	a = attr_find( e->e_attrs, mi->mi_ad_monitorCounter );
	if ( a == NULL ) {
		return -1;
	}

	free( a->a_vals[ 0 ].bv_val );
#ifdef HAVE_GMP
	/* NOTE: there should be no minus sign allowed in the counters... */
	a->a_vals[ 0 ].bv_len = mpz_sizeinbase( n, 10 );
	a->a_vals[ 0 ].bv_val = ber_memalloc( a->a_vals[ 0 ].bv_len + 1 );
	(void)mpz_get_str( a->a_vals[ 0 ].bv_val, 10, n );
	mpz_clear( n );
	/* NOTE: according to the documentation, the result 
	 * of mpz_sizeinbase() can exceed the length of the
	 * string representation of the number by 1
	 */
	if ( a->a_vals[ 0 ].bv_val[ a->a_vals[ 0 ].bv_len - 1 ] == '\0' ) {
		a->a_vals[ 0 ].bv_len--;
	}
#else /* ! HAVE_GMP */
	snprintf( buf, sizeof( buf ), "%lu", n );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );
#endif /* ! HAVE_GMP */

	return 0;
}

