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

struct monitor_ops_t {
	struct berval	rdn;
	struct berval	nrdn;
} monitor_op[] = {
	{ BER_BVC( "cn=Bind" ),		BER_BVC( "cn=bind" )		},
	{ BER_BVC( "cn=Unbind" ),	BER_BVC( "cn=unbind" )		},
	{ BER_BVC( "cn=Add" ),		BER_BVC( "cn=add" )		},
	{ BER_BVC( "cn=Delete" ),	BER_BVC( "cn=delete" )		},
	{ BER_BVC( "cn=Modrdn" ),	BER_BVC( "cn=modrdn" )		},
	{ BER_BVC( "cn=Modify" ),	BER_BVC( "cn=modify" )		},
	{ BER_BVC( "cn=Compare" ),	BER_BVC( "cn=compare" )		},
	{ BER_BVC( "cn=Search" ),	BER_BVC( "cn=search" )		},
	{ BER_BVC( "cn=Abandon" ),	BER_BVC( "cn=abandon" )		},
	{ BER_BVC( "cn=Extended" ),	BER_BVC( "cn=extended" )	},
	{ BER_BVNULL,			BER_BVNULL			}
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
		Debug( LDAP_DEBUG_ANY,
			"monitor_subsys_ops_init: "
			"unable to get entry \"%s\"\n",
			monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 
			0, 0 );
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
				"dn: %s,%s\n"
				"objectClass: %s\n"
				"structuralObjectClass: %s\n"
				"cn: %s\n"
				"%s: 0\n"
				"%s: 0\n"
				"creatorsName: %s\n"
				"modifiersName: %s\n"
				"createTimestamp: %s\n"
				"modifyTimestamp: %s\n",
				monitor_op[ i ].rdn.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_dn.bv_val,
				mi->mi_oc_monitorOperation->soc_cname.bv_val,
				mi->mi_oc_monitorOperation->soc_cname.bv_val,
				&monitor_op[ i ].rdn.bv_val[STRLENOF( "cn=" )],
				mi->mi_ad_monitorOpInitiated->ad_cname.bv_val,
				mi->mi_ad_monitorOpCompleted->ad_cname.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_creatorsName.bv_val,
				mi->mi_startTime.bv_val,
				mi->mi_startTime.bv_val );

		e = str2entry( buf );
		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to create entry \"%s,%s\"\n",
				monitor_op[ i ].rdn.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
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
			Debug( LDAP_DEBUG_ANY,
				"monitor_subsys_ops_init: "
				"unable to add entry \"%s,%s\"\n",
				monitor_op[ i ].rdn.bv_val,
				monitor_subsys[SLAPD_MONITOR_OPS].mss_ndn.bv_val, 0 );
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
	struct monitorinfo	*mi = 
		(struct monitorinfo *)op->o_bd->be_private;

#ifdef HAVE_GMP
	mpz_t			nInitiated,
				nCompleted;
#else /* ! HAVE_GMP */
	unsigned long		nInitiated = 0,
				nCompleted = 0;
	char			buf[] = "+9223372036854775807L";
#endif /* ! HAVE_GMP */
	struct berval		rdn;
	int 			i;
	Attribute		*a;
	static struct berval	bv_ops = BER_BVC( "cn=operations" );

	assert( mi );
	assert( e );

	dnRdn( &e->e_nname, &rdn );

	if ( dn_match( &rdn, &bv_ops ) ) {
#ifdef HAVE_GMP
		mpz_init( nInitiated );
		mpz_init( nCompleted );
#endif /* ! HAVE_GMP */

		ldap_pvt_thread_mutex_lock( &slap_counters.sc_ops_mutex );
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
#ifdef HAVE_GMP
			mpz_add( nInitiated, nInitiated, slap_counters.sc_ops_initiated_[ i ] );
			mpz_add( nCompleted, nCompleted, slap_counters.sc_ops_completed_[ i ] );
#else /* ! HAVE_GMP */
			nInitiated += slap_counters.sc_ops_initiated_[ i ];
			nCompleted += slap_counters.sc_ops_completed_[ i ];
#endif /* ! HAVE_GMP */
		}
		ldap_pvt_thread_mutex_unlock( &slap_counters.sc_ops_mutex );
		
	} else {
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
			if ( dn_match( &rdn, &monitor_op[ i ].nrdn ) )
			{
				ldap_pvt_thread_mutex_lock( &slap_counters.sc_ops_mutex );
#ifdef HAVE_GMP
				mpz_init_set( nInitiated, slap_counters.sc_ops_initiated_[ i ] );
				mpz_init_set( nCompleted, slap_counters.sc_ops_completed_[ i ] );
#else /* ! HAVE_GMP */
				nInitiated = slap_counters.sc_ops_initiated_[ i ];
				nCompleted = slap_counters.sc_ops_completed_[ i ];
#endif /* ! HAVE_GMP */
				ldap_pvt_thread_mutex_unlock( &slap_counters.sc_ops_mutex );
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
	free( a->a_vals[ 0 ].bv_val );
#ifdef HAVE_GMP
	/* NOTE: there should be no minus sign allowed in the counters... */
	a->a_vals[ 0 ].bv_len = mpz_sizeinbase( nInitiated, 10 );
	a->a_vals[ 0 ].bv_val = ber_memalloc( a->a_vals[ 0 ].bv_len + 1 );
	(void)mpz_get_str( a->a_vals[ 0 ].bv_val, 10, nInitiated );
	mpz_clear( nInitiated );
	/* NOTE: according to the documentation, the result 
	 * of mpz_sizeinbase() can exceed the length of the
	 * string representation of the number by 1
	 */
	if ( a->a_vals[ 0 ].bv_val[ a->a_vals[ 0 ].bv_len - 1 ] == '\0' ) {
		a->a_vals[ 0 ].bv_len--;
	}
#else /* ! HAVE_GMP */
	snprintf( buf, sizeof( buf ), "%ld", nInitiated );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );
#endif /* ! HAVE_GMP */
	
	a = attr_find( e->e_attrs, mi->mi_ad_monitorOpCompleted );
	assert ( a != NULL );
	free( a->a_vals[ 0 ].bv_val );
#ifdef HAVE_GMP
	/* NOTE: there should be no minus sign allowed in the counters... */
	a->a_vals[ 0 ].bv_len = mpz_sizeinbase( nCompleted, 10 );
	a->a_vals[ 0 ].bv_val = ber_memalloc( a->a_vals[ 0 ].bv_len + 1 );
	(void)mpz_get_str( a->a_vals[ 0 ].bv_val, 10, nCompleted );
	mpz_clear( nCompleted );
	/* NOTE: according to the documentation, the result 
	 * of mpz_sizeinbase() can exceed the length of the
	 * string representation of the number by 1
	 */
	if ( a->a_vals[ 0 ].bv_val[ a->a_vals[ 0 ].bv_len - 1 ] == '\0' ) {
		a->a_vals[ 0 ].bv_len--;
	}
#else /* ! HAVE_GMP */
	snprintf( buf, sizeof( buf ), "%ld", nCompleted );
	ber_str2bv( buf, 0, 1, &a->a_vals[ 0 ] );
#endif /* ! HAVE_GMP */
	
	return( 0 );
}

