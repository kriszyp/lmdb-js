/* init.c - initialize various things */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "lber_pvt.h"
#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

/*
 * read-only global variables or variables only written by the listener
 * thread (after they are initialized) - no need to protect them with a mutex.
 */
int		slap_debug = 0;

struct berval AllUser = BER_BVC( LDAP_ALL_USER_ATTRIBUTES );
struct berval AllOper = BER_BVC( LDAP_ALL_OPERATIONAL_ATTRIBUTES );
struct berval NoAttrs = BER_BVC( LDAP_NO_ATTRS );

/*
 * global variables that need mutex protection
 */
#ifdef LDAP_DEBUG
int ldap_syslog = LDAP_DEBUG_STATS;
#else
int ldap_syslog;
#endif

#ifdef LOG_DEBUG
int ldap_syslog_level = LOG_DEBUG;
#else
int ldap_syslog_level;
#endif

/*
 * these mutexes must be used when calling the entry2str()
 * routine since it returns a pointer to static data.
 */
static const char* slap_name = NULL;
int slapMode = SLAP_UNDEFINED_MODE;

int
slap_init( int mode, const char *name )
{
	int rc;
	int i;

	assert( mode );

	if ( slapMode != SLAP_UNDEFINED_MODE ) {
		Debug( LDAP_DEBUG_ANY,
		 "%s init: init called twice (old=%d, new=%d)\n",
		 name, slapMode, mode );

		return 1;
	}

	slapMode = mode;

	switch ( slapMode & SLAP_MODE ) {
	case SLAP_SERVER_MODE:
	case SLAP_TOOL_MODE:
		Debug( LDAP_DEBUG_TRACE,
			"%s init: initiated %s.\n",	name,
			(mode & SLAP_MODE) == SLAP_TOOL_MODE ? "tool" : "server",
			0 );


		slap_name = name;

		ldap_pvt_thread_pool_init( &SLAPD_GLOBAL(connection_pool),
				SLAPD_GLOBAL(connection_pool_max), 0);

		ldap_pvt_thread_mutex_init( &SLAPD_GLOBAL(entry2str_mutex) );
		ldap_pvt_thread_mutex_init( &SLAPD_GLOBAL(replog_mutex) );

		ldap_pvt_thread_mutex_init( &SLAPD_GLOBAL(counters).sc_sent_mutex );
		ldap_pvt_thread_mutex_init( &SLAPD_GLOBAL(counters).sc_ops_mutex );
		ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_bytes );
		ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_pdu );
		ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_entries );
		ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_refs );

		ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_ops_completed );
		ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_ops_initiated );

#ifdef SLAPD_MONITOR
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
			ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_ops_initiated_[ i ] );
			ldap_pvt_mp_init( SLAPD_GLOBAL(counters).sc_ops_completed_[ i ] );
		}
#endif /* SLAPD_MONITOR */

#ifndef HAVE_GMTIME_R
		ldap_pvt_thread_mutex_init( &SLAPD_GLOBAL(gmtime_mutex) );
#endif
#if defined( SLAPD_CRYPT ) || defined( SLAPD_SPASSWD )
		ldap_pvt_thread_mutex_init( &passwd_mutex );
#endif

		rc = slap_sasl_init();

		if( rc == 0 ) {
			rc = backend_init( );
		}

		break;

	default:
		Debug( LDAP_DEBUG_ANY,
			"%s init: undefined mode (%d).\n", name, mode, 0 );

		rc = 1;
		break;
	}

	return rc;
}

int slap_startup( Backend *be )
{
	int rc;

	Debug( LDAP_DEBUG_TRACE,
		"%s startup: initiated.\n",
		slap_name, 0, 0 );


	rc = backend_startup( be );

#ifdef LDAP_SLAPI
	if( rc == 0 ) {
		Slapi_PBlock *pb = slapi_pblock_new();

		if ( slapi_int_call_plugins( NULL, SLAPI_PLUGIN_START_FN, pb ) < 0 ) {
			rc = -1;
		}
		slapi_pblock_destroy( pb );
	}
#endif /* LDAP_SLAPI */

	return rc;
}

int slap_shutdown( Backend *be )
{
	int rc;
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;
#endif

	Debug( LDAP_DEBUG_TRACE,
		"%s shutdown: initiated\n",
		slap_name, 0, 0 );

	/* let backends do whatever cleanup they need to do */
	rc = backend_shutdown( be ); 

#ifdef LDAP_SLAPI
	pb = slapi_pblock_new();
	(void) slapi_int_call_plugins( NULL, SLAPI_PLUGIN_CLOSE_FN, pb );
	slapi_pblock_destroy( pb );
#endif /* LDAP_SLAPI */

	return rc;
}

int slap_destroy(void)
{
	int rc;
	int i;

	Debug( LDAP_DEBUG_TRACE,
		"%s destroy: freeing system resources.\n",
		slap_name, 0, 0 );

	if ( SLAPD_GLOBAL(default_referral) ) {
		ber_bvarray_free( SLAPD_GLOBAL(default_referral) );
	}

	rc = backend_destroy();

	slap_sasl_destroy();

	entry_destroy();

	switch ( slapMode & SLAP_MODE ) {
	case SLAP_SERVER_MODE:
	case SLAP_TOOL_MODE:

		ldap_pvt_thread_mutex_destroy( &SLAPD_GLOBAL(counters).sc_sent_mutex );
		ldap_pvt_thread_mutex_destroy( &SLAPD_GLOBAL(counters).sc_ops_mutex );
		ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_bytes );
		ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_pdu );
		ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_entries );
		ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_refs );
		ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_ops_completed );
		ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_ops_initiated );

#ifdef SLAPD_MONITOR
		for ( i = 0; i < SLAP_OP_LAST; i++ ) {
			ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_ops_initiated_[ i ] );
			ldap_pvt_mp_clear( SLAPD_GLOBAL(counters).sc_ops_completed_[ i ] );
		}
#endif /* SLAPD_MONITOR */
		break;

	default:
		Debug( LDAP_DEBUG_ANY,
			"slap_destroy(): undefined mode (%d).\n", slapMode, 0, 0 );

		rc = 1;
		break;

	}

	ldap_pvt_thread_destroy();

	/* should destory the above mutex */
	return rc;
}
