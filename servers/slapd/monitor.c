/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

/* Revision history
 *
 * 5-Jun-96	jeff.hodges@stanford.edu
 *	Added locking of new_conn_mutex when traversing the c[] array.
 *	Added locking of currenttime_mutex to protect call(s) to localtime().
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldapconfig.h"
#include "slap.h"

#if defined( SLAPD_MONITOR_DN )

void
monitor_info( Connection *conn, Operation *op )
{
	Entry		*e;
	char		buf[BUFSIZ], buf2[22];
	struct berval	val;
	struct berval	*vals[2];
	int		i, nconns, nwritewaiters, nreadwaiters;
	struct tm	*ltm;
	char		*p, *tmpdn;

	vals[0] = &val;
	vals[1] = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );
	/* initialize reader/writer lock */
	e->e_attrs = NULL;
	e->e_dn = ch_strdup( SLAPD_MONITOR_DN );
	e->e_ndn = dn_normalize_case( ch_strdup(SLAPD_MONITOR_DN) );
	e->e_private = NULL;

	val.bv_val = Versionstr;
	if (( p = strchr( Versionstr, '\n' )) == NULL ) {
		val.bv_len = strlen( Versionstr );
	} else {
		val.bv_len = p - Versionstr;
	}
	attr_merge( e, "version", vals );

	sprintf( buf, "%d", active_threads );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "threads", vals );

	nconns = 0;
	nwritewaiters = 0;
	nreadwaiters = 0;

	ldap_pvt_thread_mutex_lock( &new_conn_mutex );
	for ( i = 0; i < dtblsize; i++ ) {
		if ( lber_pvt_sb_in_use(&(c[i].c_sb)) ) {
			nconns++;
			if ( c[i].c_writewaiter ) {
				nwritewaiters++;
			}
			if ( c[i].c_gettingber ) {
				nreadwaiters++;
			}
			ldap_pvt_thread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
			ltm = gmtime( &c[i].c_starttime );
			strftime( buf2, sizeof(buf2), "%Y%m%d%H%M%SZ", ltm );
#else
			ltm = localtime( &c[i].c_starttime );
			strftime( buf2, sizeof(buf2), "%y%m%d%H%M%SZ", ltm );
#endif
			ldap_pvt_thread_mutex_unlock( &currenttime_mutex );

			ldap_pvt_thread_mutex_lock( &c[i].c_dnmutex );
			sprintf( buf, "%d : %s : %d : %d : %s : %s%s", i,
			    buf2, c[i].c_opsinitiated, c[i].c_opscompleted,
			    c[i].c_cdn ? c[i].c_cdn : "NULLDN",
			    c[i].c_gettingber ? "r" : "",
			    c[i].c_writewaiter ? "w" : "" );
			ldap_pvt_thread_mutex_unlock( &c[i].c_dnmutex );
			val.bv_val = buf;
			val.bv_len = strlen( buf );
			attr_merge( e, "connection", vals );
		}
	}
	ldap_pvt_thread_mutex_unlock( &new_conn_mutex );

	sprintf( buf, "%d", nconns );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "currentconnections", vals );

	sprintf( buf, "%d", num_conns );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "totalconnections", vals );

	sprintf( buf, "%d", dtblsize );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "dtablesize", vals );

	sprintf( buf, "%d", nwritewaiters );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "writewaiters", vals );

	sprintf( buf, "%d", nreadwaiters );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "readwaiters", vals );

	sprintf( buf, "%ld", ops_initiated );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "opsinitiated", vals );

	sprintf( buf, "%ld", ops_completed );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "opscompleted", vals );

	sprintf( buf, "%ld", num_entries_sent );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "entriessent", vals );

	sprintf( buf, "%ld", num_bytes_sent );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "bytessent", vals );

	ldap_pvt_thread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &currenttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	ldap_pvt_thread_mutex_unlock( &currenttime_mutex );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "currenttime", vals );

	ldap_pvt_thread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &starttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &starttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	ldap_pvt_thread_mutex_unlock( &currenttime_mutex );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "starttime", vals );

	sprintf( buf, "%d", nbackends );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "nbackends", vals );

#ifdef HAVE_THREAD_CONCURRENCY
	sprintf( buf, "%d", ldap_pvt_thread_get_concurrency() );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "concurrency", vals );
#endif

	send_search_entry( &backends[0], conn, op, e, NULL, 0 );
	send_ldap_search_result( conn, op, LDAP_SUCCESS, NULL, NULL, 1 );

	entry_free( e );
}

#endif /* slapd_monitor_dn */
