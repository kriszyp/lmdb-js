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
	char		*p;
	Connection *c;
	time_t		currenttime;

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

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	sprintf( buf, "%d", active_threads );
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "threads", vals );

	nconns = 0;
	nwritewaiters = 0;
	nreadwaiters = 0;

#ifdef LDAP_COUNTERS
	/* loop through the connections */
	for ( c = connection_first() ; c != NULL;  c = connection_next(c) ) {
		nconns++;
		if ( c->c_writewaiter ) {
			nwritewaiters++;
		}
		if ( c->c_currentber != NULL ) {
			nreadwaiters++;
		}

		ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#ifndef LDAP_LOCALTIME
		ltm = gmtime( &c->c_starttime );
		strftime( buf2, sizeof(buf2), "%Y%m%d%H%M%SZ", ltm );
#else
		ltm = localtime( &c->.c_starttime );
		strftime( buf2, sizeof(buf2), "%y%m%d%H%M%SZ", ltm );
#endif
		ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

		sprintf( buf, "%d : %s : %d : %d : %s : %s%s%s%s", i,
		    buf2, c[i].c_ops_received, c[i].c_ops_completed,
		    c[i].c_cdn ? c[i].c_cdn : "NULLDN",
		    c[i].c_gettingber ? "r" : "",
		    c[i].c_writewaiter ? "w" : "",
		    c[i].c_ops_executing ? "x" : "",
		    c[i].c_ops_pending ? "p" : ""
		);

		val.bv_val = buf;
		val.bv_len = strlen( buf );
		attr_merge( e, "connection", vals );
	}
	connection_done(c);
#endif

	sprintf( buf, "%d", nconns );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "currentconnections", vals );

	sprintf( buf, "%ld", connections_nextid() );
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

#ifdef LDAP_COUNTERS
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
#endif

	slap_set_time();
	currenttime = slap_get_time();

	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &currenttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "currenttime", vals );

#ifndef LDAP_LOCALTIME
	ltm = gmtime( &starttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &starttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

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
