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

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "ldapconfig.h"

#if defined( SLAPD_MONITOR_DN )

extern int		nbackends;
extern Backend		*backends;
extern int		active_threads;
extern int		dtblsize;
extern Connection	*c;
extern long		ops_initiated;
extern long		ops_completed;
extern long		num_entries_sent;
extern long		num_bytes_sent;
extern time_t		currenttime;
extern time_t		starttime;
extern int		num_conns;

extern pthread_mutex_t	new_conn_mutex;
extern pthread_mutex_t	currenttime_mutex;

extern char Versionstr[];

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
	entry_rdwr_init(e);
	e->e_attrs = NULL;
	e->e_dn = strdup( SLAPD_MONITOR_DN );

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

	pthread_mutex_lock( &new_conn_mutex );
	for ( i = 0; i < dtblsize; i++ ) {
		if ( c[i].c_sb.sb_sd != -1 ) {
			nconns++;
			if ( c[i].c_writewaiter ) {
				nwritewaiters++;
			}
			if ( c[i].c_gettingber ) {
				nreadwaiters++;
			}
			pthread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
			ltm = gmtime( &c[i].c_starttime );
			strftime( buf2, sizeof(buf2), "%Y%m%d%H%M%SZ", ltm );
#else
			ltm = localtime( &c[i].c_starttime );
			strftime( buf2, sizeof(buf2), "%y%m%d%H%M%SZ", ltm );
#endif
			pthread_mutex_unlock( &currenttime_mutex );

			pthread_mutex_lock( &c[i].c_dnmutex );
			sprintf( buf, "%d : %s : %ld : %ld : %s : %s%s", i,
			    buf2, c[i].c_opsinitiated, c[i].c_opscompleted,
			    c[i].c_dn ? c[i].c_dn : "NULLDN",
			    c[i].c_gettingber ? "r" : "",
			    c[i].c_writewaiter ? "w" : "" );
			pthread_mutex_unlock( &c[i].c_dnmutex );
			val.bv_val = buf;
			val.bv_len = strlen( buf );
			attr_merge( e, "connection", vals );
		}
	}
	pthread_mutex_unlock( &new_conn_mutex );

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

	pthread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &currenttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	pthread_mutex_unlock( &currenttime_mutex );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "currenttime", vals );

	pthread_mutex_lock( &currenttime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &starttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &starttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	pthread_mutex_unlock( &currenttime_mutex );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "starttime", vals );

	sprintf( buf, "%d", nbackends );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "nbackends", vals );

#ifdef THREAD_SUNOS5_LWP
	sprintf( buf, "%d", thr_getconcurrency() );
	val.bv_val = buf;
	val.bv_len = strlen( buf );
	attr_merge( e, "concurrency", vals );
#endif

	send_search_entry( &backends[0], conn, op, e, NULL, 0 );
	send_ldap_search_result( conn, op, LDAP_SUCCESS, NULL, NULL, 1 );

	entry_free( e );
}

#endif /* slapd_monitor_dn */
