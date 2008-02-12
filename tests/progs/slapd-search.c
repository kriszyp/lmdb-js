/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
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
 * This work was initially developed by Kurt Spanier for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/param.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <lutil.h>

#define LOOPS	100
#define RETRIES	0

static void
do_search( char *uri, char *host, int port, char *manager, char *passwd,
		char *sbase, char *filter, int maxloop, int maxretries, int delay );

static void
usage( char *name )
{
        fprintf( stderr,
		"usage: %s "
		"-H <uri> | ([-h <host>] -p <port>) "
		"-D <manager> "
		"-w <passwd> "
		"-b <searchbase> "
		"-f <searchfilter> "
		"[-l <loops>] "
		"[-r <maxretries>] "
		"[-t <delay>]\n",
			name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int		i;
	char		*uri = NULL;
	char		*host = "localhost";
	int		port = -1;
	char		*manager = NULL;
	char		*passwd = NULL;
	char		*sbase = NULL;
	char		*filter  = NULL;
	int		loops = LOOPS;
	int		retries = RETRIES;
	int		delay = 0;

	while ( (i = getopt( argc, argv, "b:D:f:H:h:l:p:w:r:t:" )) != EOF ) {
		switch( i ) {
		case 'H':		/* the server uri */
			uri = strdup( optarg );
			break;

		case 'h':		/* the servers host */
			host = strdup( optarg );
			break;

		case 'p':		/* the servers port */
			if ( lutil_atoi( &port, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'D':		/* the servers manager */
			manager = strdup( optarg );
			break;

		case 'w':		/* the server managers password */
			passwd = strdup( optarg );
			break;

		case 'b':		/* file with search base */
			sbase = strdup( optarg );
			break;

		case 'f':		/* the search request */
			filter = strdup( optarg );
			break;

		case 'l':		/* number of loops */
			if ( lutil_atoi( &loops, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'r':		/* number of retries */
			if ( lutil_atoi( &retries, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 't':		/* delay in seconds */
			if ( lutil_atoi( &delay, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		default:
			usage( argv[0] );
			break;
		}
	}

	if (( sbase == NULL ) || ( filter == NULL ) || ( port == -1 && uri == NULL ))
		usage( argv[0] );

	if ( *filter == '\0' ) {

		fprintf( stderr, "%s: invalid EMPTY search filter.\n",
				argv[0] );
		exit( EXIT_FAILURE );

	}

	do_search( uri, host, port, manager, passwd, sbase, filter,
			( 10 * loops ), retries, delay );
	exit( EXIT_SUCCESS );
}


static void
do_search( char *uri, char *host, int port, char *manager, char *passwd,
		char *sbase, char *filter, int maxloop, int maxretries, int delay )
{
	LDAP	*ld = NULL;
	int  	i = 0, do_retry = maxretries;
	char	*attrs[] = { "cn", "sn", NULL };
	pid_t	pid = getpid();
	int     rc = LDAP_SUCCESS;

retry:;
	if ( uri ) {
		ldap_initialize( &ld, uri );
	} else {
		ld = ldap_init( host, port );
	}
	if ( ld == NULL ) {
		perror( "ldap_init" );
		exit( EXIT_FAILURE );
	}

	{
		int version = LDAP_VERSION3;
		(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION,
			&version ); 
	}

	if ( do_retry == maxretries ) {
		fprintf( stderr, "PID=%ld - Search(%d): base=\"%s\", filter=\"%s\".\n",
				(long) pid, maxloop, sbase, filter );
	}

	rc = ldap_bind_s( ld, manager, passwd, LDAP_AUTH_SIMPLE );
	if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		switch ( rc ) {
		case LDAP_BUSY:
		case LDAP_UNAVAILABLE:
			if ( do_retry > 0 ) {
				do_retry--;
				if ( delay != 0 ) {
				    sleep( delay );
				}
				goto retry;
			}
		/* fallthru */
		default:
			break;
		}
		exit( EXIT_FAILURE );
	}

	for ( ; i < maxloop; i++ ) {
		LDAPMessage *res;

		rc = ldap_search_s( ld, sbase, LDAP_SCOPE_SUBTREE,
				filter, attrs, 0, &res );
		if ( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_search" );
			if ( rc == LDAP_BUSY && do_retry > 0 ) {
				do_retry--;
				goto retry;
			}
			if ( rc != LDAP_NO_SUCH_OBJECT ) break;
			continue;

		}

		ldap_msgfree( res );
	}

	fprintf( stderr, " PID=%ld - Search done (%d).\n", (long) pid, rc );

	ldap_unbind( ld );
}
