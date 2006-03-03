/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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

#include <ldap.h>
#include <lutil.h>

#include "slapd-common.h"

#define LOOPS	100
#define RETRIES	0

static void
do_read( char *uri, char *entry, int maxloop,
		int maxretries, int delay );

static void
usage( char *name )
{
        fprintf( stderr,
		"usage: %s "
		"-H <uri> | ([-h <host>] -p <port>) "
		"-e <entry> "
		"[-l <loops>] "
		"[-L <outerloops>] "
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
	char		*entry = NULL;
	int		loops = LOOPS;
	int		outerloops = 1;
	int		retries = RETRIES;
	int		delay = 0;

	tester_init( "slapd-read" );

	while ( (i = getopt( argc, argv, "H:h:p:e:l:L:r:t:" )) != EOF ) {
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

		case 'e':		/* DN to search for */
			entry = strdup( optarg );
			break;

		case 'l':		/* the number of loops */
			if ( lutil_atoi( &loops, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'L':		/* the number of outerloops */
			if ( lutil_atoi( &outerloops, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'r':		/* the number of retries */
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

	if (( entry == NULL ) || ( port == -1 && uri == NULL ))
		usage( argv[0] );

	if ( *entry == '\0' ) {
		fprintf( stderr, "%s: invalid EMPTY entry DN.\n",
				argv[0] );
		exit( EXIT_FAILURE );
	}

	uri = tester_uri( uri, host, port );

	for ( i = 0; i < outerloops; i++ ) {
		do_read( uri, entry, loops, retries, delay );
	}

	exit( EXIT_SUCCESS );
}


static void
do_read( char *uri, char *entry, int maxloop,
		int maxretries, int delay )
{
	LDAP	*ld = NULL;
	int  	i = 0, do_retry = maxretries;
	char	*attrs[] = { "1.1", NULL };
	pid_t	pid = getpid();
	int     rc = LDAP_SUCCESS;
	int	version = LDAP_VERSION3;
	struct berval	passwd = { 0, "" };
	
retry:;
	ldap_initialize( &ld, uri );
	if ( ld == NULL ) {
		tester_perror( "ldap_initialize" );
		exit( EXIT_FAILURE );
	}

	(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ); 

	if ( do_retry == maxretries ) {
		fprintf( stderr, "PID=%ld - Read(%d): entry=\"%s\".\n",
			(long) pid, maxloop, entry );
	}

	rc = ldap_sasl_bind_s( ld, NULL, LDAP_SASL_SIMPLE, &passwd, NULL, NULL, NULL );
	if ( rc != LDAP_SUCCESS ) {
		tester_ldap_error( ld, "ldap_sasl_bind_s" );
		switch ( rc ) {
		case LDAP_BUSY:
		case LDAP_UNAVAILABLE:
			if ( do_retry > 0 ) {
				do_retry--;
				if ( delay > 0 ) {
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

		rc = ldap_search_ext_s( ld, entry, LDAP_SCOPE_BASE,
				NULL, attrs, 1, NULL, NULL, NULL, LDAP_NO_LIMIT, &res );
		if ( rc != LDAP_SUCCESS ) {
			tester_ldap_error( ld, "ldap_search_ext_s" );
			if ( rc == LDAP_BUSY && do_retry > 0 ) {
				do_retry--;
				goto retry;
			}
			if ( rc != LDAP_NO_SUCH_OBJECT ) break;
			continue;

		}

		ldap_msgfree( res );
	}

	fprintf( stderr, " PID=%ld - Read done (%d).\n", (long) pid, rc );

	ldap_unbind_ext( ld, NULL, NULL );
}

