/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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

#define LOOPS	100

static void
do_read( char *uri, char *host, int port, char *entry, int maxloop );

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-h <host>] -p port -e <entry> [-l <loops>]\n",
			name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int		i;
	char		*uri = NULL;
	char        *host = "localhost";
	int			port = -1;
	char		*entry = NULL;
	int			loops = LOOPS;

	while ( (i = getopt( argc, argv, "H:h:p:e:l:" )) != EOF ) {
		switch( i ) {
			case 'H':		/* the server uri */
				uri = strdup( optarg );
			break;
			case 'h':		/* the servers host */
				host = strdup( optarg );
			break;

			case 'p':		/* the servers port */
				port = atoi( optarg );
				break;

			case 'e':		/* file with entry search request */
				entry = strdup( optarg );
				break;

			case 'l':		/* the number of loops */
				loops = atoi( optarg );
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

	do_read( uri, host, port, entry, ( 20 * loops ));
	exit( EXIT_SUCCESS );
}


static void
do_read( char *uri, char *host, int port, char *entry, int maxloop )
{
	LDAP	*ld = NULL;
	int  	i;
	char	*attrs[] = { "1.1", NULL };
	pid_t	pid = getpid();
	int     rc = LDAP_SUCCESS;

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

	if ( ldap_bind_s( ld, NULL, NULL, LDAP_AUTH_SIMPLE ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		 exit( EXIT_FAILURE );
	}


	fprintf( stderr, "PID=%ld - Read(%d): entry=\"%s\".\n",
		 (long) pid, maxloop, entry );

	for ( i = 0; i < maxloop; i++ ) {
		LDAPMessage *res;

		rc = ldap_search_s( ld, entry, LDAP_SCOPE_BASE,
				NULL, attrs, 1, &res );
		if ( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_read" );
			if ( rc != LDAP_NO_SUCH_OBJECT ) break;
			continue;

		}

		ldap_msgfree( res );
	}

	fprintf( stderr, " PID=%ld - Read done (%d).\n", (long) pid, rc );

	ldap_unbind( ld );
}


