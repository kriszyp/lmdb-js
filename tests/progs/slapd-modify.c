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
do_modify( char *uri, char *host, int port, char *manager, char *passwd, char *entry, 
		char *attr, char *value, int maxloop );


static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-h <host>] -p port -D <managerDN> -w <passwd> -e <entry> [-l <loops>]\n",
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
	char		*manager = NULL;
	char		*passwd = NULL;
	char		*entry = NULL;
	char		*ava = NULL;
	char		*value = NULL;
	int			loops = LOOPS;

	while ( (i = getopt( argc, argv, "H:h:p:D:w:e:a:l:" )) != EOF ) {
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
			case 'D':		/* the servers manager */
				manager = strdup( optarg );
			break;

			case 'w':		/* the server managers password */
				passwd = strdup( optarg );
			break;
			case 'e':		/* entry to modify */
				entry = strdup( optarg );
			break;
			case 'a':
				ava = strdup( optarg );
			break;
			case 'l':		/* the number of loops */
				loops = atoi( optarg );
			break;

			default:
				usage( argv[0] );
			break;
		}
	}

	if (( entry == NULL ) || ( ava == NULL ) || ( port == -1 && uri == NULL ))
		usage( argv[0] );

	if ( *entry == '\0' ) {

		fprintf( stderr, "%s: invalid EMPTY entry DN.\n",
				argv[0] );
		exit( EXIT_FAILURE );

	}
	if ( *ava  == '\0' ) {
		fprintf( stderr, "%s: invalid EMPTY AVA.\n",
				argv[0] );
		exit( EXIT_FAILURE );
	}
	
	if ( !( value = strchr( ava, ':' ))) {
		fprintf( stderr, "%s: invalid AVA.\n",
				argv[0] );
		exit( EXIT_FAILURE );
	}
	*value++ = '\0'; 
	while ( *value && isspace( (unsigned char) *value ))
		value++;

	do_modify( uri, host, port, manager, passwd, entry, ava, value, loops );
	exit( EXIT_SUCCESS );
}


static void
do_modify( char *uri, char *host, int port, char *manager,
	char *passwd, char *entry, char* attr, char* value, int maxloop )
{
	LDAP	*ld = NULL;
	int  	i;
	pid_t	pid;

	struct ldapmod mod;
	struct ldapmod *mods[2];
	char *values[2] = { value, NULL };

	pid = getpid();
	
	mod.mod_op = LDAP_MOD_ADD;
	mod.mod_type = attr;
	mod.mod_values = values;
	mods[0] = &mod;
	mods[1] = NULL;

	
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

	if ( ldap_bind_s( ld, manager, passwd, LDAP_AUTH_SIMPLE ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		 exit( EXIT_FAILURE );
	}


	fprintf( stderr, "PID=%ld - Modify(%d): entry=\"%s\".\n",
		 (long) pid, maxloop, entry );

	for ( i = 0; i < maxloop; i++ ) {
		int         rc;

		mod.mod_op = LDAP_MOD_ADD;
		if (( rc = ldap_modify_s( ld, entry, mods )) != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_modify" );
			if ( rc != LDAP_NO_SUCH_OBJECT ) break;
			continue;
		}
		
		mod.mod_op = LDAP_MOD_DELETE;
		if (( rc = ldap_modify_s( ld, entry, mods )) != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_modify" );
			if ( rc != LDAP_NO_SUCH_OBJECT ) break;
			continue;
		}

	}

	fprintf( stderr, " PID=%ld - Modify done.\n", (long) pid );

	ldap_unbind( ld );
}


