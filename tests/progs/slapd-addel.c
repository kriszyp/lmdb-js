/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
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

static char *
get_add_entry( char *filename, LDAPMod ***mods );

static void
do_addel( char *uri, char *host, int port, char *manager, char *passwd,
	char *dn, LDAPMod **attrs, int maxloop );

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-h <host>] -p port -D <managerDN> -w <passwd> -f <addfile> [-l <loops>]\n",
			name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int		i;
	char        *host = "localhost";
	char		*uri = NULL;
	int			port = -1;
	char		*manager = NULL;
	char		*passwd = NULL;
	char		*filename = NULL;
	char		*entry = NULL;
	int			loops = LOOPS;
	LDAPMod     **attrs = NULL;

	while ( (i = getopt( argc, argv, "H:h:p:D:w:f:l:" )) != EOF ) {
		switch( i ) {
			case 'H':		/* the server's URI */
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

			case 'f':		/* file with entry search request */
				filename = strdup( optarg );
				break;

			case 'l':		/* the number of loops */
				loops = atoi( optarg );
				break;

			default:
				usage( argv[0] );
				break;
		}
	}

	if (( filename == NULL ) || ( port == -1 && uri == NULL ) ||
				( manager == NULL ) || ( passwd == NULL ))
		usage( argv[0] );

	entry = get_add_entry( filename, &attrs );
	if (( entry == NULL ) || ( *entry == '\0' )) {

		fprintf( stderr, "%s: invalid entry DN in file \"%s\".\n",
				argv[0], filename );
		exit( EXIT_FAILURE );

	}

	if (( attrs == NULL ) || ( *attrs == '\0' )) {

		fprintf( stderr, "%s: invalid attrs in file \"%s\".\n",
				argv[0], filename );
		exit( EXIT_FAILURE );

	}

	do_addel( uri, host, port, manager, passwd, entry, attrs, loops );

	exit( EXIT_SUCCESS );
}


static void
addmodifyop( LDAPMod ***pmodsp, int modop, char *attr, char *value, int vlen )
{
    LDAPMod		**pmods;
    int			i, j;
    struct berval	*bvp;

    pmods = *pmodsp;
    modop |= LDAP_MOD_BVALUES;

    i = 0;
    if ( pmods != NULL ) {
		for ( ; pmods[ i ] != NULL; ++i ) {
	    	if ( strcasecmp( pmods[ i ]->mod_type, attr ) == 0 &&
		    	pmods[ i ]->mod_op == modop ) {
				break;
	    	}
		}
    }

    if ( pmods == NULL || pmods[ i ] == NULL ) {
		if (( pmods = (LDAPMod **)realloc( pmods, (i + 2) *
			sizeof( LDAPMod * ))) == NULL ) {
	    		perror( "realloc" );
	    		exit( EXIT_FAILURE );
		}
		*pmodsp = pmods;
		pmods[ i + 1 ] = NULL;
		if (( pmods[ i ] = (LDAPMod *)calloc( 1, sizeof( LDAPMod )))
			== NULL ) {
	    		perror( "calloc" );
	    		exit( EXIT_FAILURE );
		}
		pmods[ i ]->mod_op = modop;
		if (( pmods[ i ]->mod_type = strdup( attr )) == NULL ) {
	    	perror( "strdup" );
	    	exit( EXIT_FAILURE );
		}
    }

    if ( value != NULL ) {
		j = 0;
		if ( pmods[ i ]->mod_bvalues != NULL ) {
	    	for ( ; pmods[ i ]->mod_bvalues[ j ] != NULL; ++j ) {
				;
	    	}
		}
		if (( pmods[ i ]->mod_bvalues =
			(struct berval **)ber_memrealloc( pmods[ i ]->mod_bvalues,
			(j + 2) * sizeof( struct berval * ))) == NULL ) {
	    		perror( "ber_realloc" );
	    		exit( EXIT_FAILURE );
		}
		pmods[ i ]->mod_bvalues[ j + 1 ] = NULL;
		if (( bvp = (struct berval *)ber_memalloc( sizeof( struct berval )))
			== NULL ) {
	    		perror( "malloc" );
	    		exit( EXIT_FAILURE );
		}
		pmods[ i ]->mod_bvalues[ j ] = bvp;

	    bvp->bv_len = vlen;
	    if (( bvp->bv_val = (char *)malloc( vlen + 1 )) == NULL ) {
			perror( "malloc" );
			exit( EXIT_FAILURE );
	    }
	    AC_MEMCPY( bvp->bv_val, value, vlen );
	    bvp->bv_val[ vlen ] = '\0';
    }
}


static char *
get_add_entry( char *filename, LDAPMod ***mods )
{
	FILE    *fp;
	char    *entry = NULL;

	if ( (fp = fopen( filename, "r" )) != NULL ) {
		char  line[BUFSIZ];

		if ( fgets( line, BUFSIZ, fp )) {
			char *nl;

			if (( nl = strchr( line, '\r' )) || ( nl = strchr( line, '\n' )))
				*nl = '\0';
			entry = strdup( line );

		}

		while ( fgets( line, BUFSIZ, fp )) {
			char	*nl;
			char	*value;

			if (( nl = strchr( line, '\r' )) || ( nl = strchr( line, '\n' )))
				*nl = '\0';

			if ( *line == '\0' ) break;
			if ( !( value = strchr( line, ':' ))) break;

			*value++ = '\0'; 
			while ( *value && isspace( (unsigned char) *value ))
				value++;

			addmodifyop( mods, LDAP_MOD_ADD, line, value, strlen( value ));

		}
		fclose( fp );
	}

	return( entry );
}


static void
do_addel(
	char *uri,
	char *host,
	int port,
	char *manager,
	char *passwd,
	char *entry,
	LDAPMod **attrs,
	int maxloop
)
{
	LDAP	*ld = NULL;
	int  	i;
	pid_t	pid = getpid();

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

	if ( ldap_bind_s( ld, manager, passwd, LDAP_AUTH_SIMPLE )
				!= LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		 exit( EXIT_FAILURE );
	}


	fprintf( stderr, "PID=%ld - Add/Delete(%d): entry=\"%s\".\n",
					(long) pid, maxloop, entry );

	for ( i = 0; i < maxloop; i++ ) {

		/* add the entry */
		if ( ldap_add_s( ld, entry, attrs ) != LDAP_SUCCESS ) {

			ldap_perror( ld, "ldap_add" );
			break;

		}

#if 0
		/* wait a second for the add to really complete */
		/* This masks some race conditions though. */
		sleep( 1 );
#endif

		/* now delete the entry again */
		if ( ldap_delete_s( ld, entry ) != LDAP_SUCCESS ) {

			ldap_perror( ld, "ldap_delete" );
			break;

		}

	}

	fprintf( stderr, " PID=%ld - Add/Delete done.\n", (long) pid );

	ldap_unbind( ld );
}


