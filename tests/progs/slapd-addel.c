/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2018 The OpenLDAP Foundation.
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

#include "ac/stdlib.h"

#include "ac/ctype.h"
#include "ac/param.h"
#include "ac/socket.h"
#include "ac/string.h"
#include "ac/unistd.h"
#include "ac/wait.h"

#include "ldap.h"
#include "lutil.h"

#include "slapd-common.h"

static char *
get_add_entry( char *filename, LDAPMod ***mods );

static void
do_addel( struct tester_conn_args *config,
	char *dn, LDAPMod **attrs, int friendly );

static void
usage( char *name, char opt )
{
	if ( opt ) {
		fprintf( stderr, "%s: unable to handle option \'%c\'\n\n",
			name, opt );
	}

	fprintf( stderr, "usage: %s " TESTER_COMMON_HELP
		"-f <addfile> "
		"[-F]\n",
		name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int		i;
	char		*filename = NULL;
	char		*entry = NULL;
	int		friendly = 0;
	LDAPMod		**attrs = NULL;
	struct tester_conn_args	*config;

	config = tester_init( "slapd-addel", TESTER_ADDEL );

	while ( ( i = getopt( argc, argv, TESTER_COMMON_OPTS "Ff:" ) ) != EOF )
	{
		switch ( i ) {
		case 'F':
			friendly++;
			break;
			
		case 'i':
			/* ignored (!) by now */
			break;

		case 'f':		/* file with entry search request */
			filename = strdup( optarg );
			break;

		default:
			if ( tester_config_opt( config, i, optarg ) == LDAP_SUCCESS ) {
				break;
			}
			usage( argv[0], i );
			break;
		}
	}

	if ( filename == NULL )
		usage( argv[0], 0 );

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

	tester_config_finish( config );

	for ( i = 0; i < config->outerloops; i++ ) {
		do_addel( config, entry, attrs, friendly );
	}

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
	    		tester_perror( "realloc", NULL );
	    		exit( EXIT_FAILURE );
		}
		*pmodsp = pmods;
		pmods[ i + 1 ] = NULL;
		if (( pmods[ i ] = (LDAPMod *)calloc( 1, sizeof( LDAPMod )))
			== NULL ) {
	    		tester_perror( "calloc", NULL );
	    		exit( EXIT_FAILURE );
		}
		pmods[ i ]->mod_op = modop;
		if (( pmods[ i ]->mod_type = strdup( attr )) == NULL ) {
	    	tester_perror( "strdup", NULL );
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
	    		tester_perror( "ber_memrealloc", NULL );
	    		exit( EXIT_FAILURE );
		}
		pmods[ i ]->mod_bvalues[ j + 1 ] = NULL;
		if (( bvp = (struct berval *)ber_memalloc( sizeof( struct berval )))
			== NULL ) {
	    		tester_perror( "ber_memalloc", NULL );
	    		exit( EXIT_FAILURE );
		}
		pmods[ i ]->mod_bvalues[ j ] = bvp;

	    bvp->bv_len = vlen;
	    if (( bvp->bv_val = (char *)malloc( vlen + 1 )) == NULL ) {
			tester_perror( "malloc", NULL );
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
			nl = line;
			if ( !strncasecmp( nl, "dn: ", 4 ))
				nl += 4;
			entry = strdup( nl );

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
	struct tester_conn_args *config,
	char *entry,
	LDAPMod **attrs,
	int friendly )
{
	LDAP	*ld = NULL;
	int  	i = 0, do_retry = config->retries;
	int	rc = LDAP_SUCCESS;

retry:;
	if ( ld == NULL ) {
		tester_init_ld( &ld, config, 0 );
	}

	if ( do_retry == config->retries ) {
		fprintf( stderr, "PID=%ld - Add/Delete(%d): entry=\"%s\".\n",
			(long) pid, config->loops, entry );
	}

	for ( ; i < config->loops; i++ ) {

		/* add the entry */
		rc = ldap_add_ext_s( ld, entry, attrs, NULL, NULL );
		if ( rc != LDAP_SUCCESS ) {
			tester_ldap_error( ld, "ldap_add_ext_s", NULL );
			switch ( rc ) {
			case LDAP_ALREADY_EXISTS:
				/* NOTE: this likely means
				 * the delete failed
				 * during the previous round... */
				if ( !friendly ) {
					goto done;
				}
				break;

			case LDAP_BUSY:
			case LDAP_UNAVAILABLE:
				if ( do_retry > 0 ) {
					do_retry--;
					goto retry;
				}
				/* fall thru */

			default:
				goto done;
			}
		}

#if 0
		/* wait a second for the add to really complete */
		/* This masks some race conditions though. */
		sleep( 1 );
#endif

		/* now delete the entry again */
		rc = ldap_delete_ext_s( ld, entry, NULL, NULL );
		if ( rc != LDAP_SUCCESS ) {
			tester_ldap_error( ld, "ldap_delete_ext_s", NULL );
			switch ( rc ) {
			case LDAP_NO_SUCH_OBJECT:
				/* NOTE: this likely means
				 * the add failed
				 * during the previous round... */
				if ( !friendly ) {
					goto done;
				}
				break;

			case LDAP_BUSY:
			case LDAP_UNAVAILABLE:
				if ( do_retry > 0 ) {
					do_retry--;
					goto retry;
				}
				/* fall thru */

			default:
				goto done;
			}
		}
	}

done:;
	fprintf( stderr, "  PID=%ld - Add/Delete done (%d).\n", (long) pid, rc );

	ldap_unbind_ext( ld, NULL, NULL );
}


