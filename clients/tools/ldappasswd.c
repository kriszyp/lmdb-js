/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <ldap.h>

#include "ldap_defaults.h"

static int	verbose = 0;

static void
usage(const char *s)
{
	fprintf(stderr,
		"Usage: %s [options] dn\n"
		"  -A\t\tprompt for old password\n"
		"  -a secret\told password\n"
		"  -D binddn\tbind dn\n"
		"  -d level\tdebugging level\n"
		"  -h host\tldap server (default: localhost)\n"
		"  -n\t\tmake no modifications\n"
		"  -p port\tldap port\n"
		"  -S\t\tprompt for new password\n"
		"  -s secret\tnew password\n"
		"  -v\t\tincrease verbosity\n"
		"  -W\t\tprompt for bind password\n"
		"  -w passwd\tbind password (for simple authentication)\n"
		, s );

	exit( EXIT_FAILURE );
}

int
main( int argc, char *argv[] )
{
	int rc;
	char	*ldaphost = NULL;

	char	*dn = NULL;
	char	*binddn = NULL;

	char	*bindpw = NULL;
	char	*newpw = NULL;
	char	*oldpw = NULL;

	int		want_bindpw = 0;
	int		want_newpw = 0;
	int		want_oldpw = 0;

	int		noupdates = 0;
	int		i;
	int		ldapport = 0;
	int		debug = 0;
	int		version = -1;
	LDAP	       *ld;
	struct berval *bv = NULL;

	char	*retoid;
	struct berval *retdata;

	if (argc == 1)
		usage (argv[0]);

	while( (i = getopt( argc, argv,
		"Aa:D:d:h:np:Ss:vWw:" )) != EOF )
	{
		switch (i) {
		case 'A':	/* prompt for oldr password */
			want_oldpw++;
			break;
		case 'a':	/* old password (secret) */
			oldpw = strdup (optarg);

			{
				char* p;

				for( p = optarg; *p == '\0'; p++ ) {
					*p = '*';
				}
			}
			break;
		case 'D':	/* bind distinguished name */
			binddn = strdup (optarg);
			break;

		case 'd':	/* debugging option */
			debug |= atoi (optarg);
			break;

		case 'h':	/* ldap host */
			ldaphost = strdup (optarg);
			break;

		case 'n':	/* don't update entry(s) */
			noupdates++;
			break;

		case 'p':	/* ldap port */
			ldapport = strtol( optarg, NULL, 10 );
			break;

		case 'S':	/* prompt for user password */
			want_newpw++;
			break;

		case 's':	/* new password (secret) */
			newpw = strdup (optarg);

			{
				char* p;

				for( p = optarg; *p == '\0'; p++ ) {
					*p = '*';
				}
			}
			break;

		case 'v':	/* verbose */
			verbose++;
			break;

		case 'W':	/* prompt for bind password */
			want_bindpw++;
			break;

		case 'w':	/* bind password */
			bindpw = strdup (optarg);

			{
				char* p;

				for( p = optarg; *p == '\0'; p++ ) {
					*p = '*';
				}
			}
			break;


		default:
			usage (argv[0]);
		}
	}

	if( argc - optind != 1 ) {
		usage( argv[0] );
	} 

	dn = strdup( argv[optind] );

	if( want_oldpw && oldpw == NULL ) {
		/* prompt for old password */
		char *ckoldpw;
		newpw = strdup(getpass("Old password: "));
		ckoldpw = getpass("Re-enter old password: ");

		if( strncmp( oldpw, ckoldpw, strlen(oldpw) )) {
			fprintf( stderr, "passwords do not match\n" );
			return EXIT_FAILURE;
		}
	}

	if( want_newpw && newpw == NULL ) {
		/* prompt for new password */
		char *cknewpw;
		newpw = strdup(getpass("New password: "));
		cknewpw = getpass("Re-enter new password: ");

		if( strncmp( newpw, cknewpw, strlen(newpw) )) {
			fprintf( stderr, "passwords do not match\n" );
			return EXIT_FAILURE;
		}
	}

	if( binddn == NULL && dn != NULL ) {
		binddn = dn;
		dn = NULL;

		if( bindpw == NULL ) bindpw = oldpw;
	}

	if (want_bindpw && bindpw == NULL ) {
		/* handle bind password */
		fprintf( stderr, "Bind DN: %s\n", binddn );
		bindpw = strdup( getpass("Enter bind password: "));
	}

	if ( debug ) {
		if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug ) != LBER_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
		}
		if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
		}
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

	/* connect to server */
	if ((ld = ldap_init( ldaphost, ldapport )) == NULL) {
		perror("ldap_init");
		return EXIT_FAILURE;
	}

	/* don't chase referrals */
	ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF );

	version = 3;
	rc = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

	if(rc != LDAP_OPT_SUCCESS ) {
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
	}

	rc = ldap_bind_s( ld, binddn, bindpw, LDAP_AUTH_SIMPLE );

	if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		ldap_unbind( ld );
		return EXIT_FAILURE;
	}

	if( dn != NULL || oldpw != NULL || newpw != NULL ) {
		/* build change password control */
		BerElement *ber = ber_alloc_t( LBER_USE_DER );

		if( ber == NULL ) {
			perror( "ber_alloc_t" );
			ldap_unbind( ld );
			return EXIT_FAILURE;
		}

		ber_printf( ber, "{" /*}*/ );

		if( dn != NULL ) {
			ber_printf( ber, "ts",
				LDAP_TAG_EXOP_X_MODIFY_PASSWD_ID, dn );
			free(dn);
		}

		if( oldpw != NULL ) {
			ber_printf( ber, "ts",
				LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW, oldpw );
			free(oldpw);
		}

		if( newpw != NULL ) {
			ber_printf( ber, "ts",
				LDAP_TAG_EXOP_X_MODIFY_PASSWD_NEW, newpw );
			free(newpw);
		}

		ber_printf( ber, /*{*/ "}" );

		rc = ber_flatten( ber, &bv );

		if( rc < 0 ) {
			perror( "ber_flatten" );
			ldap_unbind( ld );
			return EXIT_FAILURE;
		}

		ber_free( ber, 1 );
	}

	rc = ldap_extended_operation_s( ld,
		LDAP_EXOP_X_MODIFY_PASSWD, bv, 
		NULL, NULL,
		&retoid, &retdata );

	ber_bvfree( bv );

	if( retdata != NULL ) {
		ber_tag_t tag;
		char *s;
		BerElement *ber = ber_init( retdata );

		if( ber == NULL ) {
			perror( "ber_init" );
			ldap_unbind( ld );
			return EXIT_FAILURE;
		}

		/* we should check the tag */
		tag = ber_scanf( ber, "{a}", &s);

		if( tag == LBER_ERROR ) {
			perror( "ber_scanf" );
		} else {
			printf("New password: %s\n", s);
			free( s );
		}

		ber_free( ber, 1 );
	}

	if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_extended_operation" );
		ldap_unbind( ld );
		return EXIT_FAILURE;
	}

	ldap_memfree( retoid );
	ber_bvfree( retdata );

	/* disconnect from server */
	ldap_unbind (ld);

	return ( EXIT_SUCCESS );
}
