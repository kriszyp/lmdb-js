/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
"Change the password of an LDAP entry\n\n"
"usage: %s [options] dn\n"
"	dn: the DN of the entry whose password must be changed\n"
"options:\n"
"	-a secret\told password\n"
"	-A\t\tprompt for old password\n"
"	-d level\tdebugging level\n"
"	-D binddn\tbind DN\n"
"	-E\t\trequest SASL privacy (-EE to make it critical)\n"
"	-h host\t\tLDAP server (default: localhost)\n"
"	-I\t\trequest SASL integrity checking (-II to make it\n"
"		\tcritical)\n"
"	-n\t\tmake no modifications\n"
"	-p port\t\tport on LDAP server\n"
"	-S\t\tprompt for new password\n"
"	-s secret\tnew password\n"
"	-U user\t\tSASL authentication identity (username)\n"
"	-v\t\tverbose mode\n"
"	-w passwd\tbind password (for simple authentication)\n"
"	-W\t\tprompt for bind password\n"
"	-X id\t\tSASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"	-Y mech\t\tSASL mechanism\n"
"	-Z\t\trequest the use of TLS (-ZZ to make it critical)\n"
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

	struct berval passwd = { 0, NULL};
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
	int		authmethod = LDAP_AUTH_SIMPLE;
#ifdef HAVE_CYRUS_SASL
	char		*sasl_authc_id = NULL;
	char		*sasl_authz_id = NULL;
	char		*sasl_mech = NULL;
	int		sasl_integrity = 0;
	int		sasl_privacy = 0;
#endif
	int		use_tls = 0;
	LDAP	       *ld;
	struct berval *bv = NULL;

	char	*retoid;
	struct berval *retdata;

	if (argc == 1)
		usage (argv[0]);

	while( (i = getopt( argc, argv,
		"Aa:D:d:EIh:np:Ss:U:vWw:X:Y:Z" )) != EOF )
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
			passwd.bv_val = strdup (optarg);
			{
				char* p;

				for( p = optarg; *p == '\0'; p++ ) {
					*p = '*';
				}
			}
			passwd.bv_len = strlen( passwd.bv_val );
			break;

		case 'I':
#ifdef HAVE_CYRUS_SASL
			sasl_integrity++;
			authmethod = LDAP_AUTH_SASL;
#else
			fprintf( stderr, "%s was not compiled with SASL "
				"support\n", argv[0] );
			return( EXIT_FAILURE );
#endif
			break;
		case 'E':
#ifdef HAVE_CYRUS_SASL
			sasl_privacy++;
			authmethod = LDAP_AUTH_SASL;
#else
			fprintf( stderr, "%s was not compiled with SASL "
				"support\n", argv[0] );
			return( EXIT_FAILURE );
#endif
			break;
		case 'Y':
#ifdef HAVE_CYRUS_SASL
			if ( strcasecmp( optarg, "any" ) &&
					strcmp( optarg, "*" ) ) {
				sasl_mech = strdup( optarg );
			}
			authmethod = LDAP_AUTH_SASL;
#else
			fprintf( stderr, "%s was not compiled with SASL "
				"support\n", argv[0] );
			return( EXIT_FAILURE );
#endif
			break;
		case 'U':
#ifdef HAVE_CYRUS_SASL
			sasl_authc_id = strdup( optarg );
			authmethod = LDAP_AUTH_SASL;
#else
			fprintf( stderr, "%s was not compiled with SASL "
				"support\n", argv[0] );
			return( EXIT_FAILURE );
#endif
			break;
		case 'X':
#ifdef HAVE_CYRUS_SASL
			sasl_authz_id = strdup( optarg );
			authmethod = LDAP_AUTH_SASL;
#else
			fprintf( stderr, "%s was not compiled with SASL "
				"support\n", argv[0] );
			return( EXIT_FAILURE );
#endif
			break;
		case 'Z':
#ifdef HAVE_TLS
			use_tls++;
#else
			fprintf( stderr, "%s was not compiled with TLS "
				"support\n", argv[0] );
			return( EXIT_FAILURE );
#endif
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
		newpw = strdup(getpassphrase("Old password: "));
		ckoldpw = getpassphrase("Re-enter old password: ");

		if( strncmp( oldpw, ckoldpw, strlen(oldpw) )) {
			fprintf( stderr, "passwords do not match\n" );
			return EXIT_FAILURE;
		}
	}

	if( want_newpw && newpw == NULL ) {
		/* prompt for new password */
		char *cknewpw;
		newpw = strdup(getpassphrase("New password: "));
		cknewpw = getpassphrase("Re-enter new password: ");

		if( strncmp( newpw, cknewpw, strlen(newpw) )) {
			fprintf( stderr, "passwords do not match\n" );
			return EXIT_FAILURE;
		}
	}

	if( binddn == NULL && dn != NULL ) {
		binddn = dn;
		dn = NULL;

		if( passwd.bv_val == NULL ) {
			passwd.bv_val = oldpw;
			passwd.bv_len = oldpw == NULL ? 0 : strlen( oldpw );
		}
	}

	if (want_bindpw && passwd.bv_val == NULL ) {
		/* handle bind password */
		fprintf( stderr, "Bind DN: %s\n", binddn );
		passwd.bv_val = strdup( getpassphrase("Enter bind password: "));
		passwd.bv_len = strlen( passwd.bv_val );
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

	/* LDAPv3 only */
	version = 3;
	rc = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

	if(rc != LDAP_OPT_SUCCESS ) {
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
	}

	if ( use_tls && ldap_start_tls( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		if ( use_tls > 1 ) {
			ldap_perror( ld, "ldap_start_tls" );
			return( EXIT_FAILURE );
		}
	}

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		int	minssf = 0, maxssf = 0;

		if ( sasl_integrity > 0 )
			maxssf = 1;
		if ( sasl_integrity > 1 )
			minssf = 1;
		if ( sasl_privacy > 0 )
			maxssf = 100000; /* Something big value */
		if ( sasl_privacy > 1 )
			minssf = 56;
		
		if ( ldap_set_option( ld, LDAP_OPT_X_SASL_MINSSF,
				(void *)&minssf ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_X_SASL_MINSSF"
				"%d\n", minssf);
			return( EXIT_FAILURE );
		}
		if ( ldap_set_option( ld, LDAP_OPT_X_SASL_MAXSSF,
				(void *)&maxssf ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_X_SASL_MAXSSF"
				"%d\n", maxssf);
			return( EXIT_FAILURE );
		}
		
		rc = ldap_negotiated_sasl_bind_s( ld, binddn, sasl_authc_id,
				sasl_authz_id, sasl_mech,
				passwd.bv_len ? &passwd : NULL,
				NULL, NULL );

		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_negotiated_sasl_bind_s" );
			return( EXIT_FAILURE );
		}
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
	}
	else {
		if ( ldap_bind_s( ld, binddn, passwd.bv_val, authmethod )
				!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_bind" );
			return( EXIT_FAILURE );
		}
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

	return EXIT_SUCCESS;
}
