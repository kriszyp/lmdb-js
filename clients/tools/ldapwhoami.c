/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"

static int	verbose = 0;

static void
usage(const char *s)
{
	fprintf(stderr,
"Issue LDAP Who am I? operation to request user's authzid\n\n"
"usage: %s [options]\n"

"Common options:\n"
"  -d level   set LDAP debugging level to `level'\n"
"  -D binddn  bind DN\n"
"  -e [!]<ctrl>[=<ctrlparam>] general controls (! indicates criticality)\n"
"             [!]manageDSAit   (alternate form, see -M)\n"
"             [!]noop\n"
"  -f file    read operations from `file'\n"
"  -h host    LDAP server(s)\n"
"  -H URI     LDAP Uniform Resource Indentifier(s)\n"
"  -I         use SASL Interactive mode\n"
"  -n         show what would be done but don't actually do it\n"
"  -O props   SASL security properties\n"
"  -p port    port on LDAP server\n"
"  -Q         use SASL Quiet mode\n"
"  -R realm   SASL realm\n"
"  -U authcid SASL authentication identity\n"
"  -v         run in verbose mode (diagnostics to standard output)\n"
"  -w passwd  bind passwd (for simple authentication)\n"
"  -W         prompt for bind passwd\n"
"  -x         Simple authentication\n"
"  -X authzid SASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"  -y file    Read passwd from file\n"
"  -Y mech    SASL mechanism\n"
"  -Z         Start TLS request (-ZZ to require successful response)\n"
		, s );

	exit( EXIT_FAILURE );
}

int
main( int argc, char *argv[] )
{
	int rc;
	char	*prog = NULL;
	char	*ldaphost = NULL;
	char	*ldapuri = NULL;

	char	*user = NULL;
	char	*binddn = NULL;

	struct berval passwd = { 0, NULL };

	char	*pw_file = NULL;
	int		want_bindpw = 0;

	int		not = 0;
	int		i;
	int		ldapport = 0;
	int		debug = 0;
	int		version = -1;
	int		authmethod = -1;
#ifdef HAVE_CYRUS_SASL
	unsigned	sasl_flags = LDAP_SASL_AUTOMATIC;
	char		*sasl_realm = NULL;
	char		*sasl_authc_id = NULL;
	char		*sasl_authz_id = NULL;
	char		*sasl_mech = NULL;
	char		*sasl_secprops = NULL;
#endif
	int		use_tls = 0;
	int		referrals = 0;
	LDAP	       *ld = NULL;
	int	manageDSAit=0;
	int noop=0;
	char	*control, *cvalue;
	int		crit;

	int id, code = LDAP_OTHER;
	LDAPMessage *res;
	char *matcheddn = NULL, *text = NULL, **refs = NULL;
	char	*retoid = NULL;
	struct berval *retdata = NULL;

	prog = lutil_progname( "ldapwhoami", argc, argv );

	while( (i = getopt( argc, argv, 
		"Cd:D:e:h:H:InO:p:QR:U:vw:WxX:y:Y:Z" )) != EOF )
	{
		switch (i) {
	case 'E': /* whoami controls */
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -E incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}

		/* should be extended to support comma separated list of
		 *	[!]key[=value] parameters, e.g.  -E !foo,bar=567
		 */

		crit = 0;
		cvalue = NULL;
		if( optarg[0] == '!' ) {
			crit = 1;
			optarg++;
		}

		control = strdup( optarg );
		if ( (cvalue = strchr( control, '=' )) != NULL ) {
			*cvalue++ = '\0';
		}
		fprintf( stderr, "Invalid whoami control name: %s\n", control );
		usage(prog);
		return EXIT_FAILURE;

	/* Common Options (including options we don't use) */
	case 'C':
		referrals++;
		break;
	case 'd':
	    debug |= atoi( optarg );
	    break;
	case 'D':	/* bind DN */
		if( binddn != NULL ) {
			fprintf( stderr, "%s: -D previously specified\n", prog );
			return EXIT_FAILURE;
		}
	    binddn = strdup( optarg );
	    break;
	case 'e': /* general controls */
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -e incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}

		/* should be extended to support comma separated list of
		 *	[!]key[=value] parameters, e.g.  -e !foo,bar=567
		 */

		crit = 0;
		cvalue = NULL;
		if( optarg[0] == '!' ) {
			crit = 1;
			optarg++;
		}

		control = strdup( optarg );
		if ( (cvalue = strchr( control, '=' )) != NULL ) {
			*cvalue++ = '\0';
		}

		if ( strcasecmp( control, "manageDSAit" ) == 0 ) {
			if( manageDSAit ) {
				fprintf( stderr, "manageDSAit control previously specified");
				return EXIT_FAILURE;
			}
			if( cvalue != NULL ) {
				fprintf( stderr, "manageDSAit: no control value expected" );
				usage(prog);
				return EXIT_FAILURE;
			}

			manageDSAit = 1 + crit;
			free( control );
			break;
			
		} else if ( strcasecmp( control, "noop" ) == 0 ) {
			if( noop ) {
				fprintf( stderr, "noop control previously specified");
				return EXIT_FAILURE;
			}
			if( cvalue != NULL ) {
				fprintf( stderr, "noop: no control value expected" );
				usage(prog);
				return EXIT_FAILURE;
			}

			noop = 1 + crit;
			free( control );
			break;

		} else {
			fprintf( stderr, "Invalid general control name: %s\n", control );
			usage(prog);
			return EXIT_FAILURE;
		}
	case 'h':	/* ldap host */
		if( ldapuri != NULL ) {
			fprintf( stderr, "%s: -h incompatible with -H\n", prog );
			return EXIT_FAILURE;
		}
		if( ldaphost != NULL ) {
			fprintf( stderr, "%s: -h previously specified\n", prog );
			return EXIT_FAILURE;
		}
	    ldaphost = strdup( optarg );
	    break;
	case 'H':	/* ldap URI */
		if( ldaphost != NULL ) {
			fprintf( stderr, "%s: -H incompatible with -h\n", prog );
			return EXIT_FAILURE;
		}
		if( ldapport ) {
			fprintf( stderr, "%s: -H incompatible with -p\n", prog );
			return EXIT_FAILURE;
		}
		if( ldapuri != NULL ) {
			fprintf( stderr, "%s: -H previously specified\n", prog );
			return EXIT_FAILURE;
		}
	    ldapuri = strdup( optarg );
	    break;
	case 'I':
#ifdef HAVE_CYRUS_SASL
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -I incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n",
				prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_flags = LDAP_SASL_INTERACTIVE;
		break;
#else
		fprintf( stderr, "%s: was not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
	case 'k':	/* kerberos bind */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -k incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}

		if( authmethod != -1 ) {
			fprintf( stderr, "%s: -k incompatible with previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
			
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf( stderr, "%s: not compiled with Kerberos support\n", prog );
		return EXIT_FAILURE;
#endif
	    break;
	case 'K':	/* kerberos bind, part one only */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -k incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 ) {
			fprintf( stderr, "%s: incompatible with previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}

		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf( stderr, "%s: not compiled with Kerberos support\n", prog );
		return( EXIT_FAILURE );
#endif
	    break;
	case 'n':	/* print deletes, don't actually do them */
	    ++not;
	    break;
	case 'O':
#ifdef HAVE_CYRUS_SASL
		if( sasl_secprops != NULL ) {
			fprintf( stderr, "%s: -O previously specified\n", prog );
			return EXIT_FAILURE;
		}
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -O incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_secprops = strdup( optarg );
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'p':
		if( ldapport ) {
			fprintf( stderr, "%s: -p previously specified\n", prog );
			return EXIT_FAILURE;
		}
	    ldapport = atoi( optarg );
	    break;
	case 'P':
		switch( atoi(optarg) ) {
		case 2:
			if( version == LDAP_VERSION3 ) {
				fprintf( stderr, "%s: -P 2 incompatible with version %d\n",
					prog, version );
				return EXIT_FAILURE;
			}
			version = LDAP_VERSION2;
			break;
		case 3:
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -P 2 incompatible with version %d\n",
					prog, version );
				return EXIT_FAILURE;
			}
			version = LDAP_VERSION3;
			break;
		default:
			fprintf( stderr, "%s: protocol version should be 2 or 3\n",
				prog );
			usage( prog );
			return( EXIT_FAILURE );
		} break;
	case 'Q':
#ifdef HAVE_CYRUS_SASL
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -Q incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n",
				prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_flags = LDAP_SASL_QUIET;
		break;
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
	case 'R':
#ifdef HAVE_CYRUS_SASL
		if( sasl_realm != NULL ) {
			fprintf( stderr, "%s: -R previously specified\n", prog );
			return EXIT_FAILURE;
		}
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -R incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n",
				prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_realm = strdup( optarg );
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'U':
#ifdef HAVE_CYRUS_SASL
		if( sasl_authc_id != NULL ) {
			fprintf( stderr, "%s: -U previously specified\n", prog );
			return EXIT_FAILURE;
		}
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -U incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n",
				prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_authc_id = strdup( optarg );
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'v':	/* verbose mode */
	    verbose++;
	    break;
	case 'w':	/* password */
	    passwd.bv_val = strdup( optarg );
		{
			char* p;

			for( p = optarg; *p != '\0'; p++ ) {
				*p = '\0';
			}
		}
		passwd.bv_len = strlen( passwd.bv_val );
	    break;
	case 'W':
		want_bindpw++;
		break;
	case 'y':
		pw_file = optarg;
		break;
	case 'Y':
#ifdef HAVE_CYRUS_SASL
		if( sasl_mech != NULL ) {
			fprintf( stderr, "%s: -Y previously specified\n", prog );
			return EXIT_FAILURE;
		}
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -Y incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible with authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_mech = strdup( optarg );
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'x':
		if( authmethod != -1 && authmethod != LDAP_AUTH_SIMPLE ) {
			fprintf( stderr, "%s: incompatible with previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SIMPLE;
		break;
	case 'X':
#ifdef HAVE_CYRUS_SASL
		if( sasl_authz_id != NULL ) {
			fprintf( stderr, "%s: -X previously specified\n", prog );
			return EXIT_FAILURE;
		}
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -X incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: -X incompatible with "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
		sasl_authz_id = strdup( optarg );
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Z':
#ifdef HAVE_TLS
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -Z incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
		use_tls++;
#else
		fprintf( stderr, "%s: not compiled with TLS support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;


		default:
			fprintf( stderr, "%s: unrecognized option -%c\n",
				prog, optopt );
			usage (prog);
		}
	}

	if (authmethod == -1) {
#ifdef HAVE_CYRUS_SASL
		authmethod = LDAP_AUTH_SASL;
#else
		authmethod = LDAP_AUTH_SIMPLE;
#endif
	}

	if( argc - optind > 1 ) {
		usage( prog );
	} else if ( argc - optind == 1 ) {
		user = strdup( argv[optind] );
	} else {
		user = NULL;
	}

	if ( pw_file || want_bindpw ) {
		if ( pw_file ) {
			rc = lutil_get_filed_password( pw_file, &passwd );
			if( rc ) return EXIT_FAILURE;
		} else {
			passwd.bv_val = getpassphrase( "Enter LDAP Password: " );
			passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
		}
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
	if( ( ldaphost != NULL || ldapport ) && ( ldapuri == NULL ) ) {
		if ( verbose ) {
			fprintf( stderr, "ldap_init( %s, %d )\n",
				ldaphost != NULL ? ldaphost : "<DEFAULT>",
				ldapport );
		}

		ld = ldap_init( ldaphost, ldapport );
		if( ld == NULL ) {
			perror("ldapwhoami: ldap_init");
			return EXIT_FAILURE;
		}

	} else {
		if ( verbose ) {
			fprintf( stderr, "ldap_initialize( %s )\n",
				ldapuri != NULL ? ldapuri : "<DEFAULT>" );
		}

		rc = ldap_initialize( &ld, ldapuri );
		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "Could not create LDAP session handle (%d): %s\n",
				rc, ldap_err2string(rc) );
			return EXIT_FAILURE;
		}
	}

	/* referrals */
	if (ldap_set_option( ld, LDAP_OPT_REFERRALS,
		referrals ? LDAP_OPT_ON : LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_REFERRALS %s\n",
			referrals ? "on" : "off" );
		return EXIT_FAILURE;
	}

	/* LDAPv3 only */
	version = LDAP_VERSION3;
	rc = ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

	if(rc != LDAP_OPT_SUCCESS ) {
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
		return EXIT_FAILURE;
	}

	if ( use_tls && ( ldap_start_tls_s( ld, NULL, NULL ) != LDAP_SUCCESS )) {
		ldap_perror( ld, "ldap_start_tls" );
		if ( use_tls > 1 ) {
			return( EXIT_FAILURE );
		}
	}

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		void *defaults;

		if( sasl_secprops != NULL ) {
			rc = ldap_set_option( ld, LDAP_OPT_X_SASL_SECPROPS,
				(void *) sasl_secprops );
			
			if( rc != LDAP_OPT_SUCCESS ) {
				fprintf( stderr,
					"Could not set LDAP_OPT_X_SASL_SECPROPS: %s\n",
					sasl_secprops );
				return( EXIT_FAILURE );
			}
		}
		
		defaults = lutil_sasl_defaults( ld,
			sasl_mech,
			sasl_realm,
			sasl_authc_id,
			passwd.bv_val,
			sasl_authz_id );

		rc = ldap_sasl_interactive_bind_s( ld, binddn,
			sasl_mech, NULL, NULL,
			sasl_flags, lutil_sasl_interact, defaults );

		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_sasl_interactive_bind_s" );
			return( EXIT_FAILURE );
		}
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
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

	if ( not ) {
		rc = LDAP_SUCCESS;
		goto skip;
	}

	if ( manageDSAit || noop ) {
		int err, i = 0;
		LDAPControl c1, c2;
		LDAPControl *ctrls[3];

		if ( manageDSAit ) {
			ctrls[i++] = &c1;
			ctrls[i] = NULL;
			c1.ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
			c1.ldctl_value.bv_val = NULL;
			c1.ldctl_value.bv_len = 0;
			c1.ldctl_iscritical = manageDSAit > 1;
		}

		if ( noop ) {
			ctrls[i++] = &c2;
			ctrls[i] = NULL;

			c2.ldctl_oid = LDAP_CONTROL_NOOP;
			c2.ldctl_value.bv_val = NULL;
			c2.ldctl_value.bv_len = 0;
			c2.ldctl_iscritical = noop > 1;
		}
	
		err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, ctrls );

		if( err != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set %scontrols\n",
				(c1.ldctl_iscritical || c2.ldctl_iscritical)
				? "critical " : "" );
			if ( c1.ldctl_iscritical && c2.ldctl_iscritical ) {
				return EXIT_FAILURE;
			}
		}
	}

	rc = ldap_extended_operation( ld,
		LDAP_EXOP_X_WHO_AM_I, NULL, 
		NULL, NULL, &id );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_extended_operation" );
		ldap_unbind( ld );
		return EXIT_FAILURE;
	}

	rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, &res );
	if ( rc < 0 ) {
		ldap_perror( ld, "ldappasswd: ldap_result" );
		return rc;
	}

	rc = ldap_parse_result( ld, res, &code, &matcheddn, &text, &refs, NULL, 0 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_parse_result" );
		return rc;
	}

	rc = ldap_parse_extended_result( ld, res, &retoid, &retdata, 1 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_parse_result" );
		return rc;
	}

	if( retdata != NULL ) {
		if( retdata->bv_len == 0 ) {
			printf("anonymous\n" );
		} else {
			printf("%s\n", retdata->bv_val );
		}
	}

	if( verbose || ( code != LDAP_SUCCESS ) || matcheddn || text || refs ) {
		printf( "Result: %s (%d)\n", ldap_err2string( code ), code );

		if( text && *text ) {
			printf( "Additional info: %s\n", text );
		}

		if( matcheddn && *matcheddn ) {
			printf( "Matched DN: %s\n", matcheddn );
		}

		if( refs ) {
			int i;
			for( i=0; refs[i]; i++ ) {
				printf("Referral: %s\n", refs[i] );
			}
		}
	}

	ber_memfree( text );
	ber_memfree( matcheddn );
	ber_memvfree( (void **) refs );
	ber_memfree( retoid );
	ber_bvfree( retdata );

skip:
	/* disconnect from server */
	ldap_unbind (ld);

	return code == LDAP_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
